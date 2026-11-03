"""Microsoft Key Attestation V2 (EK-wrapped restricted HMAC key).

Server side of the V2 flow described in MS-WCCE:

* 3.2.2.6.2.1.2.7  challenge generation for an initial V2 request;
* 3.2.2.6.2.1.2.8  step 6, verification of the V2 challenge response.

How it works (TCG "EK-Based Key Attestation with TPM Firmware Version"):

1. The client sends szOID_ENROLL_EK_INFO plus the V2 attributes
   (szOID_ENROLL_V2_AIK_INFO, szOID_ENROLL_V2_ATTESTATION_STATEMENT,
   szOID_ENROLL_V2_CONTAINER_NAME).
2. The CA generates a random 32-byte HMAC key and a random 32-byte nonce and
   wraps the HMAC key to the EK public key with the TPM 2.0 duplication outer
   wrapper.  The client TPM can only import it (TPM2_Import) under the EK it
   owns, so a valid answer proves the V2 AIK lives in the TPM that owns the EK.
3. The client certifies its V2 AIK with the imported *restricted* HMAC key
   (TPM2_Certify, qualifying data = nonce).  The CA verifies the HMAC with the
   key it kept in its (encrypted) server state.

This module only does cryptography and encodings.  It never decides whether the
EK is *trusted*: that decision (EK certificate chain, EK public key allow-list,
inventory, ...) belongs to the ``emit_certificate`` callback, exactly like in
the V1 flow.

Interoperability notes (things Microsoft documents as CSP specific or leaves
open; each one is isolated in a small function/constant so it is easy to adapt
after a real Windows exchange):

* The wrapped key carried in szOID_ENROLL_ATTESTATION_CHALLENGE uses the
  "BKWT" container confirmed by Microsoft (28-byte little-endian header +
  TPM2B_ENCRYPTED_SECRET + TPM2B_PRIVATE + TPM2B_PUBLIC).  The size fields are
  written as the size of the whole TPM2B structure (2-byte size included).
* The V2 challenge is a DER CRYPT_ATTRIBUTES, encoded as SET OF Attribute
  (PKCS_ATTRIBUTES).  Switch ``CRYPT_ATTRIBUTES_OUTER_TAG`` to 0x30 if a client
  ever turns out to expect SEQUENCE OF.
* Unicode strings are encoded as BMPString, like szOID_ENROLL_KSP_NAME in the
  V1 challenge wrapper.
* The layout of the attestation claim returned by the client is CSP specific.
  ``verify_hmac_attestation_claim`` therefore accepts the layouts Microsoft
  already uses (KAST / KADS containers) as well as plain TPM2B sequences and
  size-prefixed containers.  Whatever the layout, acceptance only depends on
  strict checks: HMAC with the server-held key, nonce, TPM Name of the AIK and
  AIK public key equal to the one received in szOID_ENROLL_V2_AIK_INFO.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import tpm_attestation as tpm_mod

TPMAttestationError = tpm_mod.TPMAttestationError


class V2AttestationError(TPMAttestationError):
    """Raised when a V2 key attestation request or response is invalid."""


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

TPM2_ALG_HMAC = 0x0005
TPM2_ALG_KEYEDHASH = 0x0008

HMAC_KEY_SIZE = 32
NONCE_SIZE = 32
MAX_CONTAINER_NAME_LENGTH = 256

# Restricted signing HMAC key, importable under an EK: fixedTPM and fixedParent
# MUST be clear for TPM2_Import.  userWithAuth lets the client use it with an
# empty-auth password session; noDA avoids dictionary-attack lockouts.
RESTRICTED_HMAC_OBJECT_ATTRIBUTES = (
    tpm_mod.TPMA_OBJECT_SIGN
    | tpm_mod.TPMA_OBJECT_RESTRICTED
    | tpm_mod.TPMA_OBJECT_USERWITHAUTH
    | tpm_mod.TPMA_OBJECT_NODA
)

# "BKWT" wrapped-key container (Microsoft, szOID_ENROLL_ATTESTATION_CHALLENGE).
WRAPPED_KEY_MAGIC = b"BKWT"  # bytes 42 4B 57 54, i.e. the little-endian tag 'TWKB'
WRAPPED_KEY_VERSION = 1
WRAPPED_KEY_PLATFORM_TPM20 = 2
WRAPPED_KEY_HEADER_SIZE = 28

# PKCS_ATTRIBUTES: "Attributes ::= SET OF Attribute".
CRYPT_ATTRIBUTES_OUTER_TAG = 0x31

_SERVER_STATE_MAGIC = b"ADV2"
_SERVER_STATE_VERSION = 1
_ENCRYPTED_STATE_MAGIC = b"V2SE"
_ENCRYPTED_STATE_VERSION = 1
_STATE_OAEP_LABEL = b"adcs-python tpm key attestation v2 state"
_STATE_AAD_PREFIX = b"adcs-python/tpm-v2-state/v1|"


# --------------------------------------------------------------------------- #
# Minimal DER helpers (encode + tiny decoder for diagnostics/tests)
# --------------------------------------------------------------------------- #

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _base128(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    chunks = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7
    chunks.reverse()
    return bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])


def _der_oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise ValueError(f"Invalid OID: {dotted!r}")
    body = _base128(arcs[0] * 40 + arcs[1]) + b"".join(_base128(a) for a in arcs[2:])
    return _der_tlv(0x06, body)


def _der_octet_string(value: bytes) -> bytes:
    return _der_tlv(0x04, bytes(value))


def _der_bmp_string(value: str) -> bytes:
    return _der_tlv(0x1E, value.encode("utf-16-be"))


def _der_set_of(elements: list[bytes], tag: int = 0x31) -> bytes:
    # DER requires SET OF elements to be sorted by their encoding.
    return _der_tlv(tag, b"".join(sorted(elements)))


def _der_read(data: bytes, offset: int = 0) -> tuple[int, int, int, int]:
    """Return (tag, content_start, content_end, next_offset)."""
    if offset + 2 > len(data):
        raise ValueError("Truncated DER")
    tag = data[offset]
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("Unsupported DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("Truncated DER content")
    return tag, pos, end, end


def _der_children(data: bytes) -> list[bytes]:
    """Return the full TLV encodings of the children of a constructed value."""
    _tag, start, end, _next = _der_read(data, 0)
    out = []
    pos = start
    while pos < end:
        _t, _s, _e, nxt = _der_read(data, pos)
        out.append(data[pos:nxt])
        pos = nxt
    return out


def _der_decode_oid(content: bytes) -> str:
    values = []
    current = 0
    for byte in content:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(current)
            current = 0
    first = values[0]
    if first < 80:
        arcs = [first // 40, first % 40]
    else:
        arcs = [2, first - 80]
    return ".".join(str(a) for a in arcs + values[1:])


def encode_crypt_attributes(attributes: list[tuple[str, list[bytes]]]) -> bytes:
    """DER-encode a CRYPT_ATTRIBUTES structure.

    ``attributes`` is a list of ``(oid, [value_der, ...])`` where every value is
    already a complete DER element.
    """
    encoded = [
        _der_tlv(0x30, _der_oid(oid) + _der_set_of(list(values)))
        for oid, values in attributes
    ]
    return _der_set_of(encoded, tag=CRYPT_ATTRIBUTES_OUTER_TAG)


def decode_crypt_attributes(der: bytes) -> dict[str, list[bytes]]:
    """Decode CRYPT_ATTRIBUTES into ``{oid: [value_der, ...]}`` (diagnostics/tests)."""
    result: dict[str, list[bytes]] = {}
    for attribute in _der_children(der):
        oid_tlv, values_tlv = _der_children(attribute)
        _t, s, e, _n = _der_read(oid_tlv, 0)
        result.setdefault(_der_decode_oid(oid_tlv[s:e]), []).extend(_der_children(values_tlv))
    return result


def der_string_value(value_der: bytes) -> str:
    """Decode a BMPString / UTF8String / PrintableString element to ``str``."""
    tag, start, end, _next = _der_read(value_der, 0)
    content = value_der[start:end]
    if tag == 0x1E:
        return content.decode("utf-16-be")
    if tag in (0x0C, 0x13, 0x16):
        return content.decode("utf-8")
    raise ValueError(f"Unsupported string tag 0x{tag:02x}")


# --------------------------------------------------------------------------- #
# TPM structures for the restricted HMAC key
# --------------------------------------------------------------------------- #

def _tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def tpm_object_name(public: bytes, name_alg: int) -> bytes:
    """TPM Name = nameAlg || H(TPMT_PUBLIC)."""
    digest = hashlib.new(tpm_mod._tpm_alg_to_hash(name_alg), public).digest()
    return struct.pack(">H", name_alg) + digest


def build_restricted_hmac_public(
    *,
    unique: bytes,
    name_alg: int = tpm_mod.TPM2_ALG_SHA256,
    scheme_hash_alg: int = tpm_mod.TPM2_ALG_SHA256,
    object_attributes: int = RESTRICTED_HMAC_OBJECT_ATTRIBUTES,
) -> bytes:
    """Marshal the TPMT_PUBLIC of a restricted HMAC (KEYEDHASH) signing key."""
    return (
        struct.pack(">HHI", TPM2_ALG_KEYEDHASH, name_alg, object_attributes)
        + _tpm2b(b"")  # authPolicy
        + struct.pack(">HH", TPM2_ALG_HMAC, scheme_hash_alg)  # TPMT_KEYEDHASH_SCHEME
        + _tpm2b(unique)  # TPM2B_DIGEST
    )


def build_sensitive_2b(seed_value: bytes, key: bytes) -> bytes:
    """Marshal TPM2B_SENSITIVE for a KEYEDHASH object (empty authValue)."""
    sensitive = (
        struct.pack(">H", TPM2_ALG_KEYEDHASH)
        + _tpm2b(b"")  # authValue
        + _tpm2b(seed_value)
        + _tpm2b(key)
    )
    return _tpm2b(sensitive)


@dataclass(frozen=True)
class WrappedHmacKey:
    """Importable restricted HMAC key, ready for TPM2_Import under the EK."""

    public: bytes       # TPMT_PUBLIC of the HMAC key (TPM2B_PUBLIC content)
    duplicate: bytes    # TPM2B_PRIVATE content (outer wrapper only)
    in_sym_seed: bytes  # TPM2B_ENCRYPTED_SECRET content
    name: bytes         # TPM Name of the HMAC key


def ek_default_symmetric_bits(ek_name_alg: int) -> int:
    """AES key size of the default EK templates (TCG EK Credential Profile)."""
    if ek_name_alg in (tpm_mod.TPM2_ALG_SHA1, tpm_mod.TPM2_ALG_SHA256):
        return 128
    return 256


def _encrypt_seed_to_ek(ek_pub, ek_name_alg: int, label: str) -> tuple[bytes, bytes]:
    """Return (seed, encrypted_secret) for the TPM duplication seed."""
    hash_name = tpm_mod._tpm_alg_to_hash(ek_name_alg)
    hash_size = hashlib.new(hash_name).digest_size
    hash_obj = tpm_mod._tpm_alg_to_hash_obj(ek_name_alg)
    if isinstance(ek_pub, rsa.RSAPublicKey):
        if ek_pub.key_size < 2048:
            raise V2AttestationError("RSA EK smaller than 2048 bits is not supported")
        seed = os.urandom(hash_size)
        encrypted = ek_pub.encrypt(
            seed,
            padding.OAEP(mgf=padding.MGF1(hash_obj), algorithm=hash_obj, label=label.encode("ascii") + b"\x00"),
        )
        return seed, encrypted
    if isinstance(ek_pub, ec.EllipticCurvePublicKey):
        ephemeral = ec.generate_private_key(ek_pub.curve)
        shared_z = ephemeral.exchange(ec.ECDH(), ek_pub)
        eph_bytes = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        ek_bytes = ek_pub.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        coord = (ek_pub.key_size + 7) // 8
        seed = tpm_mod._kdfe(
            ek_name_alg, shared_z, label, eph_bytes[1:1 + coord], ek_bytes[1:1 + coord], hash_size * 8
        )
        return seed, _tpm2b(eph_bytes[1:1 + coord]) + _tpm2b(eph_bytes[1 + coord:])
    raise V2AttestationError(f"Unsupported EK public key type: {type(ek_pub).__name__}")


def wrap_restricted_hmac_key_to_ek(
    ek_pub,
    hmac_key: bytes,
    *,
    ek_name_alg: Optional[int] = None,
    ek_sym_bits: Optional[int] = None,
    seed_value: Optional[bytes] = None,
) -> WrappedHmacKey:
    """Wrap ``hmac_key`` to ``ek_pub`` with the TPM 2.0 duplication outer wrapper.

    The result can be imported by the TPM that owns the EK with
    ``TPM2_Import(parentHandle = EK, duplicate, inSymSeed)`` (no inner wrapper).
    """
    if len(hmac_key) != HMAC_KEY_SIZE:
        raise ValueError(f"HMAC key must be {HMAC_KEY_SIZE} bytes")
    if ek_name_alg is None:
        ek_name_alg = tpm_mod.infer_ek_name_alg_from_public_key(ek_pub)
    if ek_sym_bits is None:
        ek_sym_bits = ek_default_symmetric_bits(ek_name_alg)
    ek_hash = tpm_mod._tpm_alg_to_hash(ek_name_alg)
    ek_hash_size = hashlib.new(ek_hash).digest_size

    key_name_alg = tpm_mod.TPM2_ALG_SHA256
    if seed_value is None:
        seed_value = os.urandom(hashlib.new("sha256").digest_size)
    # For KEYEDHASH objects the public "unique" field is H(seedValue || key).
    unique = hashlib.sha256(seed_value + hmac_key).digest()
    public = build_restricted_hmac_public(unique=unique, name_alg=key_name_alg)
    name = tpm_object_name(public, key_name_alg)
    sensitive = build_sensitive_2b(seed_value, hmac_key)

    seed, in_sym_seed = _encrypt_seed_to_ek(ek_pub, ek_name_alg, "DUPLICATE")
    sym_key = tpm_mod._kdfa(ek_name_alg, seed, "STORAGE", name, b"", ek_sym_bits)
    enc_sensitive = Cipher(algorithms.AES(sym_key), modes.CFB(b"\x00" * 16)).encryptor().update(sensitive)
    integrity_key = tpm_mod._kdfa(ek_name_alg, seed, "INTEGRITY", b"", b"", ek_hash_size * 8)
    outer_hmac = hmac.new(integrity_key, enc_sensitive + name, ek_hash).digest()
    return WrappedHmacKey(
        public=public,
        duplicate=_tpm2b(outer_hmac) + enc_sensitive,
        in_sym_seed=in_sym_seed,
        name=name,
    )


def build_wrapped_key_blob(wrapped: WrappedHmacKey) -> bytes:
    """Build the Microsoft "BKWT" value of szOID_ENROLL_ATTESTATION_CHALLENGE."""
    encrypted_secret = _tpm2b(wrapped.in_sym_seed)
    private = _tpm2b(wrapped.duplicate)
    public = _tpm2b(wrapped.public)
    header = WRAPPED_KEY_MAGIC + struct.pack(
        "<6I",
        WRAPPED_KEY_VERSION,
        WRAPPED_KEY_PLATFORM_TPM20,
        WRAPPED_KEY_HEADER_SIZE,
        len(encrypted_secret),
        len(private),
        len(public),
    )
    return header + encrypted_secret + private + public


def parse_wrapped_key_blob(blob: bytes) -> dict:
    """Parse a BKWT blob (diagnostics and tests)."""
    if len(blob) < WRAPPED_KEY_HEADER_SIZE or blob[:4] != WRAPPED_KEY_MAGIC:
        raise V2AttestationError("Not a BKWT wrapped key blob")
    version, platform, header_size, cb_secret, cb_private, cb_public = struct.unpack_from("<6I", blob, 4)
    if (version, platform, header_size) != (
        WRAPPED_KEY_VERSION, WRAPPED_KEY_PLATFORM_TPM20, WRAPPED_KEY_HEADER_SIZE
    ):
        raise V2AttestationError("Unexpected BKWT header values")
    if header_size + cb_secret + cb_private + cb_public != len(blob):
        raise V2AttestationError("BKWT sizes do not match the blob length")
    areas = []
    pos = header_size
    for size in (cb_secret, cb_private, cb_public):
        area = blob[pos:pos + size]
        if len(area) < 2 or struct.unpack(">H", area[:2])[0] != len(area) - 2:
            raise V2AttestationError("BKWT area is not a canonical TPM2B")
        areas.append(area[2:])
        pos += size
    return {"encrypted_secret": areas[0], "private": areas[1], "public": areas[2]}


# --------------------------------------------------------------------------- #
# Challenge generation (MS-WCCE 3.2.2.6.2.1.2.7)
# --------------------------------------------------------------------------- #

def ek_challenge_algorithm_attributes(ek_pub) -> tuple[str, str]:
    """CNG algorithm name and key size (decimal string) of the EK."""
    if isinstance(ek_pub, rsa.RSAPublicKey):
        return "RSA", str(ek_pub.key_size)
    if isinstance(ek_pub, ec.EllipticCurvePublicKey):
        return f"ECDH_P{ek_pub.key_size}", str(ek_pub.key_size)
    raise V2AttestationError(f"Unsupported EK public key type: {type(ek_pub).__name__}")


def validate_container_name(container_name: Optional[str]) -> str:
    if not container_name or not container_name.strip():
        raise V2AttestationError("szOID_ENROLL_V2_CONTAINER_NAME is empty")
    if len(container_name) > MAX_CONTAINER_NAME_LENGTH:
        raise V2AttestationError("szOID_ENROLL_V2_CONTAINER_NAME is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in container_name):
        raise V2AttestationError("szOID_ENROLL_V2_CONTAINER_NAME contains control characters")
    if not container_name.startswith("V2AIK-"):
        raise V2AttestationError(
            f"Invalid V2 AIK container name: {container_name!r}"
        )
    return container_name


def build_v2_challenge_attributes(
    *,
    wrapped_key_blob: bytes,
    nonce: bytes,
    container_name: str,
    ek_algorithm: str,
    ek_parameter: str,
) -> bytes:
    """DER CRYPT_ATTRIBUTES carried as the V2 attestation challenge."""
    return encode_crypt_attributes(
        [
            (tpm_mod.OID_ENROLL_ATTESTATION_CHALLENGE, [_der_octet_string(wrapped_key_blob)]),
            (tpm_mod.OID_VERISIGN_SENDER_NONCE, [_der_octet_string(nonce)]),
            (tpm_mod.OID_ENROLL_V2_CONTAINER_NAME, [_der_bmp_string(container_name)]),
            (tpm_mod.OID_ENROLL_V2_EK_ALGORITHM, [_der_bmp_string(ek_algorithm)]),
            (tpm_mod.OID_ENROLL_V2_EK_PARAMETER, [_der_bmp_string(ek_parameter)]),
        ]
    )


@dataclass(frozen=True)
class V2Challenge:
    challenge_der: bytes  # value to place in the CMC attestation challenge attribute
    server_state: bytes   # plaintext server state; encrypt before persisting
    nonce: bytes
    wrapped_key_blob: bytes


def create_v2_challenge(*, ek_pub, aik_spki_der: bytes, container_name: str) -> V2Challenge:
    container_name = validate_container_name(container_name)
    hmac_key = os.urandom(HMAC_KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    wrapped = wrap_restricted_hmac_key_to_ek(ek_pub, hmac_key)
    blob = build_wrapped_key_blob(wrapped)
    ek_algorithm, ek_parameter = ek_challenge_algorithm_attributes(ek_pub)
    return V2Challenge(
        challenge_der=build_v2_challenge_attributes(
            wrapped_key_blob=blob,
            nonce=nonce,
            container_name=container_name,
            ek_algorithm=ek_algorithm,
            ek_parameter=ek_parameter,
        ),
        server_state=pack_server_state(hmac_key, nonce, aik_spki_der),
        nonce=nonce,
        wrapped_key_blob=blob,
    )


# --------------------------------------------------------------------------- #
# Server state (HMAC key, nonce, AIK SPKI) encrypted to the CA exchange cert
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class V2ServerState:
    hmac_key: bytes
    nonce: bytes
    aik_spki_der: bytes


def pack_server_state(hmac_key: bytes, nonce: bytes, aik_spki_der: bytes) -> bytes:
    if len(hmac_key) != HMAC_KEY_SIZE or len(nonce) != NONCE_SIZE or not aik_spki_der:
        raise ValueError("Invalid V2 server state")
    return (
        _SERVER_STATE_MAGIC
        + struct.pack(">BHHH", _SERVER_STATE_VERSION, len(hmac_key), len(nonce), len(aik_spki_der))
        + hmac_key
        + nonce
        + aik_spki_der
    )


def unpack_server_state(data: bytes) -> V2ServerState:
    header = len(_SERVER_STATE_MAGIC) + 7
    if len(data) < header or data[:4] != _SERVER_STATE_MAGIC:
        raise V2AttestationError("Invalid V2 server state")
    version, n_key, n_nonce, n_spki = struct.unpack_from(">BHHH", data, 4)
    if version != _SERVER_STATE_VERSION or len(data) != header + n_key + n_nonce + n_spki:
        raise V2AttestationError("Invalid V2 server state")
    body = data[header:]
    return V2ServerState(body[:n_key], body[n_key:n_key + n_nonce], body[n_key + n_nonce:])


def _state_aad(request_id) -> bytes:
    return _STATE_AAD_PREFIX + str(int(request_id)).encode("ascii")


def encrypt_server_state(state: bytes, ket_public_key, request_id) -> bytes:
    """Encrypt the server state to the CA exchange certificate public key.

    RSA-OAEP(SHA-256) wraps a fresh AES-256-GCM key; the request id is bound as
    associated data so a state blob cannot be moved to another request.
    """
    if not isinstance(ket_public_key, rsa.RSAPublicKey):
        raise V2AttestationError("The CA exchange certificate must hold an RSA key to protect the V2 state")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped_key = ket_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=_STATE_OAEP_LABEL),
    )
    ciphertext = AESGCM(aes_key).encrypt(nonce, state, _state_aad(request_id))
    return (
        _ENCRYPTED_STATE_MAGIC
        + struct.pack(">BH", _ENCRYPTED_STATE_VERSION, len(wrapped_key))
        + wrapped_key
        + nonce
        + ciphertext
    )


def decrypt_server_state(blob: bytes, ket_private_key, request_id) -> bytes:
    if not isinstance(ket_private_key, rsa.RSAPrivateKey):
        raise V2AttestationError("The CA exchange key must be an RSA key to open the V2 state")
    if len(blob) < 7 + 12 + 16 or blob[:4] != _ENCRYPTED_STATE_MAGIC:
        raise V2AttestationError("Invalid encrypted V2 server state")
    version, wrapped_len = struct.unpack_from(">BH", blob, 4)
    if version != _ENCRYPTED_STATE_VERSION or 7 + wrapped_len + 12 + 16 > len(blob):
        raise V2AttestationError("Invalid encrypted V2 server state")
    wrapped_key = blob[7:7 + wrapped_len]
    nonce = blob[7 + wrapped_len:7 + wrapped_len + 12]
    ciphertext = blob[7 + wrapped_len + 12:]
    try:
        aes_key = ket_private_key.decrypt(
            wrapped_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=_STATE_OAEP_LABEL),
        )
        return AESGCM(aes_key).decrypt(nonce, ciphertext, _state_aad(request_id))
    except Exception:
        raise V2AttestationError("V2 server state could not be decrypted") from None


# --------------------------------------------------------------------------- #
# V2 AIK public key (szOID_ENROLL_V2_AIK_INFO)
# --------------------------------------------------------------------------- #

def load_v2_aik_public_key(decrypted_aik_info: bytes):
    """Return ``(public_key, spki_der)`` from the decrypted szOID_ENROLL_V2_AIK_INFO.

    The spec says the content is a DER SubjectPublicKeyInfo.  A SEQUENCE OF ANY
    whose first element is the SPKI (V1 AttestationIdentityKeyInfo style) is
    accepted as a fallback.
    """
    candidates = [decrypted_aik_info]
    try:
        candidates.append(_der_children(decrypted_aik_info)[0])
    except Exception:
        pass
    key = None
    for candidate in candidates:
        try:
            key = serialization.load_der_public_key(candidate)
            break
        except Exception:
            continue
    if key is None:
        raise V2AttestationError("szOID_ENROLL_V2_AIK_INFO does not contain a SubjectPublicKeyInfo")
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise V2AttestationError("V2 AIK RSA key is smaller than 2048 bits")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
            raise V2AttestationError("Unsupported V2 AIK curve")
    else:
        raise V2AttestationError(f"Unsupported V2 AIK key type: {type(key).__name__}")
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, spki


def _tpm_public_from_cryptography(pub) -> "tpm_mod.TPMPublicKey":
    """Build a TPMPublicKey view of a cryptography public key (signature checks only)."""
    if isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        return tpm_mod.TPMPublicKey(
            alg_type=tpm_mod.TPM2_ALG_RSA,
            name_alg=tpm_mod.TPM2_ALG_SHA256,
            object_attr=0,
            auth_policy=b"",
            rsa_key_bits=pub.key_size,
            rsa_exponent=numbers.e,
            rsa_modulus=numbers.n.to_bytes((pub.key_size + 7) // 8, "big"),
        )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        numbers = pub.public_numbers()
        curve = {256: tpm_mod.TPM2_ECC_NIST_P256, 384: tpm_mod.TPM2_ECC_NIST_P384}.get(pub.key_size)
        if curve is None:
            raise V2AttestationError("Unsupported V2 AIK curve")
        size = (pub.key_size + 7) // 8
        return tpm_mod.TPMPublicKey(
            alg_type=tpm_mod.TPM2_ALG_ECC,
            name_alg=tpm_mod.TPM2_ALG_SHA256,
            object_attr=0,
            auth_policy=b"",
            ecc_curve=curve,
            ecc_x=numbers.x.to_bytes(size, "big"),
            ecc_y=numbers.y.to_bytes(size, "big"),
        )
    raise V2AttestationError(f"Unsupported V2 AIK key type: {type(pub).__name__}")


# --------------------------------------------------------------------------- #
# Request time: subject-only statement certified by the V2 AIK
# --------------------------------------------------------------------------- #

def validate_v2_subject_attestation(statement_raw: bytes, aik_public_key, csr_public_key) -> dict:
    """Validate szOID_ENROLL_V2_ATTESTATION_STATEMENT (MS-WCCE 3.2.2.6.2.1.2.7 step 2).

    The statement is a subject-only claim: the V2 AIK (public key received in
    szOID_ENROLL_V2_AIK_INFO) certifies the key of the CSR.  Whether that AIK
    really lives in the TPM that owns the EK is proven later by the HMAC
    challenge.
    """
    if not statement_raw:
        raise V2AttestationError("Missing szOID_ENROLL_V2_ATTESTATION_STATEMENT")
    try:
        key_attestation = tpm_mod._parse_microsoft_key_attestation_statement(statement_raw)["key_attestation"]
    except Exception:
        key_attestation = statement_raw  # bare keyAttestation (KADS)
    try:
        parsed = tpm_mod._parse_microsoft_key_attestation(key_attestation)
    except Exception as exc:
        raise V2AttestationError(f"Unrecognised V2 attestation statement: {exc}") from None
    key_attest_raw, signature_raw, key_blob = parsed["key_attest"], parsed["signature"], parsed["key_blob"]
    if not key_attest_raw or not signature_raw or not key_blob:
        raise V2AttestationError("V2 attestation statement is missing keyAttest, signature or keyBlob")

    aik_tpm_pub = _tpm_public_from_cryptography(aik_public_key)
    tpm_mod._verify_microsoft_key_attestation_signature(key_attest_raw, signature_raw, aik_tpm_pub)
    key_attest = tpm_mod.parse_tpms_attest(key_attest_raw)
    if key_attest.magic != tpm_mod.TPM2_GENERATED_VALUE:
        raise V2AttestationError("V2 keyAttest is not TPM generated")
    if key_attest.attest_type != tpm_mod.TPM2_ST_ATTEST_CERTIFY:
        raise V2AttestationError("V2 keyAttest is not a TPM2_Certify statement")
    if not key_attest.certified_name:
        raise V2AttestationError("V2 keyAttest does not contain a certified name")

    csr_spki = csr_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for candidate in tpm_mod._iter_tpmt_public_candidates(key_blob):
        try:
            candidate_spki = candidate.to_cryptography_public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception:
            continue
        if candidate_spki != csr_spki:
            continue
        if not hmac.compare_digest(candidate.compute_name(), key_attest.certified_name):
            continue
        tpm_mod._check_key_policy(
            candidate,
            require_fixed_tpm=True,
            require_fixed_parent=True,
            require_restricted=False,
            require_sensitive_data_origin=True,
        )
        return {
            "certified_key_obj": candidate,
            "certified_key_name": key_attest.certified_name,
            "firmware_version": key_attest.firmware_version,
            "certified_key_attributes": tpm_mod.tpm_object_attributes_to_dict(candidate.object_attr),
            "certified_key_name_alg": tpm_mod._tpm_alg_name(candidate.name_alg),
            "certified_key_alg": tpm_mod._tpm_alg_name(candidate.alg_type),
        }
    raise V2AttestationError("CSR public key is not the TPM key certified by the V2 AIK")


# --------------------------------------------------------------------------- #
# Response time: HMAC-certified V2 AIK
# --------------------------------------------------------------------------- #

_HASH_ALG_BY_SIZE = {
    32: tpm_mod.TPM2_ALG_SHA256,
    48: tpm_mod.TPM2_ALG_SHA384,
    64: tpm_mod.TPM2_ALG_SHA512,
}


def _digest_size(hash_alg: int) -> Optional[int]:
    try:
        return hashlib.new(tpm_mod._tpm_alg_to_hash(hash_alg)).digest_size
    except Exception:
        return None


def _is_inline_hmac_signature(data: bytes) -> bool:
    """True if ``data`` is exactly a TPMT_SIGNATURE carrying an HMAC (TPMT_HA)."""
    if len(data) < 4 or struct.unpack(">H", data[:2])[0] != TPM2_ALG_HMAC:
        return False
    size = _digest_size(struct.unpack(">H", data[2:4])[0])
    return size is not None and len(data) == 4 + size


def _hmac_signature_candidates(signature: bytes) -> list[tuple[int, bytes]]:
    """(hash_alg, digest) candidates for an HMAC signature field.

    Accepts TPMT_SIGNATURE, TPM2B_SIGNATURE and a bare HMAC output.
    """
    out: list[tuple[int, bytes]] = []
    if _is_inline_hmac_signature(signature):
        out.append((struct.unpack(">H", signature[2:4])[0], signature[4:]))
    if len(signature) >= 6 and struct.unpack(">H", signature[:2])[0] == len(signature) - 2:
        out.extend(_hmac_signature_candidates(signature[2:]))
    if len(signature) in _HASH_ALG_BY_SIZE:
        out.append((_HASH_ALG_BY_SIZE[len(signature)], signature))
    return out


def _layouts_from_kads(blob: bytes, label: str) -> list[dict]:
    try:
        parsed = tpm_mod._parse_microsoft_key_attestation(blob)
    except Exception:
        return []
    if not parsed["key_attest"] or not parsed["signature"]:
        return []
    return [
        {
            "layout": label,
            "attest": parsed["key_attest"],
            "signatures": [parsed["signature"]],
            "publics": list(tpm_mod._iter_tpmt_public_candidates(parsed["key_blob"])),
        }
    ]


def _layouts_from_tpm2b_sequence(blob: bytes, label: str) -> list[dict]:
    """Classify a sequence of TPM2B items (+ optional trailing inline signature)."""
    items: list[bytes] = []
    trailing = b""
    pos = 0
    while pos < len(blob):
        if _is_inline_hmac_signature(blob[pos:]) or pos + 2 > len(blob):
            trailing = blob[pos:]
            break
        size = struct.unpack(">H", blob[pos:pos + 2])[0]
        if pos + 2 + size > len(blob):
            trailing = blob[pos:]
            break
        items.append(blob[pos + 2:pos + 2 + size])
        pos += 2 + size
    attests = [item for item in items if item[:4] == struct.pack(">I", tpm_mod.TPM2_GENERATED_VALUE)]
    publics = []
    for item in items:
        try:
            publics.append(tpm_mod.parse_tpmt_public(item))
        except Exception:
            continue
    signatures = [item for item in items if _hmac_signature_candidates(item)]
    if trailing:
        signatures.append(trailing)
    if not attests or not signatures:
        return []
    return [{"layout": label, "attest": attest, "signatures": signatures, "publics": publics} for attest in attests]


def _strip_tagged_container(claim: bytes) -> Optional[bytes]:
    """Strip a Microsoft-style tagged header (4-char magic, version, platform,
    header size, then area sizes) and return the concatenated areas."""
    if len(claim) < 16 or not all(0x20 <= b < 0x7F for b in claim[:4]):
        return None
    version, platform, header_size = struct.unpack_from("<3I", claim, 4)
    if version > 255 or platform not in (1, 2) or not 16 <= header_size <= min(64, len(claim)):
        return None
    count = (header_size - 16) // 4
    sizes = struct.unpack_from(f"<{count}I", claim, 16) if count else ()
    if sum(sizes) != len(claim) - header_size:
        return None
    return claim[header_size:]


def _candidate_layouts(claim: bytes, _depth: int = 0) -> list[dict]:
    layouts: list[dict] = []
    try:
        statement = tpm_mod._parse_microsoft_key_attestation_statement(claim)
        layouts += _layouts_from_kads(statement["key_attestation"], "KAST/KADS")
    except Exception:
        pass
    layouts += _layouts_from_kads(claim, "KADS")
    layouts += _layouts_from_tpm2b_sequence(claim, "TPM2B sequence")
    stripped = _strip_tagged_container(claim)
    if stripped is not None:
        layouts += _layouts_from_tpm2b_sequence(stripped, "tagged container")
    if _depth == 0 and claim[:1] == b"\x04":
        # Content that was wrapped in a DER OCTET STRING by the client.
        try:
            _tag, start, end, nxt = _der_read(claim, 0)
        except ValueError:
            return layouts
        if nxt == len(claim):
            layouts += _candidate_layouts(claim[start:end], 1)
    return layouts


def _verify_claim_layout(layout: dict, *, hmac_key: bytes, nonce: bytes, expected_aik_spki_der: bytes) -> dict:
    attest_raw = layout["attest"]

    # 1. Authenticity: only a TPM that imported the EK-wrapped key can compute this.
    hmac_hash_alg = None
    for signature in layout["signatures"]:
        for hash_alg, digest in _hmac_signature_candidates(signature):
            try:
                expected = hmac.new(hmac_key, attest_raw, tpm_mod._tpm_alg_to_hash(hash_alg)).digest()
            except Exception:
                continue
            if hmac.compare_digest(expected, digest):
                hmac_hash_alg = hash_alg
                break
        if hmac_hash_alg is not None:
            break
    if hmac_hash_alg is None:
        raise V2AttestationError("HMAC over TPMS_ATTEST does not verify with the server-held key")

    # 2. The attested structure is a fresh TPM2_Certify bound to our nonce.
    attest = tpm_mod.parse_tpms_attest(attest_raw)
    if attest.magic != tpm_mod.TPM2_GENERATED_VALUE:
        raise V2AttestationError("TPMS_ATTEST is not TPM generated")
    if attest.attest_type != tpm_mod.TPM2_ST_ATTEST_CERTIFY:
        raise V2AttestationError("TPMS_ATTEST is not a TPM2_Certify statement")
    if not hmac.compare_digest(attest.extra_data, nonce):
        raise V2AttestationError("TPMS_ATTEST qualifying data does not match the challenge nonce")
    if not attest.certified_name:
        raise V2AttestationError("TPMS_ATTEST does not contain a certified name")

    # 3. The certified object is the AIK received in szOID_ENROLL_V2_AIK_INFO.
    aik = None
    for candidate in layout["publics"]:
        if hmac.compare_digest(candidate.compute_name(), attest.certified_name):
            aik = candidate
            break
    if aik is None:
        raise V2AttestationError("No AIK public area in the claim matches the certified TPM Name")
    tpm_mod._check_aik_attributes(aik)
    aik_spki = aik.to_cryptography_public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(aik_spki, expected_aik_spki_der):
        raise V2AttestationError("AIK public key in the claim differs from szOID_ENROLL_V2_AIK_INFO")

    aik_name = aik.compute_name()
    return {
        "layout": layout["layout"],
        "aik_public_key": aik,
        "aik_name": aik_name,
        "aik_name_b64": base64.b64encode(aik_name).decode("ascii"),
        "firmware_version": attest.firmware_version,
        "hmac_hash_alg": tpm_mod._tpm_alg_name(hmac_hash_alg),
    }


def verify_hmac_attestation_claim(
    claim: bytes,
    *,
    hmac_key: bytes,
    nonce: bytes,
    expected_aik_spki_der: bytes,
) -> dict:
    """Verify the attestation claim of a V2 challenge response.

    MS-WCCE 3.2.2.6.2.1.2.8 step 6: validate the claim with the recovered HMAC
    key and nonce, and check that the AIK public key of the claim equals the AIK
    SubjectPublicKeyInfo kept in the server state.
    """
    if not claim:
        raise V2AttestationError("Empty V2 attestation claim")
    layouts = _candidate_layouts(claim)
    if not layouts:
        raise V2AttestationError("Unrecognised V2 attestation claim layout")
    failures = []
    for layout in layouts:
        try:
            return _verify_claim_layout(
                layout, hmac_key=hmac_key, nonce=nonce, expected_aik_spki_der=expected_aik_spki_der
            )
        except Exception as exc:
            failures.append(f"{layout['layout']}: {exc}")
    raise V2AttestationError("; ".join(failures))
