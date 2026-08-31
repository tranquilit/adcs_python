"""Microsoft MS-WCCE 55 Restricted-HMAC TPM primitives.

This module contains only the cryptographic and binary primitives used by the
normal AD CS CMC/PKCS#10 V2 enrollment flow.  The retired SCEP messageType
198/41 bootstrap and its RA signing/encryption machinery are intentionally not
part of the supported surface.

The value of ``szOID_ENROLL_ATTESTATION_CHALLENGE`` is the Microsoft ``BKWT``
carrier: a 28-byte little-endian header followed by canonical big-endian
``TPM2B_ENCRYPTED_SECRET``, ``TPM2B_PRIVATE`` and ``TPM2B_PUBLIC`` structures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from asn1crypto import algos as a_algos
from asn1crypto import cms as a_cms
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    TripleDES = algorithms.TripleDES

import tpm_attestation as tpm_mod


TPM2_ALG_HMAC = 0x0005
TPM2_ALG_SHA256 = 0x000B
TPM2_ALG_KEYEDHASH = 0x0008
TPM2_ALG_AES = 0x0006
TPM2_ALG_CFB = 0x0043
TPMA_OBJECT_USERWITHAUTH = 0x00000040
TPMA_OBJECT_NODA = 0x00000400
TPMA_OBJECT_RESTRICTED = 0x00010000
TPMA_OBJECT_SIGN_ENCRYPT = 0x00040000

HMAC_KEY_BYTES = 32
NONCE_BYTES = 32
STATE_PROTOCOL = "v2_restricted_hmac_cmc"

WINDOWS_WRAPPED_KEY_MAGIC = b"BKWT"
WINDOWS_WRAPPED_KEY_VERSION = 1
WINDOWS_WRAPPED_KEY_PLATFORM_TPM20 = 2
WINDOWS_WRAPPED_KEY_HEADER_SIZE = 28


class RestrictedHMACError(ValueError):
    """Raised when a Restricted-HMAC proof or carrier is invalid."""


@dataclass(frozen=True)
class RestrictedHMACSecrets:
    hmac_key: bytes
    nonce: bytes

    def __post_init__(self):
        if len(self.hmac_key) != HMAC_KEY_BYTES:
            raise RestrictedHMACError("Restricted HMAC key must be exactly 32 bytes")
        if len(self.nonce) != NONCE_BYTES:
            raise RestrictedHMACError("Restricted HMAC nonce must be exactly 32 bytes")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def generate_restricted_hmac_secrets() -> RestrictedHMACSecrets:
    return RestrictedHMACSecrets(
        hmac_key=os.urandom(HMAC_KEY_BYTES),
        nonce=os.urandom(NONCE_BYTES),
    )


def _decode_hmac_signature(signature: bytes) -> bytes:
    if len(signature) == HMAC_KEY_BYTES:
        return signature
    # TPMT_SIGNATURE(TPM_ALG_HMAC) = sigAlg || hashAlg || digest[hash-size].
    if len(signature) == 4 + HMAC_KEY_BYTES:
        sig_alg, hash_alg = struct.unpack_from(">HH", signature, 0)
        if sig_alg != TPM2_ALG_HMAC:
            raise RestrictedHMACError(
                f"AIK claim signature algorithm is not TPM_ALG_HMAC: {sig_alg:#06x}"
            )
        if hash_alg != TPM2_ALG_SHA256:
            raise RestrictedHMACError(
                f"AIK claim HMAC hash is not SHA256: {hash_alg:#06x}"
            )
        return signature[4:]
    # Some TPM marshalling layers expose the digest as TPM2B_DIGEST.
    if len(signature) == 6 + HMAC_KEY_BYTES:
        sig_alg, hash_alg, size = struct.unpack_from(">HHH", signature, 0)
        if sig_alg == TPM2_ALG_HMAC and hash_alg == TPM2_ALG_SHA256 and size == HMAC_KEY_BYTES:
            return signature[6:]
    raise RestrictedHMACError("Unsupported TPM HMAC signature encoding in AIK claim")


def _parse_restricted_hmac_claim_strict(attestation_claim_der: bytes) -> tuple[dict, dict]:
    """Parse exactly one canonical KAST/keyAttestation pair.

    The legacy parser intentionally searches for a KAST marker so it can
    recover attributes embedded by several historical Windows providers.  A
    stage-2 network proof must be unambiguous instead: no prefix, no trailing
    bytes, and no hidden bytes after the nested keyAttestation are accepted.
    """
    blob = bytes(attestation_claim_der)
    if len(blob) < 28:
        raise RestrictedHMACError("AIK claim KeyAttestationStatement is truncated")
    magic, version, platform, header_size, cb_id, cb_key, cb_opaque = struct.unpack_from(
        "<7I", blob, 0
    )
    if magic != 0x5453414B:
        raise RestrictedHMACError("AIK claim does not start with the KAST marker")
    if version != 1:
        raise RestrictedHMACError(
            f"Unsupported KeyAttestationStatement version: {version}"
        )
    if header_size < 28 or header_size > len(blob):
        raise RestrictedHMACError("Invalid KeyAttestationStatement header size")
    if header_size + cb_id + cb_key + cb_opaque != len(blob):
        raise RestrictedHMACError(
            "AIK claim KeyAttestationStatement contains trailing or inconsistent data"
        )
    statement = tpm_mod._parse_microsoft_key_attestation_statement(blob)
    if statement.get("offset") != 0:
        raise RestrictedHMACError("AIK claim KAST marker is not at offset zero")
    if statement.get("platform") != platform:
        raise RestrictedHMACError("AIK claim platform header is inconsistent")

    key_attestation = statement.get("key_attestation") or b""
    if len(key_attestation) < 24:
        raise RestrictedHMACError("AIK claim keyAttestation is truncated")
    key_magic, key_platform, key_header_size, cb_attest, cb_signature, cb_blob = struct.unpack_from(
        "<6I", key_attestation, 0
    )
    if key_magic != 0x5344414B:
        raise RestrictedHMACError("AIK claim keyAttestation has invalid magic")
    if key_platform != 2:
        raise RestrictedHMACError(
            f"Unsupported keyAttestation platform: {key_platform}"
        )
    if key_header_size < 24 or key_header_size > len(key_attestation):
        raise RestrictedHMACError("Invalid keyAttestation header size")
    if key_header_size + cb_attest + cb_signature + cb_blob != len(key_attestation):
        raise RestrictedHMACError(
            "AIK claim keyAttestation contains trailing or inconsistent data"
        )
    parsed = tpm_mod._parse_microsoft_key_attestation(key_attestation)
    return statement, parsed

def verify_aik_attestation_claim(
    *,
    attestation_claim_der: bytes,
    aik_csr: x509.CertificateSigningRequest | bytes | None = None,
    expected_aik_spki_der: bytes | None = None,
    expected_aik_public_key=None,
    hmac_key: bytes,
    nonce: bytes,
) -> dict:
    """Validate a restricted-HMAC AIK claim and bind it to the expected AIK.

    Validation is fail-closed and checks:
      * KeyAttestationStatement platform 2
      * HMAC-SHA256 over keyAttest with the 32-byte imported key
      * TPMS_ATTEST magic/type and the 32-byte CA nonce in extraData
      * certified TPM Name and exact public-key equality with the expected AIK
      * basic Name/QualifiedName consistency for the certified TPM object
      * restricted signing AIK object attributes
    """
    secrets = RestrictedHMACSecrets(bytes(hmac_key), bytes(nonce))
    expected_sources = sum(
        value is not None
        for value in (aik_csr, expected_aik_spki_der, expected_aik_public_key)
    )
    if expected_sources != 1:
        raise TypeError(
            "exactly one of aik_csr, expected_aik_spki_der, or "
            "expected_aik_public_key is required"
        )
    if isinstance(aik_csr, (bytes, bytearray, memoryview)):
        try:
            aik_csr = x509.load_der_x509_csr(bytes(aik_csr))
        except Exception as exc:
            raise RestrictedHMACError("AIK CSR is not valid DER PKCS#10") from exc
    if aik_csr is not None and not isinstance(aik_csr, x509.CertificateSigningRequest):
        raise TypeError("aik_csr must be a cryptography CSR or DER bytes")

    if aik_csr is not None:
        expected_spki = aik_csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif expected_aik_public_key is not None:
        try:
            expected_spki = expected_aik_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as exc:
            raise TypeError("expected_aik_public_key is not a public key") from exc
    else:
        try:
            expected_key = serialization.load_der_public_key(bytes(expected_aik_spki_der))
            expected_spki = expected_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as exc:
            raise RestrictedHMACError(
                "Stored V2 AIK SubjectPublicKeyInfo is invalid"
            ) from exc
        if not hmac.compare_digest(expected_spki, bytes(expected_aik_spki_der)):
            raise RestrictedHMACError(
                "Stored V2 AIK SubjectPublicKeyInfo is not canonical DER"
            )

    try:
        statement, parsed = _parse_restricted_hmac_claim_strict(attestation_claim_der)
    except RestrictedHMACError:
        raise
    except Exception as exc:
        raise RestrictedHMACError("Invalid KeyAttestationStatement in AIK claim") from exc
    if statement.get("platform") != 2:
        raise RestrictedHMACError(
            f"Unsupported AIK attestation platform: {statement.get('platform')!r}"
        )
    if statement.get("id_binding"):
        raise RestrictedHMACError("Restricted-HMAC AIK claim must not carry a legacy idBinding")
    # A codec may recover protected state from aikOpaque.  This verifier treats
    # it as opaque and leaves state authentication to the protocol handler.
    key_attestation = statement.get("key_attestation")
    if not key_attestation:
        raise RestrictedHMACError("AIK claim is missing keyAttestation")
    key_attest_raw = parsed.get("key_attest") or b""
    signature_raw = parsed.get("signature") or b""
    key_blob = parsed.get("key_blob") or b""
    if not key_attest_raw or not signature_raw or not key_blob:
        raise RestrictedHMACError("AIK claim lacks keyAttest, signature, or keyBlob")

    received_hmac = _decode_hmac_signature(signature_raw)
    expected_hmac = hmac.new(
        secrets.hmac_key, hashlib.sha256(key_attest_raw).digest(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise RestrictedHMACError("AIK claim HMAC-SHA256 validation failed")

    try:
        attest = tpm_mod.parse_tpms_attest(key_attest_raw)
    except Exception as exc:
        raise RestrictedHMACError("AIK claim does not contain a valid TPMS_ATTEST") from exc
    if attest.magic != tpm_mod.TPM2_GENERATED_VALUE:
        raise RestrictedHMACError(
            f"AIK claim has invalid TPM generated magic: {attest.magic:#010x}"
        )
    if attest.attest_type != tpm_mod.TPM2_ST_ATTEST_CERTIFY:
        raise RestrictedHMACError(
            f"AIK claim is not TPM_ST_ATTEST_CERTIFY: {attest.attest_type:#06x}"
        )
    if not hmac.compare_digest(attest.extra_data, secrets.nonce):
        raise RestrictedHMACError("AIK claim nonce does not match the CA challenge")
    if not attest.certified_name:
        raise RestrictedHMACError("AIK claim does not include a certified TPM Name")
    if not attest.certified_qname:
        raise RestrictedHMACError("AIK claim does not include a certified Qualified Name")
    if len(attest.certified_name) < 2 or len(attest.certified_qname) < 2:
        raise RestrictedHMACError("AIK claim contains a malformed TPM Name")
    if len(attest.certified_name) != len(attest.certified_qname):
        raise RestrictedHMACError(
            "AIK claim certified Name and Qualified Name have different sizes"
        )
    if not hmac.compare_digest(
        attest.certified_name[:2], attest.certified_qname[:2]
    ):
        raise RestrictedHMACError(
            "AIK claim certified Name and Qualified Name use different hash algorithms"
        )
    if hmac.compare_digest(attest.certified_name, attest.certified_qname):
        raise RestrictedHMACError(
            "AIK claim identifies an external object: certified Name equals Qualified Name"
        )

    for candidate in tpm_mod._iter_tpmt_public_candidates(key_blob):
        try:
            candidate_key = candidate.to_cryptography_public_key()
            candidate_spki = candidate_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            continue
        if not hmac.compare_digest(candidate_spki, expected_spki):
            continue
        if not hmac.compare_digest(candidate.compute_name(), attest.certified_name):
            continue
        try:
            tpm_mod._check_aik_attributes(candidate)
        except Exception as exc:
            raise RestrictedHMACError(str(exc)) from exc
        return {
            "attestation_valid": True,
            "attestation_protocol": STATE_PROTOCOL,
            "aik_public_key": candidate_key,
            "aik_public_key_spki_sha256": hashlib.sha256(candidate_spki).hexdigest(),
            "aik_name": attest.certified_name,
            "aik_name_b64": _b64(attest.certified_name),
            "firmware_version": attest.firmware_version,
            "aik_attributes": tpm_mod.tpm_object_attributes_to_dict(candidate.object_attr),
            "aik_name_alg": tpm_mod._tpm_alg_name(candidate.name_alg),
            "aik_key_alg": tpm_mod._tpm_alg_name(candidate.alg_type),
        }

    raise RestrictedHMACError(
        "AIK public key in the attestation claim does not match the expected V2 AIK and certified TPM Name"
    )

def _tpm2b(data: bytes) -> bytes:
    data = bytes(data)
    if len(data) > 0xFFFF:
        raise RestrictedHMACError("TPM2B payload exceeds the UINT16 size limit")
    return struct.pack(">H", len(data)) + data

def _decode_tpm2b_area(raw: bytes, *, label: str) -> bytes:
    """Validate one complete canonical TPM2B structure and return its buffer."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} must be bytes-like")
    raw = bytes(raw)
    if len(raw) < 2:
        raise RestrictedHMACError(f"{label} is shorter than a TPM2B size field")
    declared = struct.unpack_from(">H", raw, 0)[0]
    if declared != len(raw) - 2:
        raise RestrictedHMACError(
            f"{label} length is inconsistent: header declares {declared} bytes, "
            f"area contains {len(raw) - 2}"
        )
    return raw[2:]

def _oaep_params_sha256() -> a_algos.RSAESOAEPParams:
    return a_algos.RSAESOAEPParams(
        {
            "hash_algorithm": {"algorithm": "sha256"},
            "mask_gen_algorithm": {
                "algorithm": "mgf1",
                "parameters": {"algorithm": "sha256"},
            },
            "p_source_algorithm": {
                "algorithm": "p_specified",
                "parameters": b"",
            },
        }
    )

def encrypt_cms_enveloped_data(
    clear: bytes,
    recipient_cert_der: bytes,
    *,
    key_transport: str = "oaep_sha256",
    content_encryption: str = "aes256_cbc",
) -> bytes:
    """Build CMS EnvelopedData compatible with Windows CryptoAPI.

    The non-default ``pkcs1v15`` and ``tripledes_3key`` modes exist for
    interoperability tests and legacy Windows clients.  New server-generated
    state continues to use OAEP-SHA256 and AES-256-CBC.
    """
    cert = x509.load_der_x509_certificate(recipient_cert_der)
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise RestrictedHMACError("CMS key transport requires an RSA recipient certificate")

    if content_encryption == "aes256_cbc":
        cek = os.urandom(32)
        iv = os.urandom(16)
        cipher_algorithm = algorithms.AES(cek)
        content_algorithm = "aes256_cbc"
    elif content_encryption == "tripledes_3key":
        cek = os.urandom(24)
        iv = os.urandom(8)
        cipher_algorithm = TripleDES(cek)
        content_algorithm = "tripledes_3key"
    else:
        raise RestrictedHMACError(
            f"Unsupported CMS content encryption mode: {content_encryption!r}"
        )

    padder = sym_padding.PKCS7(cipher_algorithm.block_size).padder()
    padded = padder.update(clear) + padder.finalize()
    encryptor = Cipher(cipher_algorithm, modes.CBC(iv)).encryptor()
    encrypted_content = encryptor.update(padded) + encryptor.finalize()

    if key_transport == "oaep_sha256":
        encrypted_key = public_key.encrypt(
            cek,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        key_encryption_algorithm = {
            "algorithm": "rsaes_oaep",
            "parameters": _oaep_params_sha256(),
        }
    elif key_transport == "pkcs1v15":
        encrypted_key = public_key.encrypt(cek, padding.PKCS1v15())
        key_encryption_algorithm = {"algorithm": "rsa"}
    else:
        raise RestrictedHMACError(
            f"Unsupported CMS key transport mode: {key_transport!r}"
        )

    cert_asn1 = a_x509.Certificate.load(recipient_cert_der)
    recipient = a_cms.KeyTransRecipientInfo(
        {
            "version": "v0",
            "rid": {
                "issuer_and_serial_number": {
                    "issuer": cert_asn1.issuer,
                    "serial_number": cert_asn1.serial_number,
                }
            },
            "key_encryption_algorithm": key_encryption_algorithm,
            "encrypted_key": encrypted_key,
        }
    )
    enveloped = a_cms.EnvelopedData(
        {
            "version": "v0",
            "recipient_infos": [a_cms.RecipientInfo(name="ktri", value=recipient)],
            "encrypted_content_info": {
                "content_type": "data",
                "content_encryption_algorithm": {
                    "algorithm": content_algorithm,
                    "parameters": iv,
                },
                "encrypted_content": encrypted_content,
            },
        }
    )
    return a_cms.ContentInfo(
        {"content_type": "enveloped_data", "content": enveloped}
    ).dump()

def _marshal_restricted_hmac_public(hmac_key: bytes, obfuscate: bytes) -> bytes:
    unique = hashlib.sha256(obfuscate + hmac_key).digest()
    attributes = (
        TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_NODA
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_SIGN_ENCRYPT
    )
    return (
        struct.pack(">HHI", TPM2_ALG_KEYEDHASH, TPM2_ALG_SHA256, attributes)
        + _tpm2b(b"")
        + struct.pack(">HH", TPM2_ALG_HMAC, TPM2_ALG_SHA256)
        + _tpm2b(unique)
    )

def _marshal_restricted_hmac_sensitive(hmac_key: bytes, obfuscate: bytes) -> bytes:
    return (
        struct.pack(">H", TPM2_ALG_KEYEDHASH)
        + _tpm2b(b"")
        + _tpm2b(obfuscate)
        + _tpm2b(hmac_key)
    )

def _wrap_duplicate_seed(ek_public, seed: bytes, ek_name_alg: int) -> tuple[bytes, bytes]:
    hash_obj = tpm_mod._tpm_alg_to_hash_obj(ek_name_alg)
    if isinstance(ek_public, rsa.RSAPublicKey):
        encrypted_secret = ek_public.encrypt(
            seed,
            padding.OAEP(
                mgf=padding.MGF1(hash_obj),
                algorithm=hash_obj,
                label=b"DUPLICATE\x00",
            ),
        )
        return encrypted_secret, seed
    if isinstance(ek_public, ec.EllipticCurvePublicKey):
        ephemeral = ec.generate_private_key(ek_public.curve)
        ephemeral_public = ephemeral.public_key()
        shared = ephemeral.exchange(ec.ECDH(), ek_public)
        eph = ephemeral_public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        parent = ek_public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        coordinate_size = (ek_public.key_size + 7) // 8
        derived_seed = tpm_mod._kdfe(
            ek_name_alg,
            shared,
            "DUPLICATE",
            eph[1 : 1 + coordinate_size],
            parent[1 : 1 + coordinate_size],
            len(seed) * 8,
        )
        encrypted_secret = (
            _tpm2b(eph[1 : 1 + coordinate_size])
            + _tpm2b(eph[1 + coordinate_size :])
        )
        return encrypted_secret, derived_seed
    raise RestrictedHMACError(f"Unsupported EK public key type: {type(ek_public).__name__}")

def create_restricted_hmac_duplicate(ek_public, hmac_key: bytes) -> dict[str, bytes]:
    if len(hmac_key) != HMAC_KEY_BYTES:
        raise RestrictedHMACError("Restricted HMAC key must be exactly 32 bytes")
    obfuscate = os.urandom(32)
    public_area = _marshal_restricted_hmac_public(hmac_key, obfuscate)
    sensitive = _marshal_restricted_hmac_sensitive(hmac_key, obfuscate)
    object_name = struct.pack(">H", TPM2_ALG_SHA256) + hashlib.sha256(public_area).digest()
    ek_name_alg = tpm_mod.infer_ek_name_alg_from_public_key(ek_public)
    seed = os.urandom(hashlib.new(tpm_mod._tpm_alg_to_hash(ek_name_alg)).digest_size)
    encrypted_secret, seed = _wrap_duplicate_seed(ek_public, seed, ek_name_alg)

    sym_key = tpm_mod._kdfa(ek_name_alg, seed, "STORAGE", object_name, b"", 128)
    encryptor = Cipher(algorithms.AES(sym_key), modes.CFB(b"\x00" * 16)).encryptor()
    encrypted_sensitive = encryptor.update(_tpm2b(sensitive)) + encryptor.finalize()
    digest_bits = hashlib.new(tpm_mod._tpm_alg_to_hash(ek_name_alg)).digest_size * 8
    integrity_key = tpm_mod._kdfa(
        ek_name_alg, seed, "INTEGRITY", b"", b"", digest_bits
    )
    integrity = hmac.new(
        integrity_key,
        encrypted_sensitive + object_name,
        tpm_mod._tpm_alg_to_hash(ek_name_alg),
    ).digest()
    private_buffer = _tpm2b(integrity) + encrypted_sensitive
    encrypted_secret_tpm2b = _tpm2b(encrypted_secret)
    private_tpm2b = _tpm2b(private_buffer)
    public_tpm2b = _tpm2b(public_area)
    return {
        "encrypted_secret_tpm2b": encrypted_secret_tpm2b,
        "private_tpm2b": private_tpm2b,
        "public_tpm2b": public_tpm2b,
        "encrypted_secret_buffer": encrypted_secret,
        "private_buffer": private_buffer,
        "public_area": public_area,
        "object_name": object_name,
    }

def build_kast(*, id_binding: bytes = b"", key_attestation: bytes = b"", aik_opaque: bytes = b"") -> bytes:
    return (
        struct.pack(
            "<7I",
            0x5453414B,
            1,
            2,
            28,
            len(id_binding),
            len(key_attestation),
            len(aik_opaque),
        )
        + id_binding
        + key_attestation
        + aik_opaque
    )

def build_key_attestation(*, key_attest: bytes, signature: bytes, key_blob: bytes) -> bytes:
    return (
        struct.pack(
            "<6I",
            0x5344414B,
            2,
            24,
            len(key_attest),
            len(signature),
            len(key_blob),
        )
        + key_attest
        + signature
        + key_blob
    )

def encode_windows_wrapped_key(
    *,
    encrypted_secret_tpm2b: bytes,
    private_tpm2b: bytes,
    public_tpm2b: bytes,
) -> bytes:
    """Encode the Microsoft ``BKWT`` value carried by OID ``.21.28``.

    The 28-byte header is a Windows host structure whose integer fields are
    little-endian.  The three following areas are complete canonical TPM2B
    structures, including their two-byte big-endian size prefixes.
    """
    encrypted_secret_tpm2b = bytes(encrypted_secret_tpm2b)
    private_tpm2b = bytes(private_tpm2b)
    public_tpm2b = bytes(public_tpm2b)
    encrypted_secret = _decode_tpm2b_area(
        encrypted_secret_tpm2b, label="TPM2B_ENCRYPTED_SECRET"
    )
    private_buffer = _decode_tpm2b_area(private_tpm2b, label="TPM2B_PRIVATE")
    public_area = _decode_tpm2b_area(public_tpm2b, label="TPM2B_PUBLIC")
    if not encrypted_secret or not private_buffer or not public_area:
        raise RestrictedHMACError(
            "Microsoft wrapped-key TPM2B areas must all be non-empty"
        )
    header = struct.pack(
        "<4s6I",
        WINDOWS_WRAPPED_KEY_MAGIC,
        WINDOWS_WRAPPED_KEY_VERSION,
        WINDOWS_WRAPPED_KEY_PLATFORM_TPM20,
        WINDOWS_WRAPPED_KEY_HEADER_SIZE,
        len(encrypted_secret_tpm2b),
        len(private_tpm2b),
        len(public_tpm2b),
    )
    if len(header) != WINDOWS_WRAPPED_KEY_HEADER_SIZE:
        raise AssertionError("BKWT header size constant is inconsistent")
    return header + encrypted_secret_tpm2b + private_tpm2b + public_tpm2b

def decode_windows_wrapped_key(raw: bytes) -> dict[str, bytes | int]:
    """Strictly decode one Microsoft ``BKWT`` wrapped-key value."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("wrapped key must be bytes-like")
    raw = bytes(raw)
    if len(raw) < WINDOWS_WRAPPED_KEY_HEADER_SIZE:
        raise RestrictedHMACError("Microsoft wrapped-key value is truncated")
    (
        magic,
        version,
        platform,
        header_size,
        encrypted_secret_size,
        private_size,
        public_size,
    ) = struct.unpack_from("<4s6I", raw, 0)
    if magic != WINDOWS_WRAPPED_KEY_MAGIC:
        raise RestrictedHMACError("Microsoft wrapped-key magic is not BKWT")
    if version != WINDOWS_WRAPPED_KEY_VERSION:
        raise RestrictedHMACError(
            f"Unsupported Microsoft wrapped-key version: {version}"
        )
    if platform != WINDOWS_WRAPPED_KEY_PLATFORM_TPM20:
        raise RestrictedHMACError(
            f"Unsupported Microsoft wrapped-key platform: {platform}"
        )
    if header_size != WINDOWS_WRAPPED_KEY_HEADER_SIZE:
        raise RestrictedHMACError(
            f"Unsupported Microsoft wrapped-key header size: {header_size}"
        )
    total = header_size + encrypted_secret_size + private_size + public_size
    if total != len(raw):
        raise RestrictedHMACError(
            "Microsoft wrapped-key area lengths are inconsistent with the payload"
        )
    pos = header_size
    encrypted_secret_tpm2b = raw[pos : pos + encrypted_secret_size]
    pos += encrypted_secret_size
    private_tpm2b = raw[pos : pos + private_size]
    pos += private_size
    public_tpm2b = raw[pos : pos + public_size]
    encrypted_secret = _decode_tpm2b_area(
        encrypted_secret_tpm2b, label="TPM2B_ENCRYPTED_SECRET"
    )
    private_buffer = _decode_tpm2b_area(private_tpm2b, label="TPM2B_PRIVATE")
    public_area = _decode_tpm2b_area(public_tpm2b, label="TPM2B_PUBLIC")
    if not encrypted_secret or not private_buffer or not public_area:
        raise RestrictedHMACError(
            "Microsoft wrapped-key TPM2B areas must all be non-empty"
        )
    return {
        "magic": magic,
        "version": version,
        "platform": platform,
        "header_size": header_size,
        "encrypted_secret_size": encrypted_secret_size,
        "private_size": private_size,
        "public_size": public_size,
        "encrypted_secret_tpm2b": encrypted_secret_tpm2b,
        "private_tpm2b": private_tpm2b,
        "public_tpm2b": public_tpm2b,
        "encrypted_secret": encrypted_secret,
        "private": private_buffer,
        "public": public_area,
    }

# Protocol names retained as explicit aliases for callers; there is no runtime
# codec selection.  BKWT is the sole MS-WCCE 55 carrier implemented here.
encode_microsoft_restricted_hmac_challenge = encode_windows_wrapped_key
decode_microsoft_restricted_hmac_challenge = decode_windows_wrapped_key
