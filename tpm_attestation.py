from pathlib import Path
import base64
import hashlib
import hmac
import logging
import os
import struct
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

from asn1crypto import algos as a_algos
from asn1crypto import cms as a_cms
from asn1crypto import core as a_core
from asn1crypto import csr as a_csr
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

logger = logging.getLogger("adcs.tpm_attestation")

OID_TCG_SAN_TPM_DEVICE = "2.23.133.2"
OID_TPM_ATTESTATION_BUNDLE = "1.3.6.1.4.1.99999.1.1"
OID_MS_ENROLL_EK_INFO = "1.3.6.1.4.1.311.21.23"
OID_MS_ENROLL_AIK_INFO = "1.3.6.1.4.1.311.21.39"
OID_MS_ENROLL_KSP_NAME = "1.3.6.1.4.1.311.21.25"
OID_MS_ENROLL_ATTESTATION_STATEMENT = "1.3.6.1.4.1.311.21.33"
OID_MS_ENROLL_ATTESTATION_STATEMENT_LEGACY = "1.3.6.1.4.1.311.21.24"
OID_CMC_STATUS_INFO = "1.3.6.1.5.5.7.7.1"
OID_MS_CMC_CHALLENGE_WRAPPER = "1.3.6.1.4.1.311.10.10.1"
OID_ENROLL_KSP_NAME = "1.3.6.1.4.1.311.21.25"
OID_ENROLL_CAXCHGCERT_HASH = "1.3.6.1.4.1.311.21.27"
OID_ENROLL_ATTESTATION_CHALLENGE = "1.3.6.1.4.1.311.21.28"
OID_ENROLL_ENCRYPTION_ALGORITHM = "1.3.6.1.4.1.311.21.29"
OID_ID_CCT_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3"
OID_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"

TPM2_ST_ATTEST_CERTIFY = 32791
TPM2_ST_ATTEST_QUOTE = 32792
TPMA_OBJECT_FIXEDTPM = 0x00000002
TPMA_OBJECT_FIXEDPARENT = 0x00000010
TPMA_OBJECT_RESTRICTED = 0x00010000
TPMA_OBJECT_DECRYPT = 0x00020000
TPMA_OBJECT_SIGN = 0x00040000
TPM2_ALG_RSA = 0x0001
TPM2_ALG_ECC = 0x0023
TPM2_ALG_SHA1 = 0x0004
TPM2_ALG_SHA256 = 0x000B
TPM2_ALG_SHA384 = 0x000C
TPM2_ALG_SHA512 = 0x000D
TPM2_ALG_NULL = 0x0010
TPM2_ALG_RSASSA = 0x0014
TPM2_ALG_RSAPSS = 0x0016
TPM2_ALG_ECDSA = 0x0018
TPM2_ALG_ECDAA = 0x001A
TPM2_ALG_SM2 = 0x001B
TPM2_ALG_ECSCHNORR = 0x001C
TPM2_ECC_NIST_P256 = 0x0003
TPM2_ECC_NIST_P384 = 0x0004
TPM2_GENERATED_VALUE = 0xFF544347


@dataclass
class AttestationData:
    magic: int
    attest_type: int
    qualified_signer: bytes
    extra_data: bytes
    clock_info: bytes
    firmware_version: int
    certified_name: bytes = b""
    certified_qname: bytes = b""
    pcr_selection: bytes = b""
    pcr_digest: bytes = b""
    raw: bytes = b""


@dataclass
class TPMAttestationBundle:
    ek_cert_der: Optional[bytes] = None
    aik_pub_raw: Optional[bytes] = None
    attest_raw: Optional[bytes] = None
    attest_sig_raw: Optional[bytes] = None
    certified_key_raw: Optional[bytes] = None
    nonce: Optional[bytes] = None
    mode: str = "AIK_FULL"


class TPMAttestationError(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def raw(self, length: int) -> bytes:
        if self._pos + length > len(self._data):
            raise TPMAttestationError(
                f"Parser overrun: need {length} bytes at offset {self._pos}, only {len(self._data) - self._pos} remaining"
            )
        chunk = self._data[self._pos:self._pos + length]
        self._pos += length
        return chunk

    def u8(self) -> int:
        return struct.unpack(">B", self.raw(1))[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.raw(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.raw(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.raw(8))[0]

    def tpm2b(self) -> bytes:
        return self.raw(self.u16())

    def tell(self) -> int:
        return self._pos


def _tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _tpm_alg_to_hash(alg: int) -> str:
    mapping = {
        TPM2_ALG_SHA1: "sha1",
        TPM2_ALG_SHA256: "sha256",
        TPM2_ALG_SHA384: "sha384",
        TPM2_ALG_SHA512: "sha512",
    }
    if alg not in mapping:
        raise TPMAttestationError(f"Unsupported TPM hash algorithm: {alg:#06x}")
    return mapping[alg]


def _tpm_alg_to_hash_obj(alg: int):
    mapping = {
        TPM2_ALG_SHA1: hashes.SHA1(),
        TPM2_ALG_SHA256: hashes.SHA256(),
        TPM2_ALG_SHA384: hashes.SHA384(),
        TPM2_ALG_SHA512: hashes.SHA512(),
    }
    if alg not in mapping:
        raise TPMAttestationError(f"Unsupported TPM hash algorithm: {alg:#06x}")
    return mapping[alg]


@dataclass
class TPMPublicKey:
    alg_type: int
    name_alg: int
    object_attr: int
    auth_policy: bytes
    rsa_key_bits: int = 0
    rsa_exponent: int = 0
    rsa_modulus: bytes = b""
    ecc_curve: int = 0
    ecc_x: bytes = b""
    ecc_y: bytes = b""
    _raw_bytes: bytes | None = None

    def to_cryptography_public_key(self):
        if self.alg_type == TPM2_ALG_RSA:
            exponent = self.rsa_exponent or 65537
            modulus = int.from_bytes(self.rsa_modulus, "big")
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()
        if self.alg_type == TPM2_ALG_ECC:
            x = int.from_bytes(self.ecc_x, "big")
            y = int.from_bytes(self.ecc_y, "big")
            curve = {
                TPM2_ECC_NIST_P256: ec.SECP256R1(),
                TPM2_ECC_NIST_P384: ec.SECP384R1(),
            }.get(self.ecc_curve, ec.SECP256R1())
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        raise TPMAttestationError(f"Unsupported TPM key algorithm: {self.alg_type:#06x}")

    def compute_name(self) -> bytes:
        raw = self._raw_bytes if self._raw_bytes is not None else self._marshal()
        digest = hashlib.new(_tpm_alg_to_hash(self.name_alg), raw).digest()
        return struct.pack(">H", self.name_alg) + digest

    def _marshal(self) -> bytes:
        out = struct.pack(">HHI", self.alg_type, self.name_alg, self.object_attr)
        out += _tpm2b(self.auth_policy)
        if self.alg_type == TPM2_ALG_RSA:
            out += struct.pack(">HHHhI", TPM2_ALG_NULL, TPM2_ALG_NULL, self.rsa_key_bits, TPM2_ALG_NULL, self.rsa_exponent)
            out += _tpm2b(self.rsa_modulus)
        elif self.alg_type == TPM2_ALG_ECC:
            out += struct.pack(">HHHH", TPM2_ALG_NULL, TPM2_ALG_NULL, self.ecc_curve, TPM2_ALG_NULL)
            out += _tpm2b(self.ecc_x)
            out += _tpm2b(self.ecc_y)
        return out


@dataclass
class AttestationResult:
    success: bool
    mode: str
    message: str
    ek_cert: Optional[x509.Certificate] = None
    ek_pub: Optional[object] = None
    aik_public_key: Optional[TPMPublicKey] = None
    certified_key_obj: Optional[TPMPublicKey] = None
    is_fixed_tpm: bool = False
    is_fixed_parent: bool = False
    is_restricted: bool = False
    firmware_version: Optional[int] = None
    manufacturer: Optional[str] = None


def parse_tpms_attest(raw: bytes) -> AttestationData:
    r = _Reader(raw)
    magic = r.u32()
    attest_type = r.u16()
    qualified_signer = r.tpm2b()
    extra_data = r.tpm2b()
    clock_info = r.raw(8)
    reset_count = r.u32()
    restart_count = r.u32()
    safe = r.u8()
    firmware_version = r.u64()
    attest = AttestationData(
        magic=magic,
        attest_type=attest_type,
        qualified_signer=qualified_signer,
        extra_data=extra_data,
        clock_info=clock_info + struct.pack(">II", reset_count, restart_count) + bytes([safe]),
        firmware_version=firmware_version,
        raw=raw,
    )
    if attest_type == TPM2_ST_ATTEST_CERTIFY:
        attest.certified_name = r.tpm2b()
        attest.certified_qname = r.tpm2b()
    elif attest_type == TPM2_ST_ATTEST_QUOTE:
        count = r.u32()
        selection = b""
        for _ in range(count):
            hash_alg = r.u16()
            sel_size = r.u8()
            selection += struct.pack(">HB", hash_alg, sel_size) + r.raw(sel_size)
        attest.pcr_selection = struct.pack(">I", count) + selection
        attest.pcr_digest = r.tpm2b()
    return attest


def parse_tpmt_public(raw: bytes) -> TPMPublicKey:
    r = _Reader(raw)
    alg_type = r.u16()
    name_alg = r.u16()
    object_attr = r.u32()
    auth_policy = r.tpm2b()
    out = TPMPublicKey(alg_type=alg_type, name_alg=name_alg, object_attr=object_attr, auth_policy=auth_policy)
    if alg_type == TPM2_ALG_RSA:
        r.u16()  # symmetric
        scheme = r.u16()
        if scheme in (TPM2_ALG_RSASSA, TPM2_ALG_RSAPSS):
            r.u16()
        out.rsa_key_bits = r.u16()
        out.rsa_exponent = r.u32()
        out.rsa_modulus = r.tpm2b()
    elif alg_type == TPM2_ALG_ECC:
        r.u16()  # symmetric
        scheme = r.u16()
        if scheme in (TPM2_ALG_ECDSA, TPM2_ALG_ECDAA, TPM2_ALG_SM2, TPM2_ALG_ECSCHNORR):
            r.u16()
        out.ecc_curve = r.u16()
        r.u16()  # kdf
        out.ecc_x = r.tpm2b()
        out.ecc_y = r.tpm2b()
    else:
        raise TPMAttestationError(f"Unsupported TPMT_PUBLIC algorithm: {alg_type:#06x}")
    out._raw_bytes = raw[:r.tell()]
    return out


def _verify_signature_by(cert: x509.Certificate, issuer_cert: x509.Certificate):
    pub = issuer_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    else:
        raise TPMAttestationError("Unsupported issuer key type")


def _verify_ek_cert(ek_cert: x509.Certificate, trusted_roots: list):
    if not trusted_roots:
        return
    for root in trusted_roots:
        if root.subject != ek_cert.issuer:
            continue
        try:
            _verify_signature_by(ek_cert, root)
            return
        except Exception:
            pass
    raise TPMAttestationError(
        "EK certificate does not chain to any trusted TPM manufacturer CA root. Add the manufacturer's CA to trusted_ek_roots."
    )


def _extract_tpm_manufacturer(cert: x509.Certificate) -> Optional[str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if hasattr(name, "value") and hasattr(name.value, "type_id"):
                oid_str = name.value.type_id.dotted_string
                if oid_str.startswith(OID_TCG_SAN_TPM_DEVICE):
                    return str(name.value.value)
    except Exception:
        pass
    try:
        return cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except Exception:
        return None


def _verify_tpm_signature(data: bytes, sig_raw: bytes, pub_key: TPMPublicKey):
    r = _Reader(sig_raw)
    sig_alg = r.u16()
    hash_alg = r.u16()
    hash_obj = _tpm_alg_to_hash_obj(hash_alg)
    crypto_key = pub_key.to_cryptography_public_key()
    if sig_alg in (TPM2_ALG_RSASSA, TPM2_ALG_RSAPSS):
        sig_bytes = r.tpm2b()
        try:
            if sig_alg == TPM2_ALG_RSASSA:
                crypto_key.verify(sig_bytes, data, padding.PKCS1v15(), hash_obj)
            else:
                crypto_key.verify(
                    sig_bytes,
                    data,
                    padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.MAX_LENGTH),
                    hash_obj,
                )
        except InvalidSignature as exc:
            raise TPMAttestationError("TPM signature verification failed") from exc
        return
    if sig_alg == TPM2_ALG_ECDSA:
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        r_int = int.from_bytes(r.raw(r.u16()), "big")
        s_int = int.from_bytes(r.raw(r.u16()), "big")
        try:
            crypto_key.verify(encode_dss_signature(r_int, s_int), data, ec.ECDSA(hash_obj))
        except InvalidSignature as exc:
            raise TPMAttestationError("ECDSA signature verification failed") from exc
        return
    raise TPMAttestationError(f"Unsupported signature algorithm: {sig_alg:#06x}")


def _check_aik_attributes(aik: TPMPublicKey):
    required = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN
    if aik.object_attr & required != required:
        raise TPMAttestationError(
            f"AIK must have RESTRICTED|SIGN attributes set. Got TPMA_OBJECT={aik.object_attr:#010x}"
        )
    if aik.object_attr & TPMA_OBJECT_DECRYPT:
        raise TPMAttestationError("AIK must NOT have the DECRYPT attribute (it must be a signing-only key)")


def _check_key_policy(key: TPMPublicKey, require_fixed_tpm: bool, require_fixed_parent: bool, require_restricted: bool):
    errors = []
    if require_fixed_tpm and not (key.object_attr & TPMA_OBJECT_FIXEDTPM):
        errors.append("FIXEDTPM not set")
    if require_fixed_parent and not (key.object_attr & TPMA_OBJECT_FIXEDPARENT):
        errors.append("FIXEDPARENT not set")
    if require_restricted and not (key.object_attr & TPMA_OBJECT_RESTRICTED):
        errors.append("RESTRICTED not set")
    if errors:
        raise TPMAttestationError("Certified key does not meet policy: " + "; ".join(errors))


def _load_cert(der_or_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(der_or_pem) if b"-----BEGIN" in der_or_pem else x509.load_der_x509_certificate(der_or_pem)


def _verify_aik_full(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,
    expected_nonce: Optional[bytes],
    require_fixed_tpm: bool,
    require_fixed_parent: bool,
    require_restricted: bool,
) -> AttestationResult:
    if not bundle.ek_cert_der or not bundle.aik_pub_raw or not bundle.attest_raw or not bundle.attest_sig_raw:
        raise TPMAttestationError("AIK_FULL mode requires ek_cert_der, aik_pub_raw, attest_raw and attest_sig_raw")
    ek_cert = _load_cert(bundle.ek_cert_der)
    ek_pub = ek_cert.public_key()
    aik_pub = parse_tpmt_public(bundle.aik_pub_raw)
    _check_aik_attributes(aik_pub)
    attest = parse_tpms_attest(bundle.attest_raw)
    if attest.magic != TPM2_GENERATED_VALUE:
        raise TPMAttestationError(f"TPMS_ATTEST magic invalid: {attest.magic:#010x}")
    if expected_nonce is not None and not hmac.compare_digest(attest.extra_data, expected_nonce):
        raise TPMAttestationError("Nonce mismatch — possible replay attack")
    _verify_tpm_signature(bundle.attest_raw, bundle.attest_sig_raw, aik_pub)
    if attest.certified_name and attest.certified_name != aik_pub.compute_name():
        raise TPMAttestationError("Certified name in TPMS_ATTEST does not match AIK public key name")
    _check_key_policy(aik_pub, require_fixed_tpm, require_fixed_parent, require_restricted)
    return AttestationResult(
        success=True,
        mode="AIK_FULL",
        message="AIK attestation verified",
        ek_cert=ek_cert,
        ek_pub=ek_pub,
        aik_public_key=aik_pub,
        is_fixed_tpm=bool(aik_pub.object_attr & TPMA_OBJECT_FIXEDTPM),
        is_fixed_parent=bool(aik_pub.object_attr & TPMA_OBJECT_FIXEDPARENT),
        is_restricted=bool(aik_pub.object_attr & TPMA_OBJECT_RESTRICTED),
        firmware_version=attest.firmware_version,
        manufacturer=_extract_tpm_manufacturer(ek_cert),
    )


def _verify_certify(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,
    expected_nonce: Optional[bytes],
    require_fixed_tpm: bool,
    require_fixed_parent: bool,
    require_restricted: bool,
) -> AttestationResult:
    if not bundle.ek_cert_der or not bundle.aik_pub_raw or not bundle.certified_key_raw or not bundle.attest_raw or not bundle.attest_sig_raw:
        raise TPMAttestationError(
            "CERTIFY mode requires ek_cert_der, aik_pub_raw, certified_key_raw, attest_raw and attest_sig_raw"
        )
    ek_cert = _load_cert(bundle.ek_cert_der)
    ek_pub = ek_cert.public_key()
    aik_pub = parse_tpmt_public(bundle.aik_pub_raw)
    _check_aik_attributes(aik_pub)
    cert_key = parse_tpmt_public(bundle.certified_key_raw)
    attest = parse_tpms_attest(bundle.attest_raw)
    if attest.magic != TPM2_GENERATED_VALUE:
        raise TPMAttestationError(f"Bad magic: {attest.magic:#010x}")
    if attest.attest_type != TPM2_ST_ATTEST_CERTIFY:
        raise TPMAttestationError(
            f"Expected ST_ATTEST_CERTIFY ({TPM2_ST_ATTEST_CERTIFY:#06x}), got {attest.attest_type:#06x}"
        )
    if expected_nonce is not None and not hmac.compare_digest(attest.extra_data, expected_nonce):
        raise TPMAttestationError("Nonce mismatch — possible replay attack")
    _verify_tpm_signature(bundle.attest_raw, bundle.attest_sig_raw, aik_pub)
    if attest.certified_name != cert_key.compute_name():
        raise TPMAttestationError("certifiedName in TPMS_ATTEST does not match the certified key")
    _check_key_policy(cert_key, require_fixed_tpm, require_fixed_parent, require_restricted)
    return AttestationResult(
        success=True,
        mode="CERTIFY",
        message="TPM2_Certify attestation verified",
        ek_cert=ek_cert,
        ek_pub=ek_pub,
        aik_public_key=aik_pub,
        certified_key_obj=cert_key,
        is_fixed_tpm=bool(cert_key.object_attr & TPMA_OBJECT_FIXEDTPM),
        is_fixed_parent=bool(cert_key.object_attr & TPMA_OBJECT_FIXEDPARENT),
        is_restricted=bool(cert_key.object_attr & TPMA_OBJECT_RESTRICTED),
        firmware_version=attest.firmware_version,
        manufacturer=_extract_tpm_manufacturer(ek_cert),
    )


def verify_tpm_attestation(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: Optional[list] = None,
    expected_nonce: Optional[bytes] = None,
    require_fixed_tpm: bool = True,
    require_fixed_parent: bool = True,
    require_restricted: bool = True,
) -> AttestationResult:
    try:
        if bundle.mode == "AIK_FULL":
            return _verify_aik_full(
                bundle,
                trusted_ek_roots,
                expected_nonce,
                require_fixed_tpm,
                require_fixed_parent,
                require_restricted,
            )
        if bundle.mode == "CERTIFY":
            return _verify_certify(
                bundle,
                trusted_ek_roots,
                expected_nonce,
                require_fixed_tpm,
                require_fixed_parent,
                require_restricted,
            )
        raise TPMAttestationError(f"Unsupported attestation mode: {bundle.mode}")
    except TPMAttestationError as exc:
        logger.warning("TPM attestation failed: %s", exc)
        return AttestationResult(success=False, mode=bundle.mode, message=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during TPM attestation")
        return AttestationResult(success=False, mode=bundle.mode, message=f"Internal error: {exc}")


def _decode_any_string(value) -> Optional[str]:
    try:
        native = getattr(value, "native", None)
        if isinstance(native, str):
            return native
    except Exception:
        pass
    try:
        data = value.dump() if hasattr(value, "dump") else bytes(value)
    except Exception:
        return None
    for typ in (a_core.BMPString, a_core.UTF8String, a_core.PrintableString, a_core.TeletexString):
        try:
            return typ.load(data).native
        except Exception:
            pass
    for encoding in ("utf-16-le", "utf-16-be", "utf-8", "latin1"):
        try:
            return data.decode(encoding).rstrip("\x00")
        except Exception:
            pass
    return None


def _load_private_key_from_pem(value, password=None):
    if value is None:
        raise ValueError("Missing PEM private key")
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8") if "-----BEGIN " in value else Path(value).read_bytes()
    else:
        raise TypeError(f"Unsupported private key input type: {type(value).__name__}")
    if isinstance(password, str):
        password = password.encode("utf-8")
    return serialization.load_pem_private_key(data, password=password)


def _decrypt_cms_enveloped_data(content_info_der: bytes, recipient_cert_der: Optional[bytes], recipient_key) -> bytes:
    def _unwrap(blob: bytes) -> bytes:
        if not blob:
            raise ValueError("Empty CMS blob")
        if blob[0] == 0x30:
            return blob
        if blob[0] == 0x31:
            class _AnySet(a_core.SetOf):
                _child_spec = a_core.Any

            values = _AnySet.load(blob)
            if not values:
                raise ValueError("Empty SET for CMS attribute value")
            first = values[0]
            if hasattr(first, "dump"):
                return first.dump()
            parsed = getattr(first, "parsed", None)
            if parsed is not None and hasattr(parsed, "dump"):
                return parsed.dump()
            raise ValueError("Could not unwrap CMS ContentInfo from SET")
        raise ValueError(f"Unsupported CMS wrapper tag: 0x{blob[0]:02x}")

    def _hash_from_name_or_oid(value):
        mapping = {
            "sha1": hashes.SHA1(),
            "sha224": hashes.SHA224(),
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "1.3.14.3.2.26": hashes.SHA1(),
            "2.16.840.1.101.3.4.2.4": hashes.SHA224(),
            "2.16.840.1.101.3.4.2.1": hashes.SHA256(),
            "2.16.840.1.101.3.4.2.2": hashes.SHA384(),
            "2.16.840.1.101.3.4.2.3": hashes.SHA512(),
        }
        if value not in mapping:
            raise NotImplementedError(f"Unsupported OAEP hash algorithm: {value}")
        return mapping[value]

    ci = a_cms.ContentInfo.load(_unwrap(content_info_der))
    if ci["content_type"].native != "enveloped_data":
        raise ValueError("Expected CMS EnvelopedData")
    env = ci["content"]
    eci = env["encrypted_content_info"]
    enc_alg = eci["content_encryption_algorithm"]
    enc_name = enc_alg["algorithm"].native
    enc_params = enc_alg["parameters"]
    encrypted_content = eci["encrypted_content"].native
    if encrypted_content is None:
        raise ValueError("CMS EnvelopedData has no encrypted content")

    recipient_serial = None
    if recipient_cert_der:
        recipient_serial = x509.load_der_x509_certificate(recipient_cert_der).serial_number

    cek = None
    for ri in env["recipient_infos"]:
        if ri.name != "ktri":
            continue
        ktri = ri.chosen
        rid = ktri["rid"]
        if rid.name != "issuer_and_serial_number":
            continue
        serial = int(rid.chosen["serial_number"].native)
        if recipient_serial is not None and serial != recipient_serial:
            continue
        key_alg_field = ktri["key_encryption_algorithm"]["algorithm"]
        key_alg = getattr(key_alg_field, "dotted", None) or key_alg_field.native
        encrypted_key = ktri["encrypted_key"].native
        if key_alg in ("rsa", "rsaes_pkcs1v15", "1.2.840.113549.1.1.1"):
            cek = recipient_key.decrypt(encrypted_key, padding.PKCS1v15())
        elif key_alg in ("rsaes_oaep", "1.2.840.113549.1.1.7"):
            oaep_params = ktri["key_encryption_algorithm"]["parameters"]
            hash_alg = hashes.SHA1()
            mgf_hash_alg = hashes.SHA1()
            label = None
            if oaep_params is not None:
                native = oaep_params.native or {}
                hash_info = native.get("hash_algorithm") if isinstance(native, dict) else None
                if hash_info and hash_info.get("algorithm"):
                    hash_alg = _hash_from_name_or_oid(hash_info["algorithm"])
                mgf_info = native.get("mask_gen_algorithm") if isinstance(native, dict) else None
                if mgf_info:
                    mgf_params = mgf_info.get("parameters")
                    if mgf_params and mgf_params.get("algorithm"):
                        mgf_hash_alg = _hash_from_name_or_oid(mgf_params["algorithm"])
                p_source = native.get("p_source_algorithm") if isinstance(native, dict) else None
                if p_source:
                    psrc_params = p_source.get("parameters")
                    if isinstance(psrc_params, bytes) and psrc_params:
                        label = psrc_params
            cek = recipient_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(mgf_hash_alg), algorithm=hash_alg, label=label),
            )
        else:
            raise ValueError(f"Unsupported CMS key encryption algorithm: {key_alg}")
        break

    if cek is None:
        raise ValueError("Could not decrypt CMS EnvelopedData with provided KET certificate/private key")

    params = enc_params.native if enc_params is not None else None
    if enc_name in ("aes128_cbc", "aes192_cbc", "aes256_cbc"):
        cipher = Cipher(algorithms.AES(cek), modes.CBC(params))
    elif enc_name == "tripledes_3key":
        cipher = Cipher(algorithms.TripleDES(cek), modes.CBC(params))
    else:
        raise ValueError(f"Unsupported CMS content encryption algorithm: {enc_name}")

    padded = cipher.decryptor().update(encrypted_content) + cipher.decryptor().finalize()
    unpadder = sym_padding.PKCS7(cipher.algorithm.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _find_der_certificates_in_blob(blob: bytes) -> list[bytes]:
    certs = []
    i = 0
    while i < len(blob) - 4:
        if blob[i] != 0x30:
            i += 1
            continue
        first_len = blob[i + 1]
        header_len = 2
        if first_len & 0x80:
            num_len = first_len & 0x7F
            if num_len == 0 or i + 2 + num_len > len(blob):
                i += 1
                continue
            total_len = int.from_bytes(blob[i + 2:i + 2 + num_len], "big")
            header_len = 2 + num_len
        else:
            total_len = first_len
        end = i + header_len + total_len
        if end > len(blob):
            i += 1
            continue
        candidate = blob[i:end]
        try:
            x509.load_der_x509_certificate(candidate)
            certs.append(candidate)
            i = end
        except Exception:
            i += 1
    return certs


def decrypt_microsoft_ek_info(ek_info_raw: bytes, ket_cert_der: Optional[bytes], ket_private_key) -> dict:
    if not ek_info_raw:
        raise ValueError("ek_info_raw is empty")
    value = a_core.Any.load(ek_info_raw)
    content_info_der = None
    for candidate in (getattr(value, "parsed", None), value):
        if candidate is None:
            continue
        try:
            items = list(candidate)
            if items:
                first = items[0]
                content_info_der = first.dump() if hasattr(first, "dump") else bytes(first)
                break
        except Exception:
            pass
        try:
            content_info_der = candidate.dump() if hasattr(candidate, "dump") else bytes(candidate)
            break
        except Exception:
            pass
    if content_info_der is None:
        raise ValueError("Could not locate CMS EnvelopedData in ek_info_raw")
    decrypted = _decrypt_cms_enveloped_data(content_info_der, ket_cert_der, ket_private_key)
    certs = _find_der_certificates_in_blob(decrypted)
    return {
        "decrypted_raw": decrypted,
        "ek_cert_der": certs[0] if certs else None,
        "embedded_certificates_der": certs,
    }


def extract_microsoft_key_attestation_attributes_from_csr_der(csr_der: bytes) -> Optional[dict]:
    req = a_csr.CertificationRequest.load(csr_der)
    interesting = {
        OID_MS_ENROLL_EK_INFO,
        OID_MS_ENROLL_AIK_INFO,
        OID_MS_ENROLL_KSP_NAME,
        OID_MS_ENROLL_ATTESTATION_STATEMENT,
        OID_MS_ENROLL_ATTESTATION_STATEMENT_LEGACY,
    }

    def _extract_first_attribute_value(values_field):
        try:
            return values_field[0]
        except Exception:
            pass
        parsed = getattr(values_field, "parsed", None)
        if parsed is not None:
            try:
                return parsed[0]
            except Exception:
                pass
        try:
            return list(values_field)[0]
        except Exception:
            return values_field

    def _raw_bytes(value_obj):
        try:
            if isinstance(value_obj, a_core.OctetString):
                return bytes(value_obj.native)
        except Exception:
            pass
        try:
            return value_obj.dump()
        except Exception:
            pass
        try:
            return bytes(value_obj)
        except Exception:
            pass
        try:
            native = getattr(value_obj, "native", None)
            if isinstance(native, bytes):
                return native
        except Exception:
            pass
        return None

    result = {
        "ek_info_raw": None,
        "aik_info_raw": None,
        "attestation_statement_raw": None,
        "attestation_blob_raw": None,
        "ksp_name": None,
        "ksp_name_raw": None,
        "found": False,
    }
    for attr in req["certification_request_info"]["attributes"]:
        try:
            oid = attr["type"].dotted
        except Exception:
            continue
        if oid not in interesting:
            continue
        value_obj = _extract_first_attribute_value(attr["values"])
        raw = _raw_bytes(value_obj)
        if raw is None:
            continue
        if oid == OID_MS_ENROLL_EK_INFO:
            result["ek_info_raw"] = raw
        elif oid == OID_MS_ENROLL_AIK_INFO:
            result["aik_info_raw"] = raw
        elif oid == OID_MS_ENROLL_ATTESTATION_STATEMENT:
            try:
                result["attestation_statement_raw"] = a_core.OctetString.load(raw).native
            except Exception:
                result["attestation_statement_raw"] = raw
        elif oid == OID_MS_ENROLL_ATTESTATION_STATEMENT_LEGACY:
            try:
                result["attestation_blob_raw"] = a_core.OctetString.load(raw).native
            except Exception:
                result["attestation_blob_raw"] = raw
        elif oid == OID_MS_ENROLL_KSP_NAME:
            result["ksp_name_raw"] = raw
            result["ksp_name"] = _decode_any_string(value_obj)
        result["found"] = True
    return result if result["found"] else None


def load_trusted_ek_roots_from_dir(path: str) -> list:
    roots = []
    if not os.path.isdir(path):
        return roots
    for entry in os.listdir(path):
        file_path = os.path.join(path, entry)
        if not os.path.isfile(file_path):
            continue
        try:
            data = Path(file_path).read_bytes()
            roots.append(x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data else x509.load_der_x509_certificate(data))
        except Exception as exc:
            logger.warning("Could not load EK root from %s: %s", file_path, exc)
    return roots


def _b64_or_none(value) -> Optional[bytes]:
    return None if value is None else base64.b64decode(value)


def extract_tpm_bundle_from_pkcs10_der(csr_der: bytes) -> Optional[TPMAttestationBundle]:
    csr = x509.load_der_x509_csr(csr_der)
    try:
        for ext in csr.extensions:
            if ext.oid.dotted_string == OID_TPM_ATTESTATION_BUNDLE:
                blob = __import__("json").loads(ext.value.value.decode("utf-8", errors="replace"))
                return TPMAttestationBundle(
                    mode=blob.get("mode", "AIK_FULL"),
                    ek_cert_der=_b64_or_none(blob.get("ek_cert")),
                    aik_pub_raw=_b64_or_none(blob.get("aik_pub")),
                    attest_raw=_b64_or_none(blob.get("attest")),
                    attest_sig_raw=_b64_or_none(blob.get("sig")),
                    certified_key_raw=_b64_or_none(blob.get("cert_key")),
                    nonce=_b64_or_none(blob.get("nonce")),
                )
    except Exception as exc:
        logger.debug("Could not parse legacy TPM JSON extension: %s", exc)

    ms_attrs = extract_microsoft_key_attestation_attributes_from_csr_der(csr_der)
    if ms_attrs is None:
        return None
    bundle = TPMAttestationBundle(mode="MICROSOFT_PKCS10")
    bundle.ms_attestation_statement_raw = ms_attrs.get("attestation_statement_raw")
    bundle.ms_attestation_blob_raw = ms_attrs.get("attestation_blob_raw")
    bundle.ms_ek_info_raw = ms_attrs.get("ek_info_raw")
    bundle.ms_aik_info_raw = ms_attrs.get("aik_info_raw")
    bundle.ms_ksp_name = ms_attrs.get("ksp_name")
    bundle.ms_ksp_name_raw = ms_attrs.get("ksp_name_raw")
    return bundle


def extract_tpm_bundle_from_cmc(p7_der: bytes) -> Optional[TPMAttestationBundle]:
    from utils import exct_csr_from_cmc

    csr_der, _body_part_id, _info = exct_csr_from_cmc(p7_der)
    return extract_tpm_bundle_from_pkcs10_der(csr_der)


def pem_cert_to_der(cert_pem_text: str) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem_text.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)


def try_extract_first_cert_from_blob(blob: bytes) -> Optional[bytes]:
    certs = _find_der_certificates_in_blob(blob)
    return certs[0] if certs else None


def extract_ek_pub_from_decrypted_ek_info(
    decrypted_ek_info: bytes,
    *,
    embedded_certificates_der=None,
    ek_cert_der: Optional[bytes] = None,
):
    class _AnySequence(a_core.SequenceOf):
        _child_spec = a_core.Any

    try:
        seq = _AnySequence.load(decrypted_ek_info)
        if seq:
            first_der = seq[0].dump()
            try:
                return serialization.load_der_public_key(first_der)
            except Exception:
                pass
    except Exception:
        pass

    cert_der = ek_cert_der
    if cert_der is None and embedded_certificates_der:
        for item in embedded_certificates_der:
            if item:
                cert_der = item
                break
    if cert_der is None:
        cert_der = try_extract_first_cert_from_blob(decrypted_ek_info)
    if cert_der is None:
        raise ValueError("Could not locate an EK SubjectPublicKeyInfo or certificate inside decrypted EK_INFO")
    return x509.load_der_x509_certificate(cert_der).public_key()


def _unwrap_first_set_value_der(blob: bytes) -> bytes:
    if not blob:
        raise ValueError("Empty DER blob")
    if blob[0] == 0x30:
        return blob
    if blob[0] == 0x31:
        class _AnySet(a_core.SetOf):
            _child_spec = a_core.Any

        values = _AnySet.load(blob)
        if not values:
            raise ValueError("Empty SET OF wrapper")
        first = values[0]
        if hasattr(first, "dump"):
            return first.dump()
        parsed = getattr(first, "parsed", None)
        if parsed is not None and hasattr(parsed, "dump"):
            return parsed.dump()
        raise ValueError("Could not unwrap first value from SET OF")
    raise ValueError(f"Unsupported DER wrapper tag 0x{blob[0]:02x}")


def extract_content_encryption_algorithm_oid_from_ek_info(ms_ek_info_raw: bytes) -> str:
    ci = a_cms.ContentInfo.load(_unwrap_first_set_value_der(ms_ek_info_raw))
    if ci["content_type"].native != "enveloped_data":
        raise ValueError(f"Expected EnvelopedData in EK_INFO, got {ci['content_type'].native!r}")
    return ci["content"]["encrypted_content_info"]["content_encryption_algorithm"]["algorithm"].dotted


def extract_encryption_algorithm_for_challenge_response(ms_ek_info_raw: bytes) -> str:
    return extract_content_encryption_algorithm_oid_from_ek_info(ms_ek_info_raw)


class OrderedCertificateSet(a_cms.CertificateSet):
    def _set_contents(self, force=False):
        if self.children is None:
            self._parse_children()
        self._contents = b"".join(child.dump(force=force) for child in self)
        self._header = None
        if self._trailer != b"":
            self._trailer = b""


class BodyPartID(a_core.Integer):
    pass


class MsWrappedHeader(a_core.Sequence):
    _fields = [("bodyPartID", BodyPartID)]


class MsWrappedAttr(a_core.Sequence):
    _fields = [("oid", a_core.ObjectIdentifier), ("values", a_core.SetOf, {"spec": a_core.Any})]


class MsWrappedAttrs(a_core.SetOf):
    _child_spec = MsWrappedAttr


class MsChallengeWrapper(a_core.Sequence):
    _fields = [("version", a_core.Integer), ("header", MsWrappedHeader), ("attrs", MsWrappedAttrs)]


class TaggedAttribute(a_core.Sequence):
    _fields = [("bodyPartID", BodyPartID), ("attrType", a_core.ObjectIdentifier), ("attrValues", a_core.SetOf, {"spec": a_core.Any})]


class TaggedAttributes(a_core.SequenceOf):
    _child_spec = TaggedAttribute


class TaggedContentInfo(a_core.Sequence):
    _fields = [("bodyPartID", BodyPartID), ("contentInfo", a_cms.ContentInfo)]


class TaggedContentInfos(a_core.SequenceOf):
    _child_spec = TaggedContentInfo


class OtherMsgs(a_core.SequenceOf):
    _child_spec = a_core.Any


class BodyList(a_core.SequenceOf):
    _child_spec = a_core.Integer


class PendInfo(a_core.Sequence):
    _fields = [("pendToken", a_core.OctetString), ("pendTime", a_core.GeneralizedTime)]


class CMCStatusInfo(a_core.Sequence):
    _fields = [("cMCStatus", a_core.Integer), ("bodyList", BodyList), ("statusString", a_core.UTF8String), ("otherInfo", PendInfo)]


class ResponseBody(a_core.Sequence):
    _fields = [("controlSequence", TaggedAttributes), ("cmsSequence", TaggedContentInfos), ("otherMsgSequence", OtherMsgs)]


def _as_any_from_der(der: bytes) -> a_core.Any:
    return a_core.Any.load(der)


def build_cmc_pending_status_info(*, request_id: int, status_string: str = "En attente de traitement", pend_time=None, body_part_id: int = 1) -> bytes:
    if pend_time is None:
        pend_time = datetime.now(timezone.utc)
    pend_time = pend_time.replace(microsecond=pend_time.microsecond // 1000 * 1000)
    token_len = max(1, (int(request_id).bit_length() + 7) // 8)
    value = CMCStatusInfo(
        {
            "cMCStatus": 3,
            "bodyList": [body_part_id],
            "statusString": status_string,
            "otherInfo": {
                "pendToken": int(request_id).to_bytes(token_len, byteorder="big", signed=False),
                "pendTime": pend_time,
            },
        }
    )
    return value.dump()


def build_encryption_algorithm_attr_value(algorithm_oid: str) -> bytes:
    return a_algos.AlgorithmIdentifier({"algorithm": algorithm_oid, "parameters": a_core.Null()}).dump()


def build_ms_challenge_wrapper_value(
    *,
    encryption_algorithm_oid: str,
    aik_info_hash: bytes | None,
    ksp_name: str,
    tach_blob: bytes,
    inner_body_part_id: int = 1,
) -> bytes:
    attrs = [
        MsWrappedAttr(
            {
                "oid": a_core.ObjectIdentifier(OID_ENROLL_ENCRYPTION_ALGORITHM),
                "values": [_as_any_from_der(build_encryption_algorithm_attr_value(encryption_algorithm_oid))],
            }
        )
    ]
    if aik_info_hash is not None:
        attrs.append(
            MsWrappedAttr(
                {
                    "oid": a_core.ObjectIdentifier(OID_ENROLL_CAXCHGCERT_HASH),
                    "values": [_as_any_from_der(a_core.OctetString(aik_info_hash).dump())],
                }
            )
        )
    attrs.extend(
        [
            MsWrappedAttr(
                {
                    "oid": a_core.ObjectIdentifier(OID_ENROLL_KSP_NAME),
                    "values": [_as_any_from_der(a_core.BMPString(ksp_name).dump())],
                }
            ),
            MsWrappedAttr(
                {
                    "oid": a_core.ObjectIdentifier(OID_ENROLL_ATTESTATION_CHALLENGE),
                    "values": [_as_any_from_der(a_core.OctetString(tach_blob).dump())],
                }
            ),
        ]
    )
    return MsChallengeWrapper(
        {
            "version": 0,
            "header": {"bodyPartID": inner_body_part_id},
            "attrs": MsWrappedAttrs(attrs),
        }
    ).dump()


def build_adcs_like_control_sequence(
    *,
    request_id: int,
    encryption_algorithm_oid: str,
    aik_info_hash: bytes | None,
    tach_blob: bytes,
    ksp_name: str = "Microsoft Platform Crypto Provider",
    pend_time=None,
) -> TaggedAttributes:
    return TaggedAttributes(
        [
            TaggedAttribute(
                {
                    "bodyPartID": BodyPartID(1),
                    "attrType": a_core.ObjectIdentifier(OID_CMC_STATUS_INFO),
                    "attrValues": [
                        _as_any_from_der(
                            build_cmc_pending_status_info(
                                request_id=request_id,
                                status_string="En attente de traitement",
                                pend_time=pend_time,
                                body_part_id=1,
                            )
                        )
                    ],
                }
            ),
            TaggedAttribute(
                {
                    "bodyPartID": BodyPartID(2),
                    "attrType": a_core.ObjectIdentifier(OID_MS_CMC_CHALLENGE_WRAPPER),
                    "attrValues": [
                        _as_any_from_der(
                            build_ms_challenge_wrapper_value(
                                encryption_algorithm_oid=encryption_algorithm_oid,
                                aik_info_hash=aik_info_hash,
                                ksp_name=ksp_name,
                                tach_blob=tach_blob,
                                inner_body_part_id=1,
                            )
                        )
                    ],
                }
            ),
        ]
    )


def build_cmc_cms_sequence(*, ca_exchange_chain_der) -> TaggedContentInfos:
    return TaggedContentInfos([])


def build_cmc_pki_response(*, control_sequence: TaggedAttributes, cms_sequence: TaggedContentInfos) -> bytes:
    return ResponseBody(
        {"controlSequence": control_sequence, "cmsSequence": cms_sequence, "otherMsgSequence": OtherMsgs([])}
    ).dump()


def build_microsoft_attestation_challenge_pki_response(
    *,
    request_id: int,
    ca_exchange_chain_der,
    encryption_algorithm_oid: str,
    aik_info_hash: bytes | None,
    tach_blob: bytes,
    pend_time=None,
) -> dict:
    control_seq = build_adcs_like_control_sequence(
        request_id=request_id,
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        tach_blob=tach_blob,
        ksp_name="Microsoft Platform Crypto Provider",
        pend_time=pend_time,
    )
    cms_seq = build_cmc_cms_sequence(ca_exchange_chain_der=ca_exchange_chain_der)
    response_body_der = build_cmc_pki_response(control_sequence=control_seq, cms_sequence=cms_seq)
    return {"response_body_der": response_body_der, "content_info_der": response_body_der}


def _kdfa(hash_alg: int, key: bytes, label: str, context_u: bytes, context_v: bytes, bits: int) -> bytes:
    hash_name = _tpm_alg_to_hash(hash_alg)
    target_len = (bits + 7) // 8
    out = b""
    counter = 1
    label_bytes = label.encode("ascii") + b"\x00"
    bits_be = struct.pack(">I", bits)
    while len(out) < target_len:
        data = struct.pack(">I", counter) + label_bytes + context_u + context_v + bits_be
        out += hmac.new(key, data, hash_name).digest()
        counter += 1
    return out[:target_len]


def _kdfe(hash_alg: int, z: bytes, label: str, party_u_info: bytes, party_v_info: bytes, bits: int) -> bytes:
    hash_name = _tpm_alg_to_hash(hash_alg)
    target_len = (bits + 7) // 8
    out = b""
    counter = 1
    label_bytes = label.encode("ascii") + b"\x00"
    while len(out) < target_len:
        out += hashlib.new(
            hash_name,
            struct.pack(">I", counter) + z + label_bytes + party_u_info + party_v_info,
        ).digest()
        counter += 1
    out = out[:target_len]
    extra_bits = (8 - bits % 8) % 8
    if extra_bits:
        out = bytes([out[0] & (0xFF >> extra_bits)]) + out[1:]
    return out


def infer_ek_name_alg_from_public_key(ek_pub) -> int:
    try:
        if isinstance(ek_pub, rsa.RSAPublicKey):
            if ek_pub.key_size <= 2048:
                return TPM2_ALG_SHA256
            if ek_pub.key_size <= 4096:
                return TPM2_ALG_SHA384
        elif isinstance(ek_pub, ec.EllipticCurvePublicKey):
            if isinstance(ek_pub.curve, ec.SECP256R1):
                return TPM2_ALG_SHA256
            if isinstance(ek_pub.curve, ec.SECP384R1):
                return TPM2_ALG_SHA384
            if isinstance(ek_pub.curve, ec.SECP521R1):
                return TPM2_ALG_SHA512
    except Exception:
        pass
    return TPM2_ALG_SHA256


def tpm2_make_credential(
    ek_pub,
    object_name: bytes,
    credential_value: bytes,
    ek_name_alg: int = TPM2_ALG_SHA256,
    sym_bits: int = 128,
) -> tuple[bytes, bytes]:
    hash_size = hashlib.new(_tpm_alg_to_hash(ek_name_alg)).digest_size
    if isinstance(ek_pub, rsa.RSAPublicKey):
        seed = os.urandom(hash_size)
        encrypted_secret = ek_pub.encrypt(
            seed,
            padding.OAEP(
                mgf=padding.MGF1(_tpm_alg_to_hash_obj(ek_name_alg)),
                algorithm=_tpm_alg_to_hash_obj(ek_name_alg),
                label=b"IDENTITY\x00",
            ),
        )
    elif isinstance(ek_pub, ec.EllipticCurvePublicKey):
        ephemeral_key = ec.generate_private_key(ek_pub.curve)
        ephemeral_pub = ephemeral_key.public_key()
        shared_z = ephemeral_key.exchange(ec.ECDH(), ek_pub)
        eph_bytes = ephemeral_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        ek_bytes = ek_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        coord_size = (ek_pub.key_size + 7) // 8
        seed = _kdfe(ek_name_alg, shared_z, "IDENTITY", eph_bytes[1:1 + coord_size], ek_bytes[1:1 + coord_size], hash_size * 8)
        encrypted_secret = _tpm2b(eph_bytes[1:1 + coord_size]) + _tpm2b(eph_bytes[1 + coord_size:])
    else:
        raise TypeError(f"Unsupported EK public key type: {type(ek_pub).__name__}")

    sym_key = _kdfa(ek_name_alg, seed, "STORAGE", object_name, b"", sym_bits)
    encrypted_credential = Cipher(algorithms.AES(sym_key), modes.CFB(b"\x00" * 16)).encryptor().update(_tpm2b(credential_value))
    hmac_key = _kdfa(ek_name_alg, seed, "INTEGRITY", b"", b"", hash_size * 8)
    outer_hmac = hmac.new(hmac_key, encrypted_credential + object_name, _tpm_alg_to_hash(ek_name_alg)).digest()
    return _tpm2b(outer_hmac) + encrypted_credential, encrypted_secret


def _parse_microsoft_key_attestation_statement(blob: bytes) -> dict:
    if not blob:
        raise ValueError("Empty attestation statement")
    pos = blob.find(b"KAST")
    if pos < 0 or len(blob) < pos + 28:
        raise ValueError("KAST marker not found or truncated")
    magic, version, platform, header_size, cb_id_binding, cb_key_attestation, cb_aik_opaque = struct.unpack_from("<7I", blob, pos)
    if magic != 1414742347:
        raise ValueError(f"Unexpected KAST magic: {magic:#010x}")
    header_size = max(header_size, 28)
    start = pos + header_size
    end_id = start + cb_id_binding
    end_key = end_id + cb_key_attestation
    end_aik = end_key + cb_aik_opaque
    if end_aik > len(blob):
        raise ValueError("Truncated KAST payload")
    return {
        "offset": pos,
        "version": version,
        "platform": platform,
        "header_size": header_size,
        "id_binding": blob[start:end_id],
        "key_attestation": blob[end_id:end_key],
        "aik_opaque": blob[end_key:end_aik],
    }


def _extract_aik_name_from_id_binding(id_binding: bytes) -> bytes:
    if len(id_binding) < 2:
        raise ValueError("Empty TPM 2.0 idBinding")
    public_len = struct.unpack(">H", id_binding[:2])[0]
    if public_len <= 0 or public_len > len(id_binding) - 2:
        raise ValueError("Invalid TPM2B_PUBLIC length in idBinding")
    return parse_tpmt_public(id_binding[2:2 + public_len]).compute_name()


def _extract_aik_name_from_microsoft_attestation_blob(attestation_blob_raw: bytes) -> bytes:
    if not attestation_blob_raw:
        raise ValueError("Empty attestation blob")
    try:
        parsed = _parse_microsoft_key_attestation_statement(attestation_blob_raw)
        if parsed.get("platform") == 2 and parsed.get("id_binding"):
            return _extract_aik_name_from_id_binding(parsed["id_binding"])
    except Exception as exc:
        logger.debug("Structured KAST parse failed, falling back to heuristic scan: %s", exc)

    preferred_offsets = []
    off = 0
    while True:
        pos = attestation_blob_raw.find(b"PCPM", off)
        if pos < 0:
            break
        preferred_offsets.extend(range(max(0, pos - 96), min(len(attestation_blob_raw), pos + 1024)))
        off = pos + 1
    if not preferred_offsets:
        preferred_offsets = list(range(len(attestation_blob_raw)))

    ordered_offsets = []
    seen = set()
    for pos in preferred_offsets + list(range(len(attestation_blob_raw))):
        if pos not in seen:
            seen.add(pos)
            ordered_offsets.append(pos)

    candidates = []
    for pos in ordered_offsets:
        for raw in (attestation_blob_raw[pos:], None):
            if raw is None and pos + 2 <= len(attestation_blob_raw):
                length = struct.unpack(">H", attestation_blob_raw[pos:pos + 2])[0]
                if 0 < length <= len(attestation_blob_raw) - pos - 2:
                    raw = attestation_blob_raw[pos + 2:pos + 2 + length]
                else:
                    continue
            if raw is None or len(raw) < 16:
                continue
            try:
                pub = parse_tpmt_public(raw)
            except Exception:
                continue
            score = 0
            if pub.object_attr & TPMA_OBJECT_RESTRICTED:
                score += 3
            if pub.object_attr & TPMA_OBJECT_SIGN:
                score += 3
            if not pub.object_attr & TPMA_OBJECT_DECRYPT:
                score += 2
            if pub.alg_type in (TPM2_ALG_RSA, TPM2_ALG_ECC):
                score += 1
            if pub.name_alg in (TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512):
                score += 1
            if pub.alg_type == TPM2_ALG_RSA and pub.rsa_key_bits in (2048, 3072, 4096):
                score += 1
            candidates.append((score, pos, pub))
    if not candidates:
        raise ValueError("Could not locate a TPMT_PUBLIC candidate inside attestation blob")
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][2].compute_name()


def _make_tach_blob(
    *,
    secret: bytes,
    ek_pub,
    aik_name: bytes,
    attestation_blob_raw: bytes | None = None,
    ek_name_alg: int = TPM2_ALG_SHA256,
    sym_bits: int = 128,
) -> bytes:
    credential_blob, encrypted_secret = tpm2_make_credential(
        ek_pub=ek_pub,
        object_name=aik_name,
        credential_value=secret,
        ek_name_alg=ek_name_alg,
        sym_bits=sym_bits,
    )
    makecred_raw = _tpm2b(credential_blob) + _tpm2b(encrypted_secret)
    pcpm_tail = b""
    if attestation_blob_raw:
        try:
            parsed = _parse_microsoft_key_attestation_statement(attestation_blob_raw)
            if parsed.get("platform") == 2 and parsed.get("aik_opaque"):
                pcpm_tail = parsed["aik_opaque"]
        except Exception:
            pass
        if not pcpm_tail:
            last_pcp = attestation_blob_raw.rfind(b"PCPM")
            if last_pcp >= 0:
                pcpm_tail = attestation_blob_raw[last_pcp:]
    header = b"TACH" + struct.pack("<I", 1) + struct.pack("<I", 2 if pcpm_tail else 1) + struct.pack("<I", 24)
    header += struct.pack("<I", len(makecred_raw)) + struct.pack("<I", len(pcpm_tail))
    return header + makecred_raw + pcpm_tail


def _normalize_pem_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Unsupported PEM type: {type(value).__name__}")


def _sign_cmc_pki_response_python(
    *,
    pki_response_der: bytes,
    signer_cert_pem,
    signer_key_pem,
    extra_chain_pems=None,
    extra_certs_der=None,
) -> bytes:
    signer_cert = x509.load_pem_x509_certificate(_normalize_pem_bytes(signer_cert_pem))
    signer_cert_der = signer_cert.public_bytes(serialization.Encoding.DER)
    signer_asn1 = a_cms.Certificate.load(signer_cert_der)

    seen = set()
    cert_choices = []

    def _add_cert_der(cert_der: bytes):
        cert_der = bytes(cert_der)
        if cert_der in seen:
            return
        seen.add(cert_der)
        cert_choices.append(a_cms.CertificateChoices(name="certificate", value=a_cms.Certificate.load(cert_der)))

    _add_cert_der(signer_cert_der)
    for item in extra_chain_pems or []:
        try:
            cert = x509.load_pem_x509_certificate(_normalize_pem_bytes(item))
            _add_cert_der(cert.public_bytes(serialization.Encoding.DER))
        except Exception:
            pass
    for cert_der in extra_certs_der or []:
        try:
            _add_cert_der(cert_der)
        except Exception:
            pass

    signed_attrs = a_cms.CMSAttributes(
        [
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.3", "values": [a_cms.ContentType(OID_ID_CCT_PKI_RESPONSE)]}),
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.4", "values": [hashlib.sha256(pki_response_der).digest()]}),
        ]
    )
    signature = serialization.load_pem_private_key(_normalize_pem_bytes(signer_key_pem), password=None).sign(
        signed_attrs.dump(force=True),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signer_info = a_cms.SignerInfo(
        {
            "version": "v1",
            "sid": a_cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": a_cms.IssuerAndSerialNumber(
                        {"issuer": signer_asn1.issuer, "serial_number": signer_asn1.serial_number}
                    )
                }
            ),
            "digest_algorithm": a_cms.DigestAlgorithm({"algorithm": "sha256", "parameters": a_core.Null()}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": a_cms.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15", "parameters": a_core.Null()}
            ),
            "signature": signature,
        }
    )
    signed_data = a_cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [a_cms.DigestAlgorithm({"algorithm": "sha256", "parameters": a_core.Null()})],
            "encap_content_info": {"content_type": OID_ID_CCT_PKI_RESPONSE, "content": a_cms.ParsableOctetString(pki_response_der)},
            "certificates": OrderedCertificateSet(cert_choices),
            "signer_infos": [signer_info],
        }
    )
    return a_cms.ContentInfo({"content_type": OID_ID_SIGNED_DATA, "content": signed_data}).dump()


def build_and_sign_microsoft_attestation_challenge(
    *,
    request_id: int,
    ek_pub,
    ca_exchange_chain_der,
    encryption_algorithm_oid: str,
    aik_info_hash: bytes | None,
    signer_cert_pem,
    signer_key_pem,
    signer_chain_pems=None,
    secret: bytes | None = None,
    openssl_bin: str = "openssl",
    aik_pub_raw: bytes | None = None,
    attestation_blob_raw: bytes | None = None,
) -> dict:
    del openssl_bin
    if secret is None:
        secret = os.urandom(32)
    ek_name_alg = infer_ek_name_alg_from_public_key(ek_pub)

    aik_name = None
    if aik_pub_raw is not None:
        try:
            aik_name = parse_tpmt_public(aik_pub_raw).compute_name()
        except Exception:
            aik_name = None
    if aik_name is None and attestation_blob_raw is not None:
        aik_name = _extract_aik_name_from_microsoft_attestation_blob(attestation_blob_raw)
    if aik_name is None:
        raise ValueError(
            "Could not recover the AIK TPM name from the Microsoft attestation statement/blob; refusing to emit an invalid TPM2_MakeCredential challenge."
        )

    tach_blob = _make_tach_blob(
        secret=secret,
        ek_pub=ek_pub,
        aik_name=aik_name,
        attestation_blob_raw=attestation_blob_raw,
        ek_name_alg=ek_name_alg,
    )
    built = build_microsoft_attestation_challenge_pki_response(
        request_id=int(request_id),
        ca_exchange_chain_der=ca_exchange_chain_der,
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        tach_blob=tach_blob,
    )
    built["request_id"] = int(request_id)
    built["effective_request_id"] = int(request_id)
    built["secret"] = secret
    built["tach_blob"] = tach_blob
    built["signed_pkcs7_der"] = _sign_cmc_pki_response_python(
        pki_response_der=built["response_body_der"],
        signer_cert_pem=signer_cert_pem,
        signer_key_pem=signer_key_pem,
        extra_chain_pems=signer_chain_pems,
        extra_certs_der=ca_exchange_chain_der,
    )
    return built
