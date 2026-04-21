from pathlib import Path
"""
tpm_attestation.py — TPM EK / AIK attestation support for adcs_python
======================================================================

Implements server-side verification of TPM 2.0 attestation as defined by:
  - TCG TPM 2.0 Part 1/2/3 specifications
  - Microsoft ADCS TPM Key Attestation protocol (MS-WCCE §3.2.1.4.3)

Flow
----
1. Client sends a CSR containing:
   - An AIK public key (or a key certified by the AIK)
   - A TPM 2.0 quote / certify structure (TPMS_ATTEST) signed by the AIK
   - The EK certificate (from TPM NV or supplied out-of-band)

2. Server verifies:
   a. EK certificate chains to a trusted TPM manufacturer CA
   b. AIK is bound to the same TPM (EK proof-of-possession via ActivateCredential)
   c. Quote/certify signature is valid under the AIK public key
   d. The attested key matches the public key in the CSR
   e. Key attributes (TPMA_OBJECT) satisfy policy (e.g., fixedTPM, fixedParent)

Supported attestation sub-types
--------------------------------
- EK_ONLY  : only the EK certificate is checked (weaker, no AIK binding)
- AIK_FULL : full AIK attestation with TPMS_ATTEST quote verification
- CERTIFY  : TPM2_Certify of a key by an already-trusted AIK

References
----------
- TCG EK Credential Profile: https://trustedcomputinggroup.org/resource/
- MS-WCCE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce
"""

import base64
import hashlib
import hmac
import logging
import os
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import IntFlag, auto
from typing import Optional

from asn1crypto import cms as a_cms
from asn1crypto import csr as a_csr
from asn1crypto import core as a_core
from asn1crypto import algos as a_algos

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyasn1.codec.der import decoder as asn1_decoder
from pyasn1.type import univ

logger = logging.getLogger("adcs.tpm_attestation")

# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------

# TCG EK Certificate OIDs (TCG EK Credential Profile v2.0 §3.1)
OID_TCG_EK_CERTIFICATE            = "2.23.133.8.1"
OID_TCG_PLATFORM_CERTIFICATE      = "2.23.133.8.2"
OID_TCG_AIK_CERTIFICATE           = "2.23.133.8.3"
OID_TCG_TPMNV_NVRAM               = "2.23.133.3"

# TPM Manufacturer OIDs (used in EK SubjectAlternativeName)
OID_TCG_TPM_MANUFACTURER          = "2.23.133.2.1"
OID_TCG_TPM_MODEL                  = "2.23.133.2.2"
OID_TCG_TPM_VERSION                = "2.23.133.2.3"
OID_TCG_TPM_ID_FIDO               = "2.23.133.2.9"

# Subject alternative name for TPM devices
OID_TCG_SAN_TPM_DEVICE             = "2.23.133.2"

# Microsoft-specific
OID_MS_TPM_KEY_ATTESTATION         = "1.3.6.1.4.1.311.21.501"

# ---------------------------------------------------------------------------
# TPM 2.0 constants (subset from TPM 2.0 Part 2 §Table 31+)
# ---------------------------------------------------------------------------

# TPMI_ST_ATTEST
TPM2_ST_ATTEST_CERTIFY  = 0x8017
TPM2_ST_ATTEST_QUOTE    = 0x8018
TPM2_ST_ATTEST_NV       = 0x8014

# TPMA_OBJECT bits
TPMA_OBJECT_FIXEDTPM              = 0x00000002
TPMA_OBJECT_STCLEAR               = 0x00000004
TPMA_OBJECT_FIXEDPARENT           = 0x00000010
TPMA_OBJECT_SENSITIVEDATAORIGIN   = 0x00000020
TPMA_OBJECT_USERWITHAUTH          = 0x00000040
TPMA_OBJECT_ADMINWITHPOLICY       = 0x00000080
TPMA_OBJECT_NODA                  = 0x00000400
TPMA_OBJECT_ENCRYPTEDDUPLICATION  = 0x00000800
TPMA_OBJECT_RESTRICTED            = 0x00010000
TPMA_OBJECT_DECRYPT               = 0x00020000
TPMA_OBJECT_SIGN                  = 0x00040000

# TPM_ALG_ID
TPM2_ALG_RSA   = 0x0001
TPM2_ALG_ECC   = 0x0023
TPM2_ALG_SHA1  = 0x0004
TPM2_ALG_SHA256= 0x000B
TPM2_ALG_SHA384= 0x000C
TPM2_ALG_SHA512= 0x000D
TPM2_ALG_NULL  = 0x0010
TPM2_ALG_RSASSA= 0x0014
TPM2_ALG_RSAPSS= 0x0016
TPM2_ALG_ECDSA = 0x0018
TPM2_ALG_ECDAA = 0x001A
TPM2_ALG_SM2 = 0x001B
TPM2_ALG_ECSCHNORR = 0x001C

# TPM_ECC_CURVE
TPM2_ECC_NIST_P256 = 0x0003
TPM2_ECC_NIST_P384 = 0x0004

# Magic number in TPMS_ATTEST
TPM2_GENERATED_VALUE = 0xFF544347  # b'\xff' + b'TCG'

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TPMPublicKey:
    """Decoded TPMT_PUBLIC structure (simplified)."""
    alg_type:    int          # TPM2_ALG_RSA or TPM2_ALG_ECC
    name_alg:    int          # e.g. TPM2_ALG_SHA256
    object_attr: int          # TPMA_OBJECT bitmask
    auth_policy: bytes
    # RSA
    rsa_key_bits:  int = 0
    rsa_exponent:  int = 0
    rsa_modulus:   bytes = b""
    # ECC
    ecc_curve:     int = 0
    ecc_x:         bytes = b""
    ecc_y:         bytes = b""
    _raw_bytes:    bytes | None = None

    def to_cryptography_public_key(self):
        """Convert to a cryptography.io public key object."""
        if self.alg_type == TPM2_ALG_RSA:
            exp = self.rsa_exponent if self.rsa_exponent != 0 else 65537
            n   = int.from_bytes(self.rsa_modulus, "big")
            return rsa.RSAPublicNumbers(exp, n).public_key()
        elif self.alg_type == TPM2_ALG_ECC:
            x = int.from_bytes(self.ecc_x, "big")
            y = int.from_bytes(self.ecc_y, "big")
            curve_map = {
                TPM2_ECC_NIST_P256: ec.SECP256R1(),
                TPM2_ECC_NIST_P384: ec.SECP384R1(),
            }
            curve = curve_map.get(self.ecc_curve, ec.SECP256R1())
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        raise ValueError(f"Unsupported TPM key algorithm: {self.alg_type:#06x}")

    def compute_name(self) -> bytes:
        """
        Compute TPM name = nameAlg || Hash(nameAlg, TPMT_PUBLIC_marshalled).
        Used to match the certified key inside TPMS_ATTEST.
        """
        raw = self._raw_bytes if self._raw_bytes is not None else self._marshal()
        hash_algo = _tpm_alg_to_hash(self.name_alg)
        digest = hashlib.new(hash_algo, raw).digest()
        name_alg_bytes = struct.pack(">H", self.name_alg)
        return name_alg_bytes + digest

    def _marshal(self) -> bytes:
        """Re-marshal the TPMT_PUBLIC to bytes (for name computation)."""
        buf = struct.pack(">HHI", self.alg_type, self.name_alg, self.object_attr)
        buf += _tpm2b(self.auth_policy)
        if self.alg_type == TPM2_ALG_RSA:
            # TPMS_RSA_PARMS: symmetric + scheme + keyBits + exponent
            buf += struct.pack(">HHHhI",
                TPM2_ALG_NULL, TPM2_ALG_NULL,  # symmetric, scheme
                self.rsa_key_bits,
                TPM2_ALG_NULL,                  # scheme detail
                self.rsa_exponent,
            )
            buf += _tpm2b(self.rsa_modulus)
        elif self.alg_type == TPM2_ALG_ECC:
            buf += struct.pack(">HHHH",
                TPM2_ALG_NULL,    # symmetric
                TPM2_ALG_NULL,    # scheme
                self.ecc_curve,
                TPM2_ALG_NULL,    # kdf
            )
            buf += _tpm2b(self.ecc_x)
            buf += _tpm2b(self.ecc_y)
        return buf


@dataclass
class AttestationData:
    """Decoded TPMS_ATTEST structure."""
    magic:           int
    attest_type:     int    # TPM2_ST_ATTEST_CERTIFY, etc.
    qualified_signer: bytes  # TPM2B_NAME of signing key (AIK)
    extra_data:      bytes  # TPM2B_DATA (nonce)
    clock_info:      bytes  # TPMS_CLOCK_INFO (8 bytes)
    firmware_version: int
    # For ST_ATTEST_CERTIFY
    certified_name:  bytes = b""   # TPM2B_NAME of certified object
    certified_qname: bytes = b""   # TPM2B_NAME (qualified)
    # For ST_ATTEST_QUOTE
    pcr_selection:   bytes = b""
    pcr_digest:      bytes = b""
    raw:             bytes = b""   # original bytes (for signature check)


@dataclass
class TPMAttestationBundle:
    """
    All TPM artifacts presented by the client for attestation.

    Fields are populated from the CSR extensions or a dedicated
    attribute bag in the CES request.
    """
    # EK certificate DER bytes (from TPM NV index or supplied OOB)
    ek_cert_der:      Optional[bytes] = None
    # AIK public key in TPMT_PUBLIC marshalled form
    aik_pub_raw:      Optional[bytes] = None
    # TPMS_ATTEST (certify or quote)
    attest_raw:       Optional[bytes] = None
    # Signature over TPMS_ATTEST with AIK private key
    attest_sig_raw:   Optional[bytes] = None
    # TPMT_PUBLIC of the certified key (the key that will go in the cert)
    certified_key_raw: Optional[bytes] = None
    # Nonce used in the certify/quote (from the server challenge)
    nonce:            Optional[bytes] = None
    # Which attestation mode the client is requesting
    mode:             str = "AIK_FULL"  # "EK_ONLY" | "AIK_FULL" | "CERTIFY"


@dataclass
class AttestationResult:
    """Result returned from verify_tpm_attestation()."""
    success: bool
    mode:    str
    message: str
    # Populated on success
    ek_cert:           Optional[x509.Certificate] = None
    aik_public_key:    Optional[TPMPublicKey]      = None
    certified_key_obj: Optional[TPMPublicKey]      = None
    # Key attributes of the certified key
    is_fixed_tpm:      bool = False
    is_fixed_parent:   bool = False
    is_restricted:     bool = False
    firmware_version:  Optional[int] = None
    manufacturer:      Optional[str] = None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

class TPMAttestationError(Exception):
    pass


def verify_tpm_attestation(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,         # list of x509.Certificate (trusted TPM CA roots)
    expected_nonce: Optional[bytes] = None,
    require_fixed_tpm: bool = True,
    require_fixed_parent: bool = True,
    require_restricted: bool = True,
) -> AttestationResult:
    """
    Main entry point.  Verify a TPM attestation bundle.

    Parameters
    ----------
    bundle             : filled TPMAttestationBundle from the client request
    trusted_ek_roots   : list of trusted TPM manufacturer CA certificates
    expected_nonce     : the nonce the server previously sent (replay protection)
    require_fixed_tpm  : enforce TPMA_OBJECT_FIXEDTPM on the certified key
    require_fixed_parent: enforce TPMA_OBJECT_FIXEDPARENT
    require_restricted  : enforce TPMA_OBJECT_RESTRICTED (signing keys only)

    Returns
    -------
    AttestationResult
    """
    try:
        if bundle.mode == "EK_ONLY":
            return _verify_ek_only(bundle, trusted_ek_roots)
        elif bundle.mode == "AIK_FULL":
            return _verify_aik_full(
                bundle, trusted_ek_roots, expected_nonce,
                require_fixed_tpm, require_fixed_parent, require_restricted,
            )
        elif bundle.mode == "CERTIFY":
            return _verify_certify(
                bundle, trusted_ek_roots, expected_nonce,
                require_fixed_tpm, require_fixed_parent, require_restricted,
            )
        else:
            raise TPMAttestationError(f"Unknown attestation mode: {bundle.mode}")
    except TPMAttestationError as exc:
        logger.warning("TPM attestation failed: %s", exc)
        return AttestationResult(success=False, mode=bundle.mode, message=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during TPM attestation")
        return AttestationResult(
            success=False, mode=bundle.mode,
            message=f"Internal error: {exc}",
        )


# ---------------------------------------------------------------------------
# Verification modes
# ---------------------------------------------------------------------------

def _verify_ek_only(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,
) -> AttestationResult:
    """
    Weakest mode: only verify that the EK certificate chains to a trusted root.
    No AIK binding, no key certification.
    """
    if not bundle.ek_cert_der:
        raise TPMAttestationError("EK_ONLY mode requires ek_cert_der")

    ek_cert = _load_cert(bundle.ek_cert_der)
    _verify_ek_cert(ek_cert, trusted_ek_roots)

    manufacturer = _extract_tpm_manufacturer(ek_cert)
    logger.info("EK_ONLY attestation OK — manufacturer=%s subject=%s",
                manufacturer, ek_cert.subject.rfc4514_string())

    return AttestationResult(
        success=True,
        mode="EK_ONLY",
        message="EK certificate verified against trusted TPM CA roots",
        ek_cert=ek_cert,
        manufacturer=manufacturer,
    )


def _verify_aik_full(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,
    expected_nonce: Optional[bytes],
    require_fixed_tpm: bool,
    require_fixed_parent: bool,
    require_restricted: bool,
) -> AttestationResult:
    """
    Full AIK attestation.
    Verifies EK cert → AIK binding → quote signature → nonce.
    The AIK itself is the key that ends up in the certificate.
    """
    if not bundle.ek_cert_der:
        raise TPMAttestationError("AIK_FULL mode requires ek_cert_der")
    if not bundle.aik_pub_raw:
        raise TPMAttestationError("AIK_FULL mode requires aik_pub_raw (TPMT_PUBLIC)")
    if not bundle.attest_raw:
        raise TPMAttestationError("AIK_FULL mode requires attest_raw (TPMS_ATTEST)")
    if not bundle.attest_sig_raw:
        raise TPMAttestationError("AIK_FULL mode requires attest_sig_raw")

    # 1. Verify EK certificate
    ek_cert = _load_cert(bundle.ek_cert_der)
    _verify_ek_cert(ek_cert, trusted_ek_roots)

    # 2. Parse AIK public key
    aik_pub = parse_tpmt_public(bundle.aik_pub_raw)

    # 3. Verify that the AIK is a valid restricted signing key
    _check_aik_attributes(aik_pub)

    # 4. Parse TPMS_ATTEST
    attest = parse_tpms_attest(bundle.attest_raw)

    # 5. Verify magic
    if attest.magic != TPM2_GENERATED_VALUE:
        raise TPMAttestationError(
            f"TPMS_ATTEST magic invalid: {attest.magic:#010x}"
        )

    # 6. Verify nonce
    if expected_nonce is not None:
        if not hmac.compare_digest(attest.extra_data, expected_nonce):
            raise TPMAttestationError("Nonce mismatch — possible replay attack")

    # 7. Verify AIK signature over TPMS_ATTEST
    _verify_tpm_signature(
        data=bundle.attest_raw,
        sig_raw=bundle.attest_sig_raw,
        pub_key=aik_pub,
    )

    # 8. In AIK_FULL mode the attested object IS the AIK itself —
    #    so we check that the qualified signer matches the AIK name
    aik_name = aik_pub.compute_name()
    if attest.certified_name and attest.certified_name != aik_name:
        # Some implementations put the AIK name in certified_name
        raise TPMAttestationError(
            "Certified name in TPMS_ATTEST does not match AIK public key name"
        )

    manufacturer = _extract_tpm_manufacturer(ek_cert)
    _check_key_policy(aik_pub, require_fixed_tpm, require_fixed_parent, require_restricted)

    logger.info(
        "AIK_FULL attestation OK — manufacturer=%s firmware=%016x",
        manufacturer, attest.firmware_version,
    )
    return AttestationResult(
        success=True,
        mode="AIK_FULL",
        message="AIK attestation verified (EK chain + quote signature + nonce)",
        ek_cert=ek_cert,
        aik_public_key=aik_pub,
        is_fixed_tpm=bool(aik_pub.object_attr & TPMA_OBJECT_FIXEDTPM),
        is_fixed_parent=bool(aik_pub.object_attr & TPMA_OBJECT_FIXEDPARENT),
        is_restricted=bool(aik_pub.object_attr & TPMA_OBJECT_RESTRICTED),
        firmware_version=attest.firmware_version,
        manufacturer=manufacturer,
    )


def _verify_certify(
    bundle: TPMAttestationBundle,
    trusted_ek_roots: list,
    expected_nonce: Optional[bytes],
    require_fixed_tpm: bool,
    require_fixed_parent: bool,
    require_restricted: bool,
) -> AttestationResult:
    """
    Full TPM2_Certify flow:
    A previously-trusted AIK certifies a different key (the one in the CSR).
    """
    if not bundle.ek_cert_der:
        raise TPMAttestationError("CERTIFY mode requires ek_cert_der")
    if not bundle.aik_pub_raw:
        raise TPMAttestationError("CERTIFY mode requires aik_pub_raw")
    if not bundle.certified_key_raw:
        raise TPMAttestationError("CERTIFY mode requires certified_key_raw (TPMT_PUBLIC)")
    if not bundle.attest_raw:
        raise TPMAttestationError("CERTIFY mode requires attest_raw (TPMS_ATTEST)")
    if not bundle.attest_sig_raw:
        raise TPMAttestationError("CERTIFY mode requires attest_sig_raw")

    # 1 — EK
    ek_cert = _load_cert(bundle.ek_cert_der)
    _verify_ek_cert(ek_cert, trusted_ek_roots)

    # 2 — AIK public key
    aik_pub = parse_tpmt_public(bundle.aik_pub_raw)
    _check_aik_attributes(aik_pub)

    # 3 — Certified key (the actual key that goes in the end-entity cert)
    cert_key = parse_tpmt_public(bundle.certified_key_raw)

    # 4 — Parse TPMS_ATTEST (must be ST_ATTEST_CERTIFY)
    attest = parse_tpms_attest(bundle.attest_raw)
    if attest.magic != TPM2_GENERATED_VALUE:
        raise TPMAttestationError(f"Bad magic: {attest.magic:#010x}")
    if attest.attest_type != TPM2_ST_ATTEST_CERTIFY:
        raise TPMAttestationError(
            f"Expected ST_ATTEST_CERTIFY ({TPM2_ST_ATTEST_CERTIFY:#06x}), "
            f"got {attest.attest_type:#06x}"
        )

    # 5 — Nonce
    if expected_nonce is not None:
        if not hmac.compare_digest(attest.extra_data, expected_nonce):
            raise TPMAttestationError("Nonce mismatch — possible replay attack")

    # 6 — Signature by AIK over TPMS_ATTEST
    _verify_tpm_signature(
        data=bundle.attest_raw,
        sig_raw=bundle.attest_sig_raw,
        pub_key=aik_pub,
    )

    # 7 — Verify that TPMS_ATTEST.certifiedName == name(certifiedKey)
    expected_name = cert_key.compute_name()
    if attest.certified_name != expected_name:
        raise TPMAttestationError(
            "certifiedName in TPMS_ATTEST does not match the certified key's "
            "computed TPM name — key mismatch or tampered attestation"
        )

    # 8 — Key policy checks
    _check_key_policy(cert_key, require_fixed_tpm, require_fixed_parent, require_restricted)

    manufacturer = _extract_tpm_manufacturer(ek_cert)
    logger.info(
        "CERTIFY attestation OK — manufacturer=%s firmware=%016x",
        manufacturer, attest.firmware_version,
    )
    return AttestationResult(
        success=True,
        mode="CERTIFY",
        message="TPM2_Certify attestation verified (EK chain + AIK signature + key name match)",
        ek_cert=ek_cert,
        aik_public_key=aik_pub,
        certified_key_obj=cert_key,
        is_fixed_tpm=bool(cert_key.object_attr & TPMA_OBJECT_FIXEDTPM),
        is_fixed_parent=bool(cert_key.object_attr & TPMA_OBJECT_FIXEDPARENT),
        is_restricted=bool(cert_key.object_attr & TPMA_OBJECT_RESTRICTED),
        firmware_version=attest.firmware_version,
        manufacturer=manufacturer,
    )


# ---------------------------------------------------------------------------
# TPM binary parsers
# ---------------------------------------------------------------------------

class _Reader:
    """Simple byte-stream reader (big-endian, TPM wire format)."""

    def __init__(self, data: bytes):
        self._d = data
        self._pos = 0

    def u8(self)  -> int: return self._consume(1, ">B")[0]
    def u16(self) -> int: return self._consume(2, ">H")[0]
    def u32(self) -> int: return self._consume(4, ">I")[0]
    def u64(self) -> int: return self._consume(8, ">Q")[0]

    def tpm2b(self) -> bytes:
        size = self.u16()
        return self.raw(size)

    def raw(self, n: int) -> bytes:
        if self._pos + n > len(self._d):
            raise TPMAttestationError(
                f"Parser overrun: need {n} bytes at offset {self._pos}, "
                f"only {len(self._d) - self._pos} remaining"
            )
        chunk = self._d[self._pos: self._pos + n]
        self._pos += n
        return chunk

    def remaining(self) -> bytes:
        return self._d[self._pos:]

    def tell(self) -> int:
        return self._pos

    def _consume(self, n: int, fmt: str):
        chunk = self.raw(n)
        return struct.unpack(fmt, chunk)


def parse_tpmt_public(raw: bytes) -> TPMPublicKey:
    """
    Decode a TPMT_PUBLIC structure.

    TPMT_PUBLIC ::= SEQUENCE {
        type        TPMI_ALG_PUBLIC,
        nameAlg     TPMI_ALG_HASH,
        objectAttributes TPMA_OBJECT,
        authPolicy  TPM2B_DIGEST,
        parameters  TPMU_PUBLIC_PARMS,
        unique      TPMU_PUBLIC_ID,
    }
    """
    r = _Reader(raw)
    alg_type    = r.u16()
    name_alg    = r.u16()
    obj_attr    = r.u32()
    auth_policy = r.tpm2b()

    result = TPMPublicKey(
        alg_type=alg_type,
        name_alg=name_alg,
        object_attr=obj_attr,
        auth_policy=auth_policy,
    )

    if alg_type == TPM2_ALG_RSA:
        # TPMS_RSA_PARMS
        _sym  = r.u16()   # symmetric
        _sch  = r.u16()   # scheme
        if _sch in (TPM2_ALG_RSASSA, TPM2_ALG_RSAPSS):
            r.u16()       # scheme detail (hashAlg)
        key_bits  = r.u16()
        exponent  = r.u32()
        modulus   = r.tpm2b()
        result.rsa_key_bits = key_bits
        result.rsa_exponent = exponent
        result.rsa_modulus  = modulus

    elif alg_type == TPM2_ALG_ECC:
        # TPMS_ECC_PARMS
        _sym   = r.u16()   # symmetric
        _sch   = r.u16()   # scheme
        if _sch in (TPM2_ALG_ECDSA, TPM2_ALG_ECDAA, TPM2_ALG_SM2, TPM2_ALG_ECSCHNORR):
            r.u16()        # hash detail
        curve  = r.u16()
        _kdf   = r.u16()   # kdf
        x      = r.tpm2b()
        y      = r.tpm2b()
        result.ecc_curve = curve
        result.ecc_x     = x
        result.ecc_y     = y
    else:
        raise TPMAttestationError(
            f"Unsupported TPMT_PUBLIC algorithm: {alg_type:#06x}"
        )

    result._raw_bytes = raw[:r.tell()]
    return result


def parse_tpms_attest(raw: bytes) -> AttestationData:
    """
    Decode a TPMS_ATTEST structure.

    TPMS_ATTEST ::= {
        magic            TPM2_GENERATED_VALUE,
        type             TPMI_ST_ATTEST,
        qualifiedSigner  TPM2B_NAME,
        extraData        TPM2B_DATA,
        clockInfo        TPMS_CLOCK_INFO,
        firmwareVersion  UINT64,
        attested         TPMU_ATTEST,
    }
    """
    r = _Reader(raw)
    magic           = r.u32()
    attest_type     = r.u16()
    qualified_signer= r.tpm2b()
    extra_data      = r.tpm2b()
    clock_info      = r.raw(8)       # TPMS_CLOCK_INFO = clock(8)+resetCount(4)+restartCount(4)+safe(1) = 17 bytes
    # Actually TPMS_CLOCK_INFO is 17 bytes; the 8 above is partial — fix:
    # Rewind and re-read properly.
    # We already consumed 8; read the rest:
    reset_count   = r.u32()
    restart_count = r.u32()
    safe          = r.u8()
    full_clock_info = clock_info + struct.pack(">II", reset_count, restart_count) + bytes([safe])

    firmware_version = r.u64()

    attest = AttestationData(
        magic=magic,
        attest_type=attest_type,
        qualified_signer=qualified_signer,
        extra_data=extra_data,
        clock_info=full_clock_info,
        firmware_version=firmware_version,
        raw=raw,
    )

    if attest_type == TPM2_ST_ATTEST_CERTIFY:
        attest.certified_name  = r.tpm2b()
        attest.certified_qname = r.tpm2b()
    elif attest_type == TPM2_ST_ATTEST_QUOTE:
        # TPML_PCR_SELECTION + TPM2B_DIGEST
        count = r.u32()
        pcr_sel_bytes = b""
        for _ in range(count):
            hash_alg     = r.u16()
            sizeof_sel   = r.u8()
            pcr_sel_data = r.raw(sizeof_sel)
            pcr_sel_bytes += struct.pack(">HB", hash_alg, sizeof_sel) + pcr_sel_data
        attest.pcr_selection = struct.pack(">I", count) + pcr_sel_bytes
        attest.pcr_digest    = r.tpm2b()
    # other types (NV, etc.) are not currently decoded

    return attest


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def _verify_tpm_signature(data: bytes, sig_raw: bytes, pub_key: TPMPublicKey):
    """
    Verify TPMT_SIGNATURE over `data` using pub_key.

    TPMT_SIGNATURE ::= {
        sigAlg     TPMI_ALG_SIG_SCHEME,
        signature  TPMU_SIGNATURE,
    }
    """
    r = _Reader(sig_raw)
    sig_alg  = r.u16()
    hash_alg = r.u16()

    hash_obj = _tpm_alg_to_hash_obj(hash_alg)

    crypto_key = pub_key.to_cryptography_public_key()

    if sig_alg == TPM2_ALG_RSASSA:
        sig_bytes = r.tpm2b()
        try:
            crypto_key.verify(sig_bytes, data, padding.PKCS1v15(), hash_obj)
        except InvalidSignature:
            raise TPMAttestationError("RSASSA signature verification failed")

    elif sig_alg == TPM2_ALG_RSAPSS:
        sig_bytes = r.tpm2b()
        try:
            crypto_key.verify(
                sig_bytes, data,
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hash_obj,
            )
        except InvalidSignature:
            raise TPMAttestationError("RSAPSS signature verification failed")

    elif sig_alg == TPM2_ALG_ECDSA:
        r_size = r.u16()
        r_bytes = r.raw(r_size)
        s_size = r.u16()
        s_bytes = r.raw(s_size)
        # Build DER-encoded ECDSA signature
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        r_int = int.from_bytes(r_bytes, "big")
        s_int = int.from_bytes(s_bytes, "big")
        der_sig = encode_dss_signature(r_int, s_int)
        try:
            crypto_key.verify(der_sig, data, ec.ECDSA(hash_obj))
        except InvalidSignature:
            raise TPMAttestationError("ECDSA signature verification failed")

    else:
        raise TPMAttestationError(
            f"Unsupported signature algorithm: {sig_alg:#06x}"
        )


# ---------------------------------------------------------------------------
# EK certificate verification
# ---------------------------------------------------------------------------

def _verify_ek_cert(ek_cert: x509.Certificate, trusted_roots: list):
    """
    Verify that ek_cert chains to one of the trusted_roots.
    Also checks that the certificate has the EK OID in SubjectAlternativeName
    or Extended Key Usage (as per TCG EK Credential Profile §3).
    """
    if not trusted_roots:
        logger.warning(
            "No trusted TPM EK roots configured — skipping chain validation. "
            "This is INSECURE and should only be used in test environments."
        )
        return

    # Build a simple chain: find issuer in trusted_roots
    issuer = ek_cert.issuer
    verified = False
    for root in trusted_roots:
        if root.subject == issuer:
            try:
                _verify_signature_by(ek_cert, root)
                verified = True
                break
            except Exception:
                continue

    if not verified:
        # Try intermediate chain (simplified: 1-level deep)
        raise TPMAttestationError(
            "EK certificate does not chain to any trusted TPM manufacturer CA root. "
            "Add the manufacturer's CA to trusted_ek_roots."
        )

    # Check EK-specific OIDs (lenient — some old TPMs don't have them)
    _check_ek_oid(ek_cert)


def _verify_signature_by(cert: x509.Certificate, issuer_cert: x509.Certificate):
    """Verify that `cert` is signed by `issuer_cert`."""
    pub = issuer_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    else:
        raise TPMAttestationError("Unsupported issuer key type")


def _check_ek_oid(cert: x509.Certificate):
    """Warn (but don't fail) if the TCG EK OID is absent."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        # TCG EK SANs are in OtherName with the TPM OIDs — just log
        logger.debug("EK SAN: %s", san.value)
    except x509.ExtensionNotFound:
        logger.debug("No SubjectAlternativeName in EK certificate (may be OK for older TPMs)")


def _extract_tpm_manufacturer(cert: x509.Certificate) -> Optional[str]:
    """Try to extract the TPM manufacturer name from an EK certificate."""
    try:
        # TCG EK Credential Profile §3.2: manufacturer is in SAN OtherName
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if hasattr(name, 'value') and hasattr(name.value, 'type_id'):
                oid_str = name.value.type_id.dotted_string
                if oid_str.startswith(OID_TCG_SAN_TPM_DEVICE):
                    return str(name.value.value)
    except Exception:
        pass

    # Fallback: try O= in Subject
    try:
        return cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Attribute policy checks
# ---------------------------------------------------------------------------

def _check_aik_attributes(aik: TPMPublicKey):
    """Verify that the AIK has the required TPMA_OBJECT attributes."""
    required = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN
    if (aik.object_attr & required) != required:
        raise TPMAttestationError(
            f"AIK must have RESTRICTED|SIGN attributes set. "
            f"Got TPMA_OBJECT={aik.object_attr:#010x}"
        )
    if aik.object_attr & TPMA_OBJECT_DECRYPT:
        raise TPMAttestationError(
            "AIK must NOT have the DECRYPT attribute (it must be a signing-only key)"
        )


def _check_key_policy(
    key: TPMPublicKey,
    require_fixed_tpm: bool,
    require_fixed_parent: bool,
    require_restricted: bool,
):
    """Enforce TPMA_OBJECT policy on the certified key."""
    attr = key.object_attr
    errors = []
    if require_fixed_tpm and not (attr & TPMA_OBJECT_FIXEDTPM):
        errors.append("FIXEDTPM not set (key may be exportable from TPM)")
    if require_fixed_parent and not (attr & TPMA_OBJECT_FIXEDPARENT):
        errors.append("FIXEDPARENT not set (key hierarchy not fixed)")
    if require_restricted and not (attr & TPMA_OBJECT_RESTRICTED):
        errors.append("RESTRICTED not set (key is not restricted)")
    if errors:
        raise TPMAttestationError(
            "Certified key does not meet policy: " + "; ".join(errors)
        )


# ---------------------------------------------------------------------------
# ASN.1 / X.509 helpers for CSR extensions
# ---------------------------------------------------------------------------

# Custom OID for TPM attestation data embedded in the CSR (legacy/private tests)
OID_TPM_ATTESTATION_BUNDLE = "1.3.6.1.4.1.99999.1.1"

# Microsoft key attestation PKCS#10 attributes (MS-WCCE)
OID_MS_ENROLL_EK_INFO = "1.3.6.1.4.1.311.21.23"
OID_MS_ENROLL_AIK_INFO = "1.3.6.1.4.1.311.21.39"
OID_MS_ENROLL_CAXCHGCERT_HASH = "1.3.6.1.4.1.311.21.27"
OID_MS_ENROLL_KSP_NAME = "1.3.6.1.4.1.311.21.25"
OID_MS_ENROLL_ATTESTATION_STATEMENT = "1.3.6.1.4.1.311.21.33"
# Legacy Windows/CSP behavior is also seen with 1.3.6.1.4.1.311.21.24 for
# the same attestation blob payload. Accept both when extracting the request.
OID_MS_ENROLL_ATTESTATION_STATEMENT_LEGACY = "1.3.6.1.4.1.311.21.24"

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
    for enc in ("utf-16-le", "utf-16-be", "utf-8", "latin1"):
        try:
            return data.decode(enc).rstrip("\x00")
        except Exception:
            pass
    return None


def _load_private_key_from_pem(value, password=None):
    if value is None:
        raise ValueError("Missing PEM private key")
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        if "-----BEGIN " in value:
            data = value.encode('utf-8')
        else:
            data = Path(value).read_bytes()
    else:
        raise TypeError(f"Unsupported private key input type: {type(value).__name__}")
    if isinstance(password, str):
        password = password.encode('utf-8')
    return serialization.load_pem_private_key(data, password=password)


def _decrypt_cms_enveloped_data(content_info_der: bytes, recipient_cert_der: Optional[bytes], recipient_key) -> bytes:
    def _unwrap_content_info_der(blob: bytes) -> bytes:
        if not blob:
            raise ValueError("Empty CMS blob")
        if blob[0] == 0x30:
            return blob
        if blob[0] == 0x31:
            class _AnySet(a_core.SetOf):
                _child_spec = a_core.Any
            values = _AnySet.load(blob)
            if len(values) == 0:
                raise ValueError("Empty SET for CMS attribute value")
            first = values[0]
            try:
                return first.dump()
            except Exception:
                parsed = getattr(first, 'parsed', None)
                if parsed is not None and hasattr(parsed, 'dump'):
                    return parsed.dump()
                raise ValueError("Could not unwrap CMS ContentInfo from SET")
        raise ValueError(f"Unsupported CMS wrapper tag: 0x{blob[0]:02x}")

    def _hash_from_name_or_oid(value):
        mapping = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512(),
            '1.3.14.3.2.26': hashes.SHA1(),
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
            '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
            '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
        }
        if value in mapping:
            return mapping[value]
        raise NotImplementedError(f"Unsupported OAEP hash algorithm: {value}")

    ci = a_cms.ContentInfo.load(_unwrap_content_info_der(content_info_der))
    if ci["content_type"].native != "enveloped_data":
        raise ValueError("Expected CMS EnvelopedData")

    env = ci["content"]
    encrypted_content_info = env["encrypted_content_info"]
    enc_alg = encrypted_content_info["content_encryption_algorithm"]
    enc_alg_name = enc_alg["algorithm"].native
    enc_alg_params = enc_alg["parameters"]

    encrypted_content = encrypted_content_info["encrypted_content"].native
    if encrypted_content is None:
        raise ValueError("CMS EnvelopedData has no encrypted content")

    recipient_infos = env["recipient_infos"]
    selected_cek = None

    recipient_cert = None
    if recipient_cert_der:
        recipient_cert = x509.load_der_x509_certificate(recipient_cert_der)
        recipient_serial = recipient_cert.serial_number
    else:
        recipient_serial = None

    for ri in recipient_infos:
        if ri.name != "ktri":
            continue
        ktri = ri.chosen
        rid = ktri["rid"]
        if rid.name != "issuer_and_serial_number":
            continue
        issuer_and_serial = rid.chosen
        serial = int(issuer_and_serial["serial_number"].native)

        if recipient_serial is not None and serial != recipient_serial:
            continue

        key_enc_alg_field = ktri["key_encryption_algorithm"]["algorithm"]
        key_enc_alg = getattr(key_enc_alg_field, 'dotted', None) or key_enc_alg_field.native
        encrypted_key = ktri["encrypted_key"].native

        if key_enc_alg in ("rsa", "rsaes_pkcs1v15", "1.2.840.113549.1.1.1"):
            selected_cek = recipient_key.decrypt(encrypted_key, padding.PKCS1v15())
        elif key_enc_alg in ("rsaes_oaep", "1.2.840.113549.1.1.7"):
            oaep_params = ktri["key_encryption_algorithm"]["parameters"]
            hash_alg = hashes.SHA1()
            mgf_hash_alg = hashes.SHA1()
            label = None

            if oaep_params is not None:
                try:
                    native = oaep_params.native or {}
                except Exception:
                    native = {}

                hash_info = native.get('hash_algorithm') if isinstance(native, dict) else None
                if hash_info and hash_info.get('algorithm'):
                    hash_alg = _hash_from_name_or_oid(hash_info['algorithm'])

                mgf_info = native.get('mask_gen_algorithm') if isinstance(native, dict) else None
                if mgf_info:
                    mgf_params = mgf_info.get('parameters')
                    if mgf_params and mgf_params.get('algorithm'):
                        mgf_hash_alg = _hash_from_name_or_oid(mgf_params['algorithm'])

                p_source = native.get('p_source_algorithm') if isinstance(native, dict) else None
                if p_source:
                    psrc_params = p_source.get('parameters')
                    if isinstance(psrc_params, bytes) and psrc_params:
                        label = psrc_params

            selected_cek = recipient_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=mgf_hash_alg),
                    algorithm=hash_alg,
                    label=label,
                ),
            )
        else:
            raise ValueError(f"Unsupported CMS key encryption algorithm: {key_enc_alg}")
        break

    if selected_cek is None:
        raise ValueError("Could not decrypt CMS EnvelopedData with provided KET certificate/private key")

    params = enc_alg_params.native if enc_alg_params is not None else None

    if enc_alg_name in ("aes128_cbc", "aes192_cbc", "aes256_cbc"):
        iv = params
        cipher = Cipher(algorithms.AES(selected_cek), modes.CBC(iv))
    elif enc_alg_name == "tripledes_3key":
        iv = params
        cipher = Cipher(algorithms.TripleDES(selected_cek), modes.CBC(iv))
    else:
        raise ValueError(f"Unsupported CMS content encryption algorithm: {enc_alg_name}")

    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_content) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(cipher.algorithm.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _find_der_certificates_in_blob(blob: bytes) -> list[bytes]:
    certs = []
    n = len(blob)
    i = 0
    while i < n - 4:
        if blob[i] != 0x30:
            i += 1
            continue
        try:
            first_len = blob[i + 1]
        except IndexError:
            break
        header_len = 2
        if first_len & 0x80:
            num_len = first_len & 0x7F
            if num_len == 0 or i + 2 + num_len > n:
                i += 1
                continue
            total_len = int.from_bytes(blob[i + 2:i + 2 + num_len], 'big')
            header_len = 2 + num_len
        else:
            total_len = first_len
        end = i + header_len + total_len
        if end > n:
            i += 1
            continue
        candidate = blob[i:end]
        try:
            x509.load_der_x509_certificate(candidate)
            certs.append(candidate)
            i = end
            continue
        except Exception:
            i += 1
    return certs


def decrypt_microsoft_ek_info(ek_info_raw: bytes, ket_cert_der: Optional[bytes], ket_private_key) -> dict:
    if not ek_info_raw:
        raise ValueError("ek_info_raw is empty")

    value = a_core.Any.load(ek_info_raw)
    content_info_der = None
    for candidate in (getattr(value, 'parsed', None), value):
        if candidate is None:
            continue
        try:
            if candidate.__class__.__name__.endswith('SetOf') or hasattr(candidate, '__iter__'):
                items = list(candidate)
                if items:
                    first = items[0]
                    content_info_der = first.dump() if hasattr(first, 'dump') else bytes(first)
                    break
        except Exception:
            pass
        try:
            content_info_der = candidate.dump() if hasattr(candidate, 'dump') else bytes(candidate)
            break
        except Exception:
            pass

    if content_info_der is None:
        raise ValueError("Could not locate CMS EnvelopedData in ek_info_raw")

    decrypted = _decrypt_cms_enveloped_data(content_info_der, ket_cert_der, ket_private_key)
    certs = _find_der_certificates_in_blob(decrypted)
    ek_cert_der = certs[0] if certs else None
    return {"decrypted_raw": decrypted, "ek_cert_der": ek_cert_der, "embedded_certificates_der": certs}


def extract_microsoft_key_attestation_attributes_from_csr_der(csr_der: bytes) -> Optional[dict]:
    """
    Extract Microsoft TPM key-attestation PKCS#10 attributes from a DER CSR.

    Notes:
    - These are PKCS#10 attributes, not X.509 extensions.
    - Real Windows/AD CS flows may surface either the documented
      szOID_ENROLL_ATTESTATION_STATEMENT (1.3.6.1.4.1.311.21.33) and/or the
      Microsoft attestation blob attribute 1.3.6.1.4.1.311.21.24.
    """
    req = a_csr.CertificationRequest.load(csr_der)
    cri = req["certification_request_info"]

    oid_ek_info = OID_MS_ENROLL_EK_INFO
    oid_aik_info = OID_MS_ENROLL_AIK_INFO
    oid_ksp_name = OID_MS_ENROLL_KSP_NAME
    oid_attestation_statement = OID_MS_ENROLL_ATTESTATION_STATEMENT
    oid_attestation_blob = OID_MS_ENROLL_ATTESTATION_STATEMENT_LEGACY

    def _raw_bytes(value_obj):
        if value_obj is None:
            return None
        try:
            native = getattr(value_obj, "native", None)
            if isinstance(native, bytes):
                return native
        except Exception:
            pass
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
            return None

    def _extract_first_attribute_value(values_field):
        if values_field is None:
            return None
        try:
            if len(values_field) > 0:
                return values_field[0]
        except Exception:
            pass
        parsed = getattr(values_field, "parsed", None)
        if parsed is not None:
            try:
                if len(parsed) > 0:
                    return parsed[0]
            except Exception:
                pass
            try:
                items = list(parsed)
                if items:
                    return items[0]
            except Exception:
                pass
        try:
            items = list(values_field)
            if items:
                return items[0]
        except Exception:
            pass
        return values_field

    result = {
        "ek_info_raw": None,
        "aik_info_raw": None,
        "attestation_statement_raw": None,
        "attestation_blob_raw": None,
        "ksp_name": None,
        "ksp_name_raw": None,
        "found": False,
    }

    try:
        attr_oids = []
        for _attr in cri["attributes"]:
            try:
                attr_oids.append(_attr["type"].dotted)
            except Exception:
                attr_oids.append("<unknown>")
        logger.warning("TPM CSR PKCS10 attributes count=%d oids=%r", len(attr_oids), attr_oids)
    except Exception as exc:
        logger.warning("TPM CSR PKCS10 attributes enumeration failed: %r", exc)

    interesting = {
        oid_ek_info,
        oid_aik_info,
        oid_ksp_name,
        oid_attestation_statement,
        oid_attestation_blob,
    }

    for attr in cri["attributes"]:
        try:
            oid = attr["type"].dotted
        except Exception:
            continue
        if oid not in interesting:
            continue

        value_obj = _extract_first_attribute_value(attr["values"])
        if value_obj is None:
            logger.warning("TPM CSR attr oid=%s has no first value", oid)
            continue

        try:
            value_type = type(value_obj).__name__
        except Exception:
            value_type = "<unknown>"
        try:
            value_dump = value_obj.dump()
            value_dump_hex = value_dump.hex()
            value_dump_len = len(value_dump)
        except Exception as exc:
            value_dump = None
            value_dump_hex = f"<dump failed: {exc!r}>"
            value_dump_len = None
        try:
            value_native = getattr(value_obj, "native", None)
            if isinstance(value_native, bytes):
                value_native_repr = value_native.hex()
            else:
                value_native_repr = repr(value_native)
        except Exception as exc:
            value_native_repr = f"<native failed: {exc!r}>"

        raw = _raw_bytes(value_obj)
        raw_len = len(raw) if raw is not None else None
        raw_hex = raw.hex() if raw is not None else None
        logger.warning(
            "TPM CSR attr oid=%s type=%s value_dump_len=%r value_dump_hex=%s value_native=%s raw_len=%r raw_hex=%s",
            oid,
            value_type,
            value_dump_len,
            value_dump_hex,
            value_native_repr,
            raw_len,
            raw_hex,
        )
        if raw is None:
            continue

        if oid == oid_ek_info:
            result["ek_info_raw"] = raw
            result["found"] = True
        elif oid == oid_aik_info:
            result["aik_info_raw"] = raw
            result["found"] = True
        elif oid == oid_attestation_statement:
            try:
                octets = a_core.OctetString.load(raw)
                result["attestation_statement_raw"] = octets.native
            except Exception:
                result["attestation_statement_raw"] = raw
            result["found"] = True
        elif oid == oid_attestation_blob:
            try:
                octets = a_core.OctetString.load(raw)
                result["attestation_blob_raw"] = octets.native
            except Exception:
                result["attestation_blob_raw"] = raw
            result["found"] = True
        elif oid == oid_ksp_name:
            result["ksp_name_raw"] = raw
            result["ksp_name"] = _decode_any_string(value_obj)
            result["found"] = True

    return result if result["found"] else None


def extract_tpm_bundle_from_pkcs10_der(csr_der: bytes) -> Optional[TPMAttestationBundle]:
    """
    Best-effort TPM bundle extraction from a PKCS#10 DER request.

    Supported inputs:
      1. Legacy/private custom CSR extension (test format).
      2. Microsoft key-attestation PKCS#10 attributes: detected and surfaced.

    For Microsoft-native attestation, this function detects the relevant
    attributes and returns a shell bundle exposing the raw Microsoft fields.
    Full ASN.1 decoding/verification of the native blobs remains separate.
    """
    import json

    csr = x509.load_der_x509_csr(csr_der)

    try:
        for ext in csr.extensions:
            if ext.oid.dotted_string == OID_TPM_ATTESTATION_BUNDLE:
                raw_json = ext.value.value
                blob = json.loads(raw_json.decode("utf-8", errors="replace"))
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
    """
    Extract TPM attestation data from a CMS/PKCS#7-wrapped request.

    Microsoft documents that the key attestation lives in the inner PKCS#10
    attributes, carried inside the CMC/CMS wrapper. So we first unwrap the
    inner PKCS#10, then parse its attributes.
    """
    from utils import exct_csr_from_cmc

    csr_der, _body_part_id, _info = exct_csr_from_cmc(p7_der)
    return extract_tpm_bundle_from_pkcs10_der(csr_der)


def extract_tpm_bundle_from_csr(csr: x509.CertificateSigningRequest) -> Optional[TPMAttestationBundle]:
    """Backward-compatible wrapper for callers that already have a cryptography CSR."""
    return extract_tpm_bundle_from_pkcs10_der(csr.public_bytes(serialization.Encoding.DER))


def build_tpm_attestation_extension(result: AttestationResult) -> x509.Extension:
    """
    Build an x509 extension to embed in the issued certificate,
    recording that TPM attestation was verified.

    OID: szOID_NTDS_REPLICATION (1.3.6.1.4.1.311.25.2) is sometimes used by
    ADCS for similar purposes; we use our private OID here.
    """
    import json
    payload = {
        "tpm_attested": True,
        "mode": result.mode,
        "manufacturer": result.manufacturer,
        "firmware_version": (
            hex(result.firmware_version) if result.firmware_version is not None else None
        ),
        "fixed_tpm": result.is_fixed_tpm,
        "fixed_parent": result.is_fixed_parent,
        "restricted": result.is_restricted,
    }
    raw_json = json.dumps(payload).encode()
    return x509.Extension(
        oid=x509.ObjectIdentifier(OID_TPM_ATTESTATION_BUNDLE),
        critical=False,
        value=x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier(OID_TPM_ATTESTATION_BUNDLE),
            value=raw_json,
        ),
    )


# ---------------------------------------------------------------------------
# Trusted EK root management
# ---------------------------------------------------------------------------

def load_trusted_ek_roots_from_dir(path: str) -> list:
    """
    Load all PEM/DER certificates from `path` as trusted TPM EK roots.
    Returns a list of x509.Certificate objects.
    """
    certs = []
    if not os.path.isdir(path):
        logger.warning("trusted_ek_roots_dir=%s does not exist — no EK roots loaded", path)
        return certs
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            data = open(fpath, "rb").read()
            if b"-----BEGIN" in data:
                cert = x509.load_pem_x509_certificate(data)
            else:
                cert = x509.load_der_x509_certificate(data)
            certs.append(cert)
            logger.debug("Loaded EK root: %s from %s", cert.subject.rfc4514_string(), fname)
        except Exception as exc:
            logger.warning("Could not load EK root from %s: %s", fpath, exc)
    logger.info("Loaded %d trusted TPM EK roots from %s", len(certs), path)
    return certs


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _tpm_alg_to_hash(alg: int) -> str:
    return {
        TPM2_ALG_SHA1:   "sha1",
        TPM2_ALG_SHA256: "sha256",
        TPM2_ALG_SHA384: "sha384",
        TPM2_ALG_SHA512: "sha512",
    }.get(alg, "sha256")


def _tpm_alg_to_hash_obj(alg: int):
    return {
        TPM2_ALG_SHA1:   hashes.SHA1(),
        TPM2_ALG_SHA256: hashes.SHA256(),
        TPM2_ALG_SHA384: hashes.SHA384(),
        TPM2_ALG_SHA512: hashes.SHA512(),
    }.get(alg, hashes.SHA256())


def _tpm2b(data: bytes) -> bytes:
    """Marshal a TPM2B: 2-byte length + data."""
    return struct.pack(">H", len(data)) + data


# ---------------------------------------------------------------------------
# TPM2_MakeCredential — TCG TPM 2.0 Part 1 §24 / Part 2 §11.4.10
# ---------------------------------------------------------------------------

def _kdfa(hash_alg: int, key: bytes, label: str, context_u: bytes, context_v: bytes, bits: int) -> bytes:
    """
    KDFa as defined in TCG TPM 2.0 Part 1 §11.4.9.2.

    Produces `bits` bits of pseudorandom material using HMAC with the given
    hashAlg.  `label` is an ASCII string; the NUL separator is added here.

        K(i) = HMAC(hashAlg, key,
                    counter[4B BE] || label || 0x00 || contextU || contextV || bits[4B BE])

    The output is the concatenation of K(1), K(2), … truncated to `bits` bits.
    """
    hash_name = _tpm_alg_to_hash(hash_alg)
    digest_size = hashlib.new(hash_name).digest_size
    byte_len = (bits + 7) // 8
    result = b""
    counter = 1
    label_bytes = label.encode("ascii") + b"\x00"
    bits_be = struct.pack(">I", bits)
    while len(result) < byte_len:
        counter_be = struct.pack(">I", counter)
        data = counter_be + label_bytes + context_u + context_v + bits_be
        result += hmac.new(key, data, hash_name).digest()
        counter += 1
    return result[:byte_len]


def _kdfe(hash_alg: int, z: bytes, label: str, party_u_info: bytes, party_v_info: bytes, bits: int) -> bytes:
    """
    KDFe as defined in TCG TPM 2.0 Part 1 §11.4.9.3.

    KDFe is hash-based (not HMAC-based):

        K(i) = H(counter[4B BE] || Z || label || 0x00 || partyUInfo || partyVInfo)
    """
    hash_name = _tpm_alg_to_hash(hash_alg)
    byte_len = (bits + 7) // 8
    result = b""
    counter = 1
    label_bytes = label.encode("ascii") + b"\x00"
    while len(result) < byte_len:
        counter_be = struct.pack(">I", counter)
        result += hashlib.new(hash_name, counter_be + z + label_bytes + party_u_info + party_v_info).digest()
        counter += 1
    out = result[:byte_len]
    extra_bits = (8 - (bits % 8)) % 8
    if extra_bits:
        out = bytes([out[0] & (0xFF >> extra_bits)]) + out[1:]
    return out


def infer_ek_name_alg_from_public_key(ek_pub) -> int:
    """Best-effort mapping from EK public key strength to TCG EK template nameAlg."""
    try:
        if isinstance(ek_pub, rsa.RSAPublicKey):
            if ek_pub.key_size <= 2048:
                return TPM2_ALG_SHA256
            if ek_pub.key_size <= 4096:
                return TPM2_ALG_SHA384
        elif isinstance(ek_pub, ec.EllipticCurvePublicKey):
            curve = ek_pub.curve
            if isinstance(curve, ec.SECP256R1):
                return TPM2_ALG_SHA256
            if isinstance(curve, ec.SECP384R1):
                return TPM2_ALG_SHA384
            if isinstance(curve, ec.SECP521R1):
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
    """
    Implement TPM2_MakeCredential (TCG TPM 2.0 Part 1 §24).

    Parameters
    ----------
    ek_pub:
        RSA or ECC public key of the Endorsement Key (cryptography.io object).
    object_name:
        TPM name of the key to activate (AIK name = nameAlg || Hash(TPMT_PUBLIC)).
        Compute this via TPMPublicKey.compute_name().
    credential_value:
        The secret bytes to protect (≤ digestSize bytes for the nameAlg).
    ek_name_alg:
        TPMI_ALG_HASH — nameAlg of the target EK template, used for OAEP / KDFe /
        KDFa / HMAC in TPM2_MakeCredential.
    sym_bits:
        Symmetric key size in bits for AES-CFB (default 128 for standard EK templates).

    Returns
    -------
    (credentialBlob, encryptedSecret) — both as raw bytes (without outer TPM2B),
    ready to be concatenated as _tpm2b(credentialBlob) + _tpm2b(encryptedSecret)
    for the TACH blob.
    """
    ek_hash_name = _tpm_alg_to_hash(ek_name_alg)
    hash_size = hashlib.new(ek_hash_name).digest_size

    if isinstance(ek_pub, rsa.RSAPublicKey):
        # ── RSA EK ────────────────────────────────────────────────────────────
        # seed is a random octet string of hashSize bytes.
        seed = os.urandom(hash_size)

        # encryptedSecret = RSAES-OAEP(ekPub, seed, hashAlg, label="IDENTITY\x00")
        # Per TCG TPM 2.0 Part 1 §24.4, the OAEP label is "IDENTITY\x00".
        label = b"IDENTITY\x00"
        encrypted_secret = ek_pub.encrypt(
            seed,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=_tpm_alg_to_hash_obj(ek_name_alg)),
                algorithm=_tpm_alg_to_hash_obj(ek_name_alg),
                label=label,
            ),
        )

    elif isinstance(ek_pub, ec.EllipticCurvePublicKey):
        # ── ECC EK ────────────────────────────────────────────────────────────
        # Generate ephemeral key pair on the same curve.
        ephemeral_key = ec.generate_private_key(ek_pub.curve)
        ephemeral_pub = ephemeral_key.public_key()

        # ECDH shared Z.
        shared_z = ephemeral_key.exchange(ec.ECDH(), ek_pub)

        # Encode ephemeral public key as uncompressed point (04 || x || y).
        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        ek_pub_bytes = ek_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

        # seed = KDFe(hashAlg, Z, "IDENTITY", ephemeralPub.x, ekPub.x, hashSize*8)
        # KDFe is defined in TCG TPM 2.0 Part 1 §11.4.9.3.
        # For KDFe, contextU = ephemeralPub.x (coordinate only, not full point),
        # contextV = ekPub.x.
        coord_size = (ek_pub.key_size + 7) // 8
        ephem_x = ephemeral_pub_bytes[1:1 + coord_size]   # strip 04 prefix, take x
        ek_x    = ek_pub_bytes[1:1 + coord_size]

        seed = _kdfe(ek_name_alg, shared_z, "IDENTITY", ephem_x, ek_x, hash_size * 8)

        # encryptedSecret = ephemeralPub as TPM2B_ECC_PARAMETER (just x,y packed).
        # Per spec, it is the marshalled TPMS_ECC_POINT (TPM2B x || TPM2B y).
        encrypted_secret = _tpm2b(ephem_x) + _tpm2b(ephemeral_pub_bytes[1 + coord_size:])

    else:
        raise TypeError(f"Unsupported EK public key type: {type(ek_pub).__name__}")

    # ── Symmetric encryption of the credential (common to RSA and ECC) ────────
    # symKey = KDFa(nameAlg, seed, "STORAGE", objectName, "", sym_bits)
    sym_key = _kdfa(ek_name_alg, seed, "STORAGE", object_name, b"", sym_bits)

    # encryptedCredential = CFB_AES(symKey, IV=0, TPM2B(credential_value))
    # The plaintext is the TPM2B encoding of the credential.
    plaintext = _tpm2b(credential_value)
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(sym_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_credential = encryptor.update(plaintext) + encryptor.finalize()

    # HMAC key = KDFa(nameAlg, seed, "INTEGRITY", "", "", hashSize*8)
    hmac_key = _kdfa(ek_name_alg, seed, "INTEGRITY", b"", b"", hash_size * 8)

    # outerHMAC = HMAC(nameAlg, hmacKey, encryptedCredential || objectName)
    outer_hmac = hmac.new(
        hmac_key,
        encrypted_credential + object_name,
        ek_hash_name,
    ).digest()

    # TPMS_ID_OBJECT = TPM2B_DIGEST(integrityHMAC) || encIdentity.
    # The caller adds the outer TPM2B_ID_OBJECT wrapper via _tpm2b().
    credential_blob = _tpm2b(outer_hmac) + encrypted_credential

    return credential_blob, encrypted_secret


def _parse_microsoft_key_attestation_statement(blob: bytes) -> dict:
    """
    Parse Microsoft's KeyAttestationStatement structure (KAST).

    The structure is little-endian and starts with the ASCII magic ``KAST``
    (0x5453414B). For TPM 2.0 (Platform == 2), the idBinding field begins with
    a TPM2B_PUBLIC that identifies the AIK used for activation.
    """
    if not blob:
        raise ValueError('Empty attestation statement')

    pos = blob.find(b'KAST')
    if pos < 0:
        raise ValueError('KAST marker not found in attestation statement')
    if len(blob) < pos + 28:
        raise ValueError('Truncated KAST header')

    magic, version, platform, header_size, cb_id_binding, cb_key_attestation, cb_aik_opaque = struct.unpack_from('<7I', blob, pos)
    if magic != 0x5453414B:
        raise ValueError(f'Unexpected KAST magic: {magic:#010x}')

    minimum_header = 28
    if header_size < minimum_header:
        header_size = minimum_header

    start = pos + header_size
    end_id = start + cb_id_binding
    end_key = end_id + cb_key_attestation
    end_aik = end_key + cb_aik_opaque
    if end_aik > len(blob):
        raise ValueError('Truncated KAST payload')

    return {
        'offset': pos,
        'version': version,
        'platform': platform,
        'header_size': header_size,
        'id_binding': blob[start:end_id],
        'key_attestation': blob[end_id:end_key],
        'aik_opaque': blob[end_key:end_aik],
    }


def _extract_aik_name_from_id_binding(id_binding: bytes) -> bytes:
    """
    Recover the AIK TPM object name from the TPM 2.0 idBinding field.

    MS-WCCE defines the Platform==2 idBinding field as starting with a
    TPM2B_PUBLIC. We parse that first TPM2B_PUBLIC directly instead of guessing
    through the full blob.
    """
    if not id_binding or len(id_binding) < 2:
        raise ValueError('Empty TPM 2.0 idBinding')

    public_len = struct.unpack('>H', id_binding[:2])[0]
    if public_len <= 0 or public_len > len(id_binding) - 2:
        raise ValueError('Invalid TPM2B_PUBLIC length in idBinding')

    public_raw = id_binding[2:2 + public_len]
    pub = parse_tpmt_public(public_raw)
    return pub.compute_name()


def _extract_aik_name_from_microsoft_attestation_blob(attestation_blob_raw: bytes) -> bytes:
    """
    Best-effort extractor for an AIK TPM name from Microsoft's attestation blob
    (the KAST/PCPM payload seen in challenge requests).

    For TPM 2.0 statements, prefer the explicit KAST idBinding parsing defined
    by MS-WCCE. Fall back to the older heuristic scan only when the structured
    parse fails.
    """
    if not attestation_blob_raw:
        raise ValueError('Empty attestation blob')

    try:
        parsed = _parse_microsoft_key_attestation_statement(attestation_blob_raw)
        if parsed.get('platform') == 2 and parsed.get('id_binding'):
            aik_name = _extract_aik_name_from_id_binding(parsed['id_binding'])
            logger.warning(
                'TPM AIK parse: recovered AIK name from KAST idBinding platform=%d version=%d offset=%d name=%s',
                parsed.get('platform'),
                parsed.get('version'),
                parsed.get('offset'),
                aik_name.hex(),
            )
            return aik_name
    except Exception as exc:
        logger.debug('TPM AIK structured KAST parse failed, falling back to heuristic scan: %s', exc)

    # Prefer regions around Microsoft PCPM markers when present, but also scan
    # the whole blob as a fallback.
    preferred_offsets = []
    off = 0
    while True:
        pos = attestation_blob_raw.find(b'PCPM', off)
        if pos < 0:
            break
        preferred_offsets.extend(range(max(0, pos - 96), min(len(attestation_blob_raw), pos + 1024)))
        off = pos + 1
    if not preferred_offsets:
        preferred_offsets = list(range(len(attestation_blob_raw)))

    seen = set()
    ordered_offsets = []
    for pos in preferred_offsets + list(range(len(attestation_blob_raw))):
        if pos not in seen:
            seen.add(pos)
            ordered_offsets.append(pos)

    candidates = []
    for pos in ordered_offsets:
        # Try raw slice as TPMT_PUBLIC.
        for raw in (attestation_blob_raw[pos:], None):
            if raw is None and pos + 2 <= len(attestation_blob_raw):
                n = struct.unpack('>H', attestation_blob_raw[pos:pos+2])[0]
                if 0 < n <= len(attestation_blob_raw) - pos - 2:
                    raw = attestation_blob_raw[pos+2:pos+2+n]
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
            if not (pub.object_attr & TPMA_OBJECT_DECRYPT):
                score += 2
            if pub.alg_type in (TPM2_ALG_RSA, TPM2_ALG_ECC):
                score += 1
            if getattr(pub, 'name_alg', None) in (TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512):
                score += 1
            if pub.alg_type == TPM2_ALG_RSA and getattr(pub, 'rsa_key_bits', 0) in (2048, 3072, 4096):
                score += 1
            candidates.append((score, pos, pub))

    if not candidates:
        raise ValueError('Could not locate a TPMT_PUBLIC candidate inside attestation blob')

    candidates.sort(key=lambda item: (-item[0], item[1]))
    best_score, best_pos, best_pub = candidates[0]
    aik_name = best_pub.compute_name()
    logger.warning(
        'TPM AIK parse: pos=%d consumed=%d score=%d alg=%#06x nameAlg=%#06x attr=%#010x keyBits=%s name=%s',
        best_pos, len(best_pub._raw_bytes or b''), best_score,
        best_pub.alg_type, best_pub.name_alg, best_pub.object_attr,
        getattr(best_pub, 'rsa_key_bits', '?'),
        best_pub.compute_name().hex(),
    )
    return aik_name


def _tpm_name_from_raw_aik_info(aik_info_raw: bytes, name_alg: int = TPM2_ALG_SHA256) -> bytes:
    """
    Derive the TPM object name from the raw AIK info attribute bytes.

    The szOID_ENROLL_AIK_INFO attribute value contains the TPMT_PUBLIC of the
    AIK, possibly with a leading OctetString DER wrapper added by the Windows
    CertEnroll library.  We try to parse it as TPMT_PUBLIC directly first, and
    fall back to stripping a TPM2B (2-byte length prefix) or DER OctetString
    wrapper if needed.
    """
    candidates = [aik_info_raw]

    # Try stripping a 2-byte TPM2B length prefix.
    if len(aik_info_raw) >= 2:
        tpm2b_len = struct.unpack(">H", aik_info_raw[:2])[0]
        if tpm2b_len == len(aik_info_raw) - 2:
            candidates.append(aik_info_raw[2:])

    # Try stripping a DER OctetString wrapper (04 <len> <data>).
    if len(aik_info_raw) >= 2 and aik_info_raw[0] == 0x04:
        der_len_byte = aik_info_raw[1]
        if der_len_byte < 0x80:
            candidates.append(aik_info_raw[2:2 + der_len_byte])
        elif der_len_byte == 0x81 and len(aik_info_raw) >= 3:
            n = aik_info_raw[2]
            candidates.append(aik_info_raw[3:3 + n])
        elif der_len_byte == 0x82 and len(aik_info_raw) >= 4:
            n = struct.unpack(">H", aik_info_raw[2:4])[0]
            candidates.append(aik_info_raw[4:4 + n])

    for raw in candidates:
        try:
            aik_tpmt = parse_tpmt_public(raw)
            return aik_tpmt.compute_name()
        except Exception:
            continue

    # Last resort: treat the raw bytes as the name directly (old behaviour).
    logger.warning(
        "TPM: could not parse aik_info_raw as TPMT_PUBLIC — "
        "using nameAlg||SHA256(aik_info_raw) as fallback name"
    )
    digest = hashlib.new(_tpm_alg_to_hash(name_alg), aik_info_raw).digest()
    return struct.pack(">H", name_alg) + digest


def _make_tach_blob(
    *,
    secret: bytes,
    ek_pub,
    aik_name: bytes,
    attestation_blob_raw: bytes | None = None,
    ek_name_alg: int = TPM2_ALG_SHA256,
    sym_bits: int = 128,
) -> bytes:
    """
    Build a Microsoft TACH container around TPM2_MakeCredential output.

    Windows expects szOID_ENROLL_ATTESTATION_CHALLENGE to contain a TACH blob,
    not just the raw TPM2B credentialBlob || TPM2B encryptedSecret payload.
    We therefore wrap the raw MakeCredential payload in a simple TACH header and,
    when available, append the trailing PCPM structure copied from the client's
    Microsoft attestation blob as a best-effort compatibility payload.
    """
    credential_blob, encrypted_secret = tpm2_make_credential(
        ek_pub=ek_pub,
        object_name=aik_name,
        credential_value=secret,
        ek_name_alg=ek_name_alg,
        sym_bits=sym_bits,
    )
    # The first TACH section is a standard TPM2B_ID_OBJECT followed by a
    # TPM2B_ENCRYPTED_SECRET.
    makecred_raw = _tpm2b(credential_blob) + _tpm2b(encrypted_secret)
    logger.warning(
        'TPM TACH makecred credential_blob_len=%d encrypted_secret_len=%d prefix=%s',
        len(credential_blob),
        len(encrypted_secret),
        makecred_raw[:16].hex(),
    )

    pcpm_tail = b''
    if attestation_blob_raw:
        try:
            parsed_kast = _parse_microsoft_key_attestation_statement(attestation_blob_raw)
        except Exception:
            parsed_kast = None

        if parsed_kast and parsed_kast.get('platform') == 2 and parsed_kast.get('aik_opaque'):
            pcpm_tail = parsed_kast['aik_opaque']
            logger.warning(
                'TPM TACH using KAST aikOpaque offset=%d len=%d',
                parsed_kast.get('offset', -1) + parsed_kast.get('header_size', 0) + len(parsed_kast.get('id_binding', b'')) + len(parsed_kast.get('key_attestation', b'')),
                len(pcpm_tail),
            )
        else:
            last_pcp = attestation_blob_raw.rfind(b'PCPM')
            if last_pcp >= 0:
                pcpm_tail = attestation_blob_raw[last_pcp:]
                logger.warning(
                    'TPM TACH using PCPM tail from attestation blob offset=%d len=%d',
                    last_pcp, len(pcpm_tail)
                )
            else:
                logger.warning('TPM TACH attestation blob had no PCPM marker; building header-only TACH')

        # Preserve the provider-specific AIK opaque blob verbatim. The PCPM
        # content is opaque to the CA and mutating internal 32-byte fields has
        # been observed to yield Windows-side 0x80280009 integrity failures.
        if pcpm_tail.startswith(b'PCPM') and len(pcpm_tail) >= 0x38:
            try:
                hdr_len = struct.unpack('<I', pcpm_tail[4:8])[0]
                prop1_len = struct.unpack('<I', pcpm_tail[16:20])[0] if len(pcpm_tail) >= 20 else -1
                prop2_len = struct.unpack('<I', pcpm_tail[20:24])[0] if len(pcpm_tail) >= 24 else -1
                logger.warning(
                    'TPM PCPM diag preserved total_len=%d hdr_len=0x%x prop1_len=0x%x prop2_len=0x%x prefix=%s',
                    len(pcpm_tail), hdr_len, prop1_len, prop2_len, pcpm_tail[:80].hex()
                )
            except Exception as exc:
                logger.warning('TPM PCPM diag failed: %r', exc)

    tach_header = (
        b'TACH' +
        struct.pack('<I', 1) +
        struct.pack('<I', 2 if pcpm_tail else 1) +
        struct.pack('<I', 0x18) +
        struct.pack('<I', len(makecred_raw)) +
        struct.pack('<I', len(pcpm_tail))
    )
    tach = tach_header + makecred_raw + pcpm_tail
    logger.warning(
        'TPM TACH built version=1 sections=%d raw_len=%d tail_len=%d total_len=%d prefix=%s',
        2 if pcpm_tail else 1,
        len(makecred_raw),
        len(pcpm_tail),
        len(tach),
        tach[:32].hex(),
    )
    return tach


def _load_cert(der_or_pem: bytes) -> x509.Certificate:
    if b"-----BEGIN" in der_or_pem:
        return x509.load_pem_x509_certificate(der_or_pem)
    return x509.load_der_x509_certificate(der_or_pem)


def _b64_or_none(value) -> Optional[bytes]:
    if value is None:
        return None
    return base64.b64decode(value)


# ---------------------------------------------------------------------------
# Microsoft EK/CERTIFY challenge helpers (best-effort)
# ---------------------------------------------------------------------------

def pem_cert_to_der(cert_pem_text: str) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem_text.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        if len(seq) >= 1:
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
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key()


def _unwrap_first_set_value_der(blob: bytes) -> bytes:
    if not blob:
        raise ValueError("Empty DER blob")
    if blob[0] == 0x30:
        return blob
    if blob[0] == 0x31:
        class _AnySet(a_core.SetOf):
            _child_spec = a_core.Any
        values = _AnySet.load(blob)
        if len(values) == 0:
            raise ValueError("Empty SET OF wrapper")
        first = values[0]
        try:
            return first.dump()
        except Exception:
            parsed = getattr(first, 'parsed', None)
            if parsed is not None and hasattr(parsed, 'dump'):
                return parsed.dump()
            raise ValueError("Could not unwrap first value from SET OF")
    raise ValueError(f"Unsupported DER wrapper tag 0x{blob[0]:02x}")


def _load_content_info_from_attribute_value(blob: bytes) -> a_cms.ContentInfo:
    return a_cms.ContentInfo.load(_unwrap_first_set_value_der(blob))


def extract_content_encryption_algorithm_oid_from_ek_info(ms_ek_info_raw: bytes) -> str:
    ci = _load_content_info_from_attribute_value(ms_ek_info_raw)
    if ci['content_type'].native != 'enveloped_data':
        raise ValueError(f"Expected EnvelopedData in EK_INFO, got {ci['content_type'].native!r}")
    env = ci['content']
    eci = env['encrypted_content_info']
    return eci['content_encryption_algorithm']['algorithm'].dotted


def extract_encryption_algorithm_for_challenge_response(ms_ek_info_raw: bytes) -> str:
    return extract_content_encryption_algorithm_oid_from_ek_info(ms_ek_info_raw)


class BodyPartID(a_core.Integer):
    pass


class TaggedAttribute(a_core.Sequence):
    _fields = [
        ('bodyPartID', BodyPartID),
        ('attrType', a_core.ObjectIdentifier),
        ('attrValues', a_core.SetOf, {'spec': a_core.Any}),
    ]


class TaggedAttributes(a_core.SequenceOf):
    _child_spec = TaggedAttribute


class TaggedContentInfo(a_core.Sequence):
    _fields = [
        ('bodyPartID', BodyPartID),
        ('contentInfo', a_cms.ContentInfo),
    ]


class TaggedContentInfos(a_core.SequenceOf):
    _child_spec = TaggedContentInfo


class OtherMsgs(a_core.SequenceOf):
    _child_spec = a_core.Any


class ResponseBody(a_core.Sequence):
    _fields = [
        ('controlSequence', TaggedAttributes),
        ('cmsSequence', TaggedContentInfos),
        ('otherMsgSequence', OtherMsgs),
    ]


class OrderedCertificateSet(a_cms.CertificateSet):
    """
    Preserve insertion order when encoding CMS CertificateSet.

    CMS defines certificates as SET OF, so DER sorting may reorder certificates
    lexicographically. Some Microsoft enrollment clients appear to incorrectly
    assume the signer certificate comes first. For TPM challenge responses, keep
    the signer certificate first, followed by the issued cert/chain, matching
    ADCS behavior observed on working responses.
    """
    def _set_contents(self, force=False):
        if self.children is None:
            self._parse_children()

        child_encodings = []
        for child in self:
            child_encodings.append(child.dump(force=force))

        self._contents = b''.join(child_encodings)
        self._header = None
        if self._trailer != b'':
            self._trailer = b''



OID_CMC_STATUS_INFO = '1.3.6.1.5.5.7.7.1'
OID_MS_CMC_CHALLENGE_WRAPPER = '1.3.6.1.4.1.311.10.10.1'
OID_ENROLL_KSP_NAME = '1.3.6.1.4.1.311.21.25'
OID_ENROLL_CAXCHGCERT_HASH = '1.3.6.1.4.1.311.21.27'
OID_ENROLL_ATTESTATION_CHALLENGE = '1.3.6.1.4.1.311.21.28'
OID_ENROLL_ENCRYPTION_ALGORITHM = '1.3.6.1.4.1.311.21.29'
OID_ID_CCT_PKI_RESPONSE = '1.3.6.1.5.5.7.12.3'
OID_ID_DATA = '1.2.840.113549.1.7.1'
OID_ID_SIGNED_DATA = '1.2.840.113549.1.7.2'


class MsWrappedAttr(a_core.Sequence):
    _fields = [
        ('oid', a_core.ObjectIdentifier),
        ('values', a_core.SetOf, {'spec': a_core.Any}),
    ]


class MsWrappedAttrs(a_core.SetOf):
    _child_spec = MsWrappedAttr


class MsWrappedHeader(a_core.Sequence):
    _fields = [('bodyPartID', BodyPartID)]


class MsChallengeWrapper(a_core.Sequence):
    _fields = [
        ('version', a_core.Integer),
        ('header', MsWrappedHeader),
        ('attrs', MsWrappedAttrs),
    ]


class BodyList(a_core.SequenceOf):
    _child_spec = a_core.Integer


class PendInfo(a_core.Sequence):
    _fields = [
        ('pendToken', a_core.OctetString),
        ('pendTime', a_core.GeneralizedTime),
    ]


class CMCStatusInfo(a_core.Sequence):
    _fields = [
        ('cMCStatus', a_core.Integer),
        ('bodyList', BodyList),
        ('statusString', a_core.UTF8String),
        ('otherInfo', PendInfo),
    ]


def _as_any_from_der(der: bytes) -> a_core.Any:
    return a_core.Any.load(der)


def _content_info_with_certs(certs_der) -> a_cms.ContentInfo:
    cert_choices = []
    for cert_der in certs_der:
        cert = a_cms.Certificate.load(cert_der)
        cert_choices.append(a_cms.CertificateChoices(name='certificate', value=cert))
    signed_data = a_cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [],
        'encap_content_info': {'content_type': OID_ID_DATA, 'content': None},
        'certificates': OrderedCertificateSet(cert_choices),
        'signer_infos': [],
    })
    return a_cms.ContentInfo({'content_type': OID_ID_SIGNED_DATA, 'content': signed_data})


def build_encryption_algorithm_attr_value(algorithm_oid: str) -> bytes:
    ai = a_algos.AlgorithmIdentifier({'algorithm': algorithm_oid, 'parameters': a_core.Null()})
    return ai.dump()


def _debug_hex_preview(data: bytes | None, prefix: int = 64, suffix: int = 32) -> str:
    if data is None:
        return 'none'
    b = bytes(data)
    if len(b) <= prefix + suffix:
        return b.hex()
    return f"{b[:prefix].hex()}...{b[-suffix:].hex()}"


def _debug_cert_subjects(cert_ders) -> list[str]:
    out = []
    for cert_der in (cert_ders or []):
        try:
            cert = x509.load_der_x509_certificate(bytes(cert_der))
            out.append(cert.subject.rfc4514_string())
        except Exception as exc:
            out.append(f'<invalid:{exc}>')
    return out


def _load_tach_template_from_env() -> bytes | None:
    """Deprecated — template patching replaced by TPM2_MakeCredential."""
    tach_template_file = os.getenv('TPM_TACH_TEMPLATE_FILE', '').strip()
    tach_template_hex  = os.getenv('TPM_TACH_TEMPLATE_HEX',  '').strip()
    if tach_template_file or tach_template_hex:
        logger.warning(
            "TPM: TPM_TACH_TEMPLATE_FILE / TPM_TACH_TEMPLATE_HEX are no longer used. "
            "The TACH blob is now constructed via TPM2_MakeCredential."
        )
    return None


def build_tach_from_template(*, template_blob: bytes, challenge_encrypted: bytes) -> bytes:
    """Deprecated — use _make_tach_blob() instead."""
    raise NotImplementedError(
        "build_tach_from_template is deprecated; TACH blobs are now built via "
        "TPM2_MakeCredential through _make_tach_blob()."
    )


def build_placeholder_tach_blob(*, challenge_encrypted: bytes, ek_pub=None, secret: bytes = b'') -> bytes:
    """Deprecated — use _make_tach_blob() instead."""
    raise NotImplementedError(
        "build_placeholder_tach_blob is deprecated; TACH blobs are now built via "
        "TPM2_MakeCredential through _make_tach_blob()."
    )


def build_cmc_pending_status_info(*, request_id: int, status_string: str = 'En attente de traitement', pend_time=None, body_part_id: int = 1) -> bytes:
    request_id = int(request_id)
    if pend_time is None:
        pend_time = datetime.now(timezone.utc)
    pend_time = pend_time.replace(microsecond=(pend_time.microsecond // 1000) * 1000)

    length = (request_id.bit_length() + 7) // 8
    pendToken = request_id.to_bytes(length, byteorder="big", signed=False)
    
    value = CMCStatusInfo({
        'cMCStatus': 3,
        'bodyList': [body_part_id],
        'statusString': status_string,
        'otherInfo': {
            'pendToken': pendToken,
            'pendTime': pend_time,
        },
    })
    pend_der = value.dump()
    logger.warning(
        'TPM CMC pendInfo bodyPartID=%d request_id=%r len=%d sha256=%s hex=%s',
        body_part_id,
        request_id,
        len(pend_der),
        hashlib.sha256(pend_der).hexdigest(),
        pend_der.hex(),
    )
    return pend_der


def build_ms_challenge_wrapper_value(*, encryption_algorithm_oid: str, aik_info_hash: bytes | None, ksp_name: str, tach_blob: bytes, inner_body_part_id: int = 1) -> bytes:
    import hashlib

    enc_alg_der = build_encryption_algorithm_attr_value(encryption_algorithm_oid)
    aik_info_der = a_core.OctetString(aik_info_hash).dump() if aik_info_hash is not None else None
    ksp_name_der = a_core.BMPString(ksp_name).dump()
    tach_blob_der = a_core.OctetString(tach_blob).dump()

    logger.warning(
        'TPM WRAP encAlg oid=%s der_len=%d der_hex=%s',
        encryption_algorithm_oid,
        len(enc_alg_der),
        enc_alg_der.hex(),
    )
    if aik_info_hash is not None:
        logger.warning(
            'TPM WRAP caXchgCertHash hash_len=%d sha1=%s der_len=%d der_hex=%s',
            len(aik_info_hash),
            aik_info_hash.hex(),
            len(aik_info_der),
            aik_info_der.hex(),
        )
    else:
        logger.warning('TPM WRAP caXchgCertHash omitted')
    logger.warning(
        'TPM WRAP ksp_name=%r utf16be_hex=%s der_len=%d der_hex=%s',
        ksp_name,
        ksp_name.encode('utf-16-be').hex(),
        len(ksp_name_der),
        ksp_name_der.hex(),
    )
    logger.warning(
        'TPM WRAP tach_blob raw_len=%d sha256=%s der_len=%d der_prefix=%s der_suffix=%s',
        len(tach_blob),
        hashlib.sha256(tach_blob).hexdigest(),
        len(tach_blob_der),
        tach_blob_der[:64].hex(),
        tach_blob_der[-64:].hex(),
    )

    attr_enc = MsWrappedAttr({
        'oid': a_core.ObjectIdentifier(OID_ENROLL_ENCRYPTION_ALGORITHM),
        'values': [_as_any_from_der(enc_alg_der)],
    })
    attr_aik = None
    if aik_info_der is not None:
        attr_aik = MsWrappedAttr({
            'oid': a_core.ObjectIdentifier(OID_ENROLL_CAXCHGCERT_HASH),
            'values': [_as_any_from_der(aik_info_der)],
        })
    attr_ksp = MsWrappedAttr({
        'oid': a_core.ObjectIdentifier(OID_ENROLL_KSP_NAME),
        'values': [_as_any_from_der(a_core.BMPString(ksp_name).dump())],
    })
    attr_tach = MsWrappedAttr({
        'oid': a_core.ObjectIdentifier(OID_ENROLL_ATTESTATION_CHALLENGE),
        'values': [_as_any_from_der(a_core.OctetString(tach_blob).dump())],
    })

    attr_enc_der = attr_enc.dump()
    attr_aik_der = attr_aik.dump() if attr_aik is not None else None
    attr_ksp_der = attr_ksp.dump()
    attr_tach_der = attr_tach.dump()
    logger.warning('TPM WRAP attr_enc len=%d hex=%s', len(attr_enc_der), attr_enc_der.hex())
    if attr_aik_der is not None:
        logger.warning('TPM WRAP attr_aik len=%d hex=%s', len(attr_aik_der), attr_aik_der.hex())
    else:
        logger.warning('TPM WRAP attr_aik omitted')
    logger.warning('TPM WRAP attr_ksp len=%d hex=%s', len(attr_ksp_der), attr_ksp_der.hex())
    logger.warning(
        'TPM WRAP attr_tach len=%d hex_prefix=%s hex_suffix=%s',
        len(attr_tach_der),
        attr_tach_der[:96].hex(),
        attr_tach_der[-96:].hex(),
    )

    attrs_items = [attr_enc]
    if attr_aik is not None:
        attrs_items.append(attr_aik)
    attrs_items.extend([attr_ksp, attr_tach])
    attrs = MsWrappedAttrs(attrs_items)
    attrs_der = attrs.dump()
    logger.warning(
        'TPM WRAP attrs_set len=%d sha256=%s hex_prefix=%s hex_suffix=%s',
        len(attrs_der),
        hashlib.sha256(attrs_der).hexdigest(),
        attrs_der[:128].hex(),
        attrs_der[-128:].hex(),
    )

    wrapper = MsChallengeWrapper({
        'version': 0,
        'header': {'bodyPartID': inner_body_part_id},
        'attrs': attrs,
    })
    wrapper_der = wrapper.dump()
    logger.warning(
        'TPM WRAP wrapper inner_body_part_id=%d len=%d sha256=%s hex_prefix=%s hex_suffix=%s',
        inner_body_part_id,
        len(wrapper_der),
        hashlib.sha256(wrapper_der).hexdigest(),
        wrapper_der[:128].hex(),
        wrapper_der[-128:].hex(),
    )
    return wrapper_der


def _log_cmc_control(ctrl, label: str):
    import hashlib
    der = ctrl.dump()
    oid = None
    body_part_id = None
    try:
        oid = ctrl['attrType'].dotted
    except Exception:
        try:
            oid = ctrl['attrType'].native
        except Exception:
            oid = '<unknown>'
    try:
        body_part_id = int(ctrl['bodyPartID'])
    except Exception:
        try:
            body_part_id = int(ctrl['bodyPartID'].native)
        except Exception:
            body_part_id = None
    logger.warning(
        'TPM CMC control label=%s bodyPartID=%r oid=%r len=%d sha256=%s hex=%s',
        label,
        body_part_id,
        oid,
        len(der),
        hashlib.sha256(der).hexdigest(),
        der.hex(),
    )


def _log_cmc_response_summary(control_sequence, cms_sequence, response_body_der: bytes):
    import hashlib
    control_oids = []
    control_body_parts = []
    for ctrl in control_sequence:
        try:
            control_oids.append(ctrl['attrType'].dotted)
        except Exception:
            try:
                control_oids.append(ctrl['attrType'].native)
            except Exception:
                control_oids.append('<unknown>')
        try:
            control_body_parts.append(int(ctrl['bodyPartID']))
        except Exception:
            try:
                control_body_parts.append(int(ctrl['bodyPartID'].native))
            except Exception:
                control_body_parts.append(None)
    logger.warning(
        'TPM CMC summary controls=%d control_oids=%r control_body_parts=%r cms_items=%d response_body_len=%d response_body_sha256=%s',
        len(control_sequence),
        control_oids,
        control_body_parts,
        len(cms_sequence),
        len(response_body_der),
        hashlib.sha256(response_body_der).hexdigest(),
    )
    logger.warning(
        'TPM CMC response_body len=%d sha256=%s hex_prefix=%s hex_suffix=%s',
        len(response_body_der),
        hashlib.sha256(response_body_der).hexdigest(),
        response_body_der[:128].hex(),
        response_body_der[-128:].hex(),
    )


def build_adcs_like_control_sequence(*, request_id: int, encryption_algorithm_oid: str, aik_info_hash: bytes | None, tach_blob: bytes, ksp_name: str = 'Microsoft Platform Crypto Provider', pend_time=None) -> TaggedAttributes:
    pending_der = build_cmc_pending_status_info(request_id=request_id, status_string='En attente de traitement', pend_time=pend_time, body_part_id=1)
    ms_wrapper_der = build_ms_challenge_wrapper_value(
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        ksp_name=ksp_name,
        tach_blob=tach_blob,
        inner_body_part_id=1,
    )
    ctrl_pending = TaggedAttribute({
        'bodyPartID': BodyPartID(1),
        'attrType': a_core.ObjectIdentifier(OID_CMC_STATUS_INFO),
        'attrValues': [_as_any_from_der(pending_der)],
    })
    ctrl_ms_challenge = TaggedAttribute({
        'bodyPartID': BodyPartID(2),
        'attrType': a_core.ObjectIdentifier(OID_MS_CMC_CHALLENGE_WRAPPER),
        'attrValues': [_as_any_from_der(ms_wrapper_der)],
    })
    _log_cmc_control(ctrl_pending, 'pending')
    _log_cmc_control(ctrl_ms_challenge, 'ms_challenge')
    return TaggedAttributes([ctrl_pending, ctrl_ms_challenge])


def build_cmc_cms_sequence(*, ca_exchange_chain_der) -> TaggedContentInfos:
    # AD CS response observed with empty cmsSequence.
    return TaggedContentInfos([])


def build_cmc_pki_response(*, control_sequence: TaggedAttributes, cms_sequence: TaggedContentInfos) -> bytes:
    rb = ResponseBody({'controlSequence': control_sequence, 'cmsSequence': cms_sequence, 'otherMsgSequence': OtherMsgs([])})
    response_body_der = rb.dump()
    _log_cmc_response_summary(control_sequence, cms_sequence, response_body_der)
    return response_body_der


def wrap_pki_response_content_info(response_body_der: bytes) -> bytes:
    # For Microsoft CMC PKIResponse, the CMS eContentType already conveys pkiResponse.
    # The encapsulated octets must be the raw PKIResponse DER, not an inner ContentInfo wrapper.
    return response_body_der


def _write_temp_file(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return path


def _normalize_pem_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        if '-----BEGIN ' in value:
            return value.encode('utf-8')
        return Path(value).read_bytes()
    raise TypeError(f'Unsupported PEM type: {type(value).__name__}')


def _concat_pem_chain(chain_pems) -> bytes:
    out = b''
    for item in (chain_pems or []):
        pem = _normalize_pem_bytes(item)
        if not pem.endswith(b'\n'):
            pem += b'\n'
        out += pem
    return out


def _sign_cmc_pki_response_python(*, pki_response_der: bytes, signer_cert_pem, signer_key_pem, extra_chain_pems=None, extra_certs_der=None) -> bytes:
    """Build a CMS SignedData for a CMC PKIResponse without OpenSSL defaults."""
    logger.error('TPM DEBUG _sign_cmc_pki_response_python pki_response_len=%d', len(pki_response_der))
    signer_cert_pem_b = _normalize_pem_bytes(signer_cert_pem)
    signer_key_pem_b = _normalize_pem_bytes(signer_key_pem)
    signer_cert = x509.load_pem_x509_certificate(signer_cert_pem_b)
    signer_cert_der = signer_cert.public_bytes(serialization.Encoding.DER)
    signer_asn1 = a_cms.Certificate.load(signer_cert_der)

    cert_choices = []
    seen = set()

    def _add_cert_der(cert_der: bytes):
        cert_der = bytes(cert_der)
        if cert_der in seen:
            return
        seen.add(cert_der)
        cert_choices.append(a_cms.CertificateChoices(name='certificate', value=a_cms.Certificate.load(cert_der)))

    _add_cert_der(signer_cert_der)

    for item in (extra_chain_pems or []):
        pem = _normalize_pem_bytes(item)
        try:
            cert = x509.load_pem_x509_certificate(pem)
        except Exception:
            continue
        _add_cert_der(cert.public_bytes(serialization.Encoding.DER))

    for cert_der in (extra_certs_der or []):
        try:
            _add_cert_der(cert_der)
        except Exception:
            continue

    logger.error(
        'TPM DEBUG CMS certs count=%d subjects=%s',
        len(cert_choices), _debug_cert_subjects([c.chosen.dump() for c in cert_choices])
    )

    signed_attrs = a_cms.CMSAttributes([
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.3', 'values': [a_cms.ContentType(OID_ID_CCT_PKI_RESPONSE)]}),
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.4', 'values': [hashlib.sha256(pki_response_der).digest()]}),
    ])
    to_be_signed = signed_attrs.dump(force=True)

    private_key = serialization.load_pem_private_key(signer_key_pem_b, password=None)
    signature = private_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())

    signer_info = a_cms.SignerInfo({
        'version': 'v1',
        'sid': a_cms.SignerIdentifier({'issuer_and_serial_number': a_cms.IssuerAndSerialNumber({'issuer': signer_asn1.issuer, 'serial_number': signer_asn1.serial_number})}),
        'digest_algorithm': a_cms.DigestAlgorithm({'algorithm': 'sha256', 'parameters': a_core.Null()}),
        'signed_attrs': signed_attrs,
        'signature_algorithm': a_cms.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15', 'parameters': a_core.Null()}),
        'signature': signature,
    })

    sd = a_cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [a_cms.DigestAlgorithm({'algorithm': 'sha256', 'parameters': a_core.Null()})],
        'encap_content_info': {'content_type': OID_ID_CCT_PKI_RESPONSE, 'content': a_cms.ParsableOctetString(pki_response_der)},
        'certificates': OrderedCertificateSet(cert_choices),
        'signer_infos': [signer_info],
    })
    ci = a_cms.ContentInfo({'content_type': OID_ID_SIGNED_DATA, 'content': sd})
    out = ci.dump()
    if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01' in out and b'\x06\x08\x2b\x06\x01\x05\x05\x07\x0c\x03' not in out:
        raise ValueError('Generated CMS regressed to id-data instead of id-cct-PKIResponse')
    return out


def sign_cmc_pki_response_with_openssl(*, pki_response_der: bytes = None, content_info_der: bytes = None, signer_cert_pem=None, signer_key_pem=None, extra_chain_pems=None, extra_certs_der=None, openssl_bin: str = 'openssl') -> bytes:
    """Compatibility wrapper kept for old call sites. Does not invoke OpenSSL."""
    payload = pki_response_der if pki_response_der is not None else content_info_der
    if payload is None:
        raise TypeError('pki_response_der is required')
    return _sign_cmc_pki_response_python(
        pki_response_der=payload,
        signer_cert_pem=signer_cert_pem,
        signer_key_pem=signer_key_pem,
        extra_chain_pems=extra_chain_pems,
        extra_certs_der=extra_certs_der,
    )


def build_microsoft_attestation_challenge_pki_response(*, request_id: int, ca_exchange_chain_der, encryption_algorithm_oid: str, aik_info_hash: bytes | None, tach_blob: bytes, pend_time=None) -> dict:
    control_seq = build_adcs_like_control_sequence(
        request_id=request_id,
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        tach_blob=tach_blob,
        ksp_name='Microsoft Platform Crypto Provider',
        pend_time=pend_time,
    )
    cms_seq = build_cmc_cms_sequence(ca_exchange_chain_der=ca_exchange_chain_der)
    response_body_der = build_cmc_pki_response(control_sequence=control_seq, cms_sequence=cms_seq)
    content_info_der = wrap_pki_response_content_info(response_body_der)
    return {'response_body_der': response_body_der, 'content_info_der': content_info_der}


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
    openssl_bin: str = 'openssl',
    # Raw TPMT_PUBLIC bytes of the AIK from szOID_ENROLL_AIK_INFO when present in the CSR.
    aik_pub_raw: bytes | None = None,
    # Raw Microsoft attestation blob (KAST/PCPM), used as a fallback source to
    # recover the AIK TPM name when szOID_ENROLL_AIK_INFO is absent.
    attestation_blob_raw: bytes | None = None,
) -> dict:
    forced_request_id = os.getenv('TPM_FORCE_REQUEST_ID', '').strip()
    if forced_request_id:
        try:
            request_id = int(forced_request_id, 0)
            logger.debug('TPM override request_id from TPM_FORCE_REQUEST_ID=%r -> %d', forced_request_id, request_id)
        except Exception as exc:
            logger.error('TPM invalid TPM_FORCE_REQUEST_ID=%r err=%s', forced_request_id, exc)
    request_id = int(request_id)
    ek_name_alg = infer_ek_name_alg_from_public_key(ek_pub)
    logger.debug(
        'TPM build_and_sign_microsoft_attestation_challenge request_id=%d '
        'encryption_algorithm_oid=%s aik_hash=%s ek_name_alg=%#06x',
        request_id, encryption_algorithm_oid, (aik_info_hash.hex() if aik_info_hash is not None else 'OMITTED'), ek_name_alg,
    )

    if secret is None:
        secret = os.urandom(32)

    # Determine the AIK TPM name for TPM2_MakeCredential.
    aik_name_alg = TPM2_ALG_SHA256
    if aik_pub_raw is not None:
        try:
            aik_pub = parse_tpmt_public(aik_pub_raw)
            aik_name = aik_pub.compute_name()
            aik_name_alg = getattr(aik_pub, 'name_alg', TPM2_ALG_SHA256)
            logger.debug('TPM AIK name computed from aik_pub_raw: %s (name_alg=%#06x)', aik_name.hex(), aik_name_alg)
        except Exception as exc:
            logger.warning('TPM failed to compute AIK name from aik_pub_raw: %s', exc)
            aik_name = None
    else:
        aik_name = None

    if aik_name is None and attestation_blob_raw is not None:
        try:
            recovered = _extract_aik_name_from_microsoft_attestation_blob(attestation_blob_raw)
            aik_name = recovered
            if len(recovered) >= 2:
                aik_name_alg = struct.unpack('>H', recovered[:2])[0]
            logger.debug('TPM AIK name recovered from attestation_blob_raw: %s (name_alg=%#06x)', aik_name.hex(), aik_name_alg)
        except Exception as exc:
            logger.warning('TPM failed to recover AIK name from attestation_blob_raw: %s', exc)
            aik_name = None

    if aik_name is None:
        raise ValueError(
            'Could not recover the AIK TPM name from the Microsoft attestation '
            'statement/blob; refusing to emit an invalid TPM2_MakeCredential '
            'challenge that Windows will reject during integrity verification.'
        )

    # Build the TACH blob via TPM2_MakeCredential.
    tach_blob = _make_tach_blob(
        secret=secret,
        ek_pub=ek_pub,
        aik_name=aik_name,
        attestation_blob_raw=attestation_blob_raw,
        ek_name_alg=ek_name_alg,
    )

    built = build_microsoft_attestation_challenge_pki_response(
        request_id=request_id,
        ca_exchange_chain_der=ca_exchange_chain_der,
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        tach_blob=tach_blob,
    )
    built['request_id'] = int(request_id)
    built['effective_request_id'] = int(request_id)

    signed_pkcs7_der = _sign_cmc_pki_response_python(
        pki_response_der=built['response_body_der'],
        signer_cert_pem=signer_cert_pem,
        signer_key_pem=signer_key_pem,
        extra_chain_pems=signer_chain_pems,
        extra_certs_der=ca_exchange_chain_der,
    )
    logger.debug(
        'TPM response_body=%d bytes signed_pkcs7=%d bytes tach=%d bytes',
        len(built['response_body_der']), len(signed_pkcs7_der), len(tach_blob),
    )
    built['secret'] = secret
    built['tach_blob'] = tach_blob
    built['signed_pkcs7_der'] = signed_pkcs7_der
    return built


def extract_encryption_algorithm_for_challenge_response(ms_ek_info_raw: bytes) -> str:
    return extract_content_encryption_algorithm_oid_from_ek_info(ms_ek_info_raw)


class BodyPartID(a_core.Integer):
    pass


class TaggedAttribute(a_core.Sequence):
    _fields = [
        ('bodyPartID', BodyPartID),
        ('attrType', a_core.ObjectIdentifier),
        ('attrValues', a_core.SetOf, {'spec': a_core.Any}),
    ]


class TaggedAttributes(a_core.SequenceOf):
    _child_spec = TaggedAttribute


class TaggedContentInfo(a_core.Sequence):
    _fields = [
        ('bodyPartID', BodyPartID),
        ('contentInfo', a_cms.ContentInfo),
    ]


class TaggedContentInfos(a_core.SequenceOf):
    _child_spec = TaggedContentInfo


class OtherMsgs(a_core.SequenceOf):
    _child_spec = a_core.Any


class ResponseBody(a_core.Sequence):
    _fields = [
        ('controlSequence', TaggedAttributes),
        ('cmsSequence', TaggedContentInfos),
        ('otherMsgSequence', OtherMsgs),
    ]


OID_ENROLL_ATTESTATION_CHALLENGE = '1.3.6.1.4.1.311.21.28'
OID_ENROLL_ENCRYPTION_ALGORITHM = '1.3.6.1.4.1.311.21.29'
OID_ID_CCT_PKI_RESPONSE = '1.3.6.1.5.5.7.12.3'
OID_ID_DATA = '1.2.840.113549.1.7.1'
OID_ID_SIGNED_DATA = '1.2.840.113549.1.7.2'


def _as_any_from_der(der: bytes) -> a_core.Any:
    return a_core.Any.load(der)


def _content_info_with_certs(certs_der) -> a_cms.ContentInfo:
    cert_choices = []
    for cert_der in certs_der:
        cert = a_cms.Certificate.load(cert_der)
        cert_choices.append(a_cms.CertificateChoices(name='certificate', value=cert))
    signed_data = a_cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [],
        'encap_content_info': {'content_type': OID_ID_DATA, 'content': None},
        'certificates': OrderedCertificateSet(cert_choices),
        'signer_infos': [],
    })
    return a_cms.ContentInfo({'content_type': OID_ID_SIGNED_DATA, 'content': signed_data})


def build_encryption_algorithm_attr_value(algorithm_oid: str) -> bytes:
    ai = a_algos.AlgorithmIdentifier({'algorithm': algorithm_oid, 'parameters': a_core.Null()})
    return ai.dump()


def build_cmc_control_sequence(*, challenge_encrypted: bytes, encryption_algorithm_oid: str) -> TaggedAttributes:
    challenge_attr = TaggedAttribute({
        'bodyPartID': BodyPartID(1),
        'attrType': a_core.ObjectIdentifier(OID_ENROLL_ATTESTATION_CHALLENGE),
        'attrValues': [_as_any_from_der(a_core.OctetString(challenge_encrypted).dump())],
    })
    encalg_attr = TaggedAttribute({
        'bodyPartID': BodyPartID(2),
        'attrType': a_core.ObjectIdentifier(OID_ENROLL_ENCRYPTION_ALGORITHM),
        'attrValues': [_as_any_from_der(build_encryption_algorithm_attr_value(encryption_algorithm_oid))],
    })
    return TaggedAttributes([challenge_attr, encalg_attr])


def build_cmc_cms_sequence(*, ca_exchange_chain_der) -> TaggedContentInfos:
    # AD CS response observed with empty cmsSequence.
    return TaggedContentInfos([])


def build_cmc_pki_response(*, control_sequence: TaggedAttributes, cms_sequence: TaggedContentInfos) -> bytes:
    rb = ResponseBody({'controlSequence': control_sequence, 'cmsSequence': cms_sequence, 'otherMsgSequence': OtherMsgs([])})
    response_body_der = rb.dump()
    _log_cmc_response_summary(control_sequence, cms_sequence, response_body_der)
    return response_body_der


def wrap_pki_response_content_info(response_body_der: bytes) -> bytes:
    # For Microsoft CMC PKIResponse, the CMS eContentType already conveys pkiResponse.
    # The encapsulated octets must be the raw PKIResponse DER, not an inner ContentInfo wrapper.
    return response_body_der


def _write_temp_file(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return path


def _normalize_pem_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise TypeError(f'Unsupported PEM type: {type(value).__name__}')


def _concat_pem_chain(chain_pems) -> bytes:
    out = b''
    for item in (chain_pems or []):
        pem = _normalize_pem_bytes(item)
        if not pem.endswith(b'\n'):
            pem += b'\n'
        out += pem
    return out


def sign_cmc_pki_response_with_openssl(*, content_info_der: bytes, signer_cert_pem, signer_key_pem, extra_chain_pems=None, openssl_bin: str = 'openssl') -> bytes:
    # Delegate to the CMS builder above; keep this late definition aligned so it does not
    # overwrite the ADCS-compatible implementation with an OpenSSL cms -sign/data fallback.
    signer_cert_pem_b = _normalize_pem_bytes(signer_cert_pem)
    signer_key_pem_b = _normalize_pem_bytes(signer_key_pem)
    signer_cert = x509.load_pem_x509_certificate(signer_cert_pem_b)
    signer_cert_der = signer_cert.public_bytes(serialization.Encoding.DER)
    signer_asn1 = a_cms.Certificate.load(signer_cert_der)

    cert_choices = [a_cms.CertificateChoices(name='certificate', value=signer_asn1)]
    for item in (extra_chain_pems or []):
        pem = _normalize_pem_bytes(item)
        try:
            cert = x509.load_pem_x509_certificate(pem)
        except Exception:
            continue
        cert_choices.append(a_cms.CertificateChoices(name='certificate', value=a_cms.Certificate.load(cert.public_bytes(serialization.Encoding.DER))))

    pkiresp_der = content_info_der
    signed_attrs = a_cms.CMSAttributes([
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.3', 'values': [a_cms.ContentType(OID_ID_CCT_PKI_RESPONSE)]}),
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.4', 'values': [hashlib.sha256(pkiresp_der).digest()]}),
    ])
    to_be_signed = signed_attrs.dump(force=True)

    private_key = serialization.load_pem_private_key(signer_key_pem_b, password=None)
    signature = private_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())

    signer_info = a_cms.SignerInfo({
        'version': 'v1',
        'sid': a_cms.SignerIdentifier({'issuer_and_serial_number': a_cms.IssuerAndSerialNumber({'issuer': signer_asn1.issuer, 'serial_number': signer_asn1.serial_number})}),
        'digest_algorithm': a_cms.DigestAlgorithm({'algorithm': 'sha256', 'parameters': a_core.Null()}),
        'signed_attrs': signed_attrs,
        'signature_algorithm': a_cms.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15', 'parameters': a_core.Null()}),
        'signature': signature,
    })

    sd = a_cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [a_cms.DigestAlgorithm({'algorithm': 'sha256', 'parameters': a_core.Null()})],
        'encap_content_info': {'content_type': OID_ID_CCT_PKI_RESPONSE, 'content': a_cms.ParsableOctetString(pkiresp_der)},
        'certificates': OrderedCertificateSet(cert_choices),
        'signer_infos': [signer_info],
    })
    return a_cms.ContentInfo({'content_type': OID_ID_SIGNED_DATA, 'content': sd}).dump()


def build_and_sign_microsoft_attestation_challenge_legacy(*, ek_pub, ca_exchange_chain_der, encryption_algorithm_oid: str, signer_cert_pem, signer_key_pem, signer_chain_pems=None, secret: bytes | None = None, openssl_bin: str = 'openssl') -> dict:
    if secret is None:
        secret = os.urandom(32)
    challenge_encrypted = build_attestation_challenge(secret, ek_pub)
    control_seq = build_cmc_control_sequence(challenge_encrypted=challenge_encrypted, encryption_algorithm_oid=encryption_algorithm_oid)
    cms_seq = build_cmc_cms_sequence(ca_exchange_chain_der=ca_exchange_chain_der)
    response_body_der = build_cmc_pki_response(control_sequence=control_seq, cms_sequence=cms_seq)
    content_info_der = wrap_pki_response_content_info(response_body_der)
    signed_pkcs7_der = _sign_cmc_pki_response_python(pki_response_der=response_body_der, signer_cert_pem=signer_cert_pem, signer_key_pem=signer_key_pem, extra_chain_pems=signer_chain_pems)
    return {'secret': secret, 'response_body_der': response_body_der, 'content_info_der': content_info_der, 'signed_pkcs7_der': signed_pkcs7_der}
