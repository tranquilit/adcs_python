#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import ipaddress
import glob
from typing import Tuple, Iterable, List, Optional, Dict, Any, Set
from datetime import datetime, timezone, timedelta

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ( 
    rsa,
    ec,
    ed25519,
    ed448,
    dsa, 
)   


# -----------------------------------------------------------------------------
# CRL helpers and persistent CRLNumber sidecar
# -----------------------------------------------------------------------------

def _load_existing_crl(path: str):
    """Load an existing CRL (PEM or DER). Returns None if missing."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        try:
            return cx509.load_pem_x509_crl(data)
        except Exception:
            return cx509.load_der_x509_crl(data)
    except FileNotFoundError:
        return None


def _iter_revoked(crl) -> List[cx509.RevokedCertificate]:
    """Iterate revoked entries across cryptography versions."""
    if not crl:
        return []
    try:
        return list(crl)
    except Exception:
        rc = getattr(crl, "revoked_certificates", None)
        return list(rc) if rc else []


def _read_crl_number_from_obj(crl) -> Optional[int]:
    """Try to read CRLNumber from a CRL object."""
    if not crl:
        return None
    try:
        ext = crl.extensions.get_extension_for_oid(cx509.ExtensionOID.CRL_NUMBER).value
        return int(ext.crl_number)
    except Exception:
        pass
    try:
        for ext in crl.extensions:
            if getattr(ext, "oid", None) == cx509.ExtensionOID.CRL_NUMBER:
                try:
                    return int(ext.value.crl_number)
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _crlnum_sidecar_path(crl_path: str) -> str:
    return crl_path + ".num"


def _read_sidecar_num(path: str) -> Optional[int]:
    try:
        with open(path, "rt", encoding="utf-8") as f:
            return int(f.read().strip(), 10)
    except Exception:
        return None


def _write_sidecar_num(path: str, num: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wt", encoding="utf-8") as f:
        f.write(str(int(num)))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic on POSIX


def _next_crl_number_persistent(crl_path: str, crl, bump: bool = True) -> int:
    """
    Compute the next CRLNumber using a sidecar file (persistent across restarts).
    If bump=False, return the current value without incrementing.
    """
    sidecar = _crlnum_sidecar_path(crl_path)
    sc = _read_sidecar_num(sidecar)
    cur = _read_crl_number_from_obj(crl)

    if not bump:
        return sc if sc is not None else (cur if cur is not None else 1)

    if sc is not None:
        nxt = sc + 1
    elif cur is not None:
        nxt = cur + 1
    else:
        nxt = 1
    _write_sidecar_num(sidecar, nxt)
    return nxt


def _serial_to_int(serial) -> int:
    """Parse a serial that may be hex-string ('0x...') or decimal-string."""
    if isinstance(serial, str):
        s = serial.strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        try:
            return int(s, 16)
        except ValueError:
            return int(s, 10)
    return int(serial)


def _add_aki_if_absent(builder, ca_key):
    """Add AKI from issuer public key if not already present."""
    try:
        builder.extensions.get_extension_for_class(cx509.AuthorityKeyIdentifier)
    except Exception:
        try:
            aki = cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
            builder = builder.add_extension(aki, critical=False)
        except Exception:
            pass
    return builder


def _select_algo(hash_name: str):
    """Select a HashAlgorithm object by name, defaulting to SHA-256."""
    algo = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
        "sha1":   hashes.SHA1,
    }.get(hash_name.lower(), hashes.SHA256)
    return algo()


def _write_crl_file(crl_path: str, pem_bytes: bytes) -> None:
    """Write a PEM CRL to disk safely (create dirs, fsync, replace)."""
    dirn = os.path.dirname(crl_path) or "."
    os.makedirs(dirn, exist_ok=True)
    with open(crl_path, "wb") as f:
        f.write(pem_bytes)
        f.flush()
        os.fsync(f.fileno())


# -----------------------------------------------------------------------------
# CRL operations: revoke / unrevoke / resign
# -----------------------------------------------------------------------------

def revoke(ca_key, ca_cert: cx509.Certificate, serial, crl_path: str, next_update_hours: int = 8) -> None:
    """Add a revoked entry for `serial` and write a new CRL."""
    serial_int = _serial_to_int(serial)

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    crl_number = _next_crl_number_persistent(crl_path, old_crl, bump=True)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    # Reuse extensions (except CRL_NUMBER) from the previous CRL if present
    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass

    builder = builder.add_extension(cx509.CRLNumber(crl_number), critical=False)

    # Reinstate all previous revoked certs except the one being (re)added
    for rc in _iter_revoked(old_crl):
        if rc.serial_number == serial_int:
            continue
        builder = builder.add_revoked_certificate(rc)

    rcb = (
        cx509.RevokedCertificateBuilder()
        .serial_number(serial_int)
        .revocation_date(now)
        .add_extension(cx509.CRLReason(cx509.ReasonFlags.unspecified), critical=False)
    ).build()
    builder = builder.add_revoked_certificate(rcb)

    builder = _add_aki_if_absent(builder, ca_key)

    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)


def unrevoke(ca_key, ca_cert: cx509.Certificate, serial, crl_path: str, next_update_hours: int = 8) -> None:
    """Remove a revoked entry for `serial` and write a new CRL."""
    serial_int = _serial_to_int(serial)

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    if not old_crl:
        raise FileNotFoundError(f"CRL not found at '{crl_path}' — nothing to remove.")

    crl_number = _next_crl_number_persistent(crl_path, old_crl, bump=True)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass

    builder = builder.add_extension(cx509.CRLNumber(crl_number), critical=False)

    # Reinstate all previous revoked certs except the one being removed
    for rc in _iter_revoked(old_crl):
        if rc.serial_number == serial_int:
            continue
        builder = builder.add_revoked_certificate(rc)

    builder = _add_aki_if_absent(builder, ca_key)

    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)


def resign_crl(
    ca_key,
    ca_cert: cx509.Certificate,
    crl_path: str,
    *,
    next_update_hours: int = 8,
    bump_number: bool = True,
    hash_name: str = "sha256",
) -> int:
    """
    Re-sign the CRL even if nothing changed (bump CRLNumber and refresh dates).
    Returns the new CRLNumber.
    """
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    revoked_list = _iter_revoked(old_crl)  # may be empty and that's OK

    new_num = _next_crl_number_persistent(crl_path, old_crl, bump=bump_number)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass  # be tolerant across versions/values

    builder = builder.add_extension(cx509.CRLNumber(int(new_num)), critical=False)

    for rc in revoked_list:
        try:
            builder = builder.add_revoked_certificate(rc)
        except Exception:
            try:
                minimal = (
                    cx509.RevokedCertificateBuilder()
                    .serial_number(rc.serial_number)
                    .revocation_date(rc.revocation_date)
                    .build()
                )
                builder = builder.add_revoked_certificate(minimal)
            except Exception:
                pass

    builder = _add_aki_if_absent(builder, ca_key)

    algo = _select_algo(hash_name)
    new_crl = builder.sign(private_key=ca_key, algorithm=algo)
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)

    # Optional sanity check
    try:
        written = _load_existing_crl(crl_path)
        ext = written.extensions.get_extension_for_oid(cx509.ExtensionOID.CRL_NUMBER).value
        assert int(ext.crl_number) == int(new_num)
    except Exception:
        pass

    return int(new_num)


# -----------------------------------------------------------------------------
# Certificate issuance (new keypair + end-entity certificate)
# -----------------------------------------------------------------------------

def _coerce_san(s: str) -> cx509.GeneralName:
    s = (s or "").strip()
    if not s:
        raise ValueError("Empty SAN")
    try:
        return cx509.IPAddress(ipaddress.ip_address(s))
    except ValueError:
        return cx509.DNSName(s)


def _dedup_sans(strings: Iterable[str]) -> List[cx509.GeneralName]:
    out: List[cx509.GeneralName] = []
    seen = set()
    for s in strings or []:
        try:
            gn = _coerce_san(s)
        except ValueError:
            continue
        key = ("IP", str(gn.value)) if isinstance(gn, cx509.IPAddress) else ("DNS", gn.value.lower())
        if key not in seen:
            out.append(gn)
            seen.add(key)
    return out


def issue_cert_with_new_key(
    *,
    ca: Dict[str, Any],                     # "__certificate_der": bytes, "__key_obj": private key
    common_name: str,
    subject_sans: Iterable[str] = (),
    validity_seconds: int = 365 * 24 * 3600,
    backdate_seconds: int = 300,
    key_type: str = "rsa",                  # "rsa" | "ec" | "ed25519" | "ed448"
    rsa_key_size: int = 2048,
    ec_curve: str = "secp256r1",            # "secp384r1", "secp521r1", "secp256k1"
    key_export_password: Optional[bytes] = None,
) -> Tuple[cx509.Certificate, Any, bytes, bytes]:
    """Generate a new keypair, issue an end-entity certificate, and return (cert_obj, privkey_obj, cert_pem, key_pem)."""

    # Generate subject key
    key_type_l = (key_type or "rsa").lower()
    if key_type_l == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=int(rsa_key_size))
    elif key_type_l == "ec":
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1(),
        }
        curve = curve_map.get((ec_curve or "secp256r1").lower(), ec.SECP256R1())
        priv = ec.generate_private_key(curve)
    elif key_type_l == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    elif key_type_l == "ed448":
        priv = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unknown key_type: {key_type}")

    pub = priv.public_key()

    # CA material
    ca_cert = cx509.load_der_x509_certificate(ca["__certificate_der"])
    ca_key = ca["__key_obj"]

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(seconds=int(backdate_seconds))
    not_after = not_before + timedelta(seconds=int(validity_seconds))

    # Build certificate
    builder = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )

    # AKI
    try:
        builder = builder.add_extension(
            cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    except Exception:
        pass

    # AIA / CDP from config
    urls = ca.get("urls", {}) or {}
    if urls.get("ca_issuers_http"):
        builder = builder.add_extension(
            cx509.AuthorityInformationAccess([
                cx509.AccessDescription(
                    cx509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                    cx509.UniformResourceIdentifier(urls["ca_issuers_http"]),
                )
            ]),
            critical=False,
        )
    if urls.get("crl_http"):
        builder = builder.add_extension(
            cx509.CRLDistributionPoints([
                cx509.DistributionPoint(
                    full_name=[cx509.UniformResourceIdentifier(urls["crl_http"])],
                    relative_name=None, reasons=None, crl_issuer=None
                )
            ]),
            critical=False,
        )

    # SAN
    if subject_sans:
        sans = _dedup_sans(subject_sans)
        if sans:
            builder = builder.add_extension(cx509.SubjectAlternativeName(sans), critical=False)

    # Sign
    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = builder.sign(private_key=ca_key, algorithm=None)
    else:
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Export PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    if key_export_password:
        encryption = serialization.BestAvailableEncryption(key_export_password)
    else:
        encryption = serialization.NoEncryption()

    key_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    return cert, priv, cert_pem, key_pem


# -----------------------------------------------------------------------------
# Certificate file helpers (parsing and discovery)
# -----------------------------------------------------------------------------

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"
_CERT_EXTS = {".crt", ".pem", ".cer"}

def is_pem_blob(data: bytes) -> bool:
    return _PEM_BEGIN in data and _PEM_END in data

def load_certificate_file(path: str) -> cx509.Certificate:
    """Load a certificate from a file (PEM, DER, or raw base64 DER)."""
    with open(path, "rb") as f:
        data = f.read()
    if not is_pem_blob(data):
        # Try direct DER
        try:
            return cx509.load_der_x509_certificate(data)
        except Exception:
            # Often DER is base64 without headers
            try:
                der = base64.b64decode(data)
                return cx509.load_der_x509_certificate(der)
            except Exception as e:
                raise ValueError(f"File not recognized as X.509 certificate: {os.path.basename(path)}: {e}")
    return cx509.load_pem_x509_certificate(data)

def get_public_key_info(cert: cx509.Certificate) -> Tuple[str, Optional[int]]:
    """Return ('RSA', bits) | ('EC(name)', None) | ('DSA', bits) | (class_name, None)."""
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return ("RSA", pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        try:
            name = pk.curve.name
        except Exception:
            name = pk.curve.__class__.__name__
        return (f"EC({name})", None)
    if isinstance(pk, dsa.DSAPublicKey):
        return ("DSA", pk.key_size)
    return (pk.__class__.__name__, None)

def scan_cert_paths(cert_dir: str) -> List[str]:
    """Return a sorted list of certificate file paths in `cert_dir` (recursive)."""
    files: List[str] = []
    for ext in _CERT_EXTS:
        files.extend(glob.glob(os.path.join(cert_dir, f"**/*{ext}"), recursive=True))
    return sorted(set(files))

def revoked_serials_set(crl_path: Optional[str]) -> Set[int]:
    """Return the set of revoked serial numbers (as ints) from the CRL at `crl_path`."""
    if not crl_path:
        return set()
    crl = _load_existing_crl(crl_path)
    if not crl:
        return set()
    return {rc.serial_number for rc in _iter_revoked(crl)}

