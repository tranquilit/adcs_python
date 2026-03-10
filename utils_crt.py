#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import ipaddress
import glob
import tempfile
import sys
import stat
import uuid
import shutil
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
    ca: Dict[str, Any],
    common_name: str,
    subject_sans: Iterable[str] = (),
    validity_seconds: int = 365 * 24 * 3600,
    backdate_seconds: int = 300,
    key_type: str = "rsa",
    rsa_key_size: int = 2048,
    ec_curve: str = "secp256r1",
    key_export_password: Optional[bytes] = None,
) -> Tuple[cx509.Certificate, Any, bytes, bytes]:
    """Generate a new keypair, issue an end-entity certificate, and return (cert_obj, privkey_obj, cert_pem, key_pem)."""

    key_type_l = (key_type or "rsa").lower()
    if key_type_l == "rsa":
        if int(rsa_key_size) not in (2048, 3072, 4096):
            raise ValueError("--rsa-bits must be one of: 2048, 3072, 4096.")
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

    ca_cert = cx509.load_der_x509_certificate(ca["__certificate_der"])
    ca_key = ca["__key_obj"]

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(seconds=int(backdate_seconds))
    not_after = not_before + timedelta(seconds=int(validity_seconds))

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

    try:
        builder = builder.add_extension(
            cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    except Exception:
        pass

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

    if subject_sans:
        sans = _dedup_sans(subject_sans)
        if sans:
            builder = builder.add_extension(cx509.SubjectAlternativeName(sans), critical=False)

    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = builder.sign(private_key=ca_key, algorithm=None)
    else:
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

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
        try:
            return cx509.load_der_x509_certificate(data)
        except Exception:
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

def _extract_cn_and_sans(cert: cx509.Certificate) -> tuple[str, list[str]]:
    try:
        cn_attr = cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)
        cn = cn_attr[0].value if cn_attr else ""
    except Exception:
        cn = ""

    sans_list: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
        for n in san_ext:
            v = getattr(n, "value", None)
            if v is None:
                v = str(n)
            sans_list.append(str(v))
    except Exception:
        pass

    return cn, sans_list


def _pick_key_params_from_existing(cert: cx509.Certificate) -> dict[str, Any]:
    pk = cert.public_key()
    params: dict[str, Any] = {}

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        if hasattr(pk, "key_size") and pk.__class__.__name__.lower().startswith("rs"):
            params["key_type"] = "rsa"
            params["rsa_key_size"] = getattr(pk, "key_size", 2048) or 2048
            return params
        if hasattr(pk, "curve") and isinstance(getattr(pk, "curve", None), ec.EllipticCurve):
            params["key_type"] = "ec"
            curve = pk.curve
            curve_name = getattr(curve, "name", None)
            params["ec_curve"] = str(curve_name or "secp256r1")
            return params
        if isinstance(pk, ed25519.Ed25519PublicKey):
            params["key_type"] = "ed25519"
            return params
        if isinstance(pk, ed448.Ed448PublicKey):
            params["key_type"] = "ed448"
            return params
    except Exception:
        pass

    params["key_type"] = "rsa"
    params["rsa_key_size"] = 2048
    return params


def _atomic_write(path: str, data: bytes, mode=None) -> None:
    dirn = os.path.dirname(os.path.abspath(path)) or "."
    with tempfile.NamedTemporaryFile(dir=dirn, delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    try:
        os.replace(tmp_path, path)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    if mode is not None:
        try:
            os.chmod(path, mode)
        except Exception:
            pass


def _copy_if_different(src: str, dst: Optional[str], mode: Optional[int] = None) -> None:
    if not dst:
        return

    src_abs = os.path.abspath(src)
    dst_abs = os.path.abspath(dst)

    if src_abs == dst_abs:
        return

    dirn = os.path.dirname(dst_abs) or "."
    os.makedirs(dirn, exist_ok=True)
    shutil.copy2(src_abs, dst_abs)

    if mode is not None:
        try:
            os.chmod(dst_abs, mode)
        except Exception:
            pass


def _resolve_storage_paths_from_ca(ca: Dict[str, Any]) -> Tuple[str, str]:
    storage = ca.get("storage_paths", {}) or {}

    certs_dir = (
        storage.get("cert_dir")
        or storage.get("certs_dir")
        or ca.get("__path_cert")
    )
    private_dir = (
        storage.get("private_dir")
        or os.path.dirname(ca.get("__path_key") or "")
    )

    if not certs_dir:
        raise KeyError(f"Missing storage_paths.cert_dir/certs_dir for CA '{ca.get('id')}'")
    if not private_dir:
        raise KeyError(f"Missing storage_paths.private_dir for CA '{ca.get('id')}'")

    return certs_dir, private_dir


def _cmd_rotate_if_expiring(
    ca_id: str,
    crt_path: str,
    key_path: str,
    threshold_days: int,
    conf,
    chain_paths: Optional[list[str]] = None,
    fullchain_path: Optional[str] = None,
    write_fullchain_to_crt: bool = True,
    valid_days=365
) -> int:

    ca = _cli_find_ca_by_id(conf, ca_id)
    if not ca:
        print(f"ERROR: CA '{ca_id}' not found in adcs.yaml", file=sys.stderr)
        return 3

    if not os.path.isfile(crt_path):
        print(f"ERROR: crt file not found: {crt_path}", file=sys.stderr)
        return 4

    try:
        cert = load_certificate_file(crt_path)
    except Exception as e:
        print(f"ERROR: cannot parse certificate '{crt_path}': {e}", file=sys.stderr)
        return 5

    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    if days_left > threshold_days:
        print(f"OK: {days_left} days left (> {threshold_days}); no rotation needed.")
        return 0

    cn, sans = _extract_cn_and_sans(cert)
    request_id = uuid.uuid4().int
    total_valid_seconds = int((cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds())
    total_valid_seconds = int(valid_days * 24 * 3600)

    key_params = _pick_key_params_from_existing(cert)

    cert_obj, key_obj, cert_pem, key_pem = issue_cert_with_new_key(
        ca=ca,
        common_name=cn or "",
        subject_sans=sans,
        key_type=key_params.get("key_type", "rsa"),
        rsa_key_size=key_params.get("rsa_key_size", 2048),
        ec_curve=key_params.get("ec_curve", "secp256r1"),
        validity_seconds=total_valid_seconds,
        key_export_password=None,
    )

    cert_storage_dir = (
        ca.get('storage_paths', {}).get('cert_dir')
        or ca.get('storage_paths', {}).get('certs_dir')
        or ca.get('__path_cert')
        or os.path.dirname(crt_path)
    )
    private_storage_dir = (
        ca.get('storage_paths', {}).get('private_dir')
        or os.path.dirname(key_path)
    )

    _atomic_write(os.path.join(cert_storage_dir, f"{request_id}.pem"), cert_pem)
    _atomic_write(crt_path, cert_pem)

    if chain_paths:
        chain_bytes = _read_all_bytes(chain_paths)
        fullchain = cert_pem + chain_bytes
        target_path = fullchain_path or crt_path
        _atomic_write(target_path, fullchain)
    else:
        _atomic_write(crt_path, cert_pem)

    _atomic_write(os.path.join(private_storage_dir, f"{request_id}.key.pem"), key_pem, mode=stat.S_IRUSR | stat.S_IWUSR)
    _atomic_write(key_path, key_pem, mode=stat.S_IRUSR | stat.S_IWUSR)

    print(
        f"ROTATED: cert replaced at '{crt_path}', key replaced at '{key_path}' "
        f"(days left was {days_left} ≤ threshold {threshold_days})"
    )
    return 0


def _cli_find_ca_by_id(conf: Dict[str, Any], ca_id: str) -> Optional[Dict[str, Any]]:
    for ca in (conf.get("cas_list") or []):
        if str(ca.get("id")) == ca_id or str(ca.get("display_name")) == ca_id:
            return ca
    return None


def _guess_ca_common_name(crt_path: str, key_path: str, crl_path: str, parent_ca_id: Optional[str] = None) -> str:
    """Guess a reasonable CN for a new CA from the output file paths."""
    candidates = []
    for path in (crt_path, key_path, crl_path):
        if not path:
            continue
        name = os.path.basename(path)
        for suffix in ('.crt.pem', '.key.pem', '.crl.pem', '.pem', '.crt', '.key', '.crl', '.cer'):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
        if name:
            candidates.append(name)
    if candidates:
        first = candidates[0]
        if all(c == first for c in candidates):
            return first
        common = os.path.commonprefix(candidates).strip('._-')
        if common:
            return common
        return first
    return parent_ca_id or 'ca'


def create_ca(
    crt_path: str,
    key_path: str,
    crl_path: str,
    valid_days: int = 3650,
    parent_ca: Optional[Dict[str, Any]] = None,
    common_name: Optional[str] = None,
    rsa_key_size: int = 4096,
):
    """Create a new CA certificate/key and initialize an empty CRL.

    If parent_ca is None, the CA is self-signed. Otherwise the new CA is issued by parent_ca.
    Returns a small metadata dict describing what was created.
    """
    cn = (common_name or _guess_ca_common_name(
        crt_path, key_path, crl_path, parent_ca.get('id') if parent_ca else None
    )).strip()
    if not cn:
        raise ValueError('Could not determine Common Name for the new CA.')
    if int(valid_days) <= 0:
        raise ValueError('--valid-days must be a positive integer.')
    if int(rsa_key_size) not in (2048, 3072, 4096):
        raise ValueError('--rsa-bits must be one of: 2048, 3072, 4096.')

    key = rsa.generate_private_key(public_exponent=65537, key_size=int(rsa_key_size))
    subject = cx509.Name([
        cx509.NameAttribute(cx509.NameOID.COMMON_NAME, cn),
    ])

    now = datetime.now(timezone.utc)
    issuer_name = subject
    signer_key = key
    issuer_cert = None
    is_self_signed = parent_ca is None

    if parent_ca is not None:
        issuer_name = cx509.load_der_x509_certificate(parent_ca['__certificate_der']).subject
        issuer_cert = cx509.load_der_x509_certificate(parent_ca['__certificate_der'])
        signer_key = parent_ca['__key_obj']

    builder = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=int(valid_days)))
        .add_extension(cx509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(cx509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )

    if is_self_signed:
        builder = builder.add_extension(
            cx509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
    else:
        try:
            builder = builder.add_extension(
                cx509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False
            )
        except Exception:
            pass
        urls = (parent_ca.get('urls') or {}) if parent_ca else {}
        crl_http = urls.get('crl_http')
        ca_issuers_http = urls.get('ca_issuers_http')
        if crl_http:
            builder = builder.add_extension(
                cx509.CRLDistributionPoints([
                    cx509.DistributionPoint(
                        full_name=[cx509.UniformResourceIdentifier(str(crl_http))],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )
        if ca_issuers_http:
            builder = builder.add_extension(
                cx509.AuthorityInformationAccess([
                    cx509.AccessDescription(
                        cx509.AuthorityInformationAccessOID.CA_ISSUERS,
                        cx509.UniformResourceIdentifier(str(ca_issuers_http)),
                    )
                ]),
                critical=False,
            )

    cert = builder.sign(private_key=signer_key, algorithm=hashes.SHA256())

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    for path in (crt_path, key_path, crl_path):
        dirn = os.path.dirname(path) or '.'
        os.makedirs(dirn, exist_ok=True)

    _atomic_write(key_path, key_pem, mode=stat.S_IRUSR | stat.S_IWUSR)
    _atomic_write(crt_path, cert_pem)

    crl_builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
        .add_extension(cx509.CRLNumber(1), critical=False)
    )
    try:
        crl_builder = crl_builder.add_extension(
            cx509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
    except Exception:
        pass
    crl = crl_builder.sign(private_key=key, algorithm=hashes.SHA256())
    _write_crl_file(crl_path, crl.public_bytes(encoding=serialization.Encoding.PEM))
    _write_sidecar_num(_crlnum_sidecar_path(crl_path), 1)

    return {
        'common_name': cn,
        'self_signed': is_self_signed,
        'crt_path': crt_path,
        'key_path': key_path,
        'crl_path': crl_path,
        'issuer': cn if is_self_signed else str(parent_ca.get('id') or parent_ca.get('display_name')),
    }


def _cmd_create_ca(
    ca_id: Optional[str],
    crt_path: str,
    key_path: str,
    crl_path: str,
    valid_days: int = 3650,
    rsa_key_size: int = 4096,
    conf=None,
    cn=None
) -> int:
    parent_ca = None
    effective_crt_path = crt_path
    effective_key_path = key_path
    user_crt_path = crt_path
    user_key_path = key_path

    if ca_id:
        if conf is None:
            raise ValueError('Configuration is required when --ca-id is used.')
        parent_ca = _cli_find_ca_by_id(conf, ca_id)
        if not parent_ca:
            print(f"ERROR: parent CA '{ca_id}' not found in adcs.yaml", file=sys.stderr)
            return 3

        certs_dir, private_dir = _resolve_storage_paths_from_ca(parent_ca)
        os.makedirs(certs_dir, exist_ok=True)
        os.makedirs(private_dir, exist_ok=True)

        request_id = uuid.uuid4().int
        effective_crt_path = os.path.join(certs_dir, f"{request_id}.pem")
        effective_key_path = os.path.join(private_dir, f"{request_id}.key.pem")
        
    result = create_ca(
        crt_path=effective_crt_path,
        key_path=effective_key_path,
        crl_path=crl_path,
        valid_days=valid_days,
        parent_ca=parent_ca,
        rsa_key_size=rsa_key_size,
        common_name=cn
    )

    if ca_id:
        _copy_if_different(
            effective_crt_path,
            user_crt_path,
            mode=None,
        )
        _copy_if_different(
            effective_key_path,
            user_key_path,
            mode=stat.S_IRUSR | stat.S_IWUSR,
        )

    mode = 'self-signed' if result['self_signed'] else f"child of '{result['issuer']}'"
    print(
        f"CA created: CN='{result['common_name']}', mode={mode}, rsa={int(rsa_key_size)} bits, "
        f"cert='{effective_crt_path}', key='{effective_key_path}', crl='{result['crl_path']}'"
    )

    if ca_id:
        if os.path.abspath(user_crt_path) != os.path.abspath(effective_crt_path):
            print(f"CERT COPY: {user_crt_path}")
        if os.path.abspath(user_key_path) != os.path.abspath(effective_key_path):
            print(f"KEY COPY:  {user_key_path}")

    return 0


def _cmd_resign_crl(ca_id: str, next_update_hours: int = 8, bump_number: bool = True, conf=None) -> int:
    ca = _cli_find_ca_by_id(conf, ca_id)
    if not ca:
        print(f"ERROR: CA '{ca_id}' not found in adcs.yaml", file=sys.stderr)
        return 3

    ca_key = ca["__key_obj"]
    ca_cert_der = ca["__certificate_der"]
    crl_path = (ca.get("crl") or {}).get("path_crl")
    if not crl_path:
        raise KeyError("Missing crl.path_crl in CA config.")
    ca_cert = cx509.load_der_x509_certificate(ca_cert_der)

    new_num = resign_crl(
        ca_key=ca_key,
        ca_cert=ca_cert,
        crl_path=crl_path,
        bump_number=bump_number,
        next_update_hours=next_update_hours,
    )
    print(f"CRL re-signed for '{ca_id}' -> CRLNumber {new_num} (path: {crl_path})")
    return 0


def _read_all_bytes(paths: list[str]) -> bytes:
    out = b""
    for p in paths:
        if not p:
            continue
        if not os.path.isfile(p):
            raise FileNotFoundError(f"chain file not found: {p}")
        with open(p, "rb") as f:
            out += f.read()
            if not out.endswith(b"\n"):
                out += b"\n"
    return out
