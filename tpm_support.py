import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import tpm_restricted_hmac as rh
import tpm_attestation as tpm_mod

logger = logging.getLogger("adcs.tpm_support")



def _normalize_request_id(request_id: str | int) -> str:
    """Return a safe, canonical decimal request id for filesystem use."""
    s = str(request_id)
    if not s.isdigit():
        raise ValueError("Invalid request_id")
    return str(int(s))


def _stable_primitive(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "len": len(value)}
    if isinstance(value, dict):
        return {str(k): _stable_primitive(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_stable_primitive(v) for v in value]
    return str(value)


def _fingerprint_dict(value: dict | None, keys: tuple[str, ...]) -> str:
    selected = {}
    value = value or {}
    for key in keys:
        if key in value:
            selected[key] = _stable_primitive(value[key])
    encoded = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_TEMPLATE_CONTEXT_KEYS = (
    "common_name",
    "name",
    "display_name",
    "oid",
    "template_oid",
    "schema_version",
    "major_version",
    "minor_version",
    "flags",
)
_CA_CONTEXT_KEYS = (
    "name",
    "id",
    "ca_id",
    "common_name",
    "subject",
    "thumbprint",
    "certificate_thumbprint",
    "cert_pem",
    "signing_cert_pem",
    "ket_cert_pem",
)


def _template_fingerprint(template: dict) -> str:
    return _fingerprint_dict(template, _TEMPLATE_CONTEXT_KEYS)


def _ca_fingerprint(ca: Optional[dict]) -> str:
    return _fingerprint_dict(ca, _CA_CONTEXT_KEYS)


def _save_pending_challenge(request_id: str | int, payload: dict, pending_dir) -> None:
    """Persist a pending challenge atomically without replacing an existing ID."""
    safe_request_id = _normalize_request_id(request_id)
    pending_dir = Path(pending_dir)
    pending_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending_dir.chmod(0o700)
    path = pending_dir / f"{safe_request_id}.json"
    temp_path = pending_dir / (
        f".{safe_request_id}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    )
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError as exc:
            raise ValueError(
                "A pending TPM challenge already exists for this request_id"
            ) from exc
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        try:
            dir_fd = os.open(pending_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Directory fsync is not available on every supported filesystem.
            pass
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _load_pending_challenge(request_id: str | int,pending_dir) -> Optional[dict]:
    safe_request_id = _normalize_request_id(request_id)
    path = Path(pending_dir) / f"{safe_request_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _delete_pending_challenge(request_id: str | int,pending_dir) -> None:
    safe_request_id = _normalize_request_id(request_id)
    path = Path(pending_dir) / f"{safe_request_id}.json"
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _claim_pending_challenge(request_id: str | int, pending_dir) -> tuple[dict, Path]:
    """Atomically consume a pending challenge using a same-filesystem hard link."""
    safe_request_id = _normalize_request_id(request_id)
    pending_dir = Path(pending_dir)
    source = pending_dir / f"{safe_request_id}.json"
    claimed = pending_dir / f".{safe_request_id}.{os.getpid()}.{os.urandom(8).hex()}.claimed"
    try:
        os.link(source, claimed)
    except FileNotFoundError as exc:
        raise ValueError("No pending TPM challenge exists for this request_id") from exc
    except FileExistsError as exc:
        raise ValueError("TPM challenge is already being processed") from exc
    try:
        source.unlink()
        return json.loads(claimed.read_text(encoding="utf-8")), claimed
    except Exception:
        try:
            claimed.unlink()
        except FileNotFoundError:
            pass
        raise


def _delete_claimed_pending(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _template_tpm_policy(template: dict) -> Optional[dict]:
    flags = (template.get("flags") or {}).get("private_key_flags")
    if flags is None:
        flags_value = 0
    elif isinstance(flags, int):
        flags_value = flags
    elif isinstance(flags, dict):
        flags_value = 0
        if flags.get("attest_preferred"):
            flags_value |= 0x00001000
        if flags.get("attest_required"):
            flags_value |= 0x00002000
        if flags.get("attestation_without_policy"):
            flags_value |= 0x00004000
        if flags.get("ek_trust_on_use"):
            flags_value |= 0x00000200
        if flags.get("ek_validate_cert"):
            flags_value |= 0x00000400
        if flags.get("ek_validate_key"):
            flags_value |= 0x00000800
        if flags.get("require_v2_attestation"):
            flags_value |= 0x00008000
    else:
        raise TypeError(
            f"template flags.private_key_flags must be int or dict, got {type(flags).__name__}"
        )

    attest_required = bool(flags_value & 0x00002000)
    attest_preferred = bool(flags_value & 0x00001000)
    require_v2 = bool(flags_value & 0x00008000)
    if require_v2 and not attest_required:
        raise ValueError(
            "CT_FLAG_REQUIRE_V2_ATTESTATION (0x8000) requires "
            "CT_FLAG_ATTEST_REQUIRED (0x2000)"
        )
    if not attest_required and not attest_preferred:
        return None
    return {
        "required": attest_required,
        "preferred": attest_preferred,
        "attestation_without_policy": bool(flags_value & 0x00004000),
        "ek_trust_on_use": bool(flags_value & 0x00000200),
        "ek_validate_cert": bool(flags_value & 0x00000400),
        "ek_validate_key": bool(flags_value & 0x00000800),
        "require_v2_attestation": require_v2,
    }



def _resolve_ca_materials_for_tpm(template: dict, ca: Optional[dict] = None) -> dict:
    def _pick(*values):
        for value in values:
            if value:
                return value
        return None

    def _read_text(path: str | None) -> str | None:
        return Path(path).read_text(encoding="utf-8") if path else None

    def _split_cert_chain(pem_text: str | None) -> list[str]:
        if not pem_text:
            return []
        blocks, current, in_cert = [], [], False
        for line in pem_text.splitlines(keepends=True):
            if "BEGIN CERTIFICATE" in line:
                current = [line]
                in_cert = True
                continue
            if in_cert:
                current.append(line)
                if "END CERTIFICATE" in line:
                    blocks.append("".join(current))
                    current = []
                    in_cert = False
        return blocks

    ca = ca or {}
    ket_cert_path = _pick(template.get("ket_cert_pem"), ca.get("ket_cert_pem"))
    ket_key_path = _pick(template.get("ket_key_pem"), ca.get("ket_key_pem"))
    ket_chain_path = _pick(template.get("ket_chain_pem"), ca.get("ket_chain_pem"))

    ket_cert_pem = _pick(template.get("__ket_certificate_pem"), ca.get("__ket_certificate_pem")) or _read_text(ket_cert_path)
    ket_key_pem = _pick(template.get("__ket_key_pem"), ca.get("__ket_key_pem")) or _read_text(ket_key_path)
    if not ket_cert_pem:
        raise ValueError("Missing ket_cert_pem in template/CA config")
    if not ket_key_pem:
        raise ValueError("Missing ket_key_pem in template/CA config")

    ket_chain_pem = _read_text(ket_chain_path) if ket_chain_path else None

    return {
        "ket_cert_pem": ket_cert_pem,
        "ket_key_pem": ket_key_pem,
        "ca_exchange_chain_der": [tpm_mod.pem_cert_to_der(ket_cert_pem)] + [
            tpm_mod.pem_cert_to_der(block) for block in _split_cert_chain(ket_chain_pem)
        ],
    }


def _spki_sha256(csr: x509.CertificateSigningRequest) -> str:
    spki = csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()



def _current_microsoft_binding_from_csr(csr: x509.CertificateSigningRequest) -> Optional[dict]:
    """Re-parse and validate Microsoft key attestation from the current CSR."""
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    bundle = tpm_mod.extract_tpm_bundle_from_pkcs10_der(csr_der)
    if bundle is None:
        return None
    attestation_blob_raw = (
        getattr(bundle, "ms_attestation_statement_raw", None)
        or getattr(bundle, "ms_attestation_blob_raw", None)
    )
    if not attestation_blob_raw:
        return None
    return tpm_mod.validate_microsoft_key_attestation_binding(
        attestation_blob_raw,
        csr.public_key(),
    )

def _ek_cert_from_der(ek_cert_der: Optional[bytes]):
    if not ek_cert_der:
        return None
    return x509.load_der_x509_certificate(ek_cert_der)


def _public_key_to_spki_der(public_key) -> Optional[bytes]:
    if public_key is None:
        return None
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_key_from_spki_der(spki_der: Optional[bytes]):
    if not spki_der:
        return None
    return serialization.load_der_public_key(spki_der)


def _public_key_to_legacy_ek_hash_der(public_key) -> Optional[bytes]:
    """Return the EK public-key DER used by the legacy public hash.

    Historical callers compared ek_public_key_identity_sha256 against the SHA-256
    of RSA PKCS#1 RSAPublicKey DER, despite the field name saying SPKI. Keep
    that wire value for compatibility. For non-RSA keys, PKCS#1 is not valid,
    so fall back to SubjectPublicKeyInfo DER.
    """
    if public_key is None:
        return None
    try:
        return public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1,
        )
    except (TypeError, ValueError):
        return public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def _spki_der_from_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_keys_equal(left, right) -> bool:
    return hmac.compare_digest(_spki_der_from_public_key(left), _spki_der_from_public_key(right))



def verify_microsoft_aik_info_subject_only(
    *,
    csr: x509.CertificateSigningRequest,
    bundle,
    template: dict,
    ca: Optional[dict],
) -> dict:
    """Verify the Microsoft AIK_INFO subject-only attestation path.

    This legacy method does not use MakeCredential/ActivateCredential.  The
    AIK certificate carried in AIK_INFO supplies the public key used to verify
    the KAST signature, which in turn certifies the public key contained in the
    CSR.  Certificate-chain trust, EKU policy, revocation and all other local
    acceptance decisions are intentionally deferred to the template callback
    ``validate_tpm()`` through the returned ``tpm_result``.
    """
    if ca is None:
        raise ValueError("ca is required to validate an AIK_INFO request")

    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])
    decrypted = tpm_mod.decrypt_microsoft_hardware_key_info(
        bundle.ms_aik_info_raw,
        ket_cert_der,
        ket_priv,
    )
    decrypted_raw = decrypted.get("decrypted_raw")
    if not decrypted_raw:
        raise ValueError("Microsoft AIK_INFO was present but could not be decrypted")

    embedded_der = decrypted.get("embedded_certificates_der") or []
    leaf_der = decrypted.get("leaf_cert_der")
    if not leaf_der:
        leaf_der = tpm_mod.try_extract_first_cert_from_blob(decrypted_raw)
    if not leaf_der:
        raise ValueError("AIK_INFO does not contain an AIK certificate")
    aik_cert = x509.load_der_x509_certificate(leaf_der)

    advertised_aik_key = tpm_mod.extract_public_key_from_decrypted_hardware_key_info(
        decrypted_raw,
        embedded_certificates_der=embedded_der,
        leaf_cert_der=leaf_der,
    )
    if not _public_keys_equal(advertised_aik_key, aik_cert.public_key()):
        raise ValueError("AIK public key does not match the AIK certificate in AIK_INFO")

    aik_certificates = _normalize_certificate_list(embedded_der, leaf=aik_cert)

    attestation_blob_raw = (
        getattr(bundle, "ms_attestation_statement_raw", None)
        or getattr(bundle, "ms_attestation_blob_raw", None)
    )
    if not attestation_blob_raw:
        raise ValueError("Microsoft AIK_INFO request is missing the key-attestation statement")

    certified_binding = tpm_mod.validate_microsoft_key_attestation_binding(
        attestation_blob_raw,
        csr.public_key(),
        aik_public_key=aik_cert.public_key(),
    )
    return {
        "status": "ok",
        "used": True,
        "attestation_valid": True,
        "challenge_verified": False,
        "microsoft_native_attestation": True,
        "attestation_protocol": "legacy_aik_info_subject_only",
        "aik_cert": aik_cert,
        "aik_certificates": aik_certificates,
        "aik_cert_sha256": aik_cert.fingerprint(hashes.SHA256()).hex(),
        "aik_public_key": aik_cert.public_key(),
        "aik_spki_der": _public_key_to_spki_der(aik_cert.public_key()),
        "firmware_version": certified_binding.get("firmware_version"),
        "certified_key_obj": certified_binding.get("certified_key_obj"),
        "certified_key_attributes": certified_binding.get("certified_key_attributes"),
        "certified_key_name_alg": certified_binding.get("certified_key_name_alg"),
        "certified_key_alg": certified_binding.get("certified_key_alg"),
        "subject_only_attestation": True,
        "ek_cert": None,
        "ek_pub": None,
    }

def _select_ek_public_key_for_challenge(
    *,
    bundle,
    extracted_ek_pub,
    policy: dict,
    template: dict,
    ca: Optional[dict],
):
    """Select the EK key while keeping local trust policy out of the core.

    The core enforces only protocol invariants: an advertised EK public key
    must match the EK certificate, and a template that advertises
    ``ek_validate_cert`` must receive an EK certificate.  Chain trust,
    manufacturer allowlists, revocation and firmware decisions are made by the
    mandatory template callback ``validate_tpm()``.
    """
    del template, ca  # Policy is evaluated by the template callback.
    ek_cert = _ek_cert_from_der(bundle.ek_cert_der) if getattr(bundle, "ek_cert_der", None) else None
    if ek_cert is not None:
        ek_pub_from_cert = ek_cert.public_key()
        if extracted_ek_pub is not None and not _public_keys_equal(extracted_ek_pub, ek_pub_from_cert):
            raise ValueError("EK public key does not match EK certificate")
        return ek_cert, ek_pub_from_cert

    if policy.get("ek_validate_cert"):
        raise ValueError(
            "Template requires EK certificate validation, but no EK certificate was provided"
        )
    if extracted_ek_pub is None:
        raise ValueError("Could not locate an EK public key for TPM challenge generation")
    return None, extracted_ek_pub

def _cert_sha256(cert: Optional[x509.Certificate]) -> Optional[str]:
    if cert is None:
        return None
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _ek_pub_sha256(public_key) -> Optional[str]:
    der = _public_key_to_legacy_ek_hash_der(public_key)
    if der is None:
        return None
    return hashlib.sha256(der).hexdigest()


def _restore_ek_materials(payload: Optional[dict]) -> tuple[object | None, object | None]:
    payload = payload or {}
    ek_cert_der_b64 = payload.get("ek_cert_der_b64")
    ek_pub_der_b64 = payload.get("ek_pub_der_b64")
    ek_cert = None
    ek_pub = None
    if ek_cert_der_b64:
        try:
            ek_cert = _ek_cert_from_der(base64.b64decode(ek_cert_der_b64, validate=True))
        except Exception as exc:
            raise ValueError("Stored TPM state contains an invalid EK certificate") from exc
    if ek_pub_der_b64:
        try:
            ek_pub = _public_key_from_spki_der(base64.b64decode(ek_pub_der_b64, validate=True))
        except Exception as exc:
            raise ValueError("Stored TPM state contains an invalid EK public key") from exc
    elif ek_cert is not None:
        try:
            ek_pub = ek_cert.public_key()
        except Exception as exc:
            raise ValueError(
                "Stored TPM state EK certificate has an unusable public key"
            ) from exc
    return ek_cert, ek_pub



def _coerce_cryptography_public_key(value):
    if value is None:
        return None
    converter = getattr(value, "to_cryptography_public_key", None)
    if callable(converter):
        value = converter()
    if not callable(getattr(value, "public_bytes", None)):
        return None
    return value


def _load_x509_certificates(data: bytes) -> list[x509.Certificate]:
    """Parse one DER certificate or one/more PEM certificates.

    This is intentionally a parsing helper only. Certificate-chain trust and
    revocation policy belong to the template callback ``validate_tpm()``.
    """
    blob = bytes(data)
    if b"-----BEGIN CERTIFICATE-----" not in blob:
        return [x509.load_der_x509_certificate(blob)]

    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    certificates: list[x509.Certificate] = []
    cursor = 0
    while True:
        start = blob.find(begin, cursor)
        if start < 0:
            break
        stop = blob.find(end, start)
        if stop < 0:
            raise ValueError("Truncated PEM certificate block")
        stop += len(end)
        certificates.append(x509.load_pem_x509_certificate(blob[start:stop] + b"\n"))
        cursor = stop
    if not certificates:
        raise ValueError("No PEM certificate found")
    return certificates


def _normalize_certificate_list(items, *, leaf=None) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    seen: set[bytes] = set()

    def add(cert):
        if cert is None:
            return
        if isinstance(cert, (bytes, bytearray, memoryview)):
            try:
                loaded = _load_x509_certificates(bytes(cert))
            except Exception:
                return
            for item in loaded:
                add(item)
            return
        if not isinstance(cert, x509.Certificate):
            return
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        certs.append(cert)

    add(leaf)
    for item in items or []:
        add(item)
    return certs


def _pending_certificate_list(certs) -> list[str]:
    return [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in _normalize_certificate_list(certs)
    ]


def _restore_pending_certificates(payload: Optional[dict]) -> list[x509.Certificate]:
    restored = []
    for encoded in (payload or {}).get("ek_certificates_der_b64") or []:
        try:
            restored.append(
                x509.load_der_x509_certificate(base64.b64decode(encoded, validate=True))
            )
        except Exception as exc:
            raise ValueError(
                "Stored TPM state contains an invalid EK certificate-chain item"
            ) from exc
    leaf, _ = _restore_ek_materials(payload)
    return _normalize_certificate_list(restored, leaf=leaf)


def _finalize_tpm_result(result: dict, policy: Optional[dict]) -> dict:
    """Return the stable callback-facing TPM result shared by V1 and V2."""
    out = dict(result or {})
    out.setdefault("status", "ok")
    out["used"] = bool(out.get("used"))
    out["attestation_valid"] = bool(out.get("attestation_valid"))
    out.setdefault("challenge_verified", False)
    out.setdefault("attestation_protocol", None)
    out["tpm_result_schema_version"] = 1
    out["template_tpm_policy"] = dict(policy or {})

    ek_cert = out.get("ek_cert")
    ek_pub = _coerce_cryptography_public_key(out.get("ek_pub"))
    if ek_pub is None and isinstance(ek_cert, x509.Certificate):
        ek_pub = ek_cert.public_key()
    ek_certificates = _normalize_certificate_list(
        out.get("ek_certificates") or out.get("ek_certificates_der"),
        leaf=ek_cert,
    )
    out["ek_cert"] = ek_cert
    out["ek_certificates"] = ek_certificates
    out["ek_certificates_der"] = [
        cert.public_bytes(serialization.Encoding.DER) for cert in ek_certificates
    ]
    out["ek_pub"] = ek_pub
    ek_spki_der = _public_key_to_spki_der(ek_pub)
    out["ek_spki_der"] = ek_spki_der
    out["ek_spki_sha256"] = (
        hashlib.sha256(ek_spki_der).hexdigest() if ek_spki_der else None
    )
    out.setdefault("ek_cert_sha256", _cert_sha256(ek_cert))
    out.setdefault("ek_public_key_identity_sha256", _ek_pub_sha256(ek_pub) or "")

    aik_public_key = _coerce_cryptography_public_key(
        out.get("aik_public_key") or out.get("v2_aik_public_key")
    )
    aik_cert = out.get("aik_cert")
    if aik_public_key is None and isinstance(aik_cert, x509.Certificate):
        aik_public_key = aik_cert.public_key()
    aik_certificates = _normalize_certificate_list(
        out.get("aik_certificates"),
        leaf=aik_cert,
    )
    out["aik_cert"] = aik_cert
    out["aik_certificates"] = aik_certificates
    out["aik_certificates_der"] = [
        cert.public_bytes(serialization.Encoding.DER)
        for cert in aik_certificates
    ]
    aik_spki_der = out.get("aik_spki_der")
    if aik_spki_der is None and aik_public_key is not None:
        aik_spki_der = _public_key_to_spki_der(aik_public_key)
    if aik_spki_der is not None:
        aik_spki_der = bytes(aik_spki_der)
    out["aik_public_key"] = aik_public_key
    out["aik_spki_der"] = aik_spki_der
    out["aik_spki_sha256"] = (
        hashlib.sha256(aik_spki_der).hexdigest() if aik_spki_der else None
    )

    firmware_version = out.get("firmware_version")
    if firmware_version is not None:
        firmware_version = int(firmware_version)
        if not 0 <= firmware_version <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Attested TPM firmware version is outside UINT64")
        out["firmware_version"] = firmware_version
        out["firmware_version_hex"] = f"0x{firmware_version:016x}"
    else:
        out["firmware_version_hex"] = None

    return out



def _v2_ek_cng_parameters(ek_public) -> tuple[str, str]:
    """Return the CNG algorithm identifier and decimal key size for the EK."""
    if isinstance(ek_public, rsa.RSAPublicKey):
        return "RSA", str(ek_public.key_size)
    if isinstance(ek_public, ec.EllipticCurvePublicKey):
        curve_name = ek_public.curve.name.lower()
        mapping = {
            "secp256r1": "ECDH_P256",
            "prime256v1": "ECDH_P256",
            "secp384r1": "ECDH_P384",
            "secp521r1": "ECDH_P521",
        }
        algorithm = mapping.get(curve_name)
        if algorithm is None:
            raise ValueError(f"Unsupported V2 EK curve: {ek_public.curve.name}")
        return algorithm, str(ek_public.key_size)
    raise ValueError(f"Unsupported V2 EK public key type: {type(ek_public).__name__}")


def _validate_v2_request_metadata(*, bundle) -> tuple[str, str]:
    """Validate the provider and persistent V2 AIK container metadata."""
    provider = str(getattr(bundle, "ms_ksp_name", "") or "").strip()
    if not provider:
        raise ValueError("V2 key attestation request is missing KSP_NAME")
    if provider.casefold() != "Microsoft Platform Crypto Provider".casefold():
        raise ValueError(
            "V2 key attestation requires Microsoft Platform Crypto Provider"
        )

    container_name = str(
        getattr(bundle, "ms_v2_container_name", "") or ""
    ).strip()
    if not container_name:
        raise ValueError("V2 key attestation request is missing V2_CONTAINER_NAME")
    # MS-WCCE 55.0 requires a randomly generated GUID prefixed with the exact
    # string "V2AIK-".  Echoing a non-conforming container in the challenge can
    # cause the client to target an unrelated persistent KSP key, so validate
    # the request before any server state or wrapped HMAC material is created.
    prefix = "V2AIK-"
    if not container_name.startswith(prefix):
        raise ValueError(
            'V2_CONTAINER_NAME must start with the documented "V2AIK-" prefix'
        )
    guid_text = container_name[len(prefix):]
    try:
        parsed_guid = uuid.UUID(guid_text)
    except (AttributeError, ValueError) as exc:
        raise ValueError(
            "V2_CONTAINER_NAME must contain a canonical GUID after V2AIK-"
        ) from exc
    if len(guid_text) != 36 or str(parsed_guid).casefold() != guid_text.casefold():
        raise ValueError(
            "V2_CONTAINER_NAME must contain a canonical GUID after V2AIK-"
        )
    return provider, container_name


def _protect_cmc_v2_server_state(payload: dict, *, ket_cert_der: bytes) -> bytes:
    clear = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return rh.encrypt_cms_enveloped_data(clear, ket_cert_der)


def _unprotect_cmc_v2_server_state(
    raw: bytes,
    *,
    ket_cert_der: bytes,
    ket_private_key,
) -> dict:
    try:
        clear = tpm_mod._decrypt_cms_enveloped_data(raw, ket_cert_der, ket_private_key)
        payload = json.loads(clear.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Unable to decrypt the stored V2 attestation server state") from exc
    if not isinstance(payload, dict):
        raise ValueError("Stored V2 attestation server state is not a mapping")
    return payload


def _username_sha256(username: Optional[str]) -> Optional[str]:
    if username is None:
        return None
    return hashlib.sha256(str(username).encode("utf-8")).hexdigest()


def _ca_id_value(ca: Optional[dict], ca_id: Optional[str]) -> str:
    value = ca_id or (ca or {}).get("id") or (ca or {}).get("ca_id") or ""
    return str(value)


def _validate_pending_context(
    *,
    pending: dict,
    csr: x509.CertificateSigningRequest,
    template: dict,
    ca: Optional[dict],
    request_id: int | str,
    max_age_seconds: int,
    username: Optional[str],
    ca_id: Optional[str],
) -> None:
    safe_request_id = _normalize_request_id(request_id)
    if str(pending.get("request_id")) != safe_request_id:
        raise ValueError("pending_challenge request_id does not match the current request")
    try:
        created_at = int(pending["created_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("pending_challenge contains an invalid created_at") from exc
    age = int(time.time()) - created_at
    if age < 0 or age > int(max_age_seconds):
        raise ValueError(f"TPM challenge has expired (age={age}s, max={max_age_seconds}s)")
    if pending.get("template_fingerprint") != _template_fingerprint(template):
        raise ValueError("Current template does not match the pending TPM challenge context")
    if pending.get("ca_fingerprint") != _ca_fingerprint(ca):
        raise ValueError("Current CA does not match the pending TPM challenge context")
    current_csr_sha256 = hashlib.sha256(
        csr.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    if pending.get("csr_sha256") != current_csr_sha256:
        raise ValueError("Current CSR does not match the pending TPM challenge context")
    if pending.get("spki_sha256") != _spki_sha256(csr):
        raise ValueError("CSR public key does not match the pending challenge context")
    expected_user = pending.get("username_sha256")
    if expected_user is not None and expected_user != _username_sha256(username):
        raise ValueError("Authenticated principal does not match the pending TPM challenge")
    expected_ca_id = pending.get("ca_id")
    if expected_ca_id is not None and str(expected_ca_id) != _ca_id_value(ca, ca_id):
        raise ValueError("CA identifier does not match the pending TPM challenge")


def create_microsoft_v2_restricted_hmac_challenge_response(
    *,
    csr: x509.CertificateSigningRequest,
    bundle,
    template: dict,
    request_id: int,
    ca: dict,
    pending_dir,
    max_age_seconds: int,
    username: Optional[str] = None,
    ca_id: Optional[str] = None,
) -> dict:
    """Create the native MS-WCCE 55.0 CMC V2 Restricted-HMAC challenge."""
    if int(max_age_seconds) <= 0:
        raise ValueError("TPM pending challenge lifetime must be positive")

    provider_name, container_name = _validate_v2_request_metadata(bundle=bundle)

    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    decrypted_ek = tpm_mod.decrypt_microsoft_ek_info(
        bundle.ms_ek_info_raw, ket_cert_der, ket_priv
    )
    bundle.ms_ek_info_decrypted_raw = decrypted_ek.get("decrypted_raw")
    bundle.ms_embedded_certificates_der = (
        decrypted_ek.get("embedded_certificates_der") or []
    )
    if decrypted_ek.get("ek_cert_der") and not getattr(bundle, "ek_cert_der", None):
        bundle.ek_cert_der = decrypted_ek["ek_cert_der"]
    if not bundle.ms_ek_info_decrypted_raw:
        raise ValueError("Microsoft EK_INFO was present but could not be decrypted")
    extracted_ek_pub = tpm_mod.extract_ek_pub_from_decrypted_ek_info(
        bundle.ms_ek_info_decrypted_raw,
        embedded_certificates_der=bundle.ms_embedded_certificates_der,
        ek_cert_der=getattr(bundle, "ek_cert_der", None),
    )
    policy = dict(_template_tpm_policy(template) or {})
    ek_cert, ek_pub = _select_ek_public_key_for_challenge(
        bundle=bundle,
        extracted_ek_pub=extracted_ek_pub,
        policy=policy,
        template=template,
        ca=ca,
    )
    ek_certificates = _normalize_certificate_list(
        getattr(bundle, "ms_embedded_certificates_der", None),
        leaf=ek_cert,
    )

    v2_aik = tpm_mod.decrypt_microsoft_v2_aik_info(
        bundle.ms_v2_aik_info_raw,
        ket_cert_der,
        ket_priv,
    )
    v2_aik_spki_der = bytes(v2_aik["aik_spki_der"])
    v2_aik_public_key = v2_aik["aik_public_key"]
    initial_claim = bytes(bundle.ms_v2_attestation_statement_raw or b"")
    if not initial_claim:
        raise ValueError("V2 key attestation request is missing V2_ATTESTATION_STATEMENT")
    certified_binding = tpm_mod.validate_microsoft_key_attestation_binding(
        initial_claim,
        csr.public_key(),
        aik_public_key=v2_aik_public_key,
    )

    secrets = rh.generate_restricted_hmac_secrets()
    duplicate = rh.create_restricted_hmac_duplicate(ek_pub, secrets.hmac_key)
    wrapped_hmac_key = rh.encode_windows_wrapped_key(
        encrypted_secret_tpm2b=duplicate["encrypted_secret_tpm2b"],
        private_tpm2b=duplicate["private_tpm2b"],
        public_tpm2b=duplicate["public_tpm2b"],
    )
    ek_algorithm, ek_parameter = _v2_ek_cng_parameters(ek_pub)
    encryption_algorithm_oid = tpm_mod.extract_encryption_algorithm_for_challenge_response(
        bundle.ms_ek_info_raw
    )
    xchg_cert_der = (materials["ca_exchange_chain_der"] or [None])[0]
    aik_info_hash = hashlib.sha1(xchg_cert_der).digest() if xchg_cert_der else None
    signer_cert_pem = ca.get("__certificate_pem")
    if signer_cert_pem is None:
        raise ValueError("Missing CA certificate PEM for TPM challenge signing")

    challenge = tpm_mod.build_and_sign_microsoft_v2_attestation_challenge(
        request_id=int(request_id),
        ca_exchange_chain_der=materials["ca_exchange_chain_der"],
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        signer_cert_pem=signer_cert_pem,
        signer_key_obj=ca.get("__key_obj"),
        signer_chain_pems=[],
        wrapped_hmac_key=wrapped_hmac_key,
        nonce=secrets.nonce,
        container_name=container_name,
        ek_algorithm=ek_algorithm,
        ek_parameter=ek_parameter,
        ksp_name=provider_name,
    )

    safe_request_id = _normalize_request_id(request_id)
    now = int(time.time())
    max_age = int(max_age_seconds)
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    ek_cert_der = (
        ek_cert.public_bytes(serialization.Encoding.DER) if ek_cert is not None else None
    )
    ek_pub_der = _public_key_to_spki_der(ek_pub)
    state_payload = {
        "state_version": 3,
        "protocol": "v2_restricted_hmac_cmc",
        "request_id": safe_request_id,
        "created_at": now,
        "expires_at": now + max_age,
        "username_sha256": _username_sha256(username),
        "ca_id": _ca_id_value(ca, ca_id),
        "template_fingerprint": _template_fingerprint(template),
        "ca_fingerprint": _ca_fingerprint(ca),
        "csr_sha256": hashlib.sha256(csr_der).hexdigest(),
        "spki_sha256": _spki_sha256(csr),
        "hmac_key_b64": base64.b64encode(secrets.hmac_key).decode("ascii"),
        "nonce_b64": base64.b64encode(secrets.nonce).decode("ascii"),
        "v2_aik_spki_b64": base64.b64encode(v2_aik_spki_der).decode("ascii"),
        "v2_aik_spki_sha256": hashlib.sha256(v2_aik_spki_der).hexdigest(),
        "v2_container_name": container_name,
        "ek_algorithm": ek_algorithm,
        "ek_parameter": ek_parameter,
        "ek_cert_der_b64": base64.b64encode(ek_cert_der).decode("ascii") if ek_cert_der else None,
        "ek_certificates_der_b64": _pending_certificate_list(ek_certificates),
        "ek_cert_sha256": hashlib.sha256(ek_cert_der).hexdigest() if ek_cert_der else None,
        "ek_pub_der_b64": base64.b64encode(ek_pub_der).decode("ascii") if ek_pub_der else None,
        "ek_pub_spki_sha256": hashlib.sha256(ek_pub_der).hexdigest() if ek_pub_der else None,
    }
    protected_state = _protect_cmc_v2_server_state(
        state_payload, ket_cert_der=ket_cert_der
    )
    pending_payload = {
        "state_version": 3,
        "protocol": "v2_restricted_hmac_cmc",
        "request_id": safe_request_id,
        "created_at": now,
        "expires_at": now + max_age,
        "username_sha256": _username_sha256(username),
        "ca_id": _ca_id_value(ca, ca_id),
        "template_name": template.get("common_name"),
        "template_fingerprint": _template_fingerprint(template),
        "ca_fingerprint": _ca_fingerprint(ca),
        "csr_sha256": hashlib.sha256(csr_der).hexdigest(),
        "spki_sha256": _spki_sha256(csr),
        "attestation_challenge_b64": base64.b64encode(protected_state).decode("ascii"),
        "attestation_challenge_sha256": hashlib.sha256(protected_state).hexdigest(),
        "ek_cert_sha256": hashlib.sha256(ek_cert_der).hexdigest() if ek_cert_der else None,
        "ek_pub_spki_sha256": hashlib.sha256(ek_pub_der).hexdigest() if ek_pub_der else None,
        "v2_aik_spki_sha256": hashlib.sha256(v2_aik_spki_der).hexdigest(),
        "v2_container_name": container_name,
    }
    _save_pending_challenge(safe_request_id, pending_payload, pending_dir)
    return {
        "status": "pending",
        "used": True,
        "request_id": int(request_id),
        "challenge_pkcs7_der": challenge["signed_pkcs7_der"],
        "challenge_attributes_der": challenge["challenge_attributes_der"],
        "attestation_valid": False,
        "microsoft_native_attestation": True,
        "attestation_protocol": "v2_restricted_hmac_cmc",
        "cr_flg_challengepending": True,
        "cr_flg_v2challenge": True,
        "ek_info_decrypted": True,
        "ek_cert": ek_cert,
        "ek_certificates": ek_certificates,
        "ek_pub": ek_pub,
        "v2_aik_public_key": v2_aik_public_key,
        "aik_public_key": v2_aik_public_key,
        "aik_spki_der": v2_aik_spki_der,
        "v2_aik_spki_sha256": hashlib.sha256(v2_aik_spki_der).hexdigest(),
        "firmware_version": certified_binding.get("firmware_version"),
        "certified_key_obj": certified_binding.get("certified_key_obj"),
        "certified_key_attributes": certified_binding.get("certified_key_attributes"),
        "certified_key_name_alg": certified_binding.get("certified_key_name_alg"),
        "certified_key_alg": certified_binding.get("certified_key_alg"),
    }


def _verify_pending_v2_challenge_response(
    *,
    csr: x509.CertificateSigningRequest,
    template: dict,
    ca: dict,
    pending_challenge: dict,
    challenge_response_der: bytes,
    request_id: int,
    pending_dir: str | Path,
    max_age_seconds: int,
    username: Optional[str],
    ca_id: Optional[str],
) -> dict:
    _validate_pending_context(
        pending=pending_challenge,
        csr=csr,
        template=template,
        ca=ca,
        request_id=request_id,
        max_age_seconds=max_age_seconds,
        username=username,
        ca_id=ca_id,
    )
    claimed_path: Path | None = None
    try:
        claimed, claimed_path = _claim_pending_challenge(request_id, pending_dir)
        if claimed != pending_challenge:
            raise ValueError("Pending TPM challenge changed while it was being claimed")
        materials = _resolve_ca_materials_for_tpm(template, ca)
        ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
        ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])
        try:
            protected_state = base64.b64decode(
                claimed["attestation_challenge_b64"], validate=True
            )
        except Exception as exc:
            raise ValueError("Pending V2 challenge has an invalid protected state") from exc
        expected_state_hash = claimed.get("attestation_challenge_sha256")
        if expected_state_hash and not hmac.compare_digest(
            hashlib.sha256(protected_state).hexdigest(), expected_state_hash
        ):
            raise ValueError("Pending V2 protected state integrity metadata is invalid")
        state = _unprotect_cmc_v2_server_state(
            protected_state,
            ket_cert_der=ket_cert_der,
            ket_private_key=ket_priv,
        )
        if state.get("protocol") != "v2_restricted_hmac_cmc" or int(
            state.get("state_version", -1)
        ) != 3:
            raise ValueError("Stored V2 attestation server state has an invalid version")
        for key in (
            "request_id",
            "username_sha256",
            "ca_id",
            "template_fingerprint",
            "ca_fingerprint",
            "csr_sha256",
            "spki_sha256",
            "v2_aik_spki_sha256",
            "v2_container_name",
            "ek_cert_sha256",
            "ek_pub_spki_sha256",
        ):
            if state.get(key) != claimed.get(key):
                raise ValueError(f"Stored V2 attestation server state mismatch for {key}")
        expires_at = int(state.get("expires_at", 0))
        if int(time.time()) > expires_at:
            raise ValueError("Stored V2 attestation server state has expired")
        try:
            hmac_key = base64.b64decode(state["hmac_key_b64"], validate=True)
            nonce = base64.b64decode(state["nonce_b64"], validate=True)
            aik_spki_der = base64.b64decode(state["v2_aik_spki_b64"], validate=True)
        except Exception as exc:
            raise ValueError("Stored V2 attestation secrets are malformed") from exc
        try:
            attestation_claim = tpm_mod._decrypt_cms_enveloped_data(
                challenge_response_der, ket_cert_der, ket_priv
            )
        except Exception as exc:
            raise ValueError("Invalid encrypted V2 TPM challenge response") from exc

        proof = rh.verify_aik_attestation_claim(
            attestation_claim_der=attestation_claim,
            expected_aik_spki_der=aik_spki_der,
            hmac_key=hmac_key,
            nonce=nonce,
        )
        ek_cert, ek_pub = _restore_ek_materials(state)
        ek_certificates = _restore_pending_certificates(state)
        aik_public_key = _public_key_from_spki_der(aik_spki_der)
        result = {
            **proof,
            "status": "ok",
            "used": True,
            "attestation_valid": True,
            "challenge_verified": True,
            "microsoft_native_attestation": True,
            "attestation_protocol": "v2_restricted_hmac_cmc",
            "v2_attestation_verified": True,
            "cr_flg_challengesatisfied": True,
            "cr_flg_v2challenge": True,
            "request_id": int(request_id),
            "ek_cert": ek_cert,
            "ek_certificates": ek_certificates,
            "ek_pub": ek_pub,
            "ek_cert_sha256": _cert_sha256(ek_cert),
            "ek_public_key_identity_sha256": _ek_pub_sha256(ek_pub) or "",
            "v2_container_name": state.get("v2_container_name"),
            "v2_aik_spki_sha256": state.get("v2_aik_spki_sha256"),
            "aik_public_key": aik_public_key,
            "aik_spki_der": aik_spki_der,
            "required_certificate_extensions": [
                {
                    "oid": tpm_mod.OID_MS_CERTSRV_V2_ATTESTATION_VERIFIED,
                    "critical": False,
                    "value_der_b64": base64.b64encode(b"\x05\x00").decode("ascii"),
                }
            ],
        }
        return result
    finally:
        _delete_claimed_pending(claimed_path)


def _verify_pending_challenge_response(
    *,
    csr: x509.CertificateSigningRequest,
    template: dict,
    ca: Optional[dict],
    pending_challenge: dict,
    challenge_response_der: bytes,
    request_id: Optional[int] = None,
    pending_dir: str | Path,
    max_age_seconds: int,
    username: Optional[str] = None,
    ca_id: Optional[str] = None,
) -> dict:
    if request_id is None:
        raise ValueError("request_id is required to verify a TPM challenge response")
    safe_request_id = _normalize_request_id(request_id)

    if str(pending_challenge.get("request_id")) != safe_request_id:
        _delete_pending_challenge(safe_request_id, pending_dir)
        raise ValueError("pending_challenge request_id does not match the current request")

    protocol = pending_challenge.get("protocol") or "v1_makecredential"
    if protocol == "v2_restricted_hmac_cmc":
        if ca is None:
            raise ValueError("ca is required to verify a V2 TPM challenge response")
        return _verify_pending_v2_challenge_response(
            csr=csr,
            template=template,
            ca=ca,
            pending_challenge=pending_challenge,
            challenge_response_der=challenge_response_der,
            request_id=int(safe_request_id),
            pending_dir=pending_dir,
            max_age_seconds=max_age_seconds,
            username=username,
            ca_id=ca_id,
        )
    if protocol != "v1_makecredential":
        raise ValueError(
            f"Pending TPM state uses protocol {protocol!r}, not the V1 challenge-response protocol"
        )

    expected_secret_b64 = pending_challenge.get("secret_b64")
    if not expected_secret_b64:
        raise ValueError("pending_challenge does not contain secret_b64")

    created_at = pending_challenge.get("created_at")
    if created_at is None:
        _delete_pending_challenge(safe_request_id, pending_dir)
        raise ValueError("pending_challenge does not contain created_at; cannot verify expiry")
    try:
        age = int(time.time()) - int(created_at)
    except (TypeError, ValueError):
        _delete_pending_challenge(safe_request_id, pending_dir)
        raise ValueError("pending_challenge contains invalid created_at; cannot verify expiry")
    if age < 0 or age > max_age_seconds:
        _delete_pending_challenge(safe_request_id, pending_dir)
        raise ValueError(
            f"TPM challenge has expired (age={age}s, max={max_age_seconds}s)"
        )

    expected_template_fingerprint = pending_challenge.get("template_fingerprint")
    if expected_template_fingerprint and expected_template_fingerprint != _template_fingerprint(template):
        raise ValueError("Current template does not match the pending TPM challenge context")

    expected_ca_fingerprint = pending_challenge.get("ca_fingerprint")
    if expected_ca_fingerprint and expected_ca_fingerprint != _ca_fingerprint(ca):
        raise ValueError("Current CA does not match the pending TPM challenge context")

    expected_csr_sha256 = pending_challenge.get("csr_sha256")
    if expected_csr_sha256 and expected_csr_sha256 != hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest():
        raise ValueError("Current CSR does not match the pending TPM challenge context")

    expected_spki_sha256 = pending_challenge.get("spki_sha256")
    if not expected_spki_sha256:
        raise ValueError("pending_challenge is missing spki_sha256; cannot bind challenge response to CSR")
    current_spki_sha256 = _spki_sha256(csr)
    if current_spki_sha256 != expected_spki_sha256:
        raise ValueError("CSR public key does not match the pending challenge context")

    expected_certified_key_name_b64 = pending_challenge.get("certified_key_name_b64")
    if expected_certified_key_name_b64:
        current_binding = _current_microsoft_binding_from_csr(csr)
        if current_binding is None:
            raise ValueError("Pending challenge expects Microsoft key attestation, but current CSR does not contain it")
        current_certified_key_name_b64 = base64.b64encode(
            current_binding["certified_key_name"]
        ).decode("ascii")
        if not hmac.compare_digest(current_certified_key_name_b64, expected_certified_key_name_b64):
            raise ValueError("Certified TPM key name does not match the pending challenge context")

    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    try:
        clear = tpm_mod._decrypt_cms_enveloped_data(challenge_response_der, ket_cert_der, ket_priv)
        expected_secret = base64.b64decode(expected_secret_b64, validate=True)
    except Exception:
        raise ValueError("Invalid TPM challenge response") from None
    if not hmac.compare_digest(clear, expected_secret):
        raise ValueError("TPM challenge response does not match the pending secret")

    _delete_pending_challenge(safe_request_id, pending_dir)

    ek_cert, ek_pub = _restore_ek_materials(pending_challenge)
    ek_certificates = _restore_pending_certificates(pending_challenge)
    ek_cert_sha256 = _cert_sha256(ek_cert)
    ek_public_key_identity_sha256 = _ek_pub_sha256(ek_pub) or ""
    aik_spki_der = None
    aik_spki_b64 = pending_challenge.get("aik_spki_der_b64")
    if aik_spki_b64:
        try:
            aik_spki_der = base64.b64decode(aik_spki_b64, validate=True)
        except Exception as exc:
            raise ValueError("Pending V1 challenge contains invalid AIK SPKI") from exc

    expected_ek_cert_sha256 = pending_challenge.get("ek_cert_sha256")
    if expected_ek_cert_sha256 and expected_ek_cert_sha256 != ek_cert_sha256:
        raise ValueError("Restored EK certificate does not match the pending TPM challenge context")
    expected_ek_pub_sha256 = pending_challenge.get("ek_pub_spki_sha256")
    if expected_ek_pub_sha256 and expected_ek_pub_sha256 != ek_public_key_identity_sha256:
        raise ValueError("Restored EK public key does not match the pending TPM challenge context")

    return {
        "status": "ok",
        "used": True,
        "attestation_without_policy": pending_challenge.get("attestation_without_policy", False),
        "attestation_valid": True,
        "challenge_verified": True,
        "microsoft_native_attestation": True,
        "attestation_protocol": "v1_makecredential",
        "request_id": int(safe_request_id),
        "ek_cert": ek_cert,
        "ek_certificates": ek_certificates,
        "ek_pub": ek_pub,
        "ek_cert_sha256": ek_cert_sha256,
        "ek_public_key_identity_sha256": ek_public_key_identity_sha256,
        "aik_name_b64": pending_challenge.get("aik_name_b64"),
        "id_binding_creation_attest_type": pending_challenge.get("id_binding_creation_attest_type"),
        "id_binding_creation_name_b64": pending_challenge.get("id_binding_creation_name_b64"),
        "id_binding_creation_hash_b64": pending_challenge.get("id_binding_creation_hash_b64"),
        "certified_key_attributes": pending_challenge.get("certified_key_attributes"),
        "certified_key_name_alg": pending_challenge.get("certified_key_name_alg"),
        "certified_key_alg": pending_challenge.get("certified_key_alg"),
        "certified_key_name_b64": pending_challenge.get("certified_key_name_b64"),
        "aik_spki_der": aik_spki_der,
        "firmware_version": pending_challenge.get("firmware_version"),
    }


def create_microsoft_certify_challenge_response(*, csr, bundle, template: dict, request_id: int, ca: dict,pending_dir) -> dict:
    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    decrypted = tpm_mod.decrypt_microsoft_ek_info(bundle.ms_ek_info_raw, ket_cert_der, ket_priv)
    bundle.ms_ek_info_decrypted_raw = decrypted.get("decrypted_raw")
    bundle.ms_embedded_certificates_der = decrypted.get("embedded_certificates_der") or []
    if decrypted.get("ek_cert_der") and not getattr(bundle, "ek_cert_der", None):
        bundle.ek_cert_der = decrypted["ek_cert_der"]
    if not bundle.ms_ek_info_decrypted_raw:
        raise ValueError("Microsoft EK_INFO was present but could not be decrypted")

    extracted_ek_pub = tpm_mod.extract_ek_pub_from_decrypted_ek_info(
        bundle.ms_ek_info_decrypted_raw,
        embedded_certificates_der=bundle.ms_embedded_certificates_der,
        ek_cert_der=getattr(bundle, "ek_cert_der", None),
    )
    policy = _template_tpm_policy(template) or {}
    ek_cert, ek_pub = _select_ek_public_key_for_challenge(
        bundle=bundle,
        extracted_ek_pub=extracted_ek_pub,
        policy=policy,
        template=template,
        ca=ca,
    )
    ek_certificates = _normalize_certificate_list(
        getattr(bundle, "ms_embedded_certificates_der", None),
        leaf=ek_cert,
    )

    attestation_blob_raw = (
        getattr(bundle, "ms_attestation_statement_raw", None)
        or getattr(bundle, "ms_attestation_blob_raw", None)
    )
    if not attestation_blob_raw:
        raise ValueError("Microsoft key-attestation statement is required")
    certified_binding = tpm_mod.validate_microsoft_key_attestation_binding(
        attestation_blob_raw,
        csr.public_key(),
    )

    encryption_algorithm_oid = tpm_mod.extract_encryption_algorithm_for_challenge_response(bundle.ms_ek_info_raw)
    xchg_cert_der = (materials["ca_exchange_chain_der"] or [None])[0]
    aik_info_hash = hashlib.sha1(xchg_cert_der).digest() if xchg_cert_der else None


    signer_cert_pem = ca.get("__certificate_pem") if ca else None
    if signer_cert_pem is None:
        raise ValueError("Missing CA certificate PEM for TPM challenge signing")
    ca_key = ca.get("__key_obj") if ca else None

    challenge = tpm_mod.build_and_sign_microsoft_attestation_challenge(
        request_id=int(request_id),
        ek_pub=ek_pub,
        ca_exchange_chain_der=materials["ca_exchange_chain_der"],
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        aik_name=certified_binding["aik_name"],
        aik_pub_raw=getattr(bundle, "ms_aik_info_raw", None),
        attestation_blob_raw=attestation_blob_raw,
        signer_cert_pem=signer_cert_pem,
        signer_key_obj=ca_key,
        signer_chain_pems=[],
    )

    ek_pub_der = _public_key_to_spki_der(ek_pub)
    ek_pub_hash_der = _public_key_to_legacy_ek_hash_der(ek_pub)
    ek_cert_der = ek_cert.public_bytes(serialization.Encoding.DER) if ek_cert is not None else None
    aik_public_key = _coerce_cryptography_public_key(
        certified_binding.get("aik_public_key")
    )
    aik_spki_der = _public_key_to_spki_der(aik_public_key)
    safe_request_id = _normalize_request_id(request_id)

    pending_payload = {
        "state_version": 1,
        "protocol": "v1_makecredential",
        "request_id": safe_request_id,
        "template_name": template.get("common_name"),
        "template_fingerprint": _template_fingerprint(template),
        "ca_fingerprint": _ca_fingerprint(ca),
        "csr_sha256": hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "spki_sha256": _spki_sha256(csr),
        "secret_b64": base64.b64encode(challenge["secret"]).decode("ascii"),
        "created_at": int(time.time()),
        "encryption_algorithm_oid": encryption_algorithm_oid,
        "ek_cert_present": bool(ek_cert_der),
        "ek_cert_der_b64": base64.b64encode(ek_cert_der).decode("ascii") if ek_cert_der else None,
        "ek_certificates_der_b64": _pending_certificate_list(ek_certificates),
        "ek_cert_sha256": hashlib.sha256(ek_cert_der).hexdigest() if ek_cert_der else None,
        "ek_pub_der_b64": base64.b64encode(ek_pub_der).decode("ascii") if ek_pub_der else None,
        "ek_pub_spki_sha256": hashlib.sha256(ek_pub_hash_der).hexdigest() if ek_pub_hash_der else None,
        "attestation_without_policy": policy.get("attestation_without_policy", False),
        "aik_name_b64": certified_binding.get("aik_name_b64"),
        "id_binding_creation_attest_type": certified_binding.get("id_binding_creation_attest_type"),
        "id_binding_creation_name_b64": certified_binding.get("id_binding_creation_name_b64"),
        "id_binding_creation_hash_b64": certified_binding.get("id_binding_creation_hash_b64"),
        "certified_key_name_b64": base64.b64encode(certified_binding["certified_key_name"]).decode("ascii"),
        "certified_key_attributes": certified_binding.get("certified_key_attributes"),
        "certified_key_name_alg": certified_binding.get("certified_key_name_alg"),
        "certified_key_alg": certified_binding.get("certified_key_alg"),
        "aik_spki_der_b64": base64.b64encode(aik_spki_der).decode("ascii") if aik_spki_der else None,
        "firmware_version": certified_binding.get("firmware_version"),
    }
    _save_pending_challenge(safe_request_id, pending_payload, pending_dir)

    return {
        "status": "pending",
        "used": True,
        "request_id": int(request_id),
        "challenge_pkcs7_der": challenge["signed_pkcs7_der"],
        "attestation_valid": False,
        "microsoft_native_attestation": True,
        "attestation_protocol": "v1_makecredential",
        "ek_info_decrypted": True,
        "fully_decoded": False,
        "ek_cert": ek_cert,
        "ek_certificates": ek_certificates,
        "ek_pub": ek_pub,
        "aik_public_key": aik_public_key,
        "aik_spki_der": aik_spki_der,
        "firmware_version": certified_binding.get("firmware_version"),
        "certified_key_obj": certified_binding.get("certified_key_obj"),
        "aik_name_b64": certified_binding.get("aik_name_b64"),
        "id_binding_creation_attest_type": certified_binding.get("id_binding_creation_attest_type"),
        "id_binding_creation_name_b64": certified_binding.get("id_binding_creation_name_b64"),
        "id_binding_creation_hash_b64": certified_binding.get("id_binding_creation_hash_b64"),
        "certified_key_attributes": certified_binding.get("certified_key_attributes"),
        "certified_key_name_alg": certified_binding.get("certified_key_name_alg"),
        "certified_key_alg": certified_binding.get("certified_key_alg"),
    }


def verify_tpm_for_template(
    *,
    csr_der: bytes,
    cmc_der: Optional[bytes] = None,
    challenge_response_der: Optional[bytes] = None,
    template: dict,
    request_id: Optional[int] = None,
    ca: Optional[dict] = None,
    pending_dir: str | Path,
    pending_challenge_max_age_seconds: int,
    username: Optional[str] = None,
    ca_id: Optional[str] = None,
) -> dict:
    """Verify TPM attestation for a template.

    Strict API:
      * cmc_der is only for the initial CMC/PKCS#7 request.
      * challenge_response_der is only for the Microsoft pending challenge response.
      * Passing both is refused.
      * A challenge response is never auto-detected from cmc_der.
    """
    if cmc_der is not None and challenge_response_der is not None:
        raise ValueError("cmc_der and challenge_response_der are mutually exclusive")

    policy = _template_tpm_policy(template)
    if not policy:
        return _finalize_tpm_result(
            {
                "status": "ok",
                "used": False,
                "attestation_valid": False,
                "ek_cert": None,
                "ek_pub": None,
            },
            None,
        )

    csr = x509.load_der_x509_csr(csr_der)

    if challenge_response_der is not None:
        if request_id is None:
            raise ValueError("request_id is required to verify a TPM challenge response")
        pending_challenge = _load_pending_challenge(request_id, pending_dir)
        if pending_challenge is None:
            raise ValueError("No pending TPM challenge exists for this request_id")
        if (
            policy.get("require_v2_attestation")
            and (pending_challenge.get("protocol") or "v1_makecredential")
            != "v2_restricted_hmac_cmc"
        ):
            _delete_pending_challenge(request_id, pending_dir)
            raise ValueError(
                "The certificate template requires V2 key attestation "
                "(CT_FLAG_REQUIRE_V2_ATTESTATION, 0x8000)"
            )
        return _finalize_tpm_result(_verify_pending_challenge_response(
            csr=csr,
            template=template,
            ca=ca,
            pending_challenge=pending_challenge,
            challenge_response_der=challenge_response_der,
            request_id=request_id,
            pending_dir=pending_dir,
            max_age_seconds=pending_challenge_max_age_seconds,
            username=username,
            ca_id=ca_id,
        ), policy)

    if request_id is not None and _load_pending_challenge(request_id, pending_dir) is not None:
        raise ValueError(
            "A pending TPM challenge already exists for this request_id; submit the response via challenge_response_der"
        )

    bundle = None
    if cmc_der is not None:
        try:
            bundle = tpm_mod.extract_tpm_bundle_from_cmc(cmc_der)
        except Exception:
            raise ValueError("Invalid CMC request; refusing to treat it as a TPM challenge response") from None
    else:
        bundle = tpm_mod.extract_tpm_bundle_from_pkcs10_der(csr_der)

    if bundle is None:
        if policy["required"]:
            raise ValueError(
                "TPM attestation required by template but no Microsoft key-attestation attributes were found in the request"
            )
        return _finalize_tpm_result(
            {
                "status": "ok",
                "used": False,
                "attestation_valid": False,
                "ek_cert": None,
                "ek_pub": None,
            },
            policy,
        )

    v2_state = tpm_mod.classify_microsoft_v2_key_attestation_bundle(bundle)
    if v2_state == "partial":
        raise ValueError(
            "The request contains an incomplete MS-WCCE V2 key-attestation attribute set"
        )
    if v2_state == "complete":
        if request_id is None or ca is None:
            raise ValueError("request_id and ca are required to build a V2 TPM challenge")
        return _finalize_tpm_result(create_microsoft_v2_restricted_hmac_challenge_response(
            csr=csr,
            bundle=bundle,
            template=template,
            request_id=int(_normalize_request_id(request_id)),
            ca=ca,
            pending_dir=pending_dir,
            max_age_seconds=pending_challenge_max_age_seconds,
            username=username,
            ca_id=ca_id,
        ), policy)

    if getattr(bundle, "ms_ek_info_raw", None) is not None:
        if policy.get("require_v2_attestation"):
            raise ValueError(
                "The certificate template requires V2 key attestation "
                "(CT_FLAG_REQUIRE_V2_ATTESTATION, 0x8000)"
            )
        if request_id is None or ca is None:
            raise ValueError("request_id and ca are required to build a TPM challenge response")
        return _finalize_tpm_result(create_microsoft_certify_challenge_response(
            csr=csr,
            bundle=bundle,
            template=template,
            request_id=int(_normalize_request_id(request_id)),
            ca=ca,
            pending_dir=pending_dir,
        ), policy)

    if getattr(bundle, "ms_aik_info_raw", None) is not None:
        if policy.get("require_v2_attestation"):
            raise ValueError(
                "The certificate template requires V2 key attestation "
                "(CT_FLAG_REQUIRE_V2_ATTESTATION, 0x8000)"
            )
        return _finalize_tpm_result(verify_microsoft_aik_info_subject_only(
            csr=csr,
            bundle=bundle,
            template=template,
            ca=ca,
        ), policy)

    if policy["required"]:
        raise ValueError(
            "TPM attestation required but request did not contain usable Microsoft EK_INFO or AIK_INFO"
        )
    return _finalize_tpm_result(
        {
            "status": "ok",
            "used": False,
            "attestation_valid": False,
            "ek_cert": None,
            "ek_pub": None,
        },
        policy,
    )
