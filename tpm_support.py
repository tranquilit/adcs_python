import base64
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import tpm_attestation as tpm_mod

logger = logging.getLogger("adcs.tpm_support")
_PENDING_DIR = "/var/lib/adcs/tpm-pending"
_PENDING_CHALLENGE_MAX_AGE_SECONDS = int(os.environ.get("ADCS_TPM_PENDING_TTL_SECONDS", "300"))



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


def _save_pending_challenge(request_id: str | int, payload: dict) -> None:
    safe_request_id = _normalize_request_id(request_id)
    pending_dir = Path(_PENDING_DIR)
    pending_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending_dir.chmod(0o700)
    path = pending_dir / f"{safe_request_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _load_pending_challenge(request_id: str | int) -> Optional[dict]:
    safe_request_id = _normalize_request_id(request_id)
    path = Path(_PENDING_DIR) / f"{safe_request_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _delete_pending_challenge(request_id: str | int) -> None:
    safe_request_id = _normalize_request_id(request_id)
    path = Path(_PENDING_DIR) / f"{safe_request_id}.json"
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
        if flags.get("ek_validate_cert"):
            flags_value |= 0x00000400
    else:
        raise TypeError(
            f"template flags.private_key_flags must be int or dict, got {type(flags).__name__}"
        )

    attest_required = bool(flags_value & 0x00002000)
    attest_preferred = bool(flags_value & 0x00001000)
    if not attest_required and not attest_preferred:
        return None
    return {
        "required": attest_required,
        "preferred": attest_preferred,
        "attestation_without_policy": bool(flags_value & 0x00004000),
        "ek_validate_cert": bool(flags_value & 0x00000400),
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

    signing_cert_path = _pick(
        template.get("signing_cert_pem"),
        template.get("cert_pem"),
        ca.get("signing_cert_pem"),
        ca.get("cert_pem"),
    )
    signing_key_path = _pick(
        template.get("signing_key_pem"),
        template.get("key_pem"),
        ca.get("signing_key_pem"),
        ca.get("key_pem"),
    )
    signing_chain_path = _pick(
        template.get("signing_chain_pem"),
        template.get("chain_pem"),
        ca.get("signing_chain_pem"),
        ca.get("chain_pem"),
    )

    ket_cert_pem = _pick(template.get("__ket_certificate_pem"), ca.get("__ket_certificate_pem")) or _read_text(ket_cert_path)
    ket_key_pem = _pick(template.get("__ket_key_pem"), ca.get("__ket_key_pem")) or _read_text(ket_key_path)
    if not ket_cert_pem:
        raise ValueError("Missing ket_cert_pem in template/CA config")
    if not ket_key_pem:
        raise ValueError("Missing ket_key_pem in template/CA config")

    ca_sign_cert_pem = _pick(template.get("__certificate_pem"), ca.get("__certificate_pem")) or _read_text(signing_cert_path)
    ca_sign_key_pem = _pick(template.get("__key_pem"), ca.get("__key_pem")) or _read_text(signing_key_path)
    if not ca_sign_cert_pem or not ca_sign_key_pem:
        raise ValueError(
            "Missing signing certificate/key for CMC challenge signing; configure signing_cert_pem and signing_key_pem (or cert_pem/key_pem) with a matching pair"
        )

    ket_chain_pem = _read_text(ket_chain_path) if ket_chain_path else None
    signing_chain_pem = _read_text(signing_chain_path) if signing_chain_path else None

    return {
        "ket_cert_pem": ket_cert_pem,
        "ket_key_pem": ket_key_pem,
        "ca_exchange_chain_der": [tpm_mod.pem_cert_to_der(ket_cert_pem)] + [tpm_mod.pem_cert_to_der(block) for block in _split_cert_chain(ket_chain_pem)],
        "ca_sign_cert_pem": ca_sign_cert_pem,
        "ca_sign_key_pem": ca_sign_key_pem,
        "ca_sign_chain_pems": _split_cert_chain(signing_chain_pem),
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

    Historical callers compared ek_public_key_spki_sha256 against the SHA-256
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


def _select_ek_public_key_for_challenge(*, bundle, extracted_ek_pub, policy: dict):
    """Bind EKPub to EKCert and return the only EK public key allowed for MakeCredential.

    If an EK certificate is present, its public key is authoritative. Any separate SPKI
    found in EK_INFO must match it exactly. If the template requires EK certificate
    validation, absence of EKCert is a hard failure.
    """
    ek_cert = _ek_cert_from_der(bundle.ek_cert_der) if getattr(bundle, "ek_cert_der", None) else None
    if ek_cert is not None:
        ek_pub_from_cert = ek_cert.public_key()
        if extracted_ek_pub is not None and not _public_keys_equal(extracted_ek_pub, ek_pub_from_cert):
            raise ValueError("EK public key does not match EK certificate")
        return ek_cert, ek_pub_from_cert

    if policy.get("ek_validate_cert"):
        raise ValueError("Template requires EK certificate validation, but no EK certificate was provided")
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
            logger.debug("Could not restore EK certificate from pending payload: %s", exc)
    if ek_pub_der_b64:
        try:
            ek_pub = _public_key_from_spki_der(base64.b64decode(ek_pub_der_b64, validate=True))
        except Exception as exc:
            logger.debug("Could not restore EK public key from pending payload: %s", exc)
    elif ek_cert is not None:
        try:
            ek_pub = ek_cert.public_key()
        except Exception as exc:
            logger.debug("Could not restore EK public key from EK certificate: %s", exc)
    return ek_cert, ek_pub


def _verify_pending_challenge_response(
    *,
    csr: x509.CertificateSigningRequest,
    template: dict,
    ca: Optional[dict],
    pending_challenge: dict,
    challenge_response_der: bytes,
    request_id: Optional[int] = None,
    max_age_seconds: int = _PENDING_CHALLENGE_MAX_AGE_SECONDS,
) -> dict:
    if request_id is None:
        raise ValueError("request_id is required to verify a TPM challenge response")
    safe_request_id = _normalize_request_id(request_id)

    if str(pending_challenge.get("request_id")) != safe_request_id:
        _delete_pending_challenge(safe_request_id)
        raise ValueError("pending_challenge request_id does not match the current request")

    expected_secret_b64 = pending_challenge.get("secret_b64")
    if not expected_secret_b64:
        raise ValueError("pending_challenge does not contain secret_b64")

    created_at = pending_challenge.get("created_at")
    if created_at is None:
        _delete_pending_challenge(safe_request_id)
        raise ValueError("pending_challenge does not contain created_at; cannot verify expiry")
    try:
        age = int(time.time()) - int(created_at)
    except (TypeError, ValueError):
        _delete_pending_challenge(safe_request_id)
        raise ValueError("pending_challenge contains invalid created_at; cannot verify expiry")
    if age < 0 or age > max_age_seconds:
        _delete_pending_challenge(safe_request_id)
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

    _delete_pending_challenge(safe_request_id)

    ek_cert, ek_pub = _restore_ek_materials(pending_challenge)
    ek_cert_sha256 = _cert_sha256(ek_cert)
    ek_public_key_spki_sha256 = _ek_pub_sha256(ek_pub) or ""

    expected_ek_cert_sha256 = pending_challenge.get("ek_cert_sha256")
    if expected_ek_cert_sha256 and expected_ek_cert_sha256 != ek_cert_sha256:
        raise ValueError("Restored EK certificate does not match the pending TPM challenge context")
    expected_ek_pub_sha256 = pending_challenge.get("ek_pub_spki_sha256")
    if expected_ek_pub_sha256 and expected_ek_pub_sha256 != ek_public_key_spki_sha256:
        raise ValueError("Restored EK public key does not match the pending TPM challenge context")

    return {
        "status": "ok",
        "used": True,
        "attestation_without_policy": pending_challenge.get("attestation_without_policy", False),
        "attestation_valid": True,
        "challenge_verified": True,
        "microsoft_native_attestation": True,
        "request_id": int(safe_request_id),
        "ek_cert": ek_cert,
        "ek_pub": ek_pub,
        "ek_cert_sha256": ek_cert_sha256,
        "ek_public_key_spki_sha256": ek_public_key_spki_sha256,
        "aik_name_b64": pending_challenge.get("aik_name_b64"),
        "id_binding_creation_attest_type": pending_challenge.get("id_binding_creation_attest_type"),
        "id_binding_creation_name_b64": pending_challenge.get("id_binding_creation_name_b64"),
        "id_binding_creation_hash_b64": pending_challenge.get("id_binding_creation_hash_b64"),
        "certified_key_attributes": pending_challenge.get("certified_key_attributes"),
        "certified_key_name_alg": pending_challenge.get("certified_key_name_alg"),
        "certified_key_alg": pending_challenge.get("certified_key_alg"),
        "certified_key_name_b64": pending_challenge.get("certified_key_name_b64"),
    }


def create_microsoft_certify_challenge_response(*, csr, bundle, template: dict, request_id: int, ca: dict) -> dict:
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

    challenge = tpm_mod.build_and_sign_microsoft_attestation_challenge(
        request_id=int(request_id),
        ek_pub=ek_pub,
        ca_exchange_chain_der=materials["ca_exchange_chain_der"],
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        aik_name=certified_binding["aik_name"],
        aik_pub_raw=getattr(bundle, "ms_aik_info_raw", None),
        attestation_blob_raw=attestation_blob_raw,
        signer_cert_pem=materials["ca_sign_cert_pem"],
        signer_key_pem=materials["ca_sign_key_pem"],
        signer_chain_pems=materials["ca_sign_chain_pems"],
    )

    ek_pub_der = _public_key_to_spki_der(ek_pub)
    ek_pub_hash_der = _public_key_to_legacy_ek_hash_der(ek_pub)
    ek_cert_der = ek_cert.public_bytes(serialization.Encoding.DER) if ek_cert is not None else None
    safe_request_id = _normalize_request_id(request_id)

    pending_payload = {
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
    }
    _save_pending_challenge(safe_request_id, pending_payload)

    return {
        "status": "pending",
        "used": True,
        "request_id": int(request_id),
        "challenge_pkcs7_der": challenge["signed_pkcs7_der"],
        "attestation_valid": False,
        "microsoft_native_attestation": True,
        "ek_info_decrypted": True,
        "fully_decoded": False,
        "ek_cert": ek_cert,
        "ek_pub": ek_pub,
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
        return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}

    csr = x509.load_der_x509_csr(csr_der)

    if challenge_response_der is not None:
        if request_id is None:
            raise ValueError("request_id is required to verify a TPM challenge response")
        pending_challenge = _load_pending_challenge(request_id)
        if pending_challenge is None:
            raise ValueError("No pending TPM challenge exists for this request_id")
        return _verify_pending_challenge_response(
            csr=csr,
            template=template,
            ca=ca,
            pending_challenge=pending_challenge,
            challenge_response_der=challenge_response_der,
            request_id=request_id,
        )

    if request_id is not None and _load_pending_challenge(request_id) is not None:
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
        return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}

    if getattr(bundle, "ms_ek_info_raw", None) is not None:
        if request_id is None or ca is None:
            raise ValueError("request_id and ca are required to build a TPM challenge response")
        return create_microsoft_certify_challenge_response(
            csr=csr,
            bundle=bundle,
            template=template,
            request_id=int(_normalize_request_id(request_id)),
            ca=ca,
        )

    if getattr(bundle, "ms_aik_info_raw", None) is not None:
        raise ValueError(
            "Microsoft AIK_INFO-only key attestation requests are not supported by this path; EK_INFO is required to build the activation challenge."
        )

    if policy["required"]:
        raise ValueError("TPM attestation required but request did not contain usable Microsoft EK_INFO")
    return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}
