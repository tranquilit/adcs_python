import base64
import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import tpm_attestation as tpm_mod

logger = logging.getLogger("adcs.tpm_support")
_PENDING_DIR = "/var/lib/adcs/tpm-pending"


def _save_pending_challenge(request_id: str, payload: dict) -> None:
    pending_dir = Path(_PENDING_DIR)
    pending_dir.mkdir(parents=True, exist_ok=True)
    (pending_dir / f"{request_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def _load_pending_challenge(request_id: str | int) -> Optional[dict]:
    path = Path(_PENDING_DIR) / f"{request_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _delete_pending_challenge(request_id: str | int) -> None:
    path = Path(_PENDING_DIR) / f"{request_id}.json"
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
        "ek_trust_on_use": bool(flags_value & 0x00000200),
        "ek_validate_cert": bool(flags_value & 0x00000400),
        "ek_validate_key": bool(flags_value & 0x00000800),
    }




def _build_bundle_from_json(data: dict):
    _ALLOWED_MODES = {"CERTIFY", "AIK_FULL"}

    def _decode(key: str):
        value = data.get(key)
        return base64.b64decode(value) if value else None

    mode = data.get("mode", "CERTIFY")
    if mode not in _ALLOWED_MODES:
        raise ValueError(
            f"Invalid TPM bundle mode {mode!r}; must be one of {sorted(_ALLOWED_MODES)}"
        )
    return tpm_mod.TPMAttestationBundle(
        mode=mode,
        ek_cert_der=_decode("ek_cert"),
        aik_pub_raw=_decode("aik_pub"),
        attest_raw=_decode("attest"),
        attest_sig_raw=_decode("sig") or _decode("attest_sig"),
        certified_key_raw=_decode("certified_key") or _decode("cert_key"),
        nonce=_decode("nonce"),
    )


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


def _extract_ek_materials_from_bundle(bundle) -> tuple[object | None, object | None]:
    ek_cert = None
    ek_pub = None
    try:
        ek_cert = _ek_cert_from_der(getattr(bundle, "ek_cert_der", None))
    except Exception as exc:
        logger.debug("Could not parse EK certificate from bundle: %s", exc)
        ek_cert = None
    if ek_cert is not None:
        try:
            ek_pub = ek_cert.public_key()
        except Exception as exc:
            logger.debug("Could not extract EK public key from EK certificate: %s", exc)
            ek_pub = None
    return ek_cert, ek_pub


def _restore_ek_materials(payload: Optional[dict]) -> tuple[object | None, object | None]:
    payload = payload or {}
    ek_cert_der_b64 = payload.get("ek_cert_der_b64")
    ek_pub_der_b64 = payload.get("ek_pub_der_b64")
    ek_cert = None
    ek_pub = None
    if ek_cert_der_b64:
        try:
            ek_cert = _ek_cert_from_der(base64.b64decode(ek_cert_der_b64))
        except Exception as exc:
            logger.debug("Could not restore EK certificate from pending payload: %s", exc)
    if ek_pub_der_b64:
        try:
            ek_pub = _public_key_from_spki_der(base64.b64decode(ek_pub_der_b64))
        except Exception as exc:
            logger.debug("Could not restore EK public key from pending payload: %s", exc)
    elif ek_cert is not None:
        try:
            ek_pub = ek_cert.public_key()
        except Exception as exc:
            logger.debug("Could not restore EK public key from EK certificate: %s", exc)
    return ek_cert, ek_pub


_MAX_COERCE_BYTES = 1 * 1024 * 1024 


def _coerce_bytes(value) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        if len(value) > _MAX_COERCE_BYTES:
            raise ValueError(f"Binary value too large: {len(value)} bytes (max {_MAX_COERCE_BYTES})")
        return value
    if isinstance(value, bytearray):
        if len(value) > _MAX_COERCE_BYTES:
            raise ValueError(f"Binary value too large: {len(value)} bytes (max {_MAX_COERCE_BYTES})")
        return bytes(value)
    if isinstance(value, str):
        # Base64 overhead ≈ 4/3 — check pre-decode length to avoid allocating huge buffers
        if len(value) > _MAX_COERCE_BYTES * 4 // 3 + 4:
            raise ValueError(f"Base64 string too large: {len(value)} chars (max {_MAX_COERCE_BYTES * 4 // 3 + 4})")
        decoded = base64.b64decode(value)
        if len(decoded) > _MAX_COERCE_BYTES:
            raise ValueError(f"Decoded binary value too large: {len(decoded)} bytes (max {_MAX_COERCE_BYTES})")
        return decoded
    raise TypeError(f"Unsupported binary value type: {type(value).__name__}")


def _extract_challenge_response_der(*, p7_der: Optional[bytes], extra_request_data: Optional[dict]) -> Optional[bytes]:
    if extra_request_data:
        for key in (
            "challenge_response_der",
            "challenge_response",
            "challenge_response_b64",
            "challenge_blob",
            "challenge_blob_b64",
            "pending_response",
            "pending_response_b64",
        ):
            if key in extra_request_data and extra_request_data.get(key) is not None:
                return _coerce_bytes(extra_request_data.get(key))
    return p7_der


def _verify_pending_challenge_response(
    *,
    csr: x509.CertificateSigningRequest,
    template: dict,
    ca: Optional[dict],
    pending_challenge: dict,
    challenge_response_der: bytes,
    request_id: Optional[int] = None,
    max_age_seconds: int = 3600,
) -> dict:
    expected_secret_b64 = pending_challenge.get("secret_b64")
    if not expected_secret_b64:
        raise ValueError("pending_challenge does not contain secret_b64")

    created_at = pending_challenge.get("created_at")
    if created_at is None:
        raise ValueError("pending_challenge does not contain created_at; cannot verify expiry")
    age = int(time.time()) - int(created_at)
    if age < 0 or age > max_age_seconds:
        if request_id is not None:
            _delete_pending_challenge(request_id)
        raise ValueError(
            f"TPM challenge has expired (age={age}s, max={max_age_seconds}s)"
        )

    expected_spki_sha256 = pending_challenge.get("spki_sha256")
    if not expected_spki_sha256:
        raise ValueError("pending_challenge is missing spki_sha256; cannot bind challenge response to CSR")
    current_spki_sha256 = _spki_sha256(csr)
    if current_spki_sha256 != expected_spki_sha256:
        raise ValueError("CSR public key does not match the pending challenge context")

    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    clear = tpm_mod._decrypt_cms_enveloped_data(challenge_response_der, ket_cert_der, ket_priv)
    expected_secret = base64.b64decode(expected_secret_b64)
    if not hmac.compare_digest(clear, expected_secret):
        raise ValueError("TPM challenge response does not match the pending secret")

    if request_id is not None:
        _delete_pending_challenge(request_id)

    ek_cert, ek_pub = _restore_ek_materials(pending_challenge)

    if ek_pub:
        der = ek_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
        ek_public_key_pkcs1_sha256 = hashlib.sha256(der).hexdigest()
    else:
        ek_public_key_pkcs1_sha256 = ''

    
    return {
        "status": "ok",
        "used": True,
        "mode": pending_challenge.get("mode", "CERTIFY"),
        "attestation_without_policy": pending_challenge.get("attestation_without_policy", False),
        "attestation_valid": True,
        "challenge_verified": True,
        "microsoft_native_attestation": True,
        "request_id": int(request_id) if request_id is not None else None,
        "ek_cert": ek_cert,
        "ek_pub": ek_pub,
        "ek_public_key_pkcs1_sha256": ek_public_key_pkcs1_sha256
    }


def create_microsoft_certify_challenge_response(*, csr, bundle, template: dict, request_id: int, ca: dict) -> dict:
    materials = _resolve_ca_materials_for_tpm(template, ca)
    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    decrypted = tpm_mod.decrypt_microsoft_ek_info(bundle.ms_ek_info_raw, ket_cert_der, ket_priv)
    bundle.ms_ek_info_decrypted_raw = decrypted.get("decrypted_raw")
    bundle.ms_embedded_certificates_der = decrypted.get("embedded_certificates_der") or []
    if decrypted.get("ek_cert_der") and not bundle.ek_cert_der:
        bundle.ek_cert_der = decrypted["ek_cert_der"]
    if not bundle.ms_ek_info_decrypted_raw:
        raise ValueError("Microsoft EK_INFO was present but could not be decrypted")

    ek_pub = tpm_mod.extract_ek_pub_from_decrypted_ek_info(
        bundle.ms_ek_info_decrypted_raw,
        embedded_certificates_der=bundle.ms_embedded_certificates_der,
        ek_cert_der=bundle.ek_cert_der,
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
        aik_pub_raw=getattr(bundle, "ms_aik_info_raw", None),
        attestation_blob_raw=getattr(bundle, "ms_attestation_statement_raw", None) or getattr(bundle, "ms_attestation_blob_raw", None),
        signer_cert_pem=materials["ca_sign_cert_pem"],
        signer_key_pem=materials["ca_sign_key_pem"],
        signer_chain_pems=materials["ca_sign_chain_pems"],
    )

    ek_cert = _ek_cert_from_der(bundle.ek_cert_der) if bundle.ek_cert_der else None
    ek_pub_der = _public_key_to_spki_der(ek_pub)

    pending_payload = {
        "mode": "CERTIFY",
        "template_name": template.get("common_name"),
        "spki_sha256": _spki_sha256(csr),
        "secret_b64": base64.b64encode(challenge["secret"]).decode("ascii"),
        "created_at": int(time.time()),
        "encryption_algorithm_oid": encryption_algorithm_oid,
        "ek_cert_present": bool(bundle.ek_cert_der),
        "ek_cert_der_b64": base64.b64encode(bundle.ek_cert_der).decode("ascii") if bundle.ek_cert_der else None,
        "ek_pub_der_b64": base64.b64encode(ek_pub_der).decode("ascii") if ek_pub_der else None,
        "attestation_without_policy": (_template_tpm_policy(template) or {}).get("attestation_without_policy", False),
    }
    _save_pending_challenge(str(request_id), pending_payload)

    return {
        "status": "pending",
        "used": True,
        "mode": "CERTIFY",
        "request_id": int(request_id),
        "challenge_pkcs7_der": challenge["signed_pkcs7_der"],
        "attestation_valid": False,
        "microsoft_native_attestation": True,
        "ek_info_decrypted": True,
        "fully_decoded": False,
        "pending_challenge": pending_payload,
        "ek_cert": ek_cert,
        "ek_pub": ek_pub,
    }


def verify_tpm_for_template(
    *,
    csr_der: bytes,
    p7_der: Optional[bytes],
    template: dict,
    request_id: Optional[int] = None,
    ca: Optional[dict] = None,
    extra_request_data: Optional[dict] = None,
    pending_challenge: Optional[dict] = None,
) -> dict:
    policy = _template_tpm_policy(template)
    if not policy:
        return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}

    csr = x509.load_der_x509_csr(csr_der)

    if pending_challenge is None and request_id is not None:
        pending_challenge = _load_pending_challenge(request_id)

    challenge_response_der = _extract_challenge_response_der(
        p7_der=p7_der,
        extra_request_data=extra_request_data,
    )
    if pending_challenge and challenge_response_der:
        try:
            bundle_probe = tpm_mod.extract_tpm_bundle_from_cmc(challenge_response_der)
        except Exception:
            bundle_probe = None
        if bundle_probe is None:
            return _verify_pending_challenge_response(
                csr=csr,
                template=template,
                ca=ca,
                pending_challenge=pending_challenge,
                challenge_response_der=challenge_response_der,
                request_id=request_id,
            )

    bundle = None
    if p7_der:
        try:
            bundle = tpm_mod.extract_tpm_bundle_from_cmc(p7_der)
        except Exception as exc:
            logger.debug("Could not extract TPM bundle from CMS/CMC request: %s", exc)

    if bundle is None:
        bundle = tpm_mod.extract_tpm_bundle_from_pkcs10_der(csr_der)
    if bundle is None and extra_request_data:
        bundle = _build_bundle_from_json(extra_request_data)

    if bundle is None:
        if pending_challenge and challenge_response_der:
            return _verify_pending_challenge_response(
                csr=csr,
                template=template,
                ca=ca,
                pending_challenge=pending_challenge,
                challenge_response_der=challenge_response_der,
                request_id=request_id,
            )
        if policy["required"]:
            raise ValueError(
                "TPM attestation required by template but no Microsoft key-attestation attributes were found in the PKCS#10 request"
            )
        return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}

    if getattr(bundle, "mode", None) == "MICROSOFT_PKCS10":
        if getattr(bundle, "ms_ek_info_raw", None) is not None:
            if request_id is None or ca is None:
                raise ValueError("request_id and ca are required to build a TPM challenge response")
            return create_microsoft_certify_challenge_response(
                csr=csr,
                bundle=bundle,
                template=template,
                request_id=int(request_id),
                ca=ca,
            )
        if getattr(bundle, "ms_aik_info_raw", None) is not None:
            raise ValueError(
                "Microsoft AIK_INFO-only key attestation requests are not yet handled by this path; EK_INFO is required here to build the activation challenge."
            )

    if any(
        getattr(bundle, name, None) is not None
        for name in ("aik_pub_raw", "attest_raw", "attest_sig_raw", "certified_key_raw", "nonce")
    ):
        expected_nonce = getattr(bundle, "nonce", None)
        if expected_nonce is None:
            raise ValueError(
                "TPM bundle does not carry a nonce; refusing to verify without replay protection"
            )
        result = tpm_mod.verify_tpm_attestation(
            bundle=bundle,
            expected_nonce=expected_nonce,
            require_fixed_tpm=True,
            require_fixed_parent=True,
            require_restricted=True,
        )
        if not result.success:
            raise ValueError(result.message)

        if result.certified_key_obj is None:
            raise ValueError("TPM attestation did not include a certified key bound to the CSR")
        
        csr_pub = csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        attested_pub = result.certified_key_obj.to_cryptography_public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if csr_pub != attested_pub:
            raise ValueError("CSR public key does not match TPM certified key")
        

        return {
            "status": "ok",
            "used": True,
            "mode": result.mode,
            "manufacturer": result.manufacturer,
            "firmware_version": result.firmware_version,
            "attestation_without_policy": policy["attestation_without_policy"],
            "attestation_valid": True,
            "ek_cert": result.ek_cert,
            "ek_pub": result.ek_pub,
        }

    if pending_challenge and challenge_response_der:
        return _verify_pending_challenge_response(
            csr=csr,
            template=template,
            ca=ca,
            pending_challenge=pending_challenge,
            challenge_response_der=challenge_response_der,
            request_id=request_id,
        )

    if policy["required"]:
        raise ValueError("TPM attestation required but request did not contain usable AIK_INFO/EK_INFO")
    return {"status": "ok", "used": False, "attestation_valid": False, "ek_cert": None, "ek_pub": None}
