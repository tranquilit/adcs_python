import base64
import hashlib
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


def _pending_path(request_id: str) -> Path:
    return Path(_PENDING_DIR) / f"{request_id}.json"


def _save_pending_challenge(request_id: str, payload: dict) -> None:
    Path(_PENDING_DIR).mkdir(parents=True, exist_ok=True)
    _pending_path(request_id).write_text(json.dumps(payload), encoding="utf-8")


def _template_private_key_flags(template: dict) -> int:
    flags = (template.get("flags") or {}).get("private_key_flags")
    if flags is None:
        return 0
    if isinstance(flags, int):
        return flags
    if isinstance(flags, dict):
        value = 0
        if flags.get("attest_preferred"):
            value |= 0x00001000
        if flags.get("attest_required"):
            value |= 0x00002000
        if flags.get("attestation_without_policy"):
            value |= 0x00004000
        if flags.get("ek_trust_on_use"):
            value |= 0x00000200
        if flags.get("ek_validate_cert"):
            value |= 0x00000400
        if flags.get("ek_validate_key"):
            value |= 0x00000800
        return value
    raise TypeError(
        f"template flags.private_key_flags must be int or dict, got {type(flags).__name__}"
    )


def _has_flag(mask: int, bit: int) -> bool:
    return bool(int(mask) & int(bit))


def _template_tpm_policy(template: dict) -> Optional[dict]:
    flags = _template_private_key_flags(template)
    attest_required = _has_flag(flags, 0x00002000)
    attest_preferred = _has_flag(flags, 0x00001000)
    if not attest_required and not attest_preferred:
        return None
    return {
        "required": attest_required,
        "preferred": attest_preferred,
        "attestation_without_policy": _has_flag(flags, 0x00004000),
        "ek_trust_on_use": _has_flag(flags, 0x00000200),
        "ek_validate_cert": _has_flag(flags, 0x00000400),
        "ek_validate_key": _has_flag(flags, 0x00000800),
    }


def _load_trusted_ek_roots(template: dict, policy: dict) -> list:
    if not policy.get("ek_validate_cert"):
        return []

    roots = []
    roots_dir = template.get("trusted_ek_roots_dir")
    if roots_dir:
        roots.extend(tpm_mod.load_trusted_ek_roots_from_dir(roots_dir))
    for pem_b64 in template.get("inline_ek_roots", []) or []:
        pem_bytes = base64.b64decode(pem_b64)
        roots.append(x509.load_pem_x509_certificate(pem_bytes))

    if not roots and not policy.get("ek_trust_on_use"):
        raise ValueError(
            "EK certificate validation is enabled but no trusted EK roots are defined in the callback template"
        )
    return roots


def _build_bundle_from_json(data: dict):
    def _b64(key: str):
        value = data.get(key)
        return base64.b64decode(value) if value else None

    return tpm_mod.TPMAttestationBundle(
        mode=data.get("mode", "CERTIFY"),
        ek_cert_der=_b64("ek_cert"),
        aik_pub_raw=_b64("aik_pub"),
        attest_raw=_b64("attest"),
        attest_sig_raw=_b64("sig") or _b64("attest_sig"),
        certified_key_raw=_b64("certified_key") or _b64("cert_key"),
        nonce=_b64("nonce"),
    )


def _read_text_file(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8")


def _pem_cert_to_der(cert_pem_text: str) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem_text.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)


def _split_pem_cert_chain(pem_text: str | None) -> list[str]:
    if not pem_text:
        return []
    blocks = []
    current = []
    in_cert = False
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


def _resolve_ca_materials_for_tpm(template: dict, ca: Optional[dict] = None) -> dict:
    def _pick(*values):
        for v in values:
            if v:
                return v
        return None

    ca = ca or {}

    ket_cert_path = _pick(template.get('ket_cert_pem'), ca.get('ket_cert_pem'))
    ket_key_path = _pick(template.get('ket_key_pem'), ca.get('ket_key_pem'))
    ket_chain_path = _pick(template.get('ket_chain_pem'), ca.get('ket_chain_pem'))

    signing_cert_path = _pick(template.get('signing_cert_pem'), template.get('cert_pem'), ca.get('signing_cert_pem'), ca.get('cert_pem'))
    signing_key_path = _pick(template.get('signing_key_pem'), template.get('key_pem'), ca.get('signing_key_pem'), ca.get('key_pem'))
    signing_chain_path = _pick(template.get('signing_chain_pem'), template.get('chain_pem'), ca.get('signing_chain_pem'), ca.get('chain_pem'))

    ket_cert_pem = _pick(template.get('__ket_certificate_pem'), ca.get('__ket_certificate_pem'))
    ket_key_pem = _pick(template.get('__ket_key_pem'), ca.get('__ket_key_pem'))
    if not ket_cert_pem and ket_cert_path:
        ket_cert_pem = _read_text_file(ket_cert_path)
    if not ket_key_pem and ket_key_path:
        ket_key_pem = _read_text_file(ket_key_path)
    ket_chain_pem = _read_text_file(ket_chain_path) if ket_chain_path else None
    if not ket_cert_pem:
        raise ValueError('Missing ket_cert_pem in template/CA config')
    if not ket_key_pem:
        raise ValueError('Missing ket_key_pem in template/CA config')

    ca_sign_cert_pem = _pick(template.get('__certificate_pem'), ca.get('__certificate_pem'))
    ca_sign_key_pem = _pick(template.get('__key_pem'), ca.get('__key_pem'))
    if not ca_sign_cert_pem and signing_cert_path:
        ca_sign_cert_pem = _read_text_file(signing_cert_path)
    if not ca_sign_key_pem and signing_key_path:
        ca_sign_key_pem = _read_text_file(signing_key_path)
    ca_sign_chain_pem = _read_text_file(signing_chain_path) if signing_chain_path else None
    if not ca_sign_cert_pem or not ca_sign_key_pem:
        raise ValueError(
            'Missing signing certificate/key for CMC challenge signing; configure signing_cert_pem and signing_key_pem (or cert_pem/key_pem) with a matching pair'
        )

    ca_exchange_chain_der = [_pem_cert_to_der(ket_cert_pem)]
    for pem_block in _split_pem_cert_chain(ket_chain_pem):
        ca_exchange_chain_der.append(_pem_cert_to_der(pem_block))
    ca_sign_chain_pems = _split_pem_cert_chain(ca_sign_chain_pem)
    return {
        'ket_cert_pem': ket_cert_pem,
        'ket_key_pem': ket_key_pem,
        'ca_exchange_chain_der': ca_exchange_chain_der,
        'ca_sign_cert_pem': ca_sign_cert_pem,
        'ca_sign_key_pem': ca_sign_key_pem,
        'ca_sign_chain_pems': ca_sign_chain_pems,
    }


def _spki_sha256(csr: x509.CertificateSigningRequest) -> str:
    spki = csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _hexdump_preview(data: bytes, limit: int = 64) -> str:
    if not data:
        return ''
    return data[:limit].hex()


def _describe_ms_attestation_blob(raw: bytes | None) -> dict:
    info = {
        'present': bool(raw),
        'length': len(raw or b''),
        'sha256': None,
        'ascii_magic': None,
        'kast_offset': -1,
        'pcpm_offsets': [],
        'preview_hex': '',
    }
    if not raw:
        return info
    info['sha256'] = hashlib.sha256(raw).hexdigest()
    info['preview_hex'] = _hexdump_preview(raw)
    for magic in (b'KAST', b'PCPM'):
        pos = raw.find(magic)
        if pos >= 0 and info['ascii_magic'] is None:
            info['ascii_magic'] = magic.decode('ascii')
        if magic == b'KAST':
            info['kast_offset'] = pos
    off = 0
    while True:
        pos = raw.find(b'PCPM', off)
        if pos < 0:
            break
        info['pcpm_offsets'].append(pos)
        off = pos + 1
    return info


def create_microsoft_certify_challenge_response(*, csr, bundle, template: dict, request_id: int, ca: dict) -> dict:
    materials = _resolve_ca_materials_for_tpm(template, ca)

    ket_priv = tpm_mod._load_private_key_from_pem(materials["ket_key_pem"])
    ket_cert_der = tpm_mod.pem_cert_to_der(materials["ket_cert_pem"])

    decrypted = tpm_mod.decrypt_microsoft_ek_info(
        bundle.ms_ek_info_raw,
        ket_cert_der,
        ket_priv,
    )

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

    encryption_algorithm_oid = tpm_mod.extract_encryption_algorithm_for_challenge_response(
        bundle.ms_ek_info_raw
    )

    xchg_cert_der = (materials.get('ca_exchange_chain_der') or [None])[0]
    if xchg_cert_der:
        aik_info_hash = hashlib.sha1(xchg_cert_der).digest()
    else:
        aik_info_hash = None

    blob_meta = _describe_ms_attestation_blob(getattr(bundle, 'ms_attestation_blob_raw', None))
    logger.debug(
        'TPM challenge inputs request_id=%r ek_info_len=%d aik_info_len=%d att_stmt_len=%d att_blob_len=%d '
        'att_blob_sha256=%s att_blob_magic=%r kast_offset=%d pcpm_offsets=%r att_blob_preview=%s',
        request_id,
        len(getattr(bundle, 'ms_ek_info_raw', b'') or b''),
        len(getattr(bundle, 'ms_aik_info_raw', b'') or b''),
        len(getattr(bundle, 'ms_attestation_statement_raw', b'') or b''),
        len(getattr(bundle, 'ms_attestation_blob_raw', b'') or b''),
        blob_meta['sha256'],
        blob_meta['ascii_magic'],
        blob_meta['kast_offset'],
        blob_meta['pcpm_offsets'],
        blob_meta['preview_hex'],
    )

    challenge = tpm_mod.build_and_sign_microsoft_attestation_challenge(
        request_id=int(request_id),
        ek_pub=ek_pub,
        ca_exchange_chain_der=materials["ca_exchange_chain_der"],
        encryption_algorithm_oid=encryption_algorithm_oid,
        aik_info_hash=aik_info_hash,
        aik_pub_raw=getattr(bundle, "ms_aik_info_raw", None),
        attestation_blob_raw=(getattr(bundle, "ms_attestation_statement_raw", None) or getattr(bundle, "ms_attestation_blob_raw", None)),
        signer_cert_pem=materials["ca_sign_cert_pem"],
        signer_key_pem=materials["ca_sign_key_pem"],
        signer_chain_pems=materials["ca_sign_chain_pems"],
    )

    _save_pending_challenge(str(request_id), {
        "mode": "CERTIFY",
        "template_name": template.get("common_name"),
        "spki_sha256": _spki_sha256(csr),
        "secret_b64": base64.b64encode(challenge["secret"]).decode("ascii"),
        "created_at": int(time.time()),
        "encryption_algorithm_oid": encryption_algorithm_oid,
        "ek_cert_present": bool(bundle.ek_cert_der),
    })

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
    }


def verify_tpm_for_template(*, csr_der: bytes, p7_der: Optional[bytes], template: dict, request_id: Optional[int] = None, ca: Optional[dict] = None, extra_request_data: Optional[dict] = None) -> dict:
    policy = _template_tpm_policy(template)
    if not policy:
        return {"status": "ok", "used": False, "attestation_valid": False}

    csr = x509.load_der_x509_csr(csr_der)

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
        if policy["required"]:
            raise ValueError(
                "TPM attestation required by template but no Microsoft key-attestation attributes were found in the PKCS#10 request"
            )
        return {"status": "ok", "used": False, "attestation_valid": False}

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
                "Microsoft AIK_INFO-only key attestation requests are not yet handled by this path; "
                "EK_INFO is required here to build the activation challenge."
            )

    if any(getattr(bundle, field, None) is not None for field in ("aik_pub_raw", "attest_raw", "attest_sig_raw", "certified_key_raw", "nonce")):
        trusted_ek_roots = _load_trusted_ek_roots(template, policy)
        result = tpm_mod.verify_tpm_attestation(
            bundle=bundle,
            trusted_ek_roots=trusted_ek_roots,
            expected_nonce=None,
            require_fixed_tpm=True,
            require_fixed_parent=True,
            require_restricted=True,
        )
        if not result.success:
            raise ValueError(result.message)

        csr_pub = csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if result.certified_key_obj is not None:
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
        }

    if policy["required"]:
        raise ValueError("TPM attestation required but request did not contain usable AIK_INFO/EK_INFO")

    return {"status": "ok", "used": False, "attestation_valid": False}
