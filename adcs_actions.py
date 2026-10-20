#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Business operations shared by the non-interactive CLI and the Textual UI.

No imports from Textual or from the command-line interface are allowed here.
"""
from __future__ import annotations
import base64
import os
import shutil
import stat
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from adcs_config import build_templates_for_policy_response, _call_callback_with_params
from callback_loader import load_func
from utils_crt import (
    _cli_find_ca_by_id, _cmd_resign_crl, _compose_fullchain_pem,
    issue_cert_with_new_key, revoke, unrevoke, resign_crl,
    revoked_serials_set, load_certificate_file,
)
from adcs_cert_store import _resolve_storage_paths_from_ca

def _split_sans(values: Optional[List[str]]) -> List[str]:
    if not values:
        return []
    out: List[str] = []
    for item in values:
        if not item:
            continue
        parts = [p.strip() for p in item.replace(";", ",").split(",")]
        out.extend([p for p in parts if p])
    return out


def _decode_pem_or_der_request(raw: bytes) -> bytes:
    data = (raw or b"").strip()
    if not data:
        raise ValueError("empty CSR input")

    if data.startswith(b"-----BEGIN"):
        lines = []
        in_block = False
        for line in data.splitlines():
            stripped = line.strip()
            if stripped.startswith(b"-----BEGIN "):
                if b"CERTIFICATE REQUEST" in stripped or b"NEW CERTIFICATE REQUEST" in stripped:
                    in_block = True
                continue
            if stripped.startswith(b"-----END "):
                if in_block:
                    break
                continue
            if in_block and stripped:
                lines.append(stripped)
        if not lines:
            raise ValueError("PEM CSR block not found")
        return base64.b64decode(b"".join(lines))

    return data


class _EnrollmentRequest:
    def __init__(self, headers: Optional[Dict[str, str]] = None):
        self.headers = headers or {}
        self.host_url = "https://localhost/"


def submit_csr_request(
    *,
    ca_id: str,
    username: str,
    conf: Dict[str, Any],
    csr_data: bytes,
    template_oid: Optional[str] = None,
    template_name: Optional[str] = None,
    auth_method: str = "cli",
    request_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Issue a request from bytes and return status/data, never CLI output."""
    try:
        ca = _cli_find_ca_by_id(conf, ca_id)
        if not ca:
            raise LookupError(f"CA not found: {ca_id}")

        if not username or not username.strip():
            raise ValueError("username is required")

        if not isinstance(csr_data, bytes):
            raise TypeError('csr_data must be bytes (PEM or DER)')
        request_blob = _decode_pem_or_der_request(csr_data)
        from utils import exct_csr_from_cmc  # only CSR enrollment needs Samba
        csr_der, body_part_id, info = exct_csr_from_cmc(request_blob)

        fake_request = _EnrollmentRequest(headers=request_headers)
        templates_for_user, _ = build_templates_for_policy_response(
            conf,
            username=username.strip(),
            request=fake_request,
            auth_method=auth_method,
        )

        tmap = {(t.get("template_oid") or {}).get("value"): t for t in templates_for_user}
        tmap_name = {t.get("common_name"): t for t in templates_for_user}

        selected_template_oid = (template_oid or "").strip()
        selected_template_name = (template_name or "").strip()
        if selected_template_oid and selected_template_name:
            raise ValueError("use either --template-oid or --template-name, not both")

        if selected_template_oid:
            tpl = tmap.get(selected_template_oid)
            if tpl:
                info['oid'] = selected_template_oid
                info['name'] = tpl.get('common_name')
        elif selected_template_name:
            tpl = tmap_name.get(selected_template_name)
            if tpl:
                info['name'] = selected_template_name
                info['oid'] = (tpl.get('template_oid') or {}).get('value')
        elif info.get('oid'):
            tpl = tmap.get(info.get('oid'))
        else:
            tpl = tmap_name.get(info.get('name'))

        if not tpl:
            raise ValueError("The requested template is not valid")

        if ca.get('__refid') not in set(tpl.get('__ca_refids') or []):
            raise PermissionError(
                f"{ca['id']} not in ca_references for template "
                f"{(tpl.get('template_oid') or {}).get('value')}"
            )

        if not ((tpl.get('permissions') or {}).get('enroll')):
            raise PermissionError("You do not have permission to enroll on this template")

        cb = (tpl.get("__callback") if tpl else (conf.get("__default_callback"))) or {}
        cb_path = cb.get("path")
        cb_issue = cb.get("issue")
        if not cb_path or not cb_issue:
            raise ValueError("no issue callback configured for this template")

        emit_certificate = load_func(cb_path, cb_issue)

        request_id = uuid.uuid4().int
        result = _call_callback_with_params(
            emit_certificate,
            params=cb.get("params"),
            csr_der=csr_der,
            request_id=request_id,
            username=username.strip(),
            ca=ca,
            template=tpl,
            info=info,
            app_conf=conf,
            CAID=ca['id'],
            request=fake_request,
            auth_method=auth_method,
            body_part_id=body_part_id,
            p7_der=request_blob,
        )

        os.makedirs(ca['__path_csr'], exist_ok=True)
        csr_path_out = os.path.join(ca['__path_csr'], f"{request_id}.pem")
        if not os.path.isfile(csr_path_out):
            b64_csr = base64.b64encode(csr_der).decode('ascii')
            pem_csr = (
                "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "\n".join(textwrap.wrap(b64_csr, 64)) +
                "\n-----END CERTIFICATE REQUEST-----\n"
            )
            with open(csr_path_out, 'w') as f:
                f.write(pem_csr)

        status = str(result.get("status", "")).lower()
        response = {
            'status': status, 'request_id': str(request_id),
            'ca': ca.get('display_name') or ca.get('id'),
            'username': username.strip(), 'template': tpl.get('common_name'),
            'csr_path': csr_path_out, 'certificate_path': None, 'reason': None,
        }

        if status == "pending":
            os.makedirs(conf['path_list_request_id'], exist_ok=True)
            with open(os.path.join(conf['path_list_request_id'], str(request_id)), 'wb') as f:
                f.write(request_blob)
            return response

        if status == "denied":
            response['reason'] = result.get('status_text') or 'Denied'
            return response

        if status != "issued":
            raise ValueError(f"unknown callback status '{status}'")

        cert_val = result.get("cert")
        if isinstance(cert_val, x509.Certificate):
            cert_obj = cert_val
        elif isinstance(cert_val, (bytes, bytearray, memoryview)):
            cert_obj = x509.load_der_x509_certificate(bytes(cert_val))
        else:
            raise ValueError("Callback(issued) must return 'cert' (x509 or DER bytes)")

        cert_pem = cert_obj.public_bytes(encoding=serialization.Encoding.PEM)
        fullchain_pem = _compose_fullchain_pem(cert_pem, conf=conf, ca=ca)

        os.makedirs(ca['__path_cert'], exist_ok=True)
        cert_path_out = os.path.join(ca['__path_cert'], f"{request_id}.pem")
        with open(cert_path_out, 'wb') as f:
            f.write(fullchain_pem)

        response['certificate_path'] = cert_path_out
        return response

    except Exception:
        raise


def _cmd_issue_cert_cli(
    *,
    ca_id: str,
    common_name: str,
    sans: Optional[List[str]],
    rsa_bits: int,
    valid_days: int,
    conf: Dict[str, Any],
    key_type: str = "rsa",
    ec_curve: str = "secp256r1",
    mldsa_variant: str = "mldsa65",
    crt_path: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        ca = _cli_find_ca_by_id(conf, ca_id)
        if not ca:
            raise LookupError(f"CA not found: {ca_id}")

        if not common_name.strip():
            raise ValueError("--cn is required with --issue-cert")

        if (key_type or "rsa").lower() == "rsa" and int(rsa_bits) not in (2048, 3072, 4096):
            raise ValueError("--rsa-bits must be one of: 2048, 3072, 4096")

        if int(valid_days) <= 0:
            raise ValueError("--valid-days must be > 0")

        result = issue_certificate(
            ca, common_name=common_name, sans=sans, rsa_bits=int(rsa_bits),
            key_type=key_type, ec_curve=ec_curve, mldsa_variant=mldsa_variant,
            valid_days=int(valid_days), conf=conf, fullchain=True,
            crt_path=crt_path, key_path=key_path,
        )
        return {'ca': ca.get('display_name') or ca.get('id'),
                'common_name': common_name.strip(), **result}

    except Exception:
        raise


def _cmd_resign_all_crls(
    *,
    conf: Dict[str, Any],
    next_update_hours: int,
    bump_number: bool = True,
) -> Dict[str, Any]:
    """Return per-CA results; CLI owns human messages and exit codes."""
    results = []
    for ca in (conf.get('cas_list') or []):
        if not ca['__key_obj']:
            continue
        ca_id = ca.get('id')
        name = ca.get('display_name') or ca_id or '<unknown>'
        item = {'ca': ca_id, 'display_name': name,
                'status': 'ok', 'crl_number': None, 'crl_path': None, 'error': None}
        try:
            if not ca_id:
                raise KeyError('Missing CA id')
            crl = _cmd_resign_crl(
                ca_id=ca_id, next_update_hours=next_update_hours,
                bump_number=bump_number, conf=conf,
            )
            item['crl_number'] = crl['crl_number']
            item['crl_path'] = crl['crl_path']
        except Exception as exc:
            item['status'] = 'error'
            item['error'] = str(exc)
        results.append(item)
    ok = sum(item['status'] == 'ok' for item in results)
    return {'total': len(results), 'ok': ok, 'failed': len(results) - ok,
            'results': results}


# ---------------------------------------------------------------------------
# Shared certificate operations. The UI deliberately calls these *functions*,
# not the command-line parser or subprocesses; both front ends have identical
# certificate/CRL semantics and access the same per-user SQLite cache.
# ---------------------------------------------------------------------------


def issue_certificate(
    ca: Dict[str, Any], *, common_name: str, sans: Optional[List[str]] = None,
    rsa_bits: int = 2048, valid_days: int = 365,
    key_type: str = "rsa", ec_curve: str = "secp256r1", mldsa_variant: str = "mldsa65",
    conf: Optional[Dict[str, Any]] = None, fullchain: bool = False,
    crt_path: Optional[str] = None, key_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a leaf cert/key and store them in the CA storage directories.

    ``fullchain=False`` keeps the original Textual UI output (leaf only).
    The historical CLI writes a full chain, so it passes ``fullchain=True``.
    """
    if not common_name or not common_name.strip():
        raise ValueError('Common Name is required')
    if (key_type or "rsa").lower() == "rsa" and int(rsa_bits) not in (2048, 3072, 4096):
        raise ValueError('RSA bits must be 2048, 3072 or 4096')
    if int(valid_days) <= 0:
        raise ValueError('valid_days must be positive')

    cert_dir, private_dir = _resolve_storage_paths_from_ca(ca)
    os.makedirs(cert_dir, exist_ok=True)
    os.makedirs(private_dir, exist_ok=True)
    sans_parsed = _split_sans(sans)
    cert_obj, priv, cert_pem, key_pem = issue_cert_with_new_key(
        ca=ca, common_name=common_name.strip(), subject_sans=sans_parsed,
        key_type=key_type, rsa_key_size=int(rsa_bits),
        ec_curve=ec_curve, mldsa_variant=mldsa_variant,
        validity_seconds=int(valid_days) * 86400, key_export_password=None,
    )
    request_id = uuid.uuid4().int
    stored_cert = os.path.join(cert_dir, f'{request_id}.pem')
    final_key = key_path or os.path.join(private_dir, f'{request_id}.key.pem')
    if fullchain:
        if conf is None:
            raise ValueError('configuration required to generate the full chain')
        output_pem = _compose_fullchain_pem(cert_pem, conf=conf, ca=ca)
    else:
        output_pem = cert_pem

    os.makedirs(os.path.dirname(os.path.abspath(final_key)), exist_ok=True)
    if crt_path:
        os.makedirs(os.path.dirname(os.path.abspath(crt_path)), exist_ok=True)
    with open(stored_cert, 'wb') as f:
        f.write(output_pem)
    if crt_path and os.path.realpath(crt_path) != os.path.realpath(stored_cert):
        shutil.copy2(stored_cert, crt_path)
    with open(final_key, 'wb') as f:
        f.write(key_pem)
    os.chmod(final_key, stat.S_IRUSR | stat.S_IWUSR)
    if isinstance(priv, rsa.RSAPrivateKey):
        key_details = {'key_type': 'rsa', 'rsa_bits': priv.key_size}
    elif isinstance(priv, ec.EllipticCurvePrivateKey):
        key_details = {'key_type': 'ec', 'ec_curve': priv.curve.name}
    else:
        # All ML-DSA variants have distinct concrete private key classes.
        label = (key_type or '').lower().replace('-', '').replace('_', '')
        if label in ('mldsa', 'mldsa44', 'mldsa65', 'mldsa87'):
            selected = label if label != 'mldsa' else mldsa_variant
            selected = selected.lower().replace('ml-dsa-', 'mldsa').replace('mldsa', '')
            key_details = {'key_type': 'mldsa', 'mldsa_variant': 'mldsa' + selected}
        else:
            key_details = {'key_type': (key_type or '').lower()}
    return {
        'certificate_path': stored_cert, 'key_path': final_key,
        'copied_certificate_path': crt_path, 'serial': format(cert_obj.serial_number, 'x'),
        'sans': sans_parsed, **key_details,
    }


def _ca_crl_context(ca: Dict[str, Any]) -> tuple[Any, Any, str]:
    crl_path = (ca.get('crl') or {}).get('path_crl')
    if not crl_path:
        raise ValueError('Missing crl.path_crl in CA config')
    key = ca.get('__key_obj')
    if key is None:
        raise PermissionError('CA private signing key is not available')
    cert_der = ca.get('__certificate_der')
    if not cert_der:
        raise ValueError('CA certificate is not available')
    return key, x509.load_der_x509_certificate(cert_der), crl_path


def change_revocation(
    ca: Dict[str, Any], serial: str | List[str], *, revoke_it: bool,
    next_update_hours: int,
) -> Set[int]:
    """Sign one CRL for all serials and verify their new status."""
    ca_key, ca_cert, crl_path = _ca_crl_context(ca)
    serials = [serial] if isinstance(serial, str) else serial
    if not serials:
        return revoked_serials_set(crl_path)
    operation = revoke if revoke_it else unrevoke
    operation(ca_key=ca_key, ca_cert=ca_cert, serial=serials,
              crl_path=crl_path, next_update_hours=next_update_hours)
    current = revoked_serials_set(crl_path)
    if any((int(str(s).removeprefix('0x'), 16) in current) != revoke_it for s in serials):
        raise RuntimeError('CRL verification failed after revocation change')
    return current


def resign_ca_crl(
    ca: Dict[str, Any], *, next_update_hours: int, bump_number: bool = True,
) -> tuple[int, Set[int]]:
    ca_key, ca_cert, crl_path = _ca_crl_context(ca)
    new_number = resign_crl(
        ca_key=ca_key, ca_cert=ca_cert, crl_path=crl_path,
        bump_number=bump_number, next_update_hours=next_update_hours,
    )
    return new_number, revoked_serials_set(crl_path)


def _trashify(path: str) -> str:
    directory = os.path.dirname(path)
    trash_dir = os.path.join(directory, '.trash')
    os.makedirs(trash_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    return os.path.join(trash_dir, f'{os.path.basename(path)}.{timestamp}.{uuid.uuid4().hex[:8]}.trash')


def validate_certificate_deletion(
    ca: Dict[str, Any], *, cert_path: str, revoked: bool,
    expires_at: datetime,
) -> tuple[str, str]:
    """Check a deletion against live certificate data without changing files.

    Fails *closed*: a CA certificate or a currently valid and non-revoked
    certificate is never removed. This check must live in the shared action,
    not only in the CLI or GUI previews. The path must remain inside the CA dir.
    """
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not revoked and expires_at > datetime.now(timezone.utc):
        raise PermissionError('Certificate must be revoked or expired before deletion')
    cert_dir, private_dir = _resolve_storage_paths_from_ca(ca)
    cert_real = os.path.realpath(cert_path)
    dir_real = os.path.realpath(cert_dir)
    if os.path.commonpath([cert_real, dir_real]) != dir_real or cert_real == dir_real:
        raise ValueError('Certificate path is outside the CA storage directory')
    if not os.path.isfile(cert_real):
        raise FileNotFoundError(cert_real)
    # Re-read the actual certificate rather than trusting potentially stale
    # SQLite metadata or the CLI-provided eligibility flags. Missing/invalid
    # certificate data must not silently bypass this protection.
    cert = load_certificate_file(cert_real)
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = None
    ca_public_path = ((ca.get('pem') or {}).get('certificate_path_pem'))
    if (constraints is not None and constraints.ca) or (
        ca_public_path and os.path.realpath(str(ca_public_path)) == cert_real
    ):
        raise PermissionError('CA certificates cannot be deleted through certificate delete')
    actual_expiration = getattr(cert, 'not_valid_after_utc', None)
    if actual_expiration is None:
        actual_expiration = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not revoked and actual_expiration > datetime.now(timezone.utc):
        raise PermissionError('Certificate must be revoked or expired before deletion')
    return cert_real, private_dir


def delete_certificate(
    ca: Dict[str, Any], *, cert_path: str, revoked: bool,
    expires_at: datetime,
) -> tuple[int, int]:
    """Move an eligible leaf certificate and its key to .trash."""
    cert_real, private_dir = validate_certificate_deletion(
        ca, cert_path=cert_path, revoked=revoked, expires_at=expires_at,
    )
    fname = os.path.basename(cert_real)
    if fname.endswith('.crt.pem'):
        key_name = fname[:-8] + '.key.pem'
    else:
        key_name = os.path.splitext(fname)[0] + '.key.pem'
    key_path = os.path.join(private_dir, key_name)
    # Prepare target paths first, so failures are not confused with success.
    trash_cert = _trashify(cert_real)
    os.replace(cert_real, trash_cert)
    removed_key = 0
    if os.path.isfile(key_path):
        os.replace(key_path, _trashify(key_path))
        removed_key = 1
    return 1, removed_key


def public_ca_configuration(
    settings: Dict[str, Any], selected_ca: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Public CA info from YAML, including inherited paths without secrets.

    Does not load CA signing keys or certificates merely to list paths.
    """
    global_storage = ((settings.get('global') or {}).get('storage_paths') or {})
    entries = []
    for ca in settings.get('cas') or []:
        if selected_ca and selected_ca not in (ca.get('id'), ca.get('display_name')):
            continue
        item = _redact_configuration({
            key: value for key, value in ca.items() if not str(key).startswith('__')
        })
        sp = ca.get('storage_paths') or {}
        item['effective_storage_paths'] = {
            'cert_dir': (sp.get('cert_dir') or sp.get('certs_dir')
                         or global_storage.get('cert_dir', '/tmp/certs')),
            'csr_dir': sp.get('csr_dir') or global_storage.get('csr_dir', '/tmp/csr'),
            'private_dir': (sp.get('private_dir')
                            or global_storage.get('private_dir')
                            or sp.get('cert_dir')
                            or sp.get('certs_dir')
                            or global_storage.get('cert_dir', '/tmp/certs')),
        }
        item['parent'] = ca.get('issuer_ca_id') or '(self-signed/root)'
        entries.append(item)
    if selected_ca and not entries:
        raise LookupError(f'CA not found: {selected_ca}')
    return entries


def public_callback_configuration(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Template/auth callbacks and associated CAs, without exposing secrets."""
    entries = []
    for decl in settings.get('templates') or []:
        cb = decl.get('callback') or {}
        entries.append({
            'type': 'certificate_template',
            'path': cb.get('path'),
            'define': cb.get('define', 'define_template'),
            'issue': cb.get('issue', 'emit_certificate'),
            'ca_references': (cb.get('params') or {}).get('ca_references') or [],
            'auth_methods': (cb.get('auth_methods') if cb.get('auth_methods') is not None
                             else ['kerberos', 'username_password', 'tls']),
            'params': _redact_configuration(cb.get('params') or {}),
        })
    for decl in settings.get('auth') or []:
        if 'callback' in decl:
            entries.append({
                'type': 'authentication',
                **_redact_configuration(decl['callback'] or {}),
            })
    return entries


def _redact_configuration(value: Any) -> Any:
    """Prevent secrets loaded from adcs.yaml being emitted on stdout."""
    if isinstance(value, dict):
        return {k: ('<redacted>' if any(
            secret in str(k).lower() for secret in
            ('pin', 'password', 'passphrase', 'secret', 'token', 'private_key'))
            else _redact_configuration(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_configuration(item) for item in value]
    return value
