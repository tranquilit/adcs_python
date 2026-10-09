#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Non-interactive ADCS management, sharing data/operations with Textual UI.

No Textual imports: the server can use ``adcs-tool`` without installing a UI.
The human-readable YAML block printed by ``ca-create`` is delegated directly
and unchanged to utils_crt._cmd_create_ca() for shell redirection compatibility.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict

import yaml

from adcs_config import load_yaml_conf
from adcs_actions import (
    _cmd_issue_cert_cli, _cmd_resign_all_crls, _cmd_submit_csr_cli,
    _redact_configuration, public_ca_configuration, public_callback_configuration,
    change_revocation, delete_certificate, resign_ca_crl,
)
from adcs_cert_store import (
    MAX_ROWS_DEFAULT, ORDER_BY_FIELDS, _resolve_storage_paths_from_ca,
    _sync_certificate_cache, cached_certificate_by_serial,
    list_certificate_rows, parse_order_by,
)
from utils_crt import (
    _cli_find_ca_by_id, _cmd_create_ca, _cmd_create_ket_cert,
    _cmd_rotate_if_expiring, revoked_serials_set,
)


def _default_limit() -> int:
    try:
        value = int(os.getenv('ADCS_MAX_ROWS', str(MAX_ROWS_DEFAULT)))
        return value if value > 0 else MAX_ROWS_DEFAULT
    except ValueError:
        return MAX_ROWS_DEFAULT


def _add_global_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--confadcs', default=argparse.SUPPRESS,
        help='Path of the adcs.yaml configuration (also accepted before the command).',
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Manage ADCS CAs, certificate cache, certificates, callbacks and CRLs without the GUI.',
    )
    parser.add_argument('--confadcs', default='/etc/adcs/adcs.yaml',
                        help='Path of adcs.yaml (default: /etc/adcs/adcs.yaml)')
    commands = parser.add_subparsers(dest='command', required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text, description=help_text)
        _add_global_config(sub)
        return sub

    ca_list = command('ca-list', 'List CAs, parents, paths, AIA/CRL URLs and HSM settings.')
    ca_list.add_argument('--json', action='store_true', help='Output structured JSON.')
    ca_list.add_argument('--ca', help='Display one CA only (id or display name).')

    callbacks = command('callback-list', 'List configured callbacks, templates and associated CAs.')
    callbacks.add_argument('--json', action='store_true')

    config = command('config-show', 'Show adcs.yaml options with secret values redacted.')
    config.add_argument('--json', action='store_true')

    cert_list = command('certificate-list', 'Search, filter, sort and limit certificates of a CA via SQLite.')
    cert_list.add_argument('--ca', required=True, help='CA id or display name.')
    cert_list.add_argument('--search', '--query', default='', help='Case-insensitive substring search in certificate metadata.')
    cert_list.add_argument('--status', choices=('any', 'expired', 'expiring', 'valid'), default='any',
                           help='Expiration: expired; expiring within 30 days; valid for more than 30 days.')
    cert_list.add_argument('--revocation', choices=('any', 'revoked', 'not_revoked'), default='any')
    cert_list.add_argument('--limit', type=int, default=_default_limit(),
                           help='Maximum rows (default 1000 or ADCS_MAX_ROWS, 0 = unlimited).')
    cert_list.add_argument('--order-by', metavar='FIELD [ASC|DESC][, ...]',
                           default='not_before ASC',
                           help='Allowed fields: ' + ', '.join(ORDER_BY_FIELDS)
                           + '. Example: "expiration_date ASC, serial DESC".')
    cert_list.add_argument('--json', action='store_true', help='Include total filtered count and certificate rows as JSON.')

    cert_show = command('certificate-show', 'Show full SQLite-cached certificate details by CA and serial.')
    cert_show.add_argument('--ca', required=True)
    cert_show.add_argument('--serial', required=True, help='Certificate serial in hexadecimal (with or without 0x).')
    cert_show.add_argument('--json', action='store_true')

    for name, desc in (
        ('certificate-revoke', 'Revoke one certificate by CA and serial; update CRL.'),
        ('certificate-unrevoke', 'Remove one certificate serial from CRL.'),
        ('certificate-delete', 'Move an expired or revoked certificate and its key to .trash.'),
    ):
        sub = command(name, desc)
        sub.add_argument('--ca', required=True)
        sub.add_argument('--serial', required=True, help='Hexadecimal certificate serial number.')
        if name != 'certificate-delete':
            sub.add_argument('--next-update-hours', type=int, default=None)

    resign = command('crl-resign', 'Re-sign CRL of one CA.')
    resign.add_argument('--ca', required=True)
    resign.add_argument('--no-bump-number', action='store_true')
    resign.add_argument('--next-update-hours', type=int, default=None)

    resign_all = command('crl-resign-all', 'Re-sign CRLs of all writable CAs.')
    resign_all.add_argument('--no-bump-number', action='store_true')
    resign_all.add_argument('--next-update-hours', type=int, default=None)

    ca_create = command('ca-create', 'Create a root/intermediate CA; stdout YAML block is unchanged.')
    ca_create.add_argument('--cn', required=True)
    ca_create.add_argument('--signer-ca-id', '--ca-id', '--ca', dest='ca', default=None,
                           help='Issuer CA, omit for a self-signed root CA.')
    ca_create.add_argument('--aia-crl-base-url', required=True)
    ca_create.add_argument('--crt-path')
    ca_create.add_argument('--key-path')
    ca_create.add_argument('--crl-path')
    ca_create.add_argument('--rsa-bits', type=int, default=4096)
    ca_create.add_argument('--key-type', default='rsa',
                           choices=('rsa', 'ec', 'ecc', 'ecdsa', 'mldsa', 'ml-dsa', 'mldsa44', 'mldsa65',
                                    'mldsa87', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'))
    ca_create.add_argument('--ec-curve', default='secp256r1')
    ca_create.add_argument('--mldsa-variant', default='mldsa65')
    ca_create.add_argument('--csr-path', help='Use only the CSR public key for the CA.')
    ca_create.add_argument('--valid-days', type=int, default=3650)

    cert_issue = command('certificate-issue', 'Issue a leaf certificate and private key.')
    cert_issue.add_argument('--ca', '--signer-ca-id', required=True, dest='ca')
    cert_issue.add_argument('--cn', required=True)
    cert_issue.add_argument('--san', action='append', help='SANs; repeat or comma-separate.')
    cert_issue.add_argument('--crt-path')
    cert_issue.add_argument('--key-path')
    cert_issue.add_argument('--rsa-bits', type=int, default=3072)
    cert_issue.add_argument('--valid-days', type=int, default=365)

    ket_create = command('ket-create', 'Create a Microsoft CAExchange/KET certificate.')
    ket_create.add_argument('--ca', '--ca-id', required=True, dest='ca')
    ket_create.add_argument('--cn')
    ket_create.add_argument('--crt-path')
    ket_create.add_argument('--key-path')
    ket_create.add_argument('--rsa-bits', type=int, default=4096)
    ket_create.add_argument('--valid-days', type=int, default=3650)

    submit = command('csr-submit', 'Submit a CSR through the same enrollment callback as the server.')
    submit.add_argument('--ca', '--signer-ca-id', required=True, dest='ca')
    submit.add_argument('--username', required=True)
    submit.add_argument('--csr-path', help='Input PEM or DER file (stdin if omitted).')
    group = submit.add_mutually_exclusive_group()
    group.add_argument('--template-oid')
    group.add_argument('--template-name')

    rotate = command('certificate-rotate', 'Replace an expiring key and leaf certificate.')
    rotate.add_argument('--ca', '--signer-ca-id', required=True, dest='ca')
    rotate.add_argument('--crt-path', required=True)
    rotate.add_argument('--key-path', required=True)
    rotate.add_argument('--threshold-days', type=int, default=30)
    rotate.add_argument('--valid-days', type=int, default=365)
    rotate.add_argument('--no-write-fullchain-to-crt', action='store_true')
    return parser


def _render_dict_lines(prefix: str, obj: Any) -> list[str]:
    if isinstance(obj, dict):
        result = []
        for key, value in obj.items():
            result.extend(_render_dict_lines(f'{prefix}.{key}' if prefix else str(key), value))
        return result
    if isinstance(obj, list):
        return [f'{prefix}: ' + json.dumps(obj, ensure_ascii=False, default=str)]
    return [f'{prefix}: {obj if obj is not None else "(unset)"}']


def _output_structure(obj: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    elif isinstance(obj, list):
        for entry in obj:
            for line in _render_dict_lines('', entry):
                print(line)
            print()
    else:
        for line in _render_dict_lines('', obj):
            print(line)


def _ca(conf: Dict[str, Any], name: str) -> Dict[str, Any]:
    ca = _cli_find_ca_by_id(conf, name)
    if ca is None:
        raise LookupError(f'CA not found: {name}')
    return ca


def _load(args: argparse.Namespace, read_only: bool = True) -> Dict[str, Any]:
    return load_yaml_conf(args.confadcs, bypass_read_only=read_only)


def _ca_revocations(ca: Dict[str, Any]) -> set[int]:
    return revoked_serials_set((ca.get('crl') or {}).get('path_crl'))


def _record(args: argparse.Namespace, conf: Dict[str, Any]):
    ca = _ca(conf, args.ca)
    cert_dir, _ = _resolve_storage_paths_from_ca(ca)
    _sync_certificate_cache(cert_dir)
    record = cached_certificate_by_serial(cert_dir, args.serial)
    return ca, cert_dir, record


def _create_ca(args: argparse.Namespace) -> int:
    # Preserve stdout *byte-for-byte* with the historical CA creation logic:
    # the direct call below alone prints the YAML block for >> adcs.yaml.
    if args.aia_crl_base_url.lower().startswith('https://'):
        raise ValueError('--aia-crl-base-url must not start with https://')
    if args.valid_days <= 0:
        raise ValueError('--valid-days must be positive')
    basename = args.cn.lower().replace(' ', '_')
    crt_path = args.crt_path or f'/var/lib/adcs/pki/certs/{basename}/{basename}.crt.pem'
    key_path = args.key_path or f'/var/lib/adcs/pki/private/{basename}/{basename}.key.pem'
    crl_path = args.crl_path or f'/var/lib/adcs/pki/crl/{basename}/{basename}.crl'
    conf = _load(args, read_only=False) if args.ca else None
    return _cmd_create_ca(
        ca_id=args.ca, crt_path=crt_path, key_path=key_path,
        crl_path=crl_path, aia_crl_base_url=args.aia_crl_base_url,
        valid_days=args.valid_days, rsa_key_size=args.rsa_bits,
        key_type=args.key_type, ec_curve=args.ec_curve,
        mldsa_variant=args.mldsa_variant, conf=conf, cn=args.cn,
        csr_path=args.csr_path,
    )


def run(args: argparse.Namespace) -> int:
    cmd = args.command
    if cmd == 'ca-create':
        return _create_ca(args)
    if cmd == 'config-show':
        with open(args.confadcs, 'r', encoding='utf-8') as file:
            settings = yaml.safe_load(file) or {}
        _output_structure(_redact_configuration(settings), args.json)
        return 0
    if cmd in ('callback-list', 'ca-list'):
        # Configuration inspection remains usable even without signing keys.
        with open(args.confadcs, 'r', encoding='utf-8') as file:
            settings = yaml.safe_load(file) or {}
        if cmd == 'callback-list':
            _output_structure(public_callback_configuration(settings), args.json)
        else:
            _output_structure(public_ca_configuration(settings, args.ca), args.json)
        return 0

    read_only = cmd in ('certificate-list', 'certificate-show', 'certificate-delete')
    conf = _load(args, read_only=read_only)
    if cmd == 'certificate-list':
        if args.limit < 0:
            raise ValueError('limit must be >= 0 (0 means unlimited)')
        parse_order_by(args.order_by)
        ca = _ca(conf, args.ca)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        records, total = list_certificate_rows(
            cert_dir, query=args.search,
            status='' if args.status == 'any' else args.status,
            revocation='' if args.revocation == 'any' else args.revocation,
            revoked_serials=_ca_revocations(ca), order_by=args.order_by,
            limit=args.limit, synchronize=True,
        )
        entries = [{
            'serial': row.serial_nox, 'subject': row.subject,
            'not_before': row.not_before.isoformat(),
            'not_after': row.not_after.isoformat(),
            'days_to_expiry': row.days_to_expiry,
            'revoked': row.revoked, 'is_ca': row.is_ca,
            'filename': row.filename, 'relative_path': row.cache_key,
            'sha256': row.sha256_fingerprint,
        } for row in records]
        if args.json:
            _output_structure({'ca': ca['id'], 'total': total,
                               'shown': len(entries), 'certificates': entries}, True)
        else:
            for e in entries:
                print(f"{e['serial']}\t{e['not_after']}\t{'revoked' if e['revoked'] else 'active'}\t{e['subject']}\t{e['filename']}")
            print(f'Shown: {len(entries)}/{total}', file=sys.stderr)
        return 0
    if cmd == 'certificate-show':
        ca, cert_dir, record = _record(args, conf)
        detail = json.loads(record['details_json']) if record.get('details_json') else {}
        detail['file'] = os.path.join(cert_dir, record['relative_path'])
        detail['revoked'] = int(str(record['serial_hex']), 16) in _ca_revocations(ca)
        _output_structure(detail, args.json)
        return 0
    if cmd in ('certificate-revoke', 'certificate-unrevoke'):
        ca, _, record = _record(args, conf)
        revoke_it = cmd == 'certificate-revoke'
        serial = str(record['serial_hex'])
        change_revocation(
            ca, serial, revoke_it=revoke_it,
            next_update_hours=(args.next_update_hours or int(conf['next_update_hours_crl'])),
        )
        print(f"{'Revoked' if revoke_it else 'Unrevoked'} certificate {serial} on CA {ca['id']} (CRL verified).")
        return 0
    if cmd == 'certificate-delete':
        ca, cert_dir, record = _record(args, conf)
        serial = int(str(record['serial_hex']), 16)
        revoked = serial in _ca_revocations(ca)
        path = os.path.join(cert_dir, record['relative_path'])
        expires_at = datetime.fromisoformat(record['not_after'])
        cert_n, key_n = delete_certificate(
            ca, cert_path=path, revoked=revoked, expires_at=expires_at,
        )
        _sync_certificate_cache(cert_dir)
        print(f"Deleted (moved to .trash): certificate={cert_n}, key={key_n}; serial={record['serial_hex']}")
        return 0
    if cmd == 'crl-resign':
        ca = _ca(conf, args.ca)
        number, serials = resign_ca_crl(
            ca, next_update_hours=args.next_update_hours or int(conf['next_update_hours_crl']),
            bump_number=not args.no_bump_number,
        )
        print(f"CRL re-signed for CA {ca['id']} (CRLNumber {number}, {len(serials)} revoked serials).")
        return 0
    if cmd == 'crl-resign-all':
        ok, fail, messages = _cmd_resign_all_crls(
            conf=conf, next_update_hours=args.next_update_hours or int(conf['next_update_hours_crl']),
            bump_number=not args.no_bump_number,
        )
        for line in messages:
            print(line)
        if not fail:
            print(f'All CRLs re-signed successfully ({ok}/{ok + fail}).')
            return 0
        print(f'Partial result: ok={ok}, failed={fail}', file=sys.stderr)
        return 2 if ok else 1
    if cmd == 'certificate-issue':
        return _cmd_issue_cert_cli(
            ca_id=args.ca, common_name=args.cn, sans=args.san,
            rsa_bits=args.rsa_bits, valid_days=args.valid_days,
            conf=conf, crt_path=args.crt_path, key_path=args.key_path,
        )
    if cmd == 'ket-create':
        return _cmd_create_ket_cert(
            ca_id=args.ca, common_name=args.cn or f'{args.ca}-Xchg',
            conf=conf, crt_path=args.crt_path, key_path=args.key_path,
            rsa_bits=args.rsa_bits, valid_days=args.valid_days,
        )
    if cmd == 'csr-submit':
        return _cmd_submit_csr_cli(
            ca_id=args.ca, username=args.username, conf=conf,
            csr_path=args.csr_path, template_oid=args.template_oid,
            template_name=args.template_name,
        )
    if cmd == 'certificate-rotate':
        return _cmd_rotate_if_expiring(
            ca_id=args.ca, crt_path=args.crt_path, key_path=args.key_path,
            threshold_days=args.threshold_days, conf=conf,
            write_fullchain_to_crt=not args.no_write_fullchain_to_crt,
            valid_days=args.valid_days,
        )
    raise ValueError(f'Unknown command: {cmd}')


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (ValueError, LookupError, OSError, RuntimeError, PermissionError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
