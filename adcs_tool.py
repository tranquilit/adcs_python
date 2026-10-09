#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Non-interactive ADCS management, sharing data/operations with Textual UI.

No Textual imports: the server can use ``adcs-tool`` without installing a UI.
The human-readable YAML block printed by ``ca create`` is delegated directly
and unchanged to utils_crt._cmd_create_ca() for shell redirection compatibility.
"""
from __future__ import annotations

import argparse
import shutil
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


class FriendlyArgumentParser(argparse.ArgumentParser):
    """Concise CLI errors with contextual hints instead of a full usage dump."""

    def error(self, message: str) -> None:
        """Show contextual help for invalid or incomplete commands."""
        if (message.startswith('the following arguments are required:')
                or message.startswith('unrecognized arguments:')):
            context = getattr(self, "_active_help_parser", self)
            context.print_help(sys.stderr)
            print(f'\nError: {message}', file=sys.stderr)
            if context.prog.endswith(' ca list') and message.startswith('unrecognized arguments:'):
                extra = message.partition(':')[2].strip()
                if extra and not extra.startswith('-') and len(extra.split()) == 1:
                    root = context.prog[:-len(' ca list')]
                    print(f'Hint: To display a CA, use: {root} ca show {extra}', file=sys.stderr)
                    print(f'      To list all CAs, use: {root} ca list', file=sys.stderr)
            self.exit(2)
        print(f'Error: {message}', file=sys.stderr)
        print(f"Run '{self.prog} --help' for usage.", file=sys.stderr)
        self.exit(2)



OUTPUT_FORMATS = ('table', 'accessible', 'json')


def _default_output_format() -> str:
    value = os.environ.get('ADCS_OUTPUT_FORMAT', 'table').strip().lower()
    return value if value in OUTPUT_FORMATS else 'table'


def _add_output_format(parser: argparse.ArgumentParser, *, json_allowed: bool = True) -> None:
    parser.add_argument('--format', choices=OUTPUT_FORMATS, default=None,
                        help='Output format (default: ADCS_OUTPUT_FORMAT or table).')


def _format(args: argparse.Namespace) -> str:
    return 'json' if getattr(args, 'json', False) else (getattr(args, 'format', None) or _default_output_format())


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
    parser = FriendlyArgumentParser(
        description='Manage ADCS CAs, certificate cache, certificates, callbacks and CRLs without the GUI.',
    )
    parser.add_argument('--confadcs', default='/etc/adcs/adcs.yaml',
                        help='Path of adcs.yaml (default: /etc/adcs/adcs.yaml)')
    commands = parser.add_subparsers(dest='command', metavar='<subcommand>', parser_class=FriendlyArgumentParser)
    # Argument definitions are private templates, not public CLI commands.
    templates = argparse.ArgumentParser(add_help=False)
    definitions = templates.add_subparsers(dest='command')

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = definitions.add_parser(name, help=help_text, description=help_text)
        _add_global_config(sub)
        return sub

    ca_list = command('ca-list', 'List CA identifiers, display names and parent CAs.')
    ca_list.add_argument('--json', action='store_true', help='Output structured JSON.')
    ca_show = command('ca-show', 'Show full configuration details for one CA (secrets redacted).')
    ca_show.add_argument('ca_id', help='CA identifier from ca list (or display name).')
    ca_show.add_argument('--json', action='store_true', help='Output structured JSON.')

    callbacks = command('callback-list', 'List configured callbacks, templates and associated CAs.')
    callbacks.add_argument('--json', action='store_true')

    config = command('config-show', 'Show adcs.yaml options with secret values redacted.')
    config.add_argument('--json', action='store_true')

    cert_list = command('certificate-list', 'Search, filter, sort and limit certificates of a CA via SQLite.')
    cert_list.add_argument('--ca', required=True, help='CA id or display name.')
    cert_list.add_argument('--filter', action='store_true',
                           help='Optional for listing: --status, --revocation and --search always apply.')
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
        selection = sub.add_mutually_exclusive_group(required=True)
        selection.add_argument('--serial', help='Operate on a single hexadecimal certificate serial.')
        if name == 'certificate-delete':
            selection.add_argument('--eligible', action='store_true',
                                   help='Select certificates that are expired OR revoked.')
        selection.add_argument('--filter', action='store_true',
                               help='Select certificates matching --status/--revocation/--search.')
        sub.add_argument('--status', choices=('any', 'expired', 'expiring', 'valid'), default='any')
        sub.add_argument('--revocation', choices=('any', 'revoked', 'not_revoked'), default='any')
        sub.add_argument('--search', default='', help='Case-insensitive metadata search.')
        sub.add_argument('--order-by', default='not_after ASC',
                         help='Allowed fields: ' + ', '.join(ORDER_BY_FIELDS))
        sub.add_argument('--limit', type=int, default=0, help='Maximum selected rows (0 = all).')
        sub.add_argument('--yes', action='store_true',
                         help='Execute filtered operation; otherwise show a preview.')
        sub.add_argument('--dry-run', action='store_true',
                         help='Preview this operation without changing certificates, keys or CRLs.')
        if name != 'certificate-delete':
            sub.add_argument('--next-update-hours', type=int, default=None)

    for source in (ca_list, ca_show, callbacks, config, cert_list, cert_show):
        _add_output_format(source)
    for name in ('certificate-revoke', 'certificate-unrevoke', 'certificate-delete'):
        _add_output_format(definitions.choices[name])

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
    # Public commands are exclusively hierarchical; templates share arguments.
    groups = {
        'ca': ('Certificate authority management.', {'list': 'ca-list', 'show': 'ca-show', 'create': 'ca-create'}),
        'certificate': ('Certificate management.', {
            'list': 'certificate-list', 'show': 'certificate-show',
            'revoke': 'certificate-revoke', 'unrevoke': 'certificate-unrevoke',
            'delete': 'certificate-delete', 'issue': 'certificate-issue',
            'rotate': 'certificate-rotate'}),
        'crl': ('Certificate revocation list management.', {
            'resign': 'crl-resign', 'resign-all': 'crl-resign-all'}),
        'callback': ('Callback configuration.', {'list': 'callback-list'}),
        'config': ('Global configuration.', {'show': 'config-show'}),
        'ket': ('CAExchange certificate management.', {'create': 'ket-create'}),
        'csr': ('Certificate signing requests.', {'submit': 'csr-submit'}),
    }
    # Reuse the internal argument templates without duplicating definitions.
    originals = {name: definitions.choices[name] for _, (_, items) in groups.items()
                 for name in items.values()}
    group_parsers = {}
    action_parsers = {}
    for group_name, (description, items) in groups.items():
        group = commands.add_parser(group_name, help=description, description=description)
        group_parsers[group_name] = group
        _add_global_config(group)
        nested = group.add_subparsers(dest='operation', metavar='<subcommand>', parser_class=FriendlyArgumentParser)
        for short_name, old_name in items.items():
            old = originals[old_name]
            sub = nested.add_parser(short_name, parents=[old], add_help=False,
                                    help=old.description, description=old.description)
            sub.set_defaults(command=old_name)
            action_parsers[(group_name, short_name)] = sub
    commands.metavar = '{' + ','.join(groups) + '}'
    parser._group_parsers = group_parsers
    parser._action_parsers = action_parsers
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


def _table(headers: list[str], rows: list[list[Any]], output_format: str = 'table', *, title: str = 'Record') -> None:
    """Dependency-free readable tables, without truncating certificate identifiers."""
    if output_format == 'json':
        print(json.dumps([dict(zip(headers, row)) for row in rows], ensure_ascii=False, indent=2, default=str))
        return
    if output_format == 'accessible':
        if not rows:
            print('No results.')
        for index, row in enumerate(rows, 1):
            if index > 1:
                print()
            print(f'{title} {index} of {len(rows)}')
            for header, value in zip(headers, row):
                print(f'  {header}: {value if value is not None else "(unset)"}')
        return
    rendered = [[str(value) if value is not None else '' for value in row] for row in rows]
    columns = [str(x) for x in headers]
    widths = [max([len(columns[i])] + [len(row[i]) for row in rendered])
              for i in range(len(columns))]
    def line(values: list[str]) -> str:
        return ' | '.join(value.ljust(width) for value, width in zip(values, widths)).rstrip()
    print(line(columns))
    print('-+-'.join('-' * width for width in widths))
    for row in rendered:
        print(line(row))


def _field_rows(obj: Any) -> list[list[str]]:
    return [line.split(': ', 1) if ': ' in line else [line, '']
            for line in _render_dict_lines('', obj)]


def _output_structure(obj: Any, output_format: str = "table") -> None:
    if output_format == 'json':
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    elif isinstance(obj, list):
        if not obj:
            print('No results.' if output_format == 'accessible' else '(no results)')
        for index, entry in enumerate(obj):
            if index:
                print()
            _table(['Field', 'Value'], _field_rows(entry), output_format)
    else:
        _table(['Field', 'Value'], _field_rows(obj), output_format)


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
        _output_structure(_redact_configuration(settings), _format(args))
        return 0
    if cmd in ('callback-list', 'ca-list', 'ca-show'):
        # Configuration inspection remains usable even without signing keys.
        with open(args.confadcs, 'r', encoding='utf-8') as file:
            settings = yaml.safe_load(file) or {}
        if cmd == 'callback-list':
            _output_structure(public_callback_configuration(settings), _format(args))
        elif cmd == 'ca-show':
            _output_structure(public_ca_configuration(settings, args.ca_id)[0], _format(args))
        else:
            cas = public_ca_configuration(settings)
            summary = [
                {'id': ca.get('id', ''),
                 'display_name': ca.get('display_name', ''),
                 'parent': ca.get('parent', '')}
                for ca in cas
            ]
            if _format(args) == 'json':
                _output_structure(summary, 'json')
            elif summary:
                _table(['CA ID', 'Display name', 'Parent CA'], [
                    [item['id'], item['display_name'], item['parent']]
                    for item in summary
                ], _format(args), title='CA')
            else:
                print('(no CAs configured)')
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
        if _format(args) == 'json':
            _output_structure({'ca': ca['id'], 'total': total,
                               'shown': len(entries), 'certificates': entries}, 'json')
        else:
            if _format(args) == 'accessible':
                print(f"CA: {ca['id']}\nCertificates: {len(entries)} of {total}")
            if _format(args) == 'accessible':
                from datetime import timezone
                now = datetime.now(timezone.utc)
                _table(['Serial', 'Subject', 'Expires', 'Expiration status', 'Revocation status', 'File'], [
                    [e['serial'], e['subject'], e['not_after'],
                     'expired' if datetime.fromisoformat(e['not_after']).replace(tzinfo=timezone.utc) <= now else 'not expired',
                     'revoked' if e['revoked'] else 'not revoked', e['filename']]
                    for e in entries
                ], 'accessible', title='Certificate')
            else:
                _table(['Serial', 'Expires', 'Status', 'Subject', 'File'], [
                    [e['serial'], e['not_after'], 'revoked' if e['revoked'] else 'not revoked',
                     e['subject'], e['filename']] for e in entries
                ], 'table', title='Certificate')
            if _format(args) == 'table':
                print(f'Shown: {len(entries)}/{total}', file=sys.stderr)
        return 0
    if cmd == 'certificate-show':
        ca, cert_dir, record = _record(args, conf)
        detail = json.loads(record['details_json']) if record.get('details_json') else {}
        detail['file'] = os.path.join(cert_dir, record['relative_path'])
        detail['revoked'] = int(str(record['serial_hex']), 16) in _ca_revocations(ca)
        _output_structure(detail, _format(args))
        return 0
    if cmd in ('certificate-revoke', 'certificate-unrevoke'):
        revoke_it = cmd == 'certificate-revoke'
        if args.yes and args.dry_run:
            raise ValueError('--dry-run cannot be combined with --yes')
        if args.serial:
            if args.yes:
                raise ValueError('--yes is only used with --filter')
            ca, _, record = _record(args, conf)
            serial = str(record['serial_hex'])
            if args.dry_run:
                currently_revoked = int(serial, 16) in _ca_revocations(ca)
                _table(['Action', 'CA', 'Serial', 'Current state', 'Planned state'], [[
                    'revoke' if revoke_it else 'unrevoke', ca['id'], serial,
                    'revoked' if currently_revoked else 'not revoked',
                    'revoked' if revoke_it else 'not revoked',
                ]], _format(args), title='Certificate')
                print('DRY RUN: no certificate or CRL modified.', file=sys.stderr if _format(args) == 'json' else sys.stdout)
                return 0
            change_revocation(
                ca, serial, revoke_it=revoke_it,
                next_update_hours=(args.next_update_hours or int(conf['next_update_hours_crl'])),
            )
            print(f"{'Revoked' if revoke_it else 'Unrevoked'} certificate {serial} on CA {ca['id']} (CRL verified).")
            return 0
        if args.status == 'any' and args.revocation == 'any' and not args.search:
            raise ValueError('--filter requires --status, --revocation or --search')
        if args.limit < 0:
            raise ValueError('--limit must be >= 0')
        parse_order_by(args.order_by)
        ca = _ca(conf, args.ca)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        revocations = _ca_revocations(ca)
        rows, total = list_certificate_rows(
            cert_dir, query=args.search,
            status='' if args.status == 'any' else args.status,
            revocation='' if args.revocation == 'any' else args.revocation,
            revoked_serials=revocations, order_by=args.order_by,
            limit=args.limit, synchronize=True,
        )
        candidates = [row for row in rows if not row.is_ca and row.revoked != revoke_it]
        _table(['Serial', 'Expires', 'Current state', 'Planned state', 'Subject'], [
            [row.serial_nox, row.not_after.isoformat(),
             'revoked' if row.revoked else 'not revoked',
             'revoked' if revoke_it else 'not revoked', row.subject]
            for row in candidates
        ], _format(args), title='Certificate')
        if not args.yes:
            print(f'DRY RUN: {len(candidates)} certificate(s) selected from {total} matching row(s). '
                  'Add --yes to execute.', file=sys.stderr if _format(args) == 'json' else sys.stdout)
            return 0
        successes = failures = 0
        for row in candidates:
            try:
                change_revocation(
                    ca, row.serial_nox, revoke_it=revoke_it,
                    next_update_hours=(args.next_update_hours or int(conf['next_update_hours_crl'])),
                )
                successes += 1
            except (OSError, ValueError, PermissionError) as exc:
                failures += 1
                print(f'ERROR: {row.serial_nox}: {exc}', file=sys.stderr)
        print(f"{'Revoked' if revoke_it else 'Unrevoked'}: {successes}; failed: {failures}; selected: {len(candidates)}")
        return 2 if failures else 0
    if cmd == 'certificate-delete':
        ca = _ca(conf, args.ca)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        revocations = _ca_revocations(ca)
        if args.dry_run and args.yes:
            raise ValueError('--dry-run cannot be combined with --yes')
        if args.serial:
            _, _, record = _record(args, conf)
            serial = int(str(record['serial_hex']), 16)
            path = os.path.join(cert_dir, record['relative_path'])
            expires_at = datetime.fromisoformat(record['not_after'])
            if args.dry_run:
                from datetime import timezone
                expiry = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at
                revoked = serial in revocations
                if not revoked and expiry > datetime.now(timezone.utc):
                    raise PermissionError('Certificate must be revoked or expired before deletion')
                if record.get('is_ca'):
                    raise PermissionError('CA certificates cannot be deleted through certificate delete')
                _table(['CA', 'Serial', 'Expires', 'Revoked', 'Certificate'], [[
                    ca['id'], record['serial_hex'], expiry.isoformat(),
                    'yes' if revoked else 'no', path,
                ]], _format(args), title='Certificate')
                print('DRY RUN: certificate and associated key would be moved to .trash; no files modified.', file=sys.stderr if _format(args) == 'json' else sys.stdout)
                return 0
            cert_n, key_n = delete_certificate(
                ca, cert_path=path, revoked=serial in revocations, expires_at=expires_at,
            )
            _sync_certificate_cache(cert_dir)
            print(f"Deleted (moved to .trash): certificate={cert_n}, key={key_n}; serial={record['serial_hex']}")
            return 0
        if args.eligible and (args.status != 'any' or args.revocation != 'any'):
            raise ValueError('--eligible cannot be combined with --status or --revocation; use --filter')
        if args.filter and args.status == 'any' and args.revocation == 'any' and not args.search:
            raise ValueError('--filter requires --status, --revocation or --search')
        if args.limit < 0:
            raise ValueError('--limit must be >= 0')
        parse_order_by(args.order_by)
        rows, _ = list_certificate_rows(
            cert_dir, query=args.search,
            status='' if args.eligible or args.status == 'any' else args.status,
            revocation='' if args.eligible or args.revocation == 'any' else args.revocation,
            revoked_serials=revocations, order_by=args.order_by,
            limit=args.limit, synchronize=True,
        )
        from datetime import timezone
        now = datetime.now(timezone.utc)
        candidates = []
        for row in rows:
            expiration = row.not_after
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=timezone.utc)
            expired = expiration <= now
            if row.is_ca or not (expired or row.revoked):
                continue
            candidates.append((row, expiration))
        _table(['Serial', 'Expires', 'Revoked', 'Subject', 'File'], [
            [r.serial_nox, e.isoformat(), 'yes' if r.revoked else 'no', r.subject, r.filename]
            for r, e in candidates
        ], _format(args), title='Certificate')
        if not args.yes:
            print(f'DRY RUN: {len(candidates)} eligible certificate(s). Add --yes to move to .trash.', file=sys.stderr if _format(args) == 'json' else sys.stdout)
            return 0
        successes = 0
        failures = 0
        for row, expiry in candidates:
            try:
                # The shared action enforces the eligibility and path safety rules.
                delete_certificate(ca, cert_path=os.path.join(cert_dir, row.cache_key),
                                   revoked=row.revoked, expires_at=expiry)
                successes += 1
            except (OSError, ValueError, PermissionError) as exc:
                failures += 1
                print(f'ERROR: {row.serial_nox}: {exc}', file=sys.stderr)
        _sync_certificate_cache(cert_dir)
        print(f'Deleted: {successes}; failed: {failures}; selected: {len(candidates)}')
        return 2 if failures else 0
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


def _complete_words(words: list[str]) -> list[str]:
    """Read-only Bash completion driven by the same argparse definitions as the CLI."""
    parser = build_parser()
    if not words:
        words = ['']
    current, previous = words[-1], words[:-1]
    groups = parser._group_parsers
    group = next((value for value in previous if value in groups), None)
    operation = None
    if group:
        index = previous.index(group)
        operation = previous[index + 1] if len(previous) > index + 1 else None
    context = parser._action_parsers.get((group, operation)) if group and operation else None
    if context is None:
        context = groups.get(group, parser)

    # Resolve current --confadcs without importing services or modifying SQLite.
    config_path = '/etc/adcs/adcs.yaml'
    for index, word in enumerate(previous):
        if word == '--confadcs' and index + 1 < len(previous):
            config_path = previous[index + 1]
        elif word.startswith('--confadcs='):
            config_path = word.split('=', 1)[1]

    def ca_ids():
        try:
            with open(config_path, encoding='utf-8') as stream:
                conf = yaml.safe_load(stream) or {}
            cas = conf.get('cas', []) if isinstance(conf, dict) else []
            if isinstance(cas, dict):
                cas = cas.values()
            return [str(ca['id']) for ca in cas if isinstance(ca, dict) and ca.get('id')]
        except (OSError, yaml.YAMLError, TypeError, ValueError):
            return []

    actions = context._actions
    value_options = {opt: action for action in actions if action.nargs != 0
                     for opt in action.option_strings}
    if previous and previous[-1] in value_options:
        option = previous[-1]
        action = value_options[option]
        if option in ('--ca', '--ca-id', '--signer-ca-id'):
            choices = ca_ids()
        elif action.choices:
            choices = [str(choice) for choice in action.choices]
        elif option == '--order-by':
            choices = [str(field) for field in ORDER_BY_FIELDS]
        else:
            choices = []
    elif current.startswith('--') and '=' in current:
        option, fragment = current.split('=', 1)
        action = value_options.get(option)
        if option in ('--ca', '--ca-id', '--signer-ca-id'):
            choices = [option + '=' + ca for ca in ca_ids()]
        elif action and action.choices:
            choices = [option + '=' + str(choice) for choice in action.choices]
        else:
            choices = []
    elif current.startswith('-'):
        choices = [opt for action in actions for opt in action.option_strings]
    elif group is None:
        choices = list(groups)
    elif operation is None or operation not in [key[1] for key in parser._action_parsers if key[0] == group]:
        choices = [name for g, name in parser._action_parsers if g == group]
    elif group == 'ca' and operation == 'show' and previous[-1] == 'show':
        choices = ca_ids()
    else:
        choices = []
    return sorted(set(choice for choice in choices if choice.startswith(current)))


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == '--_complete':
        for completion in _complete_words(argv[1:]):
            print(completion)
        return 0
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    # argparse reports unknown trailing arguments through the root parser.
    # Keep the help scoped to the deepest matching subcommand.
    matched = [(i, group, operation, action) for (group, operation), action in parser._action_parsers.items()
               for i in range(len(argv) - 1) if argv[i:i + 2] == [group, operation]]
    if matched:
        parser._active_help_parser = max(matched, key=lambda item: item[0])[3]
    else:
        matched_groups = [parser._group_parsers[token] for token in argv if token in parser._group_parsers]
        if matched_groups:
            parser._active_help_parser = matched_groups[0]
    args = parser.parse_args(argv)
    if not getattr(args, 'operation', None):
        group = parser._group_parsers.get(getattr(args, 'command', None))
        (group or parser).print_help()
        return 0
    try:
        return run(args)
    except (ValueError, LookupError, OSError, RuntimeError, PermissionError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
