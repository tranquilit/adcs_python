#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Non-interactive ADCS management, sharing data/operations with Textual UI.

No Textual imports: the server can use ``adcs-tool`` without installing a UI.
CA and KET creation write their YAML configuration directly to adcs.yaml.
"""
from __future__ import annotations

import argparse
import shutil
import json
import os
import sys
import stat
import tempfile
from io import StringIO
from datetime import datetime
from contextlib import contextmanager, nullcontext
from functools import lru_cache
from typing import Any, Callable, Dict, Literal, Mapping, TypedDict

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedSeq
from ruamel.yaml.error import YAMLError
from adcs_cli_progress import CliProgress

yaml = YAML(typ="safe")

from adcs_config import load_yaml_conf
from adcs_actions import (
    _cmd_issue_cert_cli, _cmd_resign_all_crls, submit_csr_request,
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


def build_parser(parser_class=FriendlyArgumentParser) -> argparse.ArgumentParser:
    parser = parser_class(
        description='Manage ADCS CAs, certificate cache, certificates, callbacks and CRLs without the GUI.',
    )
    parser.add_argument('--confadcs', default='/etc/adcs/adcs.yaml',
                        help='Path of adcs.yaml (default: /etc/adcs/adcs.yaml)')
    commands = parser.add_subparsers(dest='command', metavar='<subcommand>', parser_class=parser_class)
    # Argument definitions are private templates, not public CLI commands.
    templates = argparse.ArgumentParser(add_help=False)
    definitions = templates.add_subparsers(dest='command', parser_class=parser_class)

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

    ca_create = command('ca-create', 'Create a root/intermediate CA and update adcs.yaml.')
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
        nested = group.add_subparsers(dest='operation', metavar='<subcommand>', parser_class=parser_class)
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


def _ca_revocations(ca: Dict[str, Any]) -> set[int]:
    return revoked_serials_set((ca.get('crl') or {}).get('path_crl'))


def _config_yaml(path):
    editor = YAML()
    editor.preserve_quotes = True
    editor.indent(mapping=2, sequence=4, offset=2)
    with open(path, encoding='utf-8') as stream:
        document = editor.load(stream)
    if not isinstance(document, dict):
        raise ValueError('Invalid adcs.yaml: expected a mapping')
    if document.get('cas') is None:
        document['cas'] = CommentedSeq()
    cas = document['cas']
    if not isinstance(cas, list) or any(not isinstance(ca, dict) for ca in cas):
        raise ValueError('Invalid adcs.yaml: cas must be a list of mappings')
    return editor, document, cas


def _save_config(path, editor, document):
    output = StringIO()
    editor.dump(document, output)
    target = os.path.realpath(path)
    info = os.stat(target)
    fd, temporary = tempfile.mkstemp(dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            for attr in os.listxattr(target):
                os.setxattr(temporary, attr, os.getxattr(target, attr))
            stream.write(output.getvalue())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class BatchResult(TypedDict):
    """Bulk revoke/unrevoke/delete result (preview or applied).

    All counts are integers; errors contain {serial, error} mappings.
    ``dry_run`` indicates a preview, not whether it succeeded.
    """
    action: str
    ca: str
    dry_run: bool
    total: int
    selected: int
    candidates: list[dict[str, Any]]
    successes: int
    failures: int
    errors: list[dict[str, str]]


class CrlItemResult(TypedDict):
    """One CA: error is set on failure, CRL fields on success."""
    ca: str
    display_name: str
    status: Literal['ok', 'error']
    crl_number: int | None
    crl_path: str | None
    error: str | None


class CrlBatchResult(TypedDict):
    """Results of a CRL re-sign batch; skipped CAs are not counted."""
    total: int
    ok: int
    failed: int
    results: list[CrlItemResult]


class CertificateListResult(TypedDict):
    """Filtered certificate listing, with total before the requested limit."""
    ca: str
    total: int
    shown: int
    certificates: list[dict[str, Any]]


class CsrSubmissionResult(TypedDict):
    """CSR status: issued/pending/denied; request_id is a decimal string.

    certificate_path is set only when issued; reason only when denied.
    """
    status: Literal['issued', 'pending', 'denied']
    request_id: str
    ca: str
    username: str
    template: str
    csr_path: str
    certificate_path: str | None
    reason: str | None


@lru_cache(maxsize=1)
def _callback_flask_app():
    from flask import Flask
    return Flask('adcs_tool_callbacks')


@contextmanager
def _callback_flask_context(values, request_headers=None):
    """Run unchanged Flask-g callbacks inside an isolated request context."""
    from flask import current_app, g, has_app_context, has_request_context

    app = current_app._get_current_object() if has_app_context() else _callback_flask_app()
    scope = (nullcontext() if has_request_context() else
             app.test_request_context(base_url='https://localhost/',
                                      headers=dict(request_headers or {})))
    with scope:
        missing = object()
        previous = {key: getattr(g, key, missing) for key in values}
        for key, value in values.items():
            setattr(g, key, value)
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is missing:
                    try:
                        delattr(g, key)
                    except AttributeError:
                        pass
                else:
                    setattr(g, key, value)


class AdcsTool:
    """Python API: named arguments, native results and Python exceptions.

    No CLI parsing or printing occurs in these methods. The CLI uses this same
    API from run(), then formats its results in main().
    """

    def __init__(self, config_path: str = '/etc/adcs/adcs.yaml', *,
                 cache_progress: Callable[[int, int, int], None] | None = None,
                 cache_status: Callable[[str], None] | None = None):
        self.config_path = os.fspath(config_path)
        # Optional display callbacks; the Python API remains silent by default.
        self._cache_progress = cache_progress
        self._cache_status = cache_status

    def _sync_cache(self, cert_dir: str) -> dict[str, int]:
        return _sync_certificate_cache(
            cert_dir, progress=self._cache_progress, status=self._cache_status,
        )

    def _status(self, message: str) -> None:
        if self._cache_status is not None:
            self._cache_status(message)

    def _settings(self) -> Dict[str, Any]:
        # Listing configuration never loads private keys.
        with open(self.config_path, encoding='utf-8') as stream:
            return yaml.load(stream) or {}

    def _conf(self, *, read_only: bool = False) -> Dict[str, Any]:
        return load_yaml_conf(self.config_path, bypass_read_only=read_only)

    def _record(self, conf: Dict[str, Any], ca_id: str, serial: str):
        ca = _ca(conf, ca_id)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        self._sync_cache(cert_dir)
        self._status("Looking up certificate in SQLite cache...")
        record = cached_certificate_by_serial(cert_dir, serial)
        return ca, cert_dir, record

    @staticmethod
    def _filters(status: str, revocation: str, limit: int, order_by: str):
        if status not in ('any', 'expired', 'expiring', 'valid'):
            raise ValueError(f'Invalid certificate status: {status}')
        if revocation not in ('any', 'revoked', 'not_revoked'):
            raise ValueError(f'Invalid revocation status: {revocation}')
        if not isinstance(limit, int) or limit < 0:
            raise ValueError('limit must be >= 0 (0 means unlimited)')
        parse_order_by(order_by)

    def list_cas(self) -> list[dict[str, Any]]:
        return [
            {'id': ca.get('id', ''), 'display_name': ca.get('display_name', ''),
             'parent': ca.get('parent', '')}
            for ca in public_ca_configuration(self._settings())
        ]

    def show_ca(self, ca_id: str) -> dict[str, Any]:
        return public_ca_configuration(self._settings(), ca_id)[0]

    def show_config(self) -> dict[str, Any]:
        return _redact_configuration(self._settings())

    def list_callbacks(self) -> list[dict[str, Any]]:
        return public_callback_configuration(self._settings())

    def create_ca(self, cn: str, aia_crl_base_url: str, *, signer_ca_id=None,
                  csr_path=None, crt_path=None, key_path=None, crl_path=None,
                  rsa_bits=4096, key_type='rsa', ec_curve='secp256r1',
                  mldsa_variant='mldsa65', valid_days=3650) -> dict[str, Any]:
        if aia_crl_base_url.lower().startswith('https://'):
            raise ValueError('--aia-crl-base-url must not start with https://')
        if valid_days <= 0:
            raise ValueError('--valid-days must be positive')
        if key_type not in ('rsa', 'ec', 'ecc', 'ecdsa', 'mldsa', 'ml-dsa', 'mldsa44',
                            'mldsa65', 'mldsa87', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'):
            raise ValueError(f'Invalid CA key type: {key_type}')
        basename = cn.lower().replace(' ', '_')
        crt_path = os.fspath(crt_path) if crt_path is not None else f'/var/lib/adcs/pki/certs/{basename}/{basename}.crt.pem'
        key_path = os.fspath(key_path) if key_path is not None else f'/var/lib/adcs/pki/private/{basename}/{basename}.key.pem'
        crl_path = os.fspath(crl_path) if crl_path is not None else f'/var/lib/adcs/pki/crl/{basename}/{basename}.crl'
        csr_path = os.fspath(csr_path) if csr_path is not None else None
        editor, document, cas = _config_yaml(self.config_path)
        if any(basename in (ca.get('id'), ca.get('display_name'))
               or cn.strip() in (ca.get('id'), ca.get('display_name')) for ca in cas):
            raise ValueError(f"CA '{basename}' already exists")
        conf = self._conf() if signer_ca_id else None
        entry = _cmd_create_ca(
            ca_id=signer_ca_id, crt_path=crt_path, key_path=key_path,
            crl_path=crl_path, aia_crl_base_url=aia_crl_base_url,
            valid_days=valid_days, rsa_key_size=rsa_bits,
            key_type=key_type, ec_curve=ec_curve, mldsa_variant=mldsa_variant,
            conf=conf, cn=cn, csr_path=csr_path,
        )
        if entry['id'] != basename or entry['display_name'] != cn.strip():
            raise ValueError('Unexpected CA configuration')
        cas.append(entry)
        _save_config(self.config_path, editor, document)
        return {'id': entry['id'], 'display_name': entry['display_name'],
                'issuer_ca_id': signer_ca_id, 'certificate_path': crt_path,
                'key_path': None if csr_path else key_path,
                'configured_key_path': entry['pem']['key_path_pem'],
                'csr_path': csr_path, 'crl_path': crl_path,
                'config_path': self.config_path, 'ca': entry}

    def create_ket(self, ca_id: str, *, cn=None, crt_path=None, key_path=None,
                   rsa_bits=4096, valid_days=3650) -> dict[str, Any]:
        editor, document, cas = _config_yaml(self.config_path)
        matches = [ca for ca in cas if ca_id in (ca.get('id'), ca.get('display_name'))]
        if len(matches) != 1:
            raise ValueError(f"CA '{ca_id}' not found or ambiguous in adcs.yaml")
        paths = _cmd_create_ket_cert(
            ca_id=ca_id, common_name=cn or f'{ca_id}-Xchg',
            conf=self._conf(), crt_path=os.fspath(crt_path) if crt_path is not None else None,
            key_path=os.fspath(key_path) if key_path is not None else None,
            rsa_bits=rsa_bits, valid_days=valid_days,
        )
        if (set(paths) != {'ket_cert_pem', 'ket_key_pem'}
                or not all(isinstance(v, str) and v for v in paths.values())):
            raise ValueError('Unexpected KET configuration output')
        matches[0].update(paths)
        _save_config(self.config_path, editor, document)
        return {'ca_id': ca_id, 'config_path': self.config_path, **paths}

    def list_certificates(self, ca_id: str, *, status='any', revocation='any',
                          search='', order_by='not_before ASC', limit=None) -> CertificateListResult:
        if limit is None:
            limit = _default_limit()
        self._filters(status, revocation, limit, order_by)
        ca = _ca(self._conf(read_only=True), ca_id)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        records, total = list_certificate_rows(
            cert_dir, query=search,
            status='' if status == 'any' else status,
            revocation='' if revocation == 'any' else revocation,
            revoked_serials=_ca_revocations(ca), order_by=order_by,
            limit=limit, synchronize=True,
            cache_progress=self._cache_progress, cache_status=self._cache_status,
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
        return {'ca': ca['id'], 'total': total, 'shown': len(entries), 'certificates': entries}

    def show_certificate(self, ca_id: str, serial: str) -> dict[str, Any]:
        conf = self._conf(read_only=True)
        ca, cert_dir, record = self._record(conf, ca_id, serial)
        detail = json.loads(record['details_json']) if record.get('details_json') else {}
        detail['file'] = os.path.join(cert_dir, record['relative_path'])
        detail['revoked'] = int(str(record['serial_hex']), 16) in _ca_revocations(ca)
        return detail

    def _change_revocation(self, ca_id: str, *, revoke_it: bool, serial=None,
                           status='any', revocation='any', search='',
                           order_by='not_after ASC', limit=0, apply=False,
                           dry_run=False, next_update_hours=None) -> dict[str, Any]:
        action = 'revoke' if revoke_it else 'unrevoke'
        if apply and dry_run:
            raise ValueError('apply=True and dry_run=True cannot be combined')
        if serial is None:
            self._filters(status, revocation, limit, order_by)
            if status == 'any' and revocation == 'any' and not search:
                raise ValueError('--filter requires --status, --revocation or --search')
        conf = self._conf()
        if serial is not None:
            if apply:
                raise ValueError('apply is only for bulk operations')
            ca, _, record = self._record(conf, ca_id, serial)
            serial = str(record['serial_hex'])
            if dry_run:
                currently_revoked = int(serial, 16) in _ca_revocations(ca)
                return {'action': action, 'ca': ca['id'], 'serial': serial,
                        'dry_run': True, 'current_revoked': currently_revoked,
                        'planned_revoked': revoke_it}
            self._status(f"{'Revoking' if revoke_it else 'Unrevoking'} certificate...")
            change_revocation(
                ca, serial, revoke_it=revoke_it,
                next_update_hours=(next_update_hours or int(conf['next_update_hours_crl'])),
            )
            return {'action': action, 'ca': ca['id'], 'serial': serial,
                    'dry_run': False, 'revoked': revoke_it}
        ca = _ca(conf, ca_id)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        rows, total = list_certificate_rows(
            cert_dir, query=search,
            status='' if status == 'any' else status,
            revocation='' if revocation == 'any' else revocation,
            revoked_serials=_ca_revocations(ca), order_by=order_by,
            limit=limit, synchronize=True,
            eligible_for=action,
            cache_progress=self._cache_progress, cache_status=self._cache_status,
        )
        candidates = [
            {'serial': row.serial_nox, 'not_after': row.not_after.isoformat(),
             'revoked': row.revoked, 'subject': row.subject}
            for row in rows
        ]
        result = {'action': action, 'ca': ca['id'], 'dry_run': not apply,
                  'total': total, 'selected': len(candidates), 'candidates': candidates,
                  'successes': 0, 'failures': 0, 'errors': []}
        if not apply:
            return result
        self._status(f"{'Revoking' if revoke_it else 'Unrevoking'} {len(rows)} certificate(s)...")
        for row in rows:
            try:
                change_revocation(
                    ca, row.serial_nox, revoke_it=revoke_it,
                    next_update_hours=(next_update_hours or int(conf['next_update_hours_crl'])),
                )
                result['successes'] += 1
            except (OSError, ValueError, PermissionError) as exc:
                result['failures'] += 1
                result['errors'].append({'serial': row.serial_nox, 'error': str(exc)})
        return result

    def revoke_certificate(self, ca_id: str, serial: str, *, dry_run=False,
                           next_update_hours=None) -> dict[str, Any]:
        return self._change_revocation(ca_id, revoke_it=True, serial=serial,
                                       dry_run=dry_run, next_update_hours=next_update_hours)

    def unrevoke_certificate(self, ca_id: str, serial: str, *, dry_run=False,
                             next_update_hours=None) -> dict[str, Any]:
        return self._change_revocation(ca_id, revoke_it=False, serial=serial,
                                       dry_run=dry_run, next_update_hours=next_update_hours)

    def revoke_certificates(self, ca_id: str, *, status='any', revocation='any',
                            search='', order_by='not_after ASC', limit=0,
                            apply=False, dry_run=False, next_update_hours=None) -> BatchResult:
        return self._change_revocation(ca_id, revoke_it=True, status=status,
                                       revocation=revocation, search=search,
                                       order_by=order_by, limit=limit, apply=apply,
                                       dry_run=dry_run, next_update_hours=next_update_hours)

    def unrevoke_certificates(self, ca_id: str, *, status='any', revocation='any',
                              search='', order_by='not_after ASC', limit=0,
                              apply=False, dry_run=False, next_update_hours=None) -> BatchResult:
        return self._change_revocation(ca_id, revoke_it=False, status=status,
                                       revocation=revocation, search=search,
                                       order_by=order_by, limit=limit, apply=apply,
                                       dry_run=dry_run, next_update_hours=next_update_hours)

    def _delete(self, ca_id: str, *, serial=None, eligible=False, status='any',
                revocation='any', search='', order_by='not_after ASC', limit=0,
                apply=False, dry_run=False) -> dict[str, Any]:
        if dry_run and apply:
            raise ValueError('apply=True and dry_run=True cannot be combined')
        if serial is None:
            self._filters(status, revocation, limit, order_by)
            if eligible and (status != 'any' or revocation != 'any'):
                raise ValueError('--eligible cannot be combined with --status or --revocation; use --filter')
            if not eligible and status == 'any' and revocation == 'any' and not search:
                raise ValueError('--filter requires --status, --revocation or --search')
        conf = self._conf(read_only=True)
        ca = _ca(conf, ca_id)
        cert_dir, _ = _resolve_storage_paths_from_ca(ca)
        revocations = _ca_revocations(ca)
        if serial is not None:
            _, _, record = self._record(conf, ca_id, serial)
            serial_int = int(str(record['serial_hex']), 16)
            path = os.path.join(cert_dir, record['relative_path'])
            expires_at = datetime.fromisoformat(record['not_after'])
            if dry_run:
                from adcs_actions import validate_certificate_deletion
                validate_certificate_deletion(
                    ca, cert_path=path, revoked=serial_int in revocations,
                    expires_at=expires_at,
                )
                from datetime import timezone
                expiry = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at
                return {'action': 'delete', 'ca': ca['id'], 'dry_run': True,
                        'serial': record['serial_hex'], 'not_after': expiry.isoformat(),
                        'revoked': serial_int in revocations, 'certificate_path': path}
            cert_n, key_n = delete_certificate(
                ca, cert_path=path, revoked=serial_int in revocations,
                expires_at=expires_at,
            )
            self._sync_cache(cert_dir)
            return {'action': 'delete', 'ca': ca['id'], 'dry_run': False,
                    'serial': record['serial_hex'], 'deleted_certificate': cert_n,
                    'deleted_key': key_n}
        rows, total = list_certificate_rows(
            cert_dir, query=search,
            status='' if eligible or status == 'any' else status,
            revocation='' if eligible or revocation == 'any' else revocation,
            revoked_serials=revocations, order_by=order_by,
            limit=limit, synchronize=True, eligible_for='delete',
            cache_progress=self._cache_progress, cache_status=self._cache_status,
        )
        candidates = [
            {'serial': r.serial_nox, 'not_after': r.not_after.isoformat(),
             'revoked': r.revoked, 'subject': r.subject, 'filename': r.filename}
            for r in rows
        ]
        result = {'action': 'delete', 'ca': ca['id'], 'dry_run': not apply,
                  'total': total, 'selected': len(candidates), 'candidates': candidates,
                  'successes': 0, 'failures': 0, 'errors': []}
        if not apply:
            return result
        self._status(f"Deleting {len(rows)} certificate(s)...")
        for row in rows:
            try:
                delete_certificate(
                    ca, cert_path=os.path.join(cert_dir, row.cache_key),
                    revoked=row.revoked, expires_at=row.not_after,
                )
                result['successes'] += 1
            except (OSError, ValueError, PermissionError) as exc:
                result['failures'] += 1
                result['errors'].append({'serial': row.serial_nox, 'error': str(exc)})
        self._sync_cache(cert_dir)
        return result

    def delete_certificate(self, ca_id: str, serial: str, *, dry_run=False) -> dict[str, Any]:
        return self._delete(ca_id, serial=serial, dry_run=dry_run)

    def delete_certificates(self, ca_id: str, *, eligible=False, status='any',
                            revocation='any', search='', order_by='not_after ASC',
                            limit=0, apply=False, dry_run=False) -> BatchResult:
        return self._delete(ca_id, eligible=eligible, status=status, revocation=revocation,
                            search=search, order_by=order_by, limit=limit,
                            apply=apply, dry_run=dry_run)

    def resign_crl(self, ca_id: str, *, bump_number=True, next_update_hours=None) -> dict[str, Any]:
        conf = self._conf()
        ca = _ca(conf, ca_id)
        number, serials = resign_ca_crl(
            ca, next_update_hours=next_update_hours or int(conf['next_update_hours_crl']),
            bump_number=bump_number,
        )
        return {'ca': ca['id'], 'crl_number': number, 'revoked_count': len(serials)}

    def resign_all_crls(self, *, bump_number=True, next_update_hours=None) -> CrlBatchResult:
        conf = self._conf()
        return _cmd_resign_all_crls(
            conf=conf, next_update_hours=next_update_hours or int(conf['next_update_hours_crl']),
            bump_number=bump_number,
        )

    def issue_certificate(self, ca_id: str, cn: str, *, sans=None, crt_path=None,
                          key_path=None, rsa_bits=3072, valid_days=365) -> dict[str, Any]:
        if isinstance(sans, str):
            sans = [sans]
        return _cmd_issue_cert_cli(
            ca_id=ca_id, common_name=cn, sans=sans,
            rsa_bits=rsa_bits, valid_days=valid_days,
            conf=self._conf(),
            crt_path=os.fspath(crt_path) if crt_path is not None else None,
            key_path=os.fspath(key_path) if key_path is not None else None,
        )

    def submit_csr(self, ca_id: str, username: str, csr_data: bytes, *,
                   template_oid: str | None = None, template_name: str | None = None,
                   auth_method: str = 'cli',
                   auth_context: Mapping[str, Any] | None = None,
                   request_headers: Mapping[str, str] | None = None) -> CsrSubmissionResult:
        """Submit PEM/DER CSR bytes for an already authenticated identity.

        The caller must authenticate ``username`` and trust ``auth_context``
        and ``request_headers``. This method never reads stdin. Callbacks
        keep using flask.g; a request context is created when needed.
        """
        if template_oid and template_name:
            raise ValueError('template_oid and template_name are mutually exclusive')
        if not username or not username.strip():
            raise ValueError('username must not be empty')
        context = dict(auth_context or {})
        context.update(username=username.strip(), auth_method=auth_method)
        with _callback_flask_context(context, request_headers):
            return submit_csr_request(
                ca_id=ca_id, username=username.strip(), csr_data=csr_data,
                conf=self._conf(), template_oid=template_oid,
                template_name=template_name, auth_method=auth_method,
                request_headers=dict(request_headers or {}),
            )

    def rotate_certificate(self, ca_id: str, crt_path, key_path, *,
                           threshold_days=30, valid_days=365,
                           write_fullchain_to_crt=True) -> dict[str, Any]:
        return _cmd_rotate_if_expiring(
            ca_id=ca_id, crt_path=os.fspath(crt_path), key_path=os.fspath(key_path),
            threshold_days=threshold_days, conf=self._conf(),
            write_fullchain_to_crt=write_fullchain_to_crt, valid_days=valid_days,
        )


def run(args: argparse.Namespace, *, progress: CliProgress | None = None) -> Any:
    """CLI adapter: call the Python API and return native Python data."""
    adcs = AdcsTool(
        args.confadcs,
        cache_progress=progress.progress if progress is not None else None,
        cache_status=progress.status if progress is not None else None,
    )
    cmd = args.command
    if cmd == 'ca-list':
        return adcs.list_cas()
    if cmd == 'ca-show':
        return adcs.show_ca(args.ca_id)
    if cmd == 'ca-create':
        return adcs.create_ca(
            cn=args.cn, aia_crl_base_url=args.aia_crl_base_url,
            signer_ca_id=args.ca, csr_path=args.csr_path,
            crt_path=args.crt_path, key_path=args.key_path, crl_path=args.crl_path,
            rsa_bits=args.rsa_bits, key_type=args.key_type, ec_curve=args.ec_curve,
            mldsa_variant=args.mldsa_variant, valid_days=args.valid_days)
    if cmd == 'ket-create':
        return adcs.create_ket(args.ca, cn=args.cn, crt_path=args.crt_path,
                               key_path=args.key_path, rsa_bits=args.rsa_bits,
                               valid_days=args.valid_days)
    if cmd == 'callback-list':
        return adcs.list_callbacks()
    if cmd == 'config-show':
        return adcs.show_config()
    if cmd == 'certificate-list':
        return adcs.list_certificates(args.ca, status=args.status, revocation=args.revocation,
                                      search=args.search, order_by=args.order_by, limit=args.limit)
    if cmd == 'certificate-show':
        return adcs.show_certificate(args.ca, args.serial)
    if cmd == 'certificate-issue':
        return adcs.issue_certificate(args.ca, args.cn, sans=args.san,
                                      crt_path=args.crt_path, key_path=args.key_path,
                                      rsa_bits=args.rsa_bits, valid_days=args.valid_days)
    if cmd in ('certificate-revoke', 'certificate-unrevoke'):
        method = adcs.revoke_certificate if cmd == 'certificate-revoke' else adcs.unrevoke_certificate
        batch_method = adcs.revoke_certificates if cmd == 'certificate-revoke' else adcs.unrevoke_certificates
        if args.serial:
            return method(args.ca, args.serial, dry_run=args.dry_run,
                          next_update_hours=args.next_update_hours)
        return batch_method(args.ca, status=args.status, revocation=args.revocation,
                            search=args.search, order_by=args.order_by, limit=args.limit,
                            apply=args.yes, dry_run=args.dry_run,
                            next_update_hours=args.next_update_hours)
    if cmd == 'certificate-delete':
        if args.serial:
            return adcs.delete_certificate(args.ca, args.serial, dry_run=args.dry_run)
        return adcs.delete_certificates(args.ca, eligible=args.eligible,
                                        status=args.status, revocation=args.revocation,
                                        search=args.search, order_by=args.order_by,
                                        limit=args.limit, apply=args.yes, dry_run=args.dry_run)
    if cmd == 'crl-resign':
        return adcs.resign_crl(args.ca, bump_number=not args.no_bump_number,
                               next_update_hours=args.next_update_hours)
    if cmd == 'crl-resign-all':
        return adcs.resign_all_crls(bump_number=not args.no_bump_number,
                                    next_update_hours=args.next_update_hours)
    if cmd == 'csr-submit':
        if args.csr_path:
            with open(args.csr_path, 'rb') as stream:
                csr_data = stream.read()
        else:
            if sys.stdin.isatty():
                raise ValueError('provide --csr-path or pipe the CSR on stdin')
            csr_data = sys.stdin.buffer.read()
        return adcs.submit_csr(args.ca, args.username, csr_data,
                               template_oid=args.template_oid, template_name=args.template_name)
    if cmd == 'certificate-rotate':
        return adcs.rotate_certificate(args.ca, args.crt_path, args.key_path,
                                       threshold_days=args.threshold_days,
                                       valid_days=args.valid_days,
                                       write_fullchain_to_crt=not args.no_write_fullchain_to_crt)
    raise ValueError(f'Unknown command: {cmd}')


def _display_result(args: argparse.Namespace, result: Any) -> None:
    """CLI-only formatting; AdcsTool methods never print."""
    cmd = args.command
    output_format = _format(args)
    if (output_format == 'json' and cmd in ('certificate-revoke', 'certificate-unrevoke',
                                          'certificate-delete') and 'serial' not in result
            and not result['dry_run']):
        result = {**result, 'exit_code': _cli_exit_code(args, result)}
    if cmd == 'ca-create':
        print(f"CA '{result['display_name']}' created successfully (updated {result['config_path']}).")
    elif cmd == 'ket-create':
        print(f"KET certificate for CA '{result['ca_id']}' created successfully (updated {result['config_path']}).")
    elif cmd == 'ca-list':
        if output_format == 'json':
            _output_structure(result, 'json')
        elif result:
            _table(['CA ID', 'Display name', 'Parent CA'], [
                [item['id'], item['display_name'], item['parent']] for item in result
            ], output_format, title='CA')
        else:
            print('(no CAs configured)')
    elif cmd in ('config-show', 'callback-list', 'ca-show', 'certificate-show'):
        _output_structure(result, output_format)
    elif cmd == 'certificate-list':
        entries = result['certificates']
        total = result['total']
        if output_format == 'json':
            _output_structure(result, 'json')
            return
        if output_format == 'accessible':
            print(f"CA: {result['ca']}\nCertificates: {len(entries)} of {total}")
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
            print(f'Shown: {len(entries)}/{total}', file=sys.stderr)
    elif cmd in ('certificate-revoke', 'certificate-unrevoke'):
        if output_format == 'json':
            _output_structure(result, 'json')
            return
        verb = 'Revoked' if result['action'] == 'revoke' else 'Unrevoked'
        if 'serial' in result:
            if result['dry_run']:
                _table(['Action', 'CA', 'Serial', 'Current state', 'Planned state'], [[
                    result['action'], result['ca'], result['serial'],
                    'revoked' if result['current_revoked'] else 'not revoked',
                    'revoked' if result['planned_revoked'] else 'not revoked',
                ]], output_format, title='Certificate')
                print('DRY RUN: no certificate or CRL modified.')
            else:
                print(f"{verb} certificate {result['serial']} on CA {result['ca']} (CRL verified).")
            return
        _table(['Serial', 'Expires', 'Current state', 'Planned state', 'Subject'], [
            [c['serial'], c['not_after'], 'revoked' if c['revoked'] else 'not revoked',
             'revoked' if result['action'] == 'revoke' else 'not revoked', c['subject']]
            for c in result['candidates']
        ], output_format, title='Certificate')
        if result['dry_run']:
            print(f"DRY RUN: {result['selected']} certificate(s) selected from {result['total']} matching row(s). Add --yes to execute.")
        else:
            for err in result['errors']:
                print(f"ERROR: {err['serial']}: {err['error']}", file=sys.stderr)
            print(f"{verb}: {result['successes']}; failed: {result['failures']}; selected: {result['selected']}")
    elif cmd == 'certificate-delete':
        if output_format == 'json':
            _output_structure(result, 'json')
            return
        if 'serial' in result:
            if result['dry_run']:
                _table(['CA', 'Serial', 'Expires', 'Revoked', 'Certificate'], [[
                    result['ca'], result['serial'], result['not_after'],
                    'yes' if result['revoked'] else 'no', result['certificate_path']
                ]], output_format, title='Certificate')
                print('DRY RUN: certificate and associated key would be moved to .trash; no files modified.')
            else:
                print(f"Deleted (moved to .trash): certificate={result['deleted_certificate']}, key={result['deleted_key']}; serial={result['serial']}")
            return
        _table(['Serial', 'Expires', 'Revoked', 'Subject', 'File'], [
            [c['serial'], c['not_after'], 'yes' if c['revoked'] else 'no',
             c['subject'], c['filename']] for c in result['candidates']
        ], output_format, title='Certificate')
        if result['dry_run']:
            print(f"DRY RUN: {result['selected']} of {result['total']} eligible certificate(s). Add --yes to move to .trash.")
        else:
            for err in result['errors']:
                print(f"ERROR: {err['serial']}: {err['error']}", file=sys.stderr)
            print(f"Deleted: {result['successes']}; failed: {result['failures']}; selected: {result['selected']}")
    elif cmd == 'crl-resign':
        print(f"CRL re-signed for CA {result['ca']} (CRLNumber {result['crl_number']}, {result['revoked_count']} revoked serials).")
    elif cmd == 'crl-resign-all':
        for item in result['results']:
            if item['status'] == 'ok':
                print(f"CRL re-signed for '{item['ca']}' -> CRLNumber {item['crl_number']} (path: {item['crl_path']})")
                print(f"OK   {item['display_name']}")
            else:
                print(f"FAIL {item['display_name']}: {item['error']}")
        if not result['failed']:
            print(f"All CRLs re-signed successfully ({result['ok']}/{result['ok'] + result['failed']}).")
        else:
            print(f"Partial result: ok={result['ok']}, failed={result['failed']}", file=sys.stderr)
    elif cmd == 'certificate-issue':
        print('Certificate issued successfully')
        print(f"CA:          {result['ca']}")
        print(f"CN:          {result['common_name']}")
        print(f"STORED CERT: {result['certificate_path']}")
        if result['copied_certificate_path']:
            print(f"COPIED CERT: {result['copied_certificate_path']}")
        print(f"KEY:         {result['key_path']}")
        print(f"RSA:         {result['rsa_bits']} bits")
        if result['sans']:
            print(f"SAN:  {', '.join(result['sans'])}")
    elif cmd == 'csr-submit':
        status = result['status']
        stream = sys.stderr if status == 'denied' else sys.stdout
        if status == 'denied':
            print('Certificate request denied', file=stream)
            print(f"REQUEST ID:  {result['request_id']}", file=stream)
            print(f"REASON:      {result['reason']}", file=stream)
        else:
            print('Certificate issued successfully' if status == 'issued' else 'Certificate request is pending', file=stream)
            print(f"REQUEST ID:  {result['request_id']}", file=stream)
            print(f"CA:          {result['ca']}", file=stream)
            print(f"USERNAME:    {result['username']}", file=stream)
            print(f"TEMPLATE:    {result['template']}", file=stream)
            if status == 'issued':
                print(f"CERT PATH:   {result['certificate_path']}", file=stream)
            print(f"CSR PATH:    {result['csr_path']}", file=stream)
    elif cmd == 'certificate-rotate':
        if result['rotated']:
            print(f"ROTATED: cert replaced at '{result['certificate_path']}', key replaced at '{result['key_path']}' "
                  f"(days left was {result['days_left']} <= threshold {result['threshold_days']})")
        else:
            print(f"OK: {result['days_left']} days left (> {result['threshold_days']}); no rotation needed.")


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
                conf = yaml.load(stream) or {}
            cas = conf.get('cas', []) if isinstance(conf, dict) else []
            if isinstance(cas, dict):
                cas = cas.values()
            return [str(ca['id']) for ca in cas if isinstance(ca, dict) and ca.get('id')]
        except (OSError, YAMLError, TypeError, ValueError):
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


def _cli_exit_code(args: argparse.Namespace, result: Any) -> int:
    """Translate Python outcomes into process exit statuses only in the CLI."""
    if args.command == 'csr-submit' and result['status'] == 'denied':
        return 1
    if args.command == 'crl-resign-all' and result['failed']:
        return 2 if result['ok'] else 1
    if args.command in ('certificate-revoke', 'certificate-unrevoke',
                        'certificate-delete') and result.get('failures'):
        return 2
    return 0


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
        # A spinner keeps the terminal responsive even during scans and key/CRL
        # operations with no numeric progress. Non-TTY stderr stays silent, and
        # JSON on stdout is never mixed with progress characters.
        labels = {
            'ca-create': 'Creating certificate authority...',
            'ket-create': 'Creating KET certificate...',
            'certificate-list': 'Preparing certificate cache...',
            'certificate-show': 'Preparing certificate cache...',
            'certificate-revoke': 'Preparing certificate cache...',
            'certificate-unrevoke': 'Preparing certificate cache...',
            'certificate-delete': 'Preparing certificate cache...',
            'certificate-issue': 'Issuing certificate...',
            'certificate-rotate': 'Checking certificate rotation...',
            'csr-submit': 'Submitting certificate request...',
            'crl-resign': 'Re-signing CRL...',
            'crl-resign-all': 'Re-signing CRLs...',
        }
        with CliProgress(labels.get(args.command, 'Working...'),
                         enabled=args.command in labels and sys.stderr.isatty()) as progress:
            result = run(args, progress=progress)
        _display_result(args, result)
        return _cli_exit_code(args, result)
    except (OSError, ValueError, LookupError, PermissionError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
