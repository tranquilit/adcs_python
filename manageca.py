#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADCS TUI — Terminal application (SSH) à la “mc”
------------------------------------------------
• Browse CAs, list certificates, search/sort/filter, view certificate details.
• Simple revocation (CRL update) via utils.revoke.
• Unrevoke support via utils.unrevoke.
• Re-sign CRL on demand (button + Ctrl+R) via utils.resign_crl.
• New certificate generation (key + cert) opens a dedicated window and uses utils.issue_cert_with_new_key.
• Delete certificate (button + Del). Moves to .trash by default.
• Shows whether a certificate is revoked (reads CRL).
• Shows whether a certificate is a CA (reads BasicConstraints).

Multi-selection:
  - Space toggles selection marker [ ] / [X]
  - Ctrl+A selects all FILTERED rows
  - Esc clears selection
  - Shift+Up / Shift+Down selects a range from anchor to cursor (plus Shift+Home/End)
  Revoke / Unrevoke / Delete apply to selected rows (or current if none selected).

Focus:
  - Focus is preserved after selection and after actions (reselects highlighted row).

Dependencies:
  pip install textual cryptography PyYAML

The app reuses your adcs.yaml and your folders.

CLI (no GUI):
  python manageca.py --resign-crl --ca-id ca-1
  python manageca.py --resign-all-crl
  python manageca.py --issue-cert --ca-id ca-1 --cn host.example --san host.example --rsa-bits 2048
"""
from __future__ import annotations
import uuid
import shutil
import os
import sys
import textwrap
import argparse
import stat
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set
import base64

from callback_loader import load_func
from adcs_config import build_templates_for_policy_response, _call_callback_with_params
from utils import exct_csr_from_cmc

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, Container
from textual.widgets import (
    Header, Footer, Static, DataTable, Input, Select, Button, Label
)
from textual.reactive import reactive
from textual import events  # to intercept keys
from rich.text import Text

# --- Textual compatibility: TextLog, ModalScreen/Screen ---
try:
    from textual.widgets import TextLog as _TextLog
except Exception:
    try:
        from textual.widgets import Log as _TextLog  # older Textual
    except Exception:
        _TextLog = Static  # last resort (plain display)

try:
    from textual.screen import ModalScreen as _BaseScreen
except Exception:
    from textual.screen import Screen as _BaseScreen  # type: ignore

# --- Terminal-native rendering ------------------------------------------------
# No RGB, hex, theme, or ANSI palette color is selected by this application.
# ``ansi_default`` means: use the terminal emulator's configured default
# foreground/background. Focus and selection are indicated with reverse video.
TERMINAL_DEFAULT = "ansi_default"

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# Your utilities
from adcs_config import load_yaml_conf
from utils_crt import (
    revoke,
    unrevoke,
    resign_crl,
    issue_cert_with_new_key,
    load_certificate_file,
    get_public_key_info,
    scan_cert_paths,
    revoked_serials_set,
    _cmd_rotate_if_expiring,
    _cli_find_ca_by_id,
    _cmd_resign_crl,
    _cmd_create_ca,
    _cmd_create_ket_cert,
    _compose_fullchain_pem,
    parse_certificate_details,
)

# =============================
# Model & parsing
# =============================

CERT_EXTS = {".crt", ".pem", ".cer"}

FULL_COLUMNS = ["Sel", "#", "Serial", "Subject", "Valid from", "Valid until",
                "Days", "Revoked", "Is CA", "Signature", "Public Key", "SHA-256", "File"]
COMPACT_COLUMNS = ["Sel", "#", "Serial", "Subject", "Valid until", "Days", "Revoked", "Is CA"]
NARROW_COLUMNS = ["Sel", "#", "Serial", "Subject", "Days", "Revoked"]
TINY_COLUMNS = ["Sel", "#", "Subject", "Days", "Revoked"]

MAX_ROWS_DEFAULT = 10000

def _mc_select(*args, **kwargs):
    """Create a borderless compact Select when supported by Textual.

    Older Textual releases don't expose the compact keyword, so keep a
    compatibility class that CSS can give the traditional 3-row height.
    """
    try:
        widget = Select(*args, compact=True, **kwargs)
        widget.add_class("mc-select-compact")
    except TypeError:
        widget = Select(*args, **kwargs)
        widget.add_class("mc-select-legacy")
    return widget


def _mc_button(label: str, **kwargs):
    """Create a compact / flat button when the installed Textual supports it."""
    try:
        return Button(label, compact=True, flat=True, **kwargs)
    except TypeError:
        try:
            return Button(label, flat=True, **kwargs)
        except TypeError:
            return Button(label, **kwargs)


@dataclass
class CertRow:
    filename: str
    serial_nox: str
    subject: str
    not_before: datetime
    not_after: datetime
    days_to_expiry: int
    sig_algo: str
    pubkey_type: str
    pubkey_bits: Optional[int]
    sha256_fingerprint: str
    revoked: bool = False  # CRL status
    is_ca: bool = False


def row_from_cert(path: str) -> CertRow:
    """Build a table row from a certificate file path."""
    cert = load_certificate_file(path)  # utils
    now = datetime.now(timezone.utc)
    subject = cert.subject.rfc4514_string()
    serial_nox = format(cert.serial_number, "x")
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_to_expiry = max(0, (not_after - now).days)
    try:
        sig_algo = cert.signature_hash_algorithm.name  # type: ignore
    except Exception:
        sig_algo = "unknown"
    pk_type, pk_bits = get_public_key_info(cert)  # utils
    fp = cert.fingerprint(hashes.SHA256()).hex()

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except Exception:
        is_ca = False

    return CertRow(
        filename=os.path.basename(path),
        serial_nox=serial_nox,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        days_to_expiry=days_to_expiry,
        sig_algo=sig_algo,
        pubkey_type=pk_type,
        pubkey_bits=pk_bits,
        sha256_fingerprint=fp,
        is_ca=is_ca,
    )


def _resolve_storage_paths_from_ca(ca: Dict[str, Any]) -> tuple[str, str]:
    sp = ca.get("storage_paths", {}) or {}
    certs_dir = sp.get("certs_dir") or sp.get("cert_dir") or ca.get("__path_cert") or "."
    private_dir = sp.get("private_dir") or certs_dir
    return str(certs_dir), str(private_dir)


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


class _CliRequest:
    def __init__(self, headers: Optional[Dict[str, str]] = None):
        self.headers = headers or {}
        self.host_url = "https://localhost/"


def _cmd_submit_csr_cli(
    *,
    ca_id: str,
    username: str,
    conf: Dict[str, Any],
    csr_path: Optional[str] = None,
    template_oid: Optional[str] = None,
    template_name: Optional[str] = None,
) -> int:
    try:
        ca = _cli_find_ca_by_id(conf, ca_id)
        if not ca:
            print(f"ERROR: CA not found: {ca_id}", file=sys.stderr)
            return 1

        if not username or not username.strip():
            print("ERROR: --username is required with --submit-csr", file=sys.stderr)
            return 1

        if csr_path:
            with open(csr_path, 'rb') as f:
                request_blob = f.read()
        else:
            if sys.stdin.isatty():
                print("ERROR: provide --csr-path or pipe the CSR on stdin", file=sys.stderr)
                return 1
            request_blob = sys.stdin.buffer.read()

        request_blob = _decode_pem_or_der_request(request_blob)
        csr_der, body_part_id, info = exct_csr_from_cmc(request_blob)

        fake_request = _CliRequest(headers={})
        templates_for_user, _ = build_templates_for_policy_response(
            conf,
            username=username.strip(),
            request=fake_request
        )

        tmap = {(t.get("template_oid") or {}).get("value"): t for t in templates_for_user}
        tmap_name = {t.get("common_name"): t for t in templates_for_user}

        selected_template_oid = (template_oid or "").strip()
        selected_template_name = (template_name or "").strip()
        if selected_template_oid and selected_template_name:
            print("ERROR: use either --template-oid or --template-name, not both", file=sys.stderr)
            return 1

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
            print("ERROR: The requested template is not valid", file=sys.stderr)
            return 1

        if ca.get('__refid') not in set(tpl.get('__ca_refids') or []):
            print(
                f"ERROR: {ca['id']} not in ca_references for template "
                f"{(tpl.get('template_oid') or {}).get('value')}",
                file=sys.stderr
            )
            return 1

        if not ((tpl.get('permissions') or {}).get('enroll')):
            print("ERROR: You do not have permission to enroll on this template", file=sys.stderr)
            return 1

        cb = (tpl.get("__callback") if tpl else (conf.get("__default_callback"))) or {}
        cb_path = cb.get("path")
        cb_issue = cb.get("issue")
        if not cb_path or not cb_issue:
            print("ERROR: no issue callback configured for this template", file=sys.stderr)
            return 1

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

        if status == "pending":
            os.makedirs(conf['path_list_request_id'], exist_ok=True)
            with open(os.path.join(conf['path_list_request_id'], str(request_id)), 'wb') as f:
                f.write(request_blob)
            print("Certificate request is pending")
            print(f"REQUEST ID:  {request_id}")
            print(f"CA:          {ca.get('display_name') or ca.get('id')}")
            print(f"USERNAME:    {username.strip()}")
            print(f"TEMPLATE:    {tpl.get('common_name')}")
            print(f"CSR PATH:    {csr_path_out}")
            return 0

        if status == "denied":
            print("Certificate request denied", file=sys.stderr)
            print(f"REQUEST ID:  {request_id}", file=sys.stderr)
            print(f"REASON:      {result.get('status_text') or 'Denied'}", file=sys.stderr)
            return 1

        if status != "issued":
            print(f"ERROR: unknown callback status '{status}'", file=sys.stderr)
            return 1

        cert_val = result.get("cert")
        if isinstance(cert_val, x509.Certificate):
            cert_obj = cert_val
        elif isinstance(cert_val, (bytes, bytearray, memoryview)):
            cert_obj = x509.load_der_x509_certificate(bytes(cert_val))
        else:
            print("ERROR: Callback(issued) must return 'cert' (x509 or DER bytes)", file=sys.stderr)
            return 1

        cert_pem = cert_obj.public_bytes(encoding=serialization.Encoding.PEM)
        fullchain_pem = _compose_fullchain_pem(cert_pem, conf=conf, ca=ca)

        os.makedirs(ca['__path_cert'], exist_ok=True)
        cert_path_out = os.path.join(ca['__path_cert'], f"{request_id}.pem")
        with open(cert_path_out, 'wb') as f:
            f.write(fullchain_pem)

        print("Certificate issued successfully")
        print(f"REQUEST ID:  {request_id}")
        print(f"CA:          {ca.get('display_name') or ca.get('id')}")
        print(f"USERNAME:    {username.strip()}")
        print(f"TEMPLATE:    {tpl.get('common_name')}")
        print(f"CERT PATH:   {cert_path_out}")
        print(f"CSR PATH:    {csr_path_out}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _cmd_issue_cert_cli(
    *,
    ca_id: str,
    common_name: str,
    sans: Optional[List[str]],
    rsa_bits: int,
    valid_days: int,
    conf: Dict[str, Any],
    crt_path: Optional[str] = None,
    key_path: Optional[str] = None,
) -> int:
    try:
        ca = _cli_find_ca_by_id(conf, ca_id)
        if not ca:
            print(f"ERROR: CA not found: {ca_id}", file=sys.stderr)
            return 1

        if not common_name.strip():
            print("ERROR: --cn is required with --issue-cert", file=sys.stderr)
            return 1

        if int(rsa_bits) not in (2048, 3072, 4096):
            print("ERROR: --rsa-bits must be one of: 2048, 3072, 4096", file=sys.stderr)
            return 1

        if int(valid_days) <= 0:
            print("ERROR: --valid-days must be > 0", file=sys.stderr)
            return 1

        certs_dir, private_dir = _resolve_storage_paths_from_ca(ca)
        os.makedirs(certs_dir, exist_ok=True)
        os.makedirs(private_dir, exist_ok=True)

        subject_sans = _split_sans(sans)

        cert_obj, key_obj, cert_pem, key_pem = issue_cert_with_new_key(
            ca=ca,
            common_name=common_name.strip(),
            subject_sans=subject_sans,
            key_type="rsa",
            rsa_key_size=int(rsa_bits),
            validity_seconds=int(valid_days) * 24 * 3600,
            key_export_password=None,
        )

        request_id = uuid.uuid4().int
        storage_crt_path = os.path.join(certs_dir, f"{request_id}.pem")
        if not key_path:
            key_path = os.path.join(private_dir, f"{request_id}.key.pem")

        if crt_path:
            crt_parent = os.path.dirname(os.path.abspath(crt_path))
            if crt_parent:
                os.makedirs(crt_parent, exist_ok=True)

        key_parent = os.path.dirname(os.path.abspath(key_path))
        if key_parent:
            os.makedirs(key_parent, exist_ok=True)

        fullchain_pem = _compose_fullchain_pem(
            cert_pem,
            conf=conf,
            ca=ca,
        )

        with open(storage_crt_path, "wb") as f:
            f.write(fullchain_pem)

        if crt_path:
            shutil.copy2(storage_crt_path, crt_path)

        with open(key_path, "wb") as f:
            f.write(key_pem)

        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

        print("Certificate issued successfully")
        print(f"CA:          {ca.get('display_name') or ca.get('id')}")
        print(f"CN:          {common_name.strip()}")
        print(f"STORED CERT: {storage_crt_path}")
        if crt_path:
            print(f"COPIED CERT: {crt_path}")
        print(f"KEY:         {key_path}")
        print(f"RSA:         {int(rsa_bits)} bits")
        if subject_sans:
            print(f"SAN:  {', '.join(subject_sans)}")

        return 0

    except Exception as e:
        print(f"ERROR: issue certificate failed: {e}", file=sys.stderr)
        return 1


def _cmd_resign_all_crls(
    *,
    conf: Dict[str, Any],
    next_update_hours: int,
    bump_number: bool = True,
) -> tuple[int, int, List[str]]:
    """Re-sign all CRLs defined in conf. Returns (ok, fail, messages)."""
    ok = 0
    fail = 0
    messages: List[str] = []

    for ca in (conf.get("cas_list") or []):
        if not ca["__key_obj"] :
            continue
        ca_name = ca.get("display_name") or ca.get("id") or "<unknown>"
        try:
            ca_id = ca.get("id")
            if not ca_id:
                raise KeyError("Missing CA id")
            rc = _cmd_resign_crl(
                ca_id=ca_id,
                next_update_hours=next_update_hours,
                bump_number=bump_number,
                conf=conf,
            )
            if rc == 0:
                ok += 1
                messages.append(f"OK   {ca_name}")
            else:
                fail += 1
                messages.append(f"FAIL {ca_name}: rc={rc}")
        except Exception as e:
            fail += 1
            messages.append(f"FAIL {ca_name}: {e}")

    return ok, fail, messages


# =============================
# New Certificate Screen
# =============================

class NewCertScreen(_BaseScreen[None]):
    """Modal dialog for issuing a new RSA certificate (key + cert)."""

    def __init__(self, parent_app: "ADCSApp", ca: Dict[str, Any]) -> None:
        super().__init__()
        self.parent_app = parent_app
        self.ca = ca

    def compose(self) -> ComposeResult:
        yield Container(
            Static("New Certificate", id="dlg_title"),
            Vertical(
                Input(placeholder="Common Name (CN)", id="nc_cn"),
                Input(placeholder="SANs (comma-separated: dns, ip, ...)", id="nc_sans"),
                Input(placeholder="RSA bits (2048/3072/4096)", id="nc_rsa_bits"),
                Input(placeholder="Validity days (default 365)", id="nc_valid_days"),
                id="dlg_form",
            ),
            Horizontal(
                Button("Create", id="nc_ok"),
                Button("Cancel", id="nc_cancel"),
                id="dlg_buttons",
            ),
            id="dlg_container",
        )

    CSS = f"""
    /* Terminal-native monochrome UI. ansi_default is supplied by the terminal.
       Focus is represented by reverse video, never by a chosen color. */
    Screen {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #dlg_container {{
        width: 80%;
        height: auto;
        border: solid $accent;
        padding: 1 2;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        margin: 2 10;
    }}
    #dlg_title {{
        content-align: center middle;
        height: 1;
        text-style: bold underline;
        color: $primary;
        background: {TERMINAL_DEFAULT};
        border: none;
    }}
    #dlg_form > * {{ margin: 0 0 1 0; }}
    #dlg_buttons {{
        height: auto;
        content-align: right middle;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #dlg_buttons Button {{ margin-left: 1; }}
    Input, Select {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    Input:focus, Select:focus {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        text-style: reverse;
    }}
    Button {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    #nc_ok {{ color: $success; }}
    #nc_cancel {{ color: $accent; }}
    Button:focus, Button:hover {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        text-style: reverse bold;
    }}
    #nc_ok:focus, #nc_ok:hover {{ color: $success; }}
    #nc_cancel:focus, #nc_cancel:hover {{ color: $accent; }}
    """

    BINDINGS = [
        Binding("enter", "do_ok", "OK"),
        Binding("escape", "do_cancel", "Cancel"),
    ]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "nc_ok":
            self.action_do_ok()
        elif event.button.id == "nc_cancel":
            self.action_do_cancel()

    def action_do_ok(self) -> None:
        self.action_do_ok_impl()

    def action_do_cancel(self) -> None:
        self.app.pop_screen()

    def action_do_ok_impl(self) -> None:
        """Validate inputs and issue a new leaf RSA certificate + key."""
        try:
            cn = (self.query_one("#nc_cn", Input).value or "").strip()
            sans_raw = (self.query_one("#nc_sans", Input).value or "").strip()
            rsa_bits_txt = (self.query_one("#nc_rsa_bits", Input).value or "").strip()
            valid_days_txt = (self.query_one("#nc_valid_days", Input).value or "").strip()
        except Exception as e:
            self.parent_app.notify(f"UI error: {e}", severity="error")
            return

        if not cn:
            self.parent_app.notify("CN is required.", severity="warning")
            return

        sans = []
        if sans_raw:
            parts = [p.strip() for p in sans_raw.replace(";", ",").split(",")]
            sans = [p for p in parts if p]

        try:
            rsa_bits = int(rsa_bits_txt) if rsa_bits_txt else 2048
        except Exception:
            rsa_bits = 0
        if rsa_bits not in (2048, 3072, 4096):
            self.parent_app.notify("RSA bits must be 2048/3072/4096.", severity="warning")
            return

        try:
            valid_days = int(valid_days_txt) if valid_days_txt else 365
            if valid_days <= 0:
                raise ValueError
        except Exception:
            self.parent_app.notify("Validity days must be a positive integer.", severity="warning")
            return

        try:
            certs_dir, private_dir = self.parent_app._resolve_storage_paths(self.ca)
            os.makedirs(certs_dir, exist_ok=True)
            os.makedirs(private_dir, exist_ok=True)
        except Exception as e:
            self.parent_app.notify(f"Storage paths error: {e}", severity="error", timeout=6)
            return

        try:
            cert_obj, key_obj, cert_pem, key_pem = issue_cert_with_new_key(
                ca=self.ca,
                common_name=cn,
                subject_sans=sans,
                key_type="rsa",
                rsa_key_size=rsa_bits,
                validity_seconds=valid_days * 24 * 3600,
                key_export_password=None,
            )
        except Exception as e:
            self.parent_app.notify(f"Issue certificate failed: {e}", severity="error", timeout=8)
            return

        request_id = uuid.uuid4().int
        crt_path = os.path.join(certs_dir, f"{request_id}.pem")
        key_path = os.path.join(private_dir, f"{request_id}.key.pem")
        try:
            with open(crt_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)
            try:
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
        except Exception as e:
            self.parent_app.notify(f"Failed to write files: {e}", severity="error", timeout=8)
            return

        try:
            self.parent_app.load_certs()
        except Exception:
            pass

        self.parent_app.notify(
            f"New RSA certificate issued ({rsa_bits} bits):\nCert: {crt_path}\nKey:  {key_path}",
            severity="success",
            timeout=8,
        )
        self.app.pop_screen()


# =============================
# TUI
# =============================

class Status(Static):
    """Small helper widget to display bold status text."""
    def set_text(self, msg: str) -> None:
        self.update(f"[b]{msg}[/b]")


class ADCSApp(App):
    # Disable Textual's built-in Ctrl+P command palette and remove it from the footer.
    ENABLE_COMMAND_PALETTE = False

    CSS = f"""
    /* Terminal-native polished UI: all foreground/background colors are ansi_default.
       This follows PuTTY/terminal defaults (dark or light). Selection/focus
       uses reverse video, so no application palette is required. */
    Screen {{
        layout: vertical;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        scrollbar-background: {TERMINAL_DEFAULT};
        scrollbar-color: {TERMINAL_DEFAULT};
        scrollbar-color-hover: {TERMINAL_DEFAULT};
        scrollbar-color-active: {TERMINAL_DEFAULT};
        scrollbar-corner-color: {TERMINAL_DEFAULT};
    }}

    Header {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        text-style: reverse bold;
    }}
    Footer {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    .footer--key {{
        background: {TERMINAL_DEFAULT};
        color: $accent;
        text-style: bold;
    }}
    .footer--description {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}

    #top {{
        height: 2;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #status {{
        height: 1;
        background: {TERMINAL_DEFAULT};
        color: $primary;
        text-style: bold;
        padding: 0 1;
    }}
    #main {{
        layout: horizontal;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #left {{
        width: 40;
        border: solid $accent;
        padding: 0 1;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #right {{
        border: solid $accent;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #filters {{
        border: none;
        padding: 1 0 0 0;
        margin: 1 0;
        height: auto;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #table {{
        height: 1fr;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #detail_pane {{
        width: 1fr;
        height: 17;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #detail {{
        height: 16;
        overflow: auto;
        border: solid $accent;
        padding: 0 1;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        scrollbar-background: {TERMINAL_DEFAULT};
        scrollbar-color: {TERMINAL_DEFAULT};
        scrollbar-color-hover: {TERMINAL_DEFAULT};
        scrollbar-color-active: {TERMINAL_DEFAULT};
        scrollbar-corner-color: {TERMINAL_DEFAULT};
    }}

    Label, Static, Container, Vertical, Horizontal {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    /* Semantic accents come only from the active Textual theme. */
    #lbl_ca {{
        color: $primary;
        text-style: bold underline;
    }}
    #filters Label {{
        color: $accent;
        text-style: bold underline;
    }}
    #actions {{
        margin-top: 1;
    }}
    #lbl_actions {{
        color: $warning;
        text-style: bold underline;
        margin: 1 0 1 0;
    }}
    #lbl_detail {{
        color: $primary;
        text-style: bold underline;
        height: 1;
        padding: 0 1;
    }}

    Input, Select {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    Input:focus, Select:focus {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        text-style: reverse;
    }}
    Button {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    Button:focus, Button:hover {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        text-style: reverse bold;
    }}

    /* Semantic action colors: all values come from the active theme. */
    #btn_reload {{
        color: $accent;
    }}
    #btn_newcert, #btn_unrevoke {{
        color: $success;
    }}
    #btn_delete, #btn_revoke {{
        color: $error;
    }}
    #btn_resign_crl {{
        color: $warning;
    }}

    /* Left command pane: compact MC-like navigation.
       Select/Button compact modes remove the widget chrome cleanly rather
       than clipping a normal 3-row Select down to one terminal row. */
    #left Input,
    #left Button {{
        width: 1fr;
        min-width: 0;
        height: 1;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        padding: 0 1;
        margin: 0;
    }}
    #left Select {{
        width: 1fr;
        min-width: 0;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        padding: 0 1;
        margin: 0;
    }}
    #left .mc-select-compact {{
        height: 1;
    }}
    #left .mc-select-legacy {{
        height: 1;
    }}

    /* Older Textual versions style the internal SelectCurrent widget
       independently. Override it explicitly so the default blue/tall
       focus frame can never leak through. */
    #left Select > SelectCurrent {{
        height: 1;
        border: none;
        padding: 0 1;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    #left Select:focus > SelectCurrent {{
        border: none;
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        text-style: reverse;
    }}
    #left Select > SelectCurrent Static#label {{
        background: transparent;
        color: {TERMINAL_DEFAULT};
    }}
    #left Select > SelectCurrent .arrow {{
        background: transparent;
        color: $accent;
    }}
    #left Select:focus > SelectCurrent Static#label {{
        background: transparent;
        color: {TERMINAL_DEFAULT};
    }}
    #left Select:focus > SelectCurrent .arrow {{
        background: transparent;
        color: $accent;
    }}
    #left Select > SelectOverlay {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    #left Button {{
        content-align: left middle;
        text-align: left;
    }}
    #left Input:focus,
    #left Select:focus,
    #left Button:focus,
    #left Button:hover {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
        text-style: reverse bold;
    }}
    #left #btn_reload:focus, #left #btn_reload:hover {{ color: $accent; }}
    #left #btn_newcert:focus, #left #btn_newcert:hover,
    #left #btn_unrevoke:focus, #left #btn_unrevoke:hover {{ color: $success; }}
    #left #btn_delete:focus, #left #btn_delete:hover,
    #left #btn_revoke:focus, #left #btn_revoke:hover {{ color: $error; }}
    #left #btn_resign_crl:focus, #left #btn_resign_crl:hover {{ color: $warning; }}
    #lbl_ca {{
        margin: 0 0 1 0;
    }}
    #sel_ca {{
        margin: 0 0 1 0;
    }}
    #filters Label {{
        margin: 0 0 1 0;
    }}
    #filters Input,
    #filters Select {{
        margin: 0 0 1 0;
    }}

    DataTable {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        background-tint: transparent;
        scrollbar-background: {TERMINAL_DEFAULT};
        scrollbar-color: {TERMINAL_DEFAULT};
        scrollbar-color-hover: {TERMINAL_DEFAULT};
        scrollbar-color-active: {TERMINAL_DEFAULT};
        scrollbar-corner-color: {TERMINAL_DEFAULT};
    }}
    DataTable:focus {{
        background-tint: transparent;
    }}
    DataTable > .datatable--odd-row,
    DataTable > .datatable--even-row {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
    }}
    DataTable > .datatable--header {{
        background: {TERMINAL_DEFAULT};
        color: $accent;
        text-style: bold underline;
    }}
    DataTable > .datatable--cursor,
    DataTable:focus > .datatable--cursor {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        text-style: reverse bold;
    }}
    DataTable > .datatable--hover {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        text-style: reverse;
    }}
    DataTable > .datatable--header-cursor,
    DataTable > .datatable--header-hover {{
        background: {TERMINAL_DEFAULT};
        color: $accent;
        text-style: bold underline;
    }}

    SelectOverlay {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        border: none;
    }}
    SelectOverlay > .option-list--option-highlighted {{
        background: {TERMINAL_DEFAULT};
        color: {TERMINAL_DEFAULT};
        text-style: reverse;
    }}

    .mono {{ text-style: italic; }}
    """

    BINDINGS = [
        Binding("?", "help", "Help"),
        Binding("/", "focus_search", "Search"),
        Binding("F5", "reload", "Reload"),
        Binding("r", "revoke_current", "Revoke"),
        Binding("u", "unrevoke_current", "Unrevoke"),
        Binding("delete", "delete_current", "Delete"),
        Binding("ctrl+r", "resign_crl", "Re-sign CRL"),
        Binding("ctrl+n", "open_new_certificate", "New cert"),
        Binding("tab", "next_pane", "Next"),
        Binding("shift+tab", "prev_pane", "Prev"),
        Binding("q", "quit", "Quit"),

        # --- Multi-selection ---
        Binding("space", "toggle_select", "Select"),
        Binding("escape", "clear_selection", "Clear sel"),
        Binding("ctrl+a", "select_all_filtered", "Select all"),

        # --- Range selection (Shift + arrows/home/end) ---
        Binding("shift+up", "range_up", "Range up", show=False),
        Binding("shift+down", "range_down", "Range down", show=False),
        Binding("shift+home", "range_home", "Range home", show=False),
        Binding("shift+end", "range_end", "Range end", show=False),
    ]

    confadcs: Dict[str, Any] = {}
    current_ca: reactive[Optional[Dict[str, Any]]] = reactive(None)
    cert_rows: List[CertRow] = []
    revoked_serials: Set[int] = set()

    compact_mode: reactive[bool] = reactive(False)
    details_side_by_side: reactive[bool] = reactive(False)
    _table_density: str = "full"

    filter_q: reactive[str] = reactive("")
    filter_status: reactive[str] = reactive("")

    max_rows: reactive[int] = reactive(MAX_ROWS_DEFAULT)

    # Keep-focus support: filename to reselect after refresh
    _pending_select_filename: Optional[str] = None

    # Multi-selection state
    selected_filenames: reactive[Set[str]] = reactive(set)

    # Range selection anchor
    _range_anchor_filename: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top"):
            yield Status(id="status")
        with Container(id="main"):
            with Vertical(id="left"):
                yield Label("Certification Authority", id="lbl_ca")
                yield _mc_select(options=[], id="sel_ca")
                with Container(id="filters"):
                    yield Label("Search & Status", id="lbl_filters")
                    yield Input(placeholder="Search… (/)", id="inp_q")
                    yield _mc_select(
                        options=[
                            ("(Status: any)", ""),
                            ("Expiring ≤ 30d", "expiring"),
                            ("Valid > 30d", "valid"),
                            ("Expired", "expired"),
                        ],
                        id="sel_status",
                        value="",
                    )
                with Container(id="actions"):
                    yield Label("Actions", id="lbl_actions")
                    yield _mc_button("New Certificate (Ctrl+N)", id="btn_newcert")
                    yield _mc_button("Delete (Del)", id="btn_delete")
                    yield _mc_button("Reload (F5)", id="btn_reload")
                    with Container():
                        yield _mc_button("Revoke (R)", id="btn_revoke")
                        yield _mc_button("Unrevoke (U)", id="btn_unrevoke")
                        yield _mc_button("Re-sign CRL (Ctrl+R)", id="btn_resign_crl")
            with Vertical(id="right"):
                yield DataTable(id="table", zebra_stripes=False)
                with Vertical(id="detail_pane"):
                    yield Label("Certificate details", id="lbl_detail")
                    yield _TextLog(id="detail")
        yield Footer()

    # ---------- helpers ----------
    def _table(self) -> DataTable:
        return self.query_one("#table", DataTable)

    def _maybe_table(self) -> Optional[DataTable]:
        try:
            return self.query_one("#table", DataTable)
        except Exception:
            return None

    def _remember_cursor_filename(self) -> Optional[str]:
        r = self._get_current_row()
        return r.filename if r else None

    def _request_reselect(self, filename: Optional[str]) -> None:
        self._pending_select_filename = filename

    # ---------- range selection helpers ----------
    def _ensure_range_anchor(self) -> Optional[str]:
        """Ensure we have a range anchor; if none, use current row."""
        if self._range_anchor_filename:
            return self._range_anchor_filename
        r = self._get_current_row()
        if not r:
            return None
        self._range_anchor_filename = r.filename
        return self._range_anchor_filename

    def _select_range_between_visible(self, a_fn: str, b_fn: str) -> None:
        """Select [a..b] range in the currently visible rows."""
        rows = self.current_rows()
        idx = {r.filename: i for i, r in enumerate(rows)}
        if a_fn not in idx or b_fn not in idx:
            return
        a, b = idx[a_fn], idx[b_fn]
        lo, hi = (a, b) if a <= b else (b, a)
        for r in rows[lo:hi + 1]:
            self.selected_filenames.add(r.filename)

    def _range_move_and_select(self, move_fn_name: str) -> None:
        """Move cursor (via DataTable action) then select anchor -> cursor."""
        anchor = self._ensure_range_anchor()
        if not anchor:
            return

        table = self._table()
        try:
            getattr(table, move_fn_name)()
        except Exception:
            pass

        cur = self._get_current_row()
        if not cur:
            return

        self._select_range_between_visible(anchor, cur.filename)
        self._request_reselect(cur.filename)
        self.refresh_table()

    def action_range_up(self) -> None:
        self._range_move_and_select("action_cursor_up")

    def action_range_down(self) -> None:
        self._range_move_and_select("action_cursor_down")

    def action_range_home(self) -> None:
        self._range_move_and_select("action_cursor_home")

    def action_range_end(self) -> None:
        self._range_move_and_select("action_cursor_end")

    # ---------- filesystem helpers ----------
    def _find_cert_path_by_filename(self, ca: Dict[str, Any], filename: str) -> Optional[str]:
        certs_dir, _ = self._resolve_storage_paths(ca)
        for p in scan_cert_paths(certs_dir):  # utils
            if os.path.basename(p) == filename:
                return p
        return None

    def _trashify(self, path: str) -> str:
        base_dir = os.path.dirname(path)
        trash_dir = os.path.join(base_dir, ".trash")
        os.makedirs(trash_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(trash_dir, f"{os.path.basename(path)}.{ts}.trash")

    def _delete_pair(self, cert_path: str, ca: Dict[str, Any]) -> tuple[int, int]:
        n_cert = 0
        n_key = 0
        if os.path.isfile(cert_path):
            try:
                os.replace(cert_path, self._trashify(cert_path))
                n_cert = 1
            except Exception:
                pass

        certs_dir, private_dir = self._resolve_storage_paths(ca)
        fname = os.path.basename(cert_path)
        if fname.endswith(".crt.pem"):
            key_name = fname[:-8] + ".key.pem"
        else:
            stem = os.path.splitext(fname)[0]
            key_name = stem + ".key.pem"
        key_path = os.path.join(private_dir, key_name)

        if os.path.isfile(key_path):
            try:
                os.replace(key_path, self._trashify(key_path))
                n_key = 1
            except Exception:
                pass

        return n_cert, n_key

    def _show_detail_current_row(self) -> None:
        table = self._table()
        rows = self.current_rows()
        if not rows:
            return
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        self.show_detail(rows[row_idx])

    def current_rows(self) -> List[CertRow]:
        all_rows = self.filtered_rows()
        if self.max_rows <= 0:
            return all_rows
        return all_rows[: self.max_rows]

    def _get_target_rows(self) -> List[CertRow]:
        if self.selected_filenames:
            rows = self.filtered_rows()
            targets = [r for r in rows if r.filename in self.selected_filenames]
            if targets:
                return targets
        r = self._get_current_row()
        return [r] if r else []

    # ---------- Responsive helpers ----------
    def _apply_layout_mode(self) -> None:
        main = self.query_one("#main")
        left = self.query_one("#left")
        right = self.query_one("#right")
        table = self.query_one("#table", DataTable)
        detail_pane = self.query_one("#detail_pane")
        detail = self.query_one("#detail")
        filters = self.query_one("#filters")
        actions = self.query_one("#actions")
        lbl_ca = self.query_one("#lbl_ca", Label)
        lbl_filters = self.query_one("#lbl_filters", Label)
        sel_ca = self.query_one("#sel_ca")
        inp_q = self.query_one("#inp_q", Input)
        sel_status = self.query_one("#sel_status")

        try:
            main.styles.layout = "vertical" if self.compact_mode else "horizontal"
        except Exception:
            pass

        try:
            left.styles.width = "1fr" if self.compact_mode else 40
            left.styles.height = 4 if self.compact_mode else "1fr"
            right.styles.width = "1fr"
            right.styles.height = "1fr"
        except Exception:
            pass

        # When height is scarce but width is still comfortable, keep the compact
        # CA/search strip at the top and use the remaining area horizontally:
        # certificate table on the left, certificate details on the right.
        try:
            right.styles.layout = "horizontal" if self.details_side_by_side else "vertical"
            table.styles.width = "7fr" if self.details_side_by_side else "1fr"
            table.styles.height = "1fr"
            detail_pane.styles.width = "5fr" if self.details_side_by_side else "1fr"

            if self.details_side_by_side:
                # In short+wide mode the details pane is beside the table, so it
                # can use the full available height without stealing table rows.
                detail_pane.styles.height = "1fr"
                detail.styles.height = "1fr"
            elif self.compact_mode:
                # In stacked compact mode, keep details deliberately shallow so
                # the certificate table remains useful on low-height terminals.
                # The detail widget is scrollable, so no information is lost.
                pane_height = max(7, min(10, self.size.height // 3))
                detail_pane.styles.height = pane_height
                detail.styles.height = max(6, pane_height - 1)
            else:
                detail_pane.styles.height = 17
                detail.styles.height = 16
        except Exception:
            pass

        # Compact mode is deliberately minimal: one CA row + one search row.
        # The surrounding border makes the complete top block four terminal rows.
        try:
            lbl_ca.display = "none" if self.compact_mode else "block"
            lbl_filters.display = "none" if self.compact_mode else "block"
            sel_status.display = "none" if self.compact_mode else "block"
            actions.display = "none" if self.compact_mode else "block"
            filters.display = "block"
        except Exception:
            pass

        try:
            filters.styles.padding = 0 if self.compact_mode else (1, 0, 0, 0)
            filters.styles.margin = 0 if self.compact_mode else (1, 0)
            filters.styles.height = 1 if self.compact_mode else "auto"
            sel_ca.styles.margin = 0 if self.compact_mode else (0, 0, 1, 0)
            inp_q.styles.margin = 0 if self.compact_mode else (0, 0, 1, 0)
        except Exception:
            pass

        self.ensure_table_columns()
        self.refresh_table()
        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        prefix = "Compact mode — " if self.compact_mode else ""
        self.query_one(Status).set_text(f"{prefix}{ca_name}")

    @staticmethod
    def _density_for_width(width: int, compact: bool, details_side_by_side: bool = False) -> str:
        if not compact:
            return "full"

        # In short+wide mode only part of the terminal is available to the table.
        # 7/12 mirrors the table/detail split used by _apply_layout_mode().
        table_width = int(width * 7 / 12) if details_side_by_side else width
        if table_width < 80:
            return "tiny"
        if table_width < 100:
            return "narrow"
        return "compact"

    def _table_view_width(self) -> int:
        try:
            width = int(self._table().size.width)
            if width > 0:
                return width
        except Exception:
            pass
        if self.details_side_by_side:
            return max(1, int(self.size.width * 7 / 12))
        return max(1, self.size.width)

    def _detail_view_width(self) -> int:
        try:
            width = int(self.query_one("#detail").size.width)
            if width > 0:
                return width
        except Exception:
            pass
        if self.details_side_by_side:
            return max(24, int(self.size.width * 5 / 12))
        return max(24, self.size.width)

    def _auto_pick_layout(self) -> None:
        w, h = self.size.width, self.size.height

        # A short but wide terminal has enough horizontal room to move details
        # beside the table. If width also becomes constrained, fall back to the
        # stacked compact layout.
        want_side_by_side = (h < 28) and (w >= 120)
        want_compact = (w < 120) or (h < 28)
        want_density = self._density_for_width(w, want_compact, want_side_by_side)

        if (
            want_compact != self.compact_mode
            or want_side_by_side != self.details_side_by_side
            or want_density != self._table_density
        ):
            self.compact_mode = want_compact
            self.details_side_by_side = want_side_by_side
            self._table_density = want_density
            self._apply_layout_mode()

    # ---------- Init ----------
    def on_mount(self) -> None:
        self.query_one(Status).set_text("Loading configuration…")
        try:
            env_limit = int(os.getenv("ADCS_MAX_ROWS", "") or "0")
            if env_limit > 0:
                self.max_rows = env_limit
        except Exception:
            pass

        try:
            self.confadcs = load_yaml_conf(args.confadcs)
        except Exception as e:
            self.notify(f"Unable to load adcs.yaml: {e}", severity="error")
            raise

        sel = self.query_one("#sel_ca", Select)
        options = []
        for ca in (self.confadcs.get("cas_list") or []):
            label = ca.get("display_name") or ca.get("id")
            options.append((label, str(ca.get("__refid"))))
        sel.set_options(options)
        if options:
            sel.value = options[0][1]
            self.switch_ca(int(sel.value))

        table = self._table()
        table.cursor_type = "row"
        self.ensure_table_columns()
        self._auto_pick_layout()
        self.query_one(Status).set_text("Ready. Press '?' for help.")

    def on_resize(self, event) -> None:
        try:
            self._auto_pick_layout()
        except Exception:
            pass

    # ---------- DataTable columns ----------
    def _expected_table_columns(self) -> List[str]:
        if self._table_density == "tiny":
            return TINY_COLUMNS
        if self._table_density == "narrow":
            return NARROW_COLUMNS
        if self._table_density == "compact":
            return COMPACT_COLUMNS
        return FULL_COLUMNS

    def ensure_table_columns(self) -> None:
        table = self._table()
        expected = self._expected_table_columns()

        current = 0
        if hasattr(table, "column_count"):
            try:
                current = table.column_count  # type: ignore[attr-defined]
            except Exception:
                current = 0
        else:
            ordered = getattr(table, "ordered_columns", None)
            if ordered is not None:
                current = len(ordered)

        if current != len(expected):
            try:
                table.clear(columns=True)
            except Exception:
                try:
                    table.clear()
                except Exception:
                    pass
            try:
                table.add_columns(*expected)
            except Exception:
                for col in expected:
                    try:
                        table.add_column(col)
                    except Exception:
                        pass

    # ---------- CA & data ----------
    def switch_ca(self, refid: int) -> None:
        ca = self.confadcs["cas_by_refid"].get(refid)
        if not ca:
            self.notify("CA not found", severity="warning")
            return
        self.current_ca = ca

        # Clear selection and anchor when switching CA
        self.selected_filenames.clear()
        self._pending_select_filename = None
        self._range_anchor_filename = None

        crl_path = (ca.get("crl") or {}).get("path_crl")
        self.revoked_serials = revoked_serials_set(crl_path)  # utils
        self.load_certs()

    def _resolve_storage_paths(self, ca: Dict[str, Any]) -> tuple[str, str]:
        return _resolve_storage_paths_from_ca(ca)

    def load_certs(self) -> None:
        ca = self.current_ca
        if not ca:
            return
        certs_dir, _private_dir = self._resolve_storage_paths(ca)
        paths = scan_cert_paths(certs_dir)  # utils
        self.cert_rows = []
        for p in paths:
            try:
                row = row_from_cert(p)
                try:
                    serial_int = int(row.serial_nox, 16)
                except ValueError:
                    serial_int = int(row.serial_nox, 10)
                row.revoked = serial_int in self.revoked_serials
                self.cert_rows.append(row)
            except Exception as e:
                now = datetime.now(timezone.utc)
                self.cert_rows.append(CertRow(
                    filename=os.path.basename(p) + " (ERROR)",
                    serial_nox="(error)",
                    subject=f"Error: {e}",
                    not_before=now, not_after=now,
                    days_to_expiry=0, sig_algo="-",
                    pubkey_type="-", pubkey_bits=None,
                    sha256_fingerprint="-",
                    revoked=False,
                    is_ca=False,
                ))
        self.refresh_table()

    # ---------- Filters & view ----------
    def filtered_rows(self) -> List[CertRow]:
        q = self.filter_q.lower().strip()
        status = self.filter_status
        rows = self.cert_rows

        if q:
            rows = [r for r in rows if q in r.subject.lower()
                    or q in r.serial_nox.lower()
                    or q in r.sha256_fingerprint.lower()
                    or q in r.filename.lower()]

        if status:
            if status == 'expiring':
                rows = [r for r in rows if 0 < r.days_to_expiry <= 30]
            elif status == 'valid':
                rows = [r for r in rows if r.days_to_expiry > 30]
            elif status == 'expired':
                rows = [r for r in rows if r.days_to_expiry == 0]

        return sorted(rows, key=lambda r: (r.not_before))

    @staticmethod
    def _mc_cell(value: object, marked: bool = False) -> object:
        """Emphasize marked rows without imposing a color outside the theme."""
        if not marked:
            return value
        return Text(str(value), style="bold")

    def refresh_table(self) -> None:
        """Rebuild the DataTable based on current (filtered/limited) rows, preserving focus."""
        table = self._table()
        self.ensure_table_columns()
        try:
            table.clear()
        except TypeError:
            while getattr(table, "row_count", 0):
                table.remove_row(0)

        all_rows = self.filtered_rows()
        total = len(all_rows)

        # keep selection consistent (drop missing files)
        visible_set = {r.filename for r in all_rows}
        self.selected_filenames = {fn for fn in self.selected_filenames if fn in visible_set}

        rows = self.current_rows()

        for i, r in enumerate(rows, start=1):
            selected = (r.filename in self.selected_filenames)
            sel_mark = "[X]" if selected else "[ ]"

            subj = r.subject
            serial = r.serial_nox
            table_width = self._table_view_width()

            if self._table_density == "tiny":
                subject_limit = max(12, min(28, table_width - 30))
                if len(subj) > subject_limit:
                    subj = subj[:max(1, subject_limit - 1)] + "…"
                table.add_row(
                    self._mc_cell(sel_mark, selected),
                    self._mc_cell(str(i), selected),
                    self._mc_cell(subj, selected),
                    self._mc_cell(str(r.days_to_expiry), selected),
                    self._mc_cell("yes" if r.revoked else "no", selected),
                )
            elif self._table_density == "narrow":
                if len(serial) > 14:
                    serial = serial[:11] + "…"
                subject_limit = max(18, min(28, table_width - 54))
                if len(subj) > subject_limit:
                    subj = subj[:max(1, subject_limit - 1)] + "…"
                table.add_row(
                    self._mc_cell(sel_mark, selected),
                    self._mc_cell(str(i), selected),
                    self._mc_cell(serial, selected),
                    self._mc_cell(subj, selected),
                    self._mc_cell(str(r.days_to_expiry), selected),
                    self._mc_cell("yes" if r.revoked else "no", selected),
                )
            elif self._table_density == "compact":
                if table_width < 120:
                    if len(serial) > 18:
                        serial = serial[:15] + "…"
                    subject_limit = max(24, min(32, table_width - 82))
                else:
                    subject_limit = 48
                if len(subj) > subject_limit:
                    subj = subj[:max(1, subject_limit - 1)] + "…"
                table.add_row(
                    self._mc_cell(sel_mark, selected),
                    self._mc_cell(str(i), selected),
                    self._mc_cell(serial, selected),
                    self._mc_cell(subj, selected),
                    self._mc_cell(r.not_after.strftime("%Y-%m-%dT%H:%M"), selected),
                    self._mc_cell(str(r.days_to_expiry), selected),
                    self._mc_cell("yes" if r.revoked else "no", selected),
                    self._mc_cell("yes" if r.is_ca else "no", selected),
                )
            else:
                table.add_row(
                    self._mc_cell(sel_mark, selected),
                    self._mc_cell(str(i), selected),
                    self._mc_cell(r.serial_nox, selected),
                    self._mc_cell(subj, selected),
                    self._mc_cell(r.not_before.strftime("%Y-%m-%dT%H:%M"), selected),
                    self._mc_cell(r.not_after.strftime("%Y-%m-%dT%H:%M"), selected),
                    self._mc_cell(str(r.days_to_expiry), selected),
                    self._mc_cell("yes" if r.revoked else "no", selected),
                    self._mc_cell("yes" if r.is_ca else "no", selected),
                    self._mc_cell(r.sig_algo, selected),
                    self._mc_cell(f"{r.pubkey_type}{' '+str(r.pubkey_bits)+' bits' if r.pubkey_bits else ''}", selected),
                    self._mc_cell(r.sha256_fingerprint, selected),
                    self._mc_cell(r.filename, selected),
                )

        # --- reselect logic (NO forced row=0) ---
        target_idx = 0
        if self._pending_select_filename:
            for idx, r in enumerate(rows):
                if r.filename == self._pending_select_filename:
                    target_idx = idx
                    break
            self._pending_select_filename = None
        else:
            try:
                cur = getattr(table, "cursor_row", 0)
                if isinstance(cur, int) and 0 <= cur < len(rows):
                    target_idx = cur
            except Exception:
                pass

        if rows:
            try:
                table.move_cursor(row=target_idx, column=0)
            except Exception:
                try:
                    table.cursor_coordinate = (target_idx, 0)
                except Exception:
                    pass
            try:
                table.focus()
            except Exception:
                pass
            self._show_detail_current_row()

        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        prefix = "Compact mode — " if self.compact_mode else ""
        limit_note = ""
        if total > len(rows):
            limit_note = f" (limited to {len(rows)}/{total})"
        sel_note = f" — selected: {len(self.selected_filenames)}"
        self.query_one(Status).set_text(f"{prefix}{len(rows)}/{total} certificates{sel_note} — CA: {ca_name}{limit_note}")

    # ---------- Actions ----------
    def action_help(self) -> None:
        msg = textwrap.dedent("""
        Keyboard shortcuts
        ------------------
        / : Quick search

        Space : Toggle selection [ ]/[X] on current row
        Ctrl+A : Select all (filtered)
        Esc : Clear selection
        Shift+Up/Down : Range select from anchor
        Shift+Home/End : Range select to start/end (visible)

        r : Revoke selected certificates (or current row if none selected)
        u : Unrevoke selected certificates (or current row if none selected)
        Del : Delete selected certificates (moves Cert & Key to .trash)
        Ctrl+R : Re-sign CRL (bump CRLNumber, refresh dates)
        Ctrl+N : New certificate (open form)
        F5 : Reload CA
        Tab / Shift+Tab : Move between left/right panes
        q : Quit
        """)
        self.notify(msg, title="Help", severity="information", timeout=12)

    def action_focus_search(self) -> None:
        self.query_one("#inp_q", Input).focus()

    def action_reload(self) -> None:
        cursor_fn = self._remember_cursor_filename()
        ca = self.current_ca
        if ca:
            crl_path = (ca.get("crl") or {}).get("path_crl")
            self.revoked_serials = revoked_serials_set(crl_path)
        self._request_reselect(cursor_fn)
        self.load_certs()

    def _get_current_row(self) -> Optional[CertRow]:
        table = self._table()
        rows = self.current_rows()
        if not rows:
            self.notify("No certificates to operate on.", severity="warning")
            return None
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        return rows[row_idx]

    # --- Multi-selection actions (preserve focus + manage anchor) ---
    def action_toggle_select(self) -> None:
        cursor_fn = self._remember_cursor_filename()

        r = self._get_current_row()
        if not r:
            return
        fn = r.filename

        if fn in self.selected_filenames:
            self.selected_filenames.remove(fn)
        else:
            self.selected_filenames.add(fn)

        # update anchor to current row
        self._range_anchor_filename = fn

        self._request_reselect(cursor_fn)
        self.refresh_table()

    def action_clear_selection(self) -> None:
        cursor_fn = self._remember_cursor_filename()
        self.selected_filenames.clear()
        self._range_anchor_filename = None
        self._request_reselect(cursor_fn)
        self.refresh_table()

    def action_select_all_filtered(self) -> None:
        cursor_fn = self._remember_cursor_filename()
        for r in self.filtered_rows():
            self.selected_filenames.add(r.filename)
        # keep anchor as-is (or set to cursor)
        if not self._range_anchor_filename:
            self._range_anchor_filename = cursor_fn
        self._request_reselect(cursor_fn)
        self.refresh_table()

    # --- Revoke / Unrevoke with multi-selection ---
    def action_revoke_current(self) -> None:
        cursor_fn = self._remember_cursor_filename()

        ca = self.current_ca
        if not ca:
            self.notify("No CA selected.", severity="warning")
            return
        try:
            ca_key = ca["__key_obj"]
            ca_cert_der = ca["__certificate_der"]
            crl_path = (ca.get("crl") or {}).get("path_crl")
            if not crl_path:
                raise KeyError("Missing crl.path_crl in CA config.")
        except Exception as e:
            self.notify(f"Incomplete CA config for revoke: {e}", severity="error", timeout=6)
            return

        targets = self._get_target_rows()
        if not targets:
            return

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        ok, fail = 0, 0
        failed_serials: List[str] = []

        for r in targets:
            try:
                revoke(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    serial=r.serial_nox,
                    crl_path=crl_path,
                    next_update_hours=self.confadcs['next_update_hours_crl']
                )
                ok += 1
            except Exception:
                fail += 1
                failed_serials.append(r.serial_nox)

        try:
            self.revoked_serials = revoked_serials_set(crl_path)
        except Exception:
            pass

        self._request_reselect(cursor_fn)
        self.load_certs()

        if fail == 0:
            self.notify(f"Revoked: {ok} certificate(s) — CRL updated: {crl_path}", severity="success", timeout=6)
        else:
            self.notify(
                f"Revoke: ok={ok}, failed={fail} — failed serials: {', '.join(failed_serials[:10])}"
                + ("…" if len(failed_serials) > 10 else ""),
                severity="warning",
                timeout=10,
            )

    def action_unrevoke_current(self) -> None:
        cursor_fn = self._remember_cursor_filename()

        ca = self.current_ca
        if not ca:
            self.notify("No CA selected.", severity="warning")
            return
        try:
            ca_key = ca["__key_obj"]
            ca_cert_der = ca["__certificate_der"]
            crl_path = (ca.get("crl") or {}).get("path_crl")
            if not crl_path:
                raise KeyError("Missing crl.path_crl in CA config.")
        except Exception as e:
            self.notify(f"Incomplete CA config for unrevoke: {e}", severity="error", timeout=6)
            return

        targets = self._get_target_rows()
        if not targets:
            return

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        ok, fail = 0, 0
        failed_serials: List[str] = []

        for r in targets:
            try:
                unrevoke(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    serial=r.serial_nox,
                    crl_path=crl_path,
                    next_update_hours=self.confadcs['next_update_hours_crl']
                )
                ok += 1
            except Exception:
                fail += 1
                failed_serials.append(r.serial_nox)

        try:
            self.revoked_serials = revoked_serials_set(crl_path)
        except Exception:
            pass

        self._request_reselect(cursor_fn)
        self.load_certs()

        if fail == 0:
            self.notify(f"Unrevoked: {ok} certificate(s) — CRL updated: {crl_path}", severity="success", timeout=6)
        else:
            self.notify(
                f"Unrevoke: ok={ok}, failed={fail} — failed serials: {', '.join(failed_serials[:10])}"
                + ("…" if len(failed_serials) > 10 else ""),
                severity="warning",
                timeout=10,
            )

    def action_resign_crl(self) -> None:
        cursor_fn = self._remember_cursor_filename()

        ca = self.current_ca
        if not ca:
            self.notify("No CA selected.", severity="warning")
            return
        try:
            ca_key = ca["__key_obj"]
            ca_cert_der = ca["__certificate_der"]
            crl_path = (ca.get("crl") or {}).get("path_crl")
            if not crl_path:
                raise KeyError("Missing crl.path_crl in CA config.")
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"CRL re-sign config error: {e}", severity="error", timeout=6)
            return
        try:
            new_num = resign_crl(
                ca_key=ca_key,
                ca_cert=ca_cert,
                crl_path=crl_path,
                bump_number=True,
                next_update_hours=self.confadcs['next_update_hours_crl']
            )
            self.revoked_serials = revoked_serials_set(crl_path)
            self._request_reselect(cursor_fn)
            self.load_certs()
            self.notify(f"CRL re-signed (CRLNumber {new_num}) — {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"CRL re-sign failed: {e}", severity="error", timeout=8)

    # -------- Delete actions (multi-selection) --------
    def action_delete_current(self) -> None:
        self._delete_selected()

    def _delete_selected(self) -> None:
        cursor_fn = self._remember_cursor_filename()

        ca = self.current_ca
        if not ca:
            self.notify("No CA selected.", severity="warning")
            return

        targets = self._get_target_rows()
        if not targets:
            return

        blocked: List[str] = []
        deleted_ok = 0
        deleted_fail = 0
        cert_deleted = 0
        key_deleted = 0

        for r in targets:
            if not r.revoked and r.days_to_expiry > 0:
                blocked.append(r.filename)
                continue

            cert_path = self._find_cert_path_by_filename(ca, r.filename.replace(" (ERROR)", ""))
            if not cert_path:
                deleted_fail += 1
                continue

            try:
                n_cert, n_key = self._delete_pair(cert_path, ca=ca)
                cert_deleted += n_cert
                key_deleted += n_key
                deleted_ok += 1
                if r.filename in self.selected_filenames:
                    self.selected_filenames.remove(r.filename)
            except Exception:
                deleted_fail += 1

        self._request_reselect(cursor_fn)
        try:
            self.load_certs()
        except Exception:
            pass

        msg = f"Delete: ok={deleted_ok}, failed={deleted_fail}, blocked={len(blocked)} — moved to .trash. (cert:{cert_deleted}, key:{key_deleted})"
        severity = "success" if (deleted_fail == 0 and not blocked) else ("warning" if deleted_ok > 0 else "error")
        self.notify(msg, severity=severity, timeout=10)

        if blocked:
            self.notify(
                "Blocked (must be revoked or expired): " + ", ".join(blocked[:10]) + ("…" if len(blocked) > 10 else ""),
                severity="warning",
                timeout=10,
            )

    def action_open_new_certificate(self) -> None:
        if not self.current_ca:
            self.notify("No CA selected.", severity="warning")
            return
        self.push_screen(NewCertScreen(self, self.current_ca))

    def action_new_certificate_keyboard(self) -> None:
        self.action_open_new_certificate()

    def action_next_pane(self) -> None:
        self.set_focus_next()

    def action_prev_pane(self) -> None:
        self.set_focus_previous()

    # ---------- UI Events ----------
    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "sel_ca" and event.value:
            try:
                self.switch_ca(int(event.value))
            except Exception:
                pass
        elif event.select.id == "sel_status":
            cursor_fn = self._remember_cursor_filename()
            self.filter_status = event.value or ""
            self._request_reselect(cursor_fn)
            self.refresh_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "inp_q":
            cursor_fn = self._remember_cursor_filename()
            self.filter_q = event.value or ""
            self._request_reselect(cursor_fn)
            self.refresh_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_reload":
            self.action_reload()
        elif event.button.id == "btn_revoke":
            self.action_revoke_current()
        elif event.button.id == "btn_unrevoke":
            self.action_unrevoke_current()
        elif event.button.id == "btn_resign_crl":
            self.action_resign_crl()
        elif event.button.id == "btn_newcert":
            self.action_open_new_certificate()
        elif event.button.id == "btn_delete":
            self.action_delete_current()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            self._show_detail_current_row()
        except Exception:
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            self._show_detail_current_row()
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:
        table = self._maybe_table()
        if table is not None and self.focused is table:
            if event.key in ("up", "down", "pageup", "pagedown", "home", "end"):
                self.set_timer(0.05, self._show_detail_current_row)

    # ---------- Certificate detail panel ----------
    @staticmethod
    def _wrap_detail_lines(lines: List[str], width: int) -> List[str]:
        """Wrap certificate detail text so narrow terminals never need horizontal scrolling."""
        width = max(24, width)
        wrapped: List[str] = []
        for line in lines:
            if not line or len(line) <= width:
                wrapped.append(line)
                continue

            leading = len(line) - len(line.lstrip(" "))
            indent = " " * leading
            continuation = indent + "  "
            parts = textwrap.wrap(
                line,
                width=width,
                subsequent_indent=continuation,
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=True,
            )
            wrapped.extend(parts or [line])
        return wrapped

    def show_detail(self, r: CertRow) -> None:
        ca = self.current_ca
        if not ca:
            return
        certs_dir, _private_dir = self._resolve_storage_paths(ca)
        cert_path = None
        for p in scan_cert_paths(certs_dir):  # utils
            if os.path.basename(p) == r.filename.replace(" (ERROR)", ""):
                cert_path = p
                break
        log = self.query_one("#detail")
        if hasattr(log, "clear"):
            try:
                log.clear()
            except Exception:
                pass
        if not cert_path or not os.path.isfile(cert_path):
            msg = "[b]File not found for details.[/b]"
            if hasattr(log, "write"):
                log.write(msg)
            elif hasattr(log, "write_line"):
                log.write_line(msg)
            else:
                log.update(msg)
            return
        try:
            cert = load_certificate_file(cert_path)  # utils
            details = parse_certificate_details(cert)

            serial_int = int(details["serial_number"])
            is_revoked = serial_int in self.revoked_serials
            bc_info = details["basic_constraints"]
            is_ca = bool(bc_info["is_ca"])
            path_length = bc_info["path_length"]

            lines: List[str] = []
            lines.append("=== Certificate ===")
            lines.append(f"File: {cert_path}")
            lines.append(f"Subject: {details['subject']}")
            lines.append(f"Issuer: {details['issuer']}")
            if self.compact_mode:
                for idx, prefix in ((2, "Subject: "), (3, "Issuer: ")):
                    if len(lines[idx]) > 96 and lines[idx].startswith(prefix):
                        rest = lines[idx][len(prefix):]
                        lines[idx] = prefix + rest[:80] + "\n" + (" " * len(prefix)) + rest[80:]

            lines.append(f"Serial (hex): {details['serial_hex']}")
            lines.append(f"Version: {details['version']}")
            lines.append(f"Validity: {details['not_valid_before']} -> {details['not_valid_after']}")
            lines.append(f"Revoked: {'yes' if is_revoked else 'no'}")
            lines.append(f"Is CA: {'yes' if is_ca else 'no'}")
            lines.append(f"Path length: {path_length if path_length is not None else '(none)'}")

            sig = details["signature"]
            lines.append(f"Signature: {sig['display']}; hash={sig['hash'] or 'n/a'}")

            pk = details["public_key"]
            lines.append(f"Public Key: {pk['type']}{' '+str(pk['bits'])+' bits' if pk['bits'] else ''}")
            lines.append(f"SHA-256: {details['fingerprints']['sha256']}")
            lines.append(f"Subject Key ID: {details['subject_key_identifier'] or '(n/a)'}")
            lines.append(f"Authority Key ID: {details['authority_key_identifier'] or '(n/a)'}")

            lines.append("")
            lines.append("=== AD CS / Active Directory ===")
            ms = details["microsoft"]
            template = ms["template"]
            lines.append(f"Template name: {template.get('name') or '(n/a)'}")
            lines.append(f"Template OID: {template.get('oid') or '(n/a)'}")
            if template.get("major") is not None or template.get("minor") is not None:
                lines.append(
                    f"Template version: {template.get('major') if template.get('major') is not None else '?'}"
                    f".{template.get('minor') if template.get('minor') is not None else '?'}"
                )
            else:
                lines.append("Template version: (n/a)")

            lines.append(f"Object SID: {ms.get('object_sid') or '(n/a)'}")

            app_policies = ms.get("application_policies") or []
            app_policy_text = ", ".join(item["display"] for item in app_policies)
            lines.append(f"Application Policies: {app_policy_text or '(n/a)'}")

            lines.append("")
            lines.append("=== Subject Alternative Name ===")
            san_entries = details.get("san") or []
            if san_entries:
                for item in san_entries:
                    lines.append(f"  - {item['display']}")
            else:
                lines.append("  (none)")

            lines.append("")
            lines.append("=== Usage / Distribution ===")
            ku_names = details.get("key_usage") or []
            lines.append(f"Key Usage: {', '.join(ku_names) if ku_names else '(n/a)'}")

            eku = details.get("extended_key_usage") or []
            eku_text = ", ".join(item["display"] for item in eku)
            lines.append(f"EKU: {eku_text or '(n/a)'}")

            cert_policies = details.get("certificate_policies") or []
            cert_policy_text = ", ".join(item["display"] for item in cert_policies)
            lines.append(f"Certificate Policies: {cert_policy_text or '(n/a)'}")

            aia = details.get("aia") or []
            aia_text = ", ".join(f"{item['method']}={item['location']}" for item in aia)
            lines.append(f"AIA: {aia_text or '(n/a)'}")

            cdp = details.get("crl_distribution_points") or []
            lines.append(f"CRL Distribution Points: {', '.join(cdp) if cdp else '(n/a)'}")

            extensions = details.get("extensions") or []
            lines.append(f"Extensions: {len(extensions)}")

            if self.compact_mode:
                detail_width = max(24, self._detail_view_width() - 4)
                lines = self._wrap_detail_lines(lines, detail_width)

            text = "\n".join(lines)
            if hasattr(log, "write"):
                log.write(text)
            elif hasattr(log, "write_line"):
                for ln in lines:
                    log.write_line(ln)
            else:
                log.update(text)
        except Exception as e:
            msg = f"[b]Parsing error: {e}[/b]"
            if hasattr(log, "write"):
                log.write(msg)
            elif hasattr(log, "write_line"):
                log.write_line(msg)
            else:
                log.update(msg)


# -----------------------------
# CLI entrypoint
# -----------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ADCS TUI / tools")
    p.add_argument("--confadcs", default="/etc/adcs/adcs.yaml",
                   help="Path to the adcs.yaml file (default: adcs.yaml next to this script)")
    p.add_argument("--resign-crl", action="store_true",
                   help="Re-sign the CRL of the specified CA and exit (no GUI).")
    p.add_argument("--resign-all-crl", action="store_true",
                   help="Re-sign all CRLs from adcs.yaml and exit (no GUI).")
    p.add_argument("--create-ca", action="store_true",
                   help="Create a new CA certificate, private key and an empty CRL, then exit (no GUI).")
    p.add_argument("--issue-cert", action="store_true",
                   help="Issue a new RSA leaf certificate + private key and exit (no GUI).")
    p.add_argument("--create-ket-cert", action="store_true",
                   help="Issue a Microsoft KET/CAExchange-style certificate + private key and exit (no GUI).")
    p.add_argument("--signer-ca-id", "--ca-id", dest="ca_id", type=str,
                   help="When used with --create-ca, --issue-cert or --resign-crl: CA identifier as defined in adcs.yaml (field 'id' or 'display_name'). For --create-ca, this is the parent CA; if omitted, the new CA is self-signed.")
    p.add_argument("--cn", type=str,
                   help="Common Name for --issue-cert.")
    p.add_argument("--san", action="append",
                   help="SAN entry or comma-separated SAN list for --issue-cert. Repeat the option if needed.")
    p.add_argument("--rsa-bits", type=int, default=None,
                   help="RSA key size for --issue-cert and --create-ca (2048/3072/4096; default: 2048 for --issue-cert, 4096 for --create-ca).")
    p.add_argument("--key-type", choices=("rsa", "ec", "ecc", "ecdsa", "mldsa", "ml-dsa", "mldsa44", "mldsa65", "mldsa87", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"), default="rsa",
                   help="Key type for --create-ca (default: rsa). Use 'ec'/'ecc'/'ecdsa' for ECC or 'mldsa' for ML-DSA.")
    p.add_argument("--ec-curve", default="secp256r1",
                   help="ECC curve for --create-ca when --key-type is ec/ecc/ecdsa (secp256r1, secp384r1, secp521r1; aliases: prime256v1, p-256, p-384, p-521).")
    p.add_argument("--mldsa-variant", default="mldsa65",
                   help="ML-DSA variant for --create-ca when --key-type is mldsa/ml-dsa (mldsa44, mldsa65, mldsa87; aliases: ml-dsa-44, ml-dsa-65, ml-dsa-87, 44, 65, 87).")
    p.add_argument("--no-bump-number", action="store_true",
                   help="Do not increment CRLNumber when re-signing (keep the same number).")
    p.add_argument("--next-update-hours", default=None,
                   help="Hours until NextUpdate when re-signing (default: next_update_hours_crl in confadcs).")
    p.add_argument("--rotate-if-expiring", action="store_true",
                   help="If the given certificate expires in ≤ threshold-days, re-issue a new key+cert with same SAN/CN using --ca-id and overwrite --crt-path/--key-path.")
    p.add_argument("--crt-path", type=str,
                   help="Certificate path (PEM). With --create-ca, path where the new CA certificate will be written.")
    p.add_argument("--key-path", type=str,
                   help="Private key path (PEM). With --create-ca, path where the new CA key will be written.")
    p.add_argument("--crl-path", "--crl-path", dest="crl_path", type=str,
                   help="CRL path (PEM). With --create-ca, path where the initial CRL will be written.")
    p.add_argument("--aia-crl-base-url", type=str,
                   help="Public base URL used by --create-ca to write ca_issuers_http and crl_http in the generated adcs.yaml block, for example http://testadcs.mydomain.lan.")
    p.add_argument("--threshold-days", type=int, default=30,
                   help="Rotate when the certificate expires in ≤ this many days (default: 30).")
    p.add_argument("--no-write-fullchain-to-crt", action="store_true",
                   help="Do not write the full chain into --crt-path (useful if you want to keep only the leaf cert).")
    p.add_argument("--valid-days", type=int,
                   help="Validity period of the new certificate in days (takes precedence over the original duration).")
    p.add_argument("--submit-csr", action="store_true",
                   help="Submit a CSR locally through the same issuance path as /CES/<CAID> and exit (no GUI).")
    p.add_argument("--username", type=str,
                   help="Username to use with --submit-csr (equivalent to g.username in app.py).")
    p.add_argument("--csr-path", type=str,
                   help="CSR/CMC request file (PEM or DER). With --create-ca, only the CSR public key is used; the CSR subject/extensions are ignored.")
    p.add_argument("--template-oid", type=str,
                   help="Certificate template OID to use with --submit-csr. Bypasses template extraction from the CSR when provided.")
    p.add_argument("--template-name", type=str,
                   help="Certificate template common name to use with --submit-csr. Bypasses template extraction from the CSR when provided.")
    return p


if __name__ == "__main__":
    parser = _build_arg_parser()
    args, unknown = parser.parse_known_args()

    if args.create_ca:
        if not args.cn:
            print("ERROR: --cn is required", file=sys.stderr)
            sys.exit(1)
        if not args.aia_crl_base_url:
            print("ERROR: --aia-crl-base-url is required with --create-ca", file=sys.stderr)
            sys.exit(1)
        if args.aia_crl_base_url.lower().startswith("https://"):
            print("ERROR: --aia-crl-base-url must not start with https://", file=sys.stderr)
            sys.exit(1)

        cnstrip = args.cn.lower().replace(' ','_')

        if not args.crt_path:
            crt_path = f"/var/lib/adcs/pki/certs/{cnstrip}/{cnstrip}.crt.pem"
        else:
            crt_path = args.crt_path

        if not args.key_path:
            key_path = f"/var/lib/adcs/pki/private/{cnstrip}/{cnstrip}.key.pem"
        else:
            key_path = args.key_path

        if not args.crl_path:
            crl_path = f"/var/lib/adcs/pki/crl/{cnstrip}/{cnstrip}.crl"
        else:
            crl_path = args.crl_path

        if not args.rsa_bits:
            rsa_bits = 4096
        else:
            rsa_bits = int(args.rsa_bits)

        confadcs = load_yaml_conf(args.confadcs) if args.ca_id else None
        rc = _cmd_create_ca(
            ca_id=args.ca_id,
            crt_path=crt_path,
            key_path=key_path,
            crl_path=crl_path,
            aia_crl_base_url=args.aia_crl_base_url,
            valid_days=args.valid_days if args.valid_days else 3650,
            rsa_key_size=rsa_bits,
            key_type=args.key_type,
            ec_curve=args.ec_curve,
            mldsa_variant=args.mldsa_variant,
            conf=confadcs,
            cn=args.cn,
            csr_path=args.csr_path,
        )
        sys.exit(rc)

    if args.issue_cert:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --issue-cert", file=sys.stderr)
            sys.exit(1)
        if not args.cn:
            print("ERROR: --cn is required with --issue-cert", file=sys.stderr)
            sys.exit(1)

        if not args.rsa_bits:
            rsa_bits = 3072
        else:
            rsa_bits = int(args.rsa_bits)

        confadcs = load_yaml_conf(args.confadcs)
        rc = _cmd_issue_cert_cli(
            ca_id=args.ca_id,
            common_name=args.cn,
            sans=args.san,
            rsa_bits=rsa_bits,
            valid_days=args.valid_days if args.valid_days else 365,
            conf=confadcs,
            crt_path=args.crt_path,
            key_path=args.key_path,
        )
        sys.exit(rc)

    if args.create_ket_cert:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --create-ket-cert", file=sys.stderr)
            sys.exit(1)
        if not args.cn:
            cn = "%s-Xchg" %  args.ca_id
        else:
            cn = args.cn

        if not args.rsa_bits:
            rsa_bits = 4096
        else:
            rsa_bits = int(args.rsa_bits)

        confadcs = load_yaml_conf(args.confadcs)
        rc = _cmd_create_ket_cert(
            ca_id=args.ca_id,
            common_name=cn,
            conf=confadcs,
            crt_path=args.crt_path,
            key_path=args.key_path,
            rsa_bits=rsa_bits,
            valid_days=args.valid_days if args.valid_days else 3650
        )
        sys.exit(rc)

    if args.submit_csr:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --submit-csr", file=sys.stderr)
            sys.exit(1)
        if not args.username:
            print("ERROR: --username is required with --submit-csr", file=sys.stderr)
            sys.exit(1)

        confadcs = load_yaml_conf(args.confadcs)
        rc = _cmd_submit_csr_cli(
            ca_id=args.ca_id,
            username=args.username,
            conf=confadcs,
            csr_path=args.csr_path,
            template_oid=args.template_oid,
            template_name=args.template_name,
        )
        sys.exit(rc)

    if args.rotate_if_expiring:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --rotate-if-expiring", file=sys.stderr)
            sys.exit(1)
        if not args.crt_path or not args.key_path:
            print("ERROR: --crt-path and --key-path are required with --rotate-if-expiring", file=sys.stderr)
            sys.exit(1)

        rc = _cmd_rotate_if_expiring(
            ca_id=args.ca_id,
            crt_path=args.crt_path,
            key_path=args.key_path,
            threshold_days=int(args.threshold_days),
            conf=load_yaml_conf(args.confadcs),
            write_fullchain_to_crt=(not args.no_write_fullchain_to_crt),
            valid_days=args.valid_days if args.valid_days else 365
        )
        sys.exit(rc)

    if args.resign_all_crl:
        confadcs = load_yaml_conf(args.confadcs)
        if not args.next_update_hours:
            next_update_hours = int(confadcs['next_update_hours_crl'])
        else:
            next_update_hours = int(args.next_update_hours)

        ok, fail, messages = _cmd_resign_all_crls(
            conf=confadcs,
            next_update_hours=int(next_update_hours),
            bump_number=(not args.no_bump_number),
        )

        for line in messages:
            print(line)

        if fail == 0:
            print(f"All CRLs re-signed successfully ({ok}/{ok + fail}).")
            sys.exit(0)
        elif ok > 0:
            print(f"Partial success: ok={ok}, failed={fail}", file=sys.stderr)
            sys.exit(2)
        else:
            print(f"ERROR: all CRL re-sign operations failed ({fail}).", file=sys.stderr)
            sys.exit(1)

    if args.resign_crl:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --resign-crl", file=sys.stderr)
            sys.exit(1)
        confadcs = load_yaml_conf(args.confadcs)
        if not args.next_update_hours:
            next_update_hours = int(confadcs['next_update_hours_crl'])
        else:
            next_update_hours = int(args.next_update_hours)
        rc = _cmd_resign_crl(
            ca_id=args.ca_id,
            next_update_hours=int(next_update_hours),
            bump_number=(not args.no_bump_number),
            conf=confadcs
        )
        sys.exit(rc)

    # Keep ANSI default colors native. ``ansi_default`` is emitted as the
    # terminal default foreground/background, so PuTTY controls dark/light
    # appearance. Reverse video is used for focus/selection.
    ADCSApp(ansi_color=True).run()
