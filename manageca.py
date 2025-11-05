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
• Delete certificate (button + Del; Shift+Del permanent). Moves to .trash by default.
• Shows whether a certificate is revoked (reads CRL).
• Keyboard: see help (press '?').

Dependencies:
  pip install textual cryptography PyYAML

The app reuses your adcs.yaml and your folders.

CLI (no GUI):
  python manageca.py --resign-crl --ca-id ca-1
"""
from __future__ import annotations
import uuid
import os
import sys
import csv
import textwrap
import argparse
import stat
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, Container
from textual.widgets import (
    Header, Footer, Static, DataTable, Input, Select, Button, Label
)
from textual.reactive import reactive
from textual import events  # to intercept keys

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

from cryptography import x509
from cryptography.hazmat.primitives import hashes

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
    _cmd_resign_crl
)

# =============================
# Model & parsing
# =============================

# Kept if other modules reference these extensions
CERT_EXTS = {".crt", ".pem", ".cer"}

# Columns for large and small layouts
FULL_COLUMNS = ["#", "Serial", "Subject", "Valid from", "Valid until",
                "Days", "Revoked", "Signature", "Public Key", "SHA-256", "File"]
COMPACT_COLUMNS = ["#", "Serial", "Subject", "Valid until", "Days", "Revoked"]

# Default display limit (configurable via ADCS_MAX_ROWS)
MAX_ROWS_DEFAULT = 10000

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
    )

# =============================
# New Certificate Screen
# =============================

class NewCertScreen(_BaseScreen[None]):
    """Modal dialog for issuing a new certificate (key + cert)."""

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
                Horizontal(
                    Select(options=[("RSA", "rsa"), ("EC", "ec"), ("Ed25519", "ed25519"), ("Ed448", "ed448")],
                           value="rsa", id="nc_keytype"),
                    Input(placeholder="RSA bits (2048/3072/4096)", id="nc_rsa_bits"),
                ),
                Horizontal(
                    Select(options=[("secp256r1", "secp256r1"), ("secp384r1", "secp384r1"),
                                    ("secp521r1", "secp521r1"), ("secp256k1", "secp256k1")],
                           value="secp256r1", id="nc_ec_curve"),
                    Input(placeholder="Validity days (default 365)", id="nc_valid_days"),
                ),
                id="dlg_form",
            ),
            Horizontal(
                Button("Create", id="nc_ok", variant="success"),
                Button("Cancel", id="nc_cancel"),
                id="dlg_buttons",
            ),
            id="dlg_container",
        )

    CSS = """
    #dlg_container {
        width: 80%;
        height: auto;
        border: round $primary;
        padding: 1 2;
        background: $surface;
        margin: 2 10;
    }
    #dlg_title {
        content-align: center middle;
        height: 3;
        text-style: bold;
        border: none;
    }
    #dlg_form > * { margin: 0 0 1 0; }
    #dlg_buttons {
        height: auto;
        content-align: right middle;
    }
    #dlg_buttons Button { margin-left: 1; }
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
        """Validate inputs and issue a new leaf certificate + key."""
        try:
            cn = (self.query_one("#nc_cn", Input).value or "").strip()
            sans_raw = (self.query_one("#nc_sans", Input).value or "").strip()
            keytype = (self.query_one("#nc_keytype", Select).value or "rsa").strip().lower()
            rsa_bits_txt = (self.query_one("#nc_rsa_bits", Input).value or "").strip()
            ec_curve = (self.query_one("#nc_ec_curve", Select).value or "secp256r1").strip()
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

        rsa_bits = 0
        try:
            rsa_bits = int(rsa_bits_txt) if rsa_bits_txt else 0
        except Exception:
            rsa_bits = 0
        if keytype == "rsa" and rsa_bits not in (0, 2048, 3072, 4096):
            self.parent_app.notify("RSA bits must be 2048/3072/4096 (or empty).", severity="warning")
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
                key_type=keytype,
                rsa_key_size=(rsa_bits or 2048),
                ec_curve=ec_curve,
                validity_seconds=valid_days * 24 * 3600,
                key_export_password=None,
            )
        except Exception as e:
            self.parent_app.notify(f"Issue certificate failed: {e}", severity="error", timeout=8)
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_cn = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in cn)
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
            f"New certificate issued:\nCert: {crt_path}\nKey:  {key_path}",
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
    CSS = """
    Screen { layout: vertical; }
    #top { height: 3; }
    #main { layout: horizontal; }
    #left { width: 40; border: tall; }
    #right { border: tall; }
    #filters { border: round $accent; padding: 1 1; height: auto; }
    #table { height: 1fr; }
    #detail { height: 12; overflow: auto; border: round $primary; }
    #status { height: 1; }
    .mono { text-style: italic; }
    """

    BINDINGS = [
        Binding("?", "help", "Help"),
        Binding("/", "focus_search", "Search"),
        Binding("f", "toggle_filters", "Filters"),
        Binding("F5", "reload", "Reload"),
        Binding("enter", "open_detail", "Details"),
        Binding("e", "export_csv", "Export CSV"),
        Binding("r", "revoke_current", "Revoke"),
        Binding("u", "unrevoke_current", "Unrevoke"),
        Binding("delete", "delete_current", "Delete"),
        Binding("shift+delete", "delete_current_permanent", "Del!"),
        Binding("ctrl+r", "resign_crl", "Re-sign CRL"),
        Binding("ctrl+n", "open_new_certificate", "New cert"),
        Binding("c", "toggle_compact", "Compact"),
        Binding("A", "toggle_show_all_rows", "All rows"),
        Binding("tab", "next_pane", "Next"),
        Binding("shift+tab", "prev_pane", "Prev"),
        Binding("q", "quit", "Quit"),
    ]

    confadcs: Dict[str, Any] = {}
    current_ca: reactive[Dict[str, Any] | None] = reactive(None)
    cert_rows: List[CertRow] = []
    revoked_serials: Set[int] = set()

    compact_mode: reactive[bool] = reactive(False)

    filter_q: reactive[str] = reactive("")
    filter_status: reactive[str] = reactive("")

    # Display limitation
    show_all_rows: reactive[bool] = reactive(False)
    max_rows: reactive[int] = reactive(MAX_ROWS_DEFAULT)

    # === NEW: keep-focus support ===
    # Filename to reselect after a refresh; None means default to first row.
    _pending_select_filename: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top"):
            yield Status(id="status")
        with Container(id="main"):
            with Vertical(id="left"):
                yield Label("Certification Authority", id="lbl_ca")
                yield Select(options=[], id="sel_ca")
                with Container(id="filters"):
                    yield Label("Search & Status")
                    yield Input(placeholder="Search… (/)", id="inp_q")
                    yield Select(
                        options=[
                            ("(Status: any)", ""),
                            ("Expiring ≤ 30d", "expiring"),
                            ("Valid > 30d", "valid"),
                            ("Expired", "expired"),
                        ],
                        id="sel_status",
                    )
                    yield Button("Apply", id="btn_apply")
                yield Button("New Certificate (Ctrl+N)", id="btn_newcert")
                yield Button("Delete (Del)", id="btn_delete")
                yield Button("Reload (F5)", id="btn_reload")
                with Container():
                    yield Button("Revoke (R)", id="btn_revoke")
                    yield Button("Unrevoke (U)", id="btn_unrevoke")
                    yield Button("Re-sign CRL (Ctrl+R)", id="btn_resign_crl")
            with Vertical(id="right"):
                yield DataTable(id="table", zebra_stripes=True)
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

    def _find_cert_path_by_filename(self, ca: Dict[str, Any], filename: str) -> Optional[str]:
        """Resolve a certificate absolute path by its filename within a CA storage."""
        certs_dir, _ = self._resolve_storage_paths(ca)
        for p in scan_cert_paths(certs_dir):  # utils
            if os.path.basename(p) == filename:
                return p
        return None

    def _trashify(self, path: str) -> str:
        """Return a timestamped path inside a local .trash folder next to the original file."""
        base_dir = os.path.dirname(path)
        trash_dir = os.path.join(base_dir, ".trash")
        os.makedirs(trash_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(trash_dir, f"{os.path.basename(path)}.{ts}.trash")

    def _delete_pair(self, cert_path: str, permanent: bool, ca: Dict[str, Any]) -> tuple[int, int]:
        """Delete (or move to trash) the certificate and its paired private key if present."""
        n_cert = 0
        n_key = 0
        if os.path.isfile(cert_path):
            try:
                if permanent:
                    os.remove(cert_path)
                else:
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
                if permanent:
                    os.remove(key_path)
                else:
                    os.replace(key_path, self._trashify(key_path))
                n_key = 1
            except Exception:
                pass

        return n_cert, n_key
    
    def _show_detail_current_row(self) -> None:
        """Refresh the details pane based on the current highlighted row."""
        table = self._table()
        rows = self.current_rows()
        if not rows:
            return
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        self.show_detail(rows[row_idx])

    def current_rows(self) -> List[CertRow]:
        """Return the currently displayed list (limited or full)."""
        all_rows = self.filtered_rows()
        if self.show_all_rows or self.max_rows <= 0:
            return all_rows
        return all_rows[: self.max_rows]

    # --- selection helpers (NEW) ---
    def _remember_current_selection(self) -> Optional[str]:
        """Return a stable identifier for the current row (here: filename)."""
        r = self._get_current_row()
        return (r.filename if r else None)

    def _request_reselect(self, filename: Optional[str]) -> None:
        """Ask refresh_table() to reselect the given filename after reload."""
        self._pending_select_filename = filename

    # ---------- Responsive helpers ----------
    def _apply_layout_mode(self) -> None:
        """Apply compact vs normal layout: columns, filter visibility, widths."""
        main = self.query_one("#main")
        left = self.query_one("#left")
        filters = self.query_one("#filters")

        try:
            main.styles.layout = "vertical" if self.compact_mode else "horizontal"
        except Exception:
            pass
        try:
            left.styles.width = 40 if not self.compact_mode else "auto"
        except Exception:
            pass
        try:
            filters.display = "none" if self.compact_mode else "block"
        except Exception:
            pass

        self.ensure_table_columns()
        self.refresh_table()
        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        prefix = "Compact mode — " if self.compact_mode else ""
        self.query_one(Status).set_text(f"{prefix}{ca_name}")

    def _auto_pick_layout(self) -> None:
        """Auto-toggle compact layout depending on current terminal size."""
        w, h = self.size.width, self.size.height
        want_compact = (w < 120) or (h < 28)
        if want_compact != self.compact_mode:
            self.compact_mode = want_compact
            self._apply_layout_mode()

    # ---------- Init ----------
    def on_mount(self) -> None:
        """Initial app setup: config, CA select, table columns, layout."""
        self.query_one(Status).set_text("Loading configuration…")
        # Read display limit from environment if present
        try:
            env_limit = int(os.getenv("ADCS_MAX_ROWS", "") or "0")
            if env_limit > 0:
                self.max_rows = env_limit
        except Exception:
            pass

        try:
            self.confadcs = load_yaml_conf("adcs.yaml")
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
        """Re-evaluate layout on terminal resize."""
        try:
            self._auto_pick_layout()
        except Exception:
            pass

    # ---------- DataTable columns ----------
    def ensure_table_columns(self) -> None:
        """Ensure DataTable has the expected columns for the current layout."""
        table = self._table()
        expected = FULL_COLUMNS if not self.compact_mode else COMPACT_COLUMNS

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
        """Switch current CA by its internal reference id and reload data."""
        ca = self.confadcs["cas_by_refid"].get(refid)
        if not ca:
            self.notify("CA not found", severity="warning")
            return
        self.current_ca = ca
        crl_path = (ca.get("crl") or {}).get("path_crl")
        self.revoked_serials = revoked_serials_set(crl_path)  # utils
        self.load_certs()

    def _resolve_storage_paths(self, ca: Dict[str, Any]) -> tuple[str, str]:
        """Return (certs_dir, private_dir) for the given CA."""
        sp = ca.get("storage_paths", {}) or {}
        certs_dir = sp.get("certs_dir") or ca.get("__path_cert") or "."
        private_dir = sp.get("private_dir") or certs_dir
        return str(certs_dir), str(private_dir)

    def load_certs(self) -> None:
        """Scan the CA storage and rebuild in-memory rows, then refresh table."""
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
                    filename=os.path.basename(p)+" (ERROR)",
                    serial_nox="(error)",
                    subject=f"Error: {e}",
                    not_before=now, not_after=now,
                    days_to_expiry=0, sig_algo="-",
                    pubkey_type="-", pubkey_bits=None,
                    sha256_fingerprint="-",
                    revoked=False,
                ))
        self.refresh_table()

    # ---------- Filters & view ----------
    def filtered_rows(self) -> List[CertRow]:
        """Apply text and status filters, then sort rows."""
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

        # Sort revoked last? Current sort puts non-revoked first (not r.revoked)
        rows = sorted(rows, key=lambda r: (r.not_before))
        return rows

    def refresh_table(self) -> None:
        """Rebuild the DataTable based on current (filtered/limited) rows.

        Also reselects the previously focused row if _pending_select_filename is set.
        """
        table = self._table()
        self.ensure_table_columns()
        try:
            table.clear()
        except TypeError:
            # Older Textual versions may lack clear(columns=True)
            while getattr(table, "row_count", 0):
                table.remove_row(0)

        all_rows = self.filtered_rows()
        total = len(all_rows)
        rows = self.current_rows()

        for i, r in enumerate(rows, start=1):
            subj = r.subject
            if self.compact_mode and len(subj) > 48:
                subj = subj[:45] + "…"

            if self.compact_mode:
                table.add_row(
                    str(i),
                    r.serial_nox,
                    subj,
                    r.not_after.strftime('%Y-%m-%d'),
                    str(r.days_to_expiry),
                    "yes" if r.revoked else "no",
                )
            else:
                table.add_row(
                    str(i),
                    r.serial_nox,
                    subj,
                    r.not_before.strftime('%Y-%m-%d'),
                    r.not_after.strftime('%Y-%m-%d'),
                    str(r.days_to_expiry),
                    "yes" if r.revoked else "no",
                    r.sig_algo,
                    f"{r.pubkey_type}{' '+str(r.pubkey_bits)+' bits' if r.pubkey_bits else ''}",
                    r.sha256_fingerprint,
                    r.filename,
                )

        # --- NEW reselection logic ---
        target_idx = 0
        if self._pending_select_filename:
            for idx, r in enumerate(rows):
                if r.filename == self._pending_select_filename:
                    target_idx = idx
                    break
            self._pending_select_filename = None

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
        if not self.show_all_rows and total > len(rows):
            limit_note = f" (limited to {len(rows)}/{total}; press Shift+A to show all)"
        self.query_one(Status).set_text(f"{prefix}{len(rows)}/{total} certificates — CA: {ca_name}{limit_note}")

    # ---------- Actions ----------
    def action_help(self) -> None:
        """Show a quick keyboard help popup."""
        msg = textwrap.dedent("""
        Keyboard shortcuts
        ------------------
        / : Quick search
        f : Toggle filters
        Enter : Show details for current row
        e : Export current (filtered) list to CSV in cwd
        r : Revoke selected certificate
        u : Unrevoke selected certificate
        Del : Delete selected certificate (moves Cert & Key to .trash)
        Shift+Del : Permanently delete selected certificate (and its key if found)
        Ctrl+R : Re-sign CRL (bump CRLNumber, refresh dates)
        Ctrl+N : New certificate (open form)
        c : Toggle compact mode
        Shift+A : Toggle show all rows (bypass max rows limit)
        F5 : Reload CA
        Tab / Shift+Tab : Move between left/right panes
        q : Quit
        """)
        self.notify(msg, title="Help", severity="information", timeout=8)

    def action_focus_search(self) -> None:
        """Focus the quick search input."""
        self.query_one("#inp_q", Input).focus()

    def action_toggle_filters(self) -> None:
        """Toggle visibility of the filter container."""
        filters = self.query_one("#filters")
        filters.display = ("none" if filters.display != "none" else "block")

    def action_toggle_compact(self) -> None:
        """Toggle compact layout."""
        self.compact_mode = not self.compact_mode
        self._apply_layout_mode()

    def action_reload(self) -> None:
        """Reload CRL and certificates for current CA."""
        ca = self.current_ca
        if ca:
            crl_path = (ca.get("crl") or {}).get("path_crl")
            self.revoked_serials = revoked_serials_set(crl_path)
        self.load_certs()

    def action_open_detail(self) -> None:
        """Show details for the currently highlighted row."""
        self._show_detail_current_row()

    def action_export_csv(self) -> None:
        """Export the currently filtered rows to a CSV file in the CWD."""
        rows = self.filtered_rows()
        fn = f"certs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(fn, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["serial","subject","valid_from","valid_until","days","revoked","signature","pubkey","pubkey_bits","sha256","filename"])
            for r in rows:
                w.writerow([
                    r.serial_nox, r.subject, r.not_before.isoformat(), r.not_after.isoformat(), r.days_to_expiry,
                    "yes" if r.revoked else "no",
                    r.sig_algo, r.pubkey_type, r.pubkey_bits or '', r.sha256_fingerprint, r.filename
                ])
        self.notify(f"Exported: {fn}", severity="success")

    def _get_current_row(self) -> Optional[CertRow]:
        """Return the CertRow currently highlighted by the cursor, or None."""
        table = self._table()
        rows = self.current_rows()
        if not rows:
            self.notify("No certificates to operate on.", severity="warning")
            return None
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        return rows[row_idx]

    def action_revoke_current(self) -> None:
        """Revoke the currently selected certificate and update the CRL, keeping selection."""
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

        r = self._get_current_row()
        if not r:
            return

        # NEW: remember the selection before the operation
        selected_filename = r.filename

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        serial = r.serial_nox
        try:
            revoke(ca_key=ca_key, ca_cert=ca_cert, serial=serial, crl_path=crl_path)
            self.revoked_serials = revoked_serials_set(crl_path)
            # NEW: request reselection of the same row after reload
            self._request_reselect(selected_filename)
            self.load_certs()
            self.notify(f"Cert {serial} revoked — CRL updated: {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"Revoke failed: {e}", severity="error", timeout=8)

    def action_unrevoke_current(self) -> None:
        """Unrevoke the currently selected certificate and update the CRL, keeping selection."""
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

        r = self._get_current_row()
        if not r:
            return

        # NEW: remember the selection before the operation
        selected_filename = r.filename

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        serial = r.serial_nox
        try:
            unrevoke(ca_key=ca_key, ca_cert=ca_cert, serial=serial, crl_path=crl_path)
            self.revoked_serials = revoked_serials_set(crl_path)
            # NEW: request reselection of the same row after reload
            self._request_reselect(selected_filename)
            self.load_certs()
            self.notify(f"Cert {serial} unrevoked — CRL updated: {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"Unrevoke failed: {e}", severity="error", timeout=8)


    def action_resign_crl(self) -> None:


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
            new_num = resign_crl(ca_key=ca_key, ca_cert=ca_cert, crl_path=crl_path, bump_number=True)
            self.revoked_serials = revoked_serials_set(crl_path)
            self.load_certs()
            self.notify(f"CRL re-signed (CRLNumber {new_num}) — {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"CRL re-sign failed: {e}", severity="error", timeout=8)

    # -------- Delete actions --------
    def action_delete_current(self) -> None:
        """Soft-delete (move to .trash) the currently selected certificate + key."""
        self._delete_selected(permanent=False)

    def action_delete_current_permanent(self) -> None:
        """Permanently delete the currently selected certificate + key."""
        self._delete_selected(permanent=True)

    def _delete_selected(self, permanent: bool) -> None:
        """Common delete routine with basic safety checks."""
        ca = self.current_ca
        if not ca:
            self.notify("No CA selected.", severity="warning")
            return

        r = self._get_current_row()
        if not r:
            return

        if not r.revoked and r.days_to_expiry > 0:
            self.notify(
                "Deletion blocked: you can only delete a revoked or expired certificate.",
                severity="warning",
                timeout=6,
            )
            return
    
        cert_path = self._find_cert_path_by_filename(ca, r.filename.replace(" (ERROR)", ""))
        if not cert_path:
            self.notify("Unable to resolve certificate path.", severity="warning")
            return

        try:
            n_cert, n_key = self._delete_pair(cert_path, permanent=permanent, ca=ca)
        except Exception as e:
            self.notify(f"Delete failed: {e}", severity="error", timeout=8)
            return

        try:
            self.load_certs()
        except Exception:
            pass

        where = "permanently deleted" if permanent else "moved to .trash"
        self.notify(f"Certificate {os.path.basename(cert_path)} {where}. "
                    f"(cert:{n_cert}, key:{n_key})", severity="success", timeout=6)

    def action_open_new_certificate(self) -> None:
        """Open the modal to create a new certificate."""
        if not self.current_ca:
            self.notify("No CA selected.", severity="warning")
            return
        self.push_screen(NewCertScreen(self, self.current_ca))

    def action_new_certificate_keyboard(self) -> None:
        """Alias for keyboard binding."""
        self.action_open_new_certificate()

    def action_next_pane(self) -> None:
        """Move focus to the next focusable widget."""
        self.set_focus_next()

    def action_prev_pane(self) -> None:
        """Move focus to the previous focusable widget."""
        self.set_focus_previous()

    def action_toggle_show_all_rows(self) -> None:
        """Toggle the display limit on/off and refresh."""
        self.show_all_rows = not self.show_all_rows
        self.refresh_table()

    # ---------- UI Events ----------
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle changes in CA selection and status filter."""
        if event.select.id == "sel_ca" and event.value:
            try:
                self.switch_ca(int(event.value))
            except Exception:
                pass
        elif event.select.id == "sel_status":
            self.filter_status = event.value or ""
            self.refresh_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Apply quick search when Enter is pressed."""
        if event.input.id == "inp_q":
            self.filter_q = event.value or ""
            self.refresh_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Map button clicks to actions."""
        if event.button.id == "btn_apply":
            q = self.query_one("#inp_q", Input).value or ""
            self.filter_q = q
            self.refresh_table()
        elif event.button.id == "btn_reload":
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

    # --- Auto-update the details panel when the row changes ---
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Keep the details pane in sync with the highlighted row."""
        try:
            self._show_detail_current_row()
        except Exception:
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Also refresh details when a row is selected."""
        try:
            self._show_detail_current_row()
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:
        """Detect navigation keys while the table is focused and debounce details update."""
        table = self._maybe_table()
        if table is not None and self.focused is table:
            if event.key in ("up", "down", "pageup", "pagedown", "home", "end"):
                self.set_timer(0.05, self._show_detail_current_row)
    
    # ---------- Certificate detail panel ----------
    def show_detail(self, r: CertRow) -> None:
        """Populate the right-side log with details of the given CertRow."""
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
            msg = "[red]File not found for details.[/red]"
            if hasattr(log, "write"):
                log.write(msg)
            elif hasattr(log, "write_line"):
                log.write_line(msg)
            else:
                log.update(msg)
            return
        try:
            cert = load_certificate_file(cert_path)  # utils
            try:
                serial_int = int(format(cert.serial_number, "x"), 16)
            except ValueError:
                serial_int = int(cert.serial_number)
            is_revoked = serial_int in self.revoked_serials

            lines: List[str] = []
            lines.append(f"File: {cert_path}")
            lines.append(f"Subject: {cert.subject.rfc4514_string()}")
            if self.compact_mode and len(lines[1]) > 96:
                subj_prefix = "Subject: "
                if lines[1].startswith(subj_prefix):
                    rest = lines[1][len(subj_prefix):]
                    lines[1] = subj_prefix + rest[:80] + "\n           " + rest[80:]

            lines.append(f"Serial (hex): {format(cert.serial_number, 'x')}")
            lines.append(f"Validity: {cert.not_valid_before} -> {cert.not_valid_after}")
            lines.append(f"Revoked: {'yes' if is_revoked else 'no'}")
            try:
                sig_algo = cert.signature_hash_algorithm.name
            except Exception:
                sig_algo = "unknown"
            pk_type, pk_bits = get_public_key_info(cert)  # utils
            lines.append(f"Public Key: {pk_type}{' '+str(pk_bits)+' bits' if pk_bits else ''}")
            fp = cert.fingerprint(hashes.SHA256()).hex()
            lines.append(f"SHA-256: {fp}")
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                san_vals = ", ".join(str(n.value) for n in san)
            except Exception:
                san_vals = "(none)"
            lines.append(f"SAN: {san_vals}")
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                lines.append(f"KeyUsage: DS={ku.digital_signature} KE={ku.key_encipherment} KCS={ku.key_cert_sign} CRL={ku.crl_sign}")
            except Exception:
                lines.append("KeyUsage: (n/a)")
            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                eku_vals = ", ".join(getattr(oid, "_name", oid.dotted_string) for oid in eku)
            except Exception:
                eku_vals = "(n/a)"
            lines.append(f"EKU: {eku_vals}")
            text = "\n".join(lines)
            if hasattr(log, "write"):
                log.write(text)
            elif hasattr(log, "write_line"):
                for ln in lines:
                    log.write_line(ln)
            else:
                log.update(text)
        except Exception as e:
            msg = f"[red]Parsing error: {e}[/red]"
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
    """Build the CLI parser for non-GUI utilities."""
    p = argparse.ArgumentParser(description="ADCS TUI / tools")
    p.add_argument("--resign-crl", action="store_true",
                   help="Re-sign the CRL of the specified CA and exit (no GUI).")
    p.add_argument("--ca-id", type=str,
                   help="CA identifier as defined in adcs.yaml (field 'id' or 'display_name').")
    p.add_argument("--no-bump-number", action="store_true",
                   help="Do not increment CRLNumber when re-signing (keep the same number).")
    p.add_argument("--next-update-hours", type=int, default=8,
                   help="Hours until NextUpdate when re-signing (default: 8).")
    p.add_argument("--rotate-if-expiring", action="store_true",
                   help="If the given certificate expires in ≤ threshold-days, re-issue a new key+cert with same SAN/CN using --ca-id and overwrite --crt-path/--key-path.")
    p.add_argument("--crt-path", type=str,
                   help="Path to the existing certificate (PEM) to check/replace.")
    p.add_argument("--key-path", type=str,
                   help="Path to the existing private key (PEM) to replace.")
    p.add_argument("--threshold-days", type=int, default=30,
                   help="Rotate when the certificate expires in ≤ this many days (default: 30).")
    p.add_argument("--chain", action="append",
                   help="PEM path to a chain certificate (intermediate or root). "
                        "Repeat the option for each file, in order: leaf -> intermediate(s) -> root.")
    p.add_argument("--fullchain-path", type=str,
                   help="Path to write the full chain to (default: --crt-path).")
    p.add_argument("--no-write-fullchain-to-crt", action="store_true",
                   help="Do not write the full chain into --crt-path (useful if you want to keep only the leaf cert).")
    p.add_argument("--valid-days", type=int,
                   help="Validity period of the new certificate in days (takes precedence over the original duration).")
    return p


if __name__ == "__main__":
    parser = _build_arg_parser()
    args, unknown = parser.parse_known_args()

    if args.rotate_if_expiring:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --rotate-if-expiring", file=sys.stderr)
            sys.exit(1)
        if not args.crt_path or not args.key_path:
            print("ERROR: --crt-path and --key-path are required with --rotate-if-expiring", file=sys.stderr)
            sys.exit(1)

        chain_paths = []
        if args.chain:
            # Also supports a comma-separated list given to a single --chain
            for item in args.chain:
                parts = [p.strip() for p in item.split(",") if p.strip()]
                chain_paths.extend(parts)
    

        rc = _cmd_rotate_if_expiring(
            ca_id=args.ca_id,
            crt_path=args.crt_path,
            key_path=args.key_path,
            threshold_days=int(args.threshold_days),
            conf=load_yaml_conf("adcs.yaml"),
            chain_paths=chain_paths or None,
            fullchain_path=args.fullchain_path,
            write_fullchain_to_crt=(not args.no_write_fullchain_to_crt),
            valid_days=args.valid_days if args.valid_days else 365
        )
        sys.exit(rc)
    
    

    if args.resign_crl:
        if not args.ca_id:
            print("ERROR: --ca-id is required with --resign-crl", file=sys.stderr)
            sys.exit(1)
        rc = _cmd_resign_crl(
            ca_id=args.ca_id,
            next_update_hours=int(args.next_update_hours),
            bump_number=(not args.no_bump_number),
        )
        sys.exit(rc)

    ADCSApp().run()
