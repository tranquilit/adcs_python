#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADCS TUI — Terminal application (SSH) à la “mc”
------------------------------------------------
• Browse CAs, list certificates, search/sort/filter, view certificate details.
• Simple revocation (CRL update) via utils.revoke.
• Unrevoke support via utils.unrevoke.
• Shows whether a certificate is revoked (reads CRL).
• Keyboard: see help (press '?').

Dependencies:
  pip install textual cryptography PyYAML

The app reuses your adcs.yaml and your folders (certs, list_request_id).
"""
from __future__ import annotations

import os
import glob
import csv
import base64
import textwrap
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Container
from textual.widgets import (
    Header, Footer, Static, DataTable, Input, Select, Button, Label,
)
from textual.reactive import reactive
from textual import events  # to intercept keys

# --- Textual compatibility: TextLog may not exist depending on version ---
try:
    from textual.widgets import TextLog as _TextLog
except Exception:
    try:
        from textual.widgets import Log as _TextLog  # older Textual
    except Exception:
        _TextLog = Static  # last resort (plain display)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

# Your utilities
from adcs_config import load_yaml_conf
from utils import revoke, unrevoke  # revoke/unrevoke CRL entries

# =============================
# Model & parsing
# =============================

CERT_EXTS = {".crt", ".pem", ".cer"}

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

PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_END = b"-----END CERTIFICATE-----"

def _is_pem(data: bytes) -> bool:
    return PEM_BEGIN in data and PEM_END in data

def _load_certificate(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    if not _is_pem(data):
        try:
            return x509.load_der_x509_certificate(data)
        except Exception:
            try:
                der = base64.b64decode(data)
                return x509.load_der_x509_certificate(der)
            except Exception as e:
                raise ValueError(f"File not recognized as X.509 certificate: {os.path.basename(path)}: {e}")
    return x509.load_pem_x509_certificate(data)

def _get_pubkey_info(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return ("RSA", pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        try:
            name = pk.curve.name
        except Exception:
            name = pk.curve.__class__.__name__
        return (f"EC({name})", None)
    if isinstance(pk, dsa.DSAPublicKey):
        return ("DSA", pk.key_size)
    return (pk.__class__.__name__, None)

def row_from_cert(path: str) -> CertRow:
    cert = _load_certificate(path)
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
    pk_type, pk_bits = _get_pubkey_info(cert)
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

def scan_cert_paths(cert_dir: str) -> List[str]:
    files: List[str] = []
    for ext in CERT_EXTS:
        files.extend(glob.glob(os.path.join(cert_dir, f"**/*{ext}"), recursive=True))
    return sorted(set(files))

# --- CRL helpers (local read, robust) ---
def _load_existing_crl(path: str):
    """Load an existing CRL (PEM or DER). Returns None if missing."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        try:
            return x509.load_pem_x509_crl(data)
        except Exception:
            return x509.load_der_x509_crl(data)
    except FileNotFoundError:
        return None

def _iter_revoked(crl) -> List[x509.RevokedCertificate]:
    """Iterate revoked entries across cryptography versions."""
    if not crl:
        return []
    try:
        return list(crl)  # CRL objects are often iterable
    except Exception:
        rc = getattr(crl, "revoked_certificates", None)
        return list(rc) if rc else []

def _revoked_serials_set(crl_path: Optional[str]) -> Set[int]:
    """Return the set of revoked serial numbers (as ints) from the CRL."""
    if not crl_path:
        return set()
    crl = _load_existing_crl(crl_path)
    if not crl:
        return set()
    return {rc.serial_number for rc in _iter_revoked(crl)}

# =============================
# TUI
# =============================

class Status(Static):
    """Compact status bar."""
    def set_text(self, msg: str) -> None:
        self.update(f"[b]{msg}[/b]")

class ADCSApp(App):
    CSS = """
    Screen { layout: vertical; }
    #top { height: 3; }
    #main { layout: horizontal; }
    #left { width: 36; border: tall; }
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
        Binding("r", "revoke_current", "Revoke"),          # R
        Binding("u", "unrevoke_current", "Unrevoke"),      # U
        Binding("tab", "next_pane", "Next"),
        Binding("shift+tab", "prev_pane", "Prev"),
        Binding("q", "quit", "Quit"),
    ]

    # State
    confadcs: Dict[str, Any] = {}
    current_ca: reactive[Dict[str, Any] | None] = reactive(None)
    cert_rows: List[CertRow] = []
    revoked_serials: Set[int] = set()  # current CRL set

    # Filters
    filter_q: reactive[str] = reactive("")
    filter_algo: reactive[str] = reactive("")
    filter_keytype: reactive[str] = reactive("")
    filter_status: reactive[str] = reactive("")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top"):
            yield Status(id="status")
        with Container(id="main"):
            with Vertical(id="left"):
                yield Label("Certification Authority", id="lbl_ca")
                yield Select(options=[], id="sel_ca")
                with Container(id="filters"):
                    yield Label("Filters (press 'f' to toggle)")
                    yield Input(placeholder="Search… (/)", id="inp_q")
                    yield Select(options=[("(Algo: any)", ""), ("SHA-256", "sha256"), ("SHA-384", "sha384"), ("SHA-512", "sha512")], id="sel_algo")
                    yield Select(options=[("(Key: any)", ""), ("RSA", "rsa"), ("EC", "ec"), ("DSA", "dsa")], id="sel_key")
                    yield Select(options=[("(Status: any)", ""), ("Expiring ≤ 30d", "expiring"), ("Valid > 30d", "valid"), ("Expired", "expired")], id="sel_status")
                    yield Button("Apply", id="btn_apply")
                yield Button("Export CSV (e)", id="btn_export")
                yield Button("Reload (F5)", id="btn_reload")
                with Container():
                    yield Button("Revoke (R)", id="btn_revoke")
                    yield Button("Unrevoke (U)", id="btn_unrevoke")
            with Vertical(id="right"):
                yield DataTable(id="table", zebra_stripes=True)
                yield _TextLog(id="detail")
        yield Footer()

    # ---------- helpers ----------
    def _table(self) -> DataTable:
        return self.query_one(DataTable)

    def _show_detail_current_row(self) -> None:
        """Display details for the current table row (if any)."""
        table = self._table()
        rows = self.filtered_rows()
        if not rows:
            return
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        self.show_detail(rows[row_idx])

    # ---------- Init ----------
    def on_mount(self) -> None:
        self.query_one(Status).set_text("Loading configuration…")
        try:
            self.confadcs = load_yaml_conf("adcs.yaml")
        except Exception as e:
            self.notify(f"Unable to load adcs.yaml: {e}", severity="error")
            raise

        # Populate CA select
        sel = self.query_one("#sel_ca", Select)
        options = []
        for ca in (self.confadcs.get("cas_list") or []):
            label = ca.get("display_name") or ca.get("id")
            options.append((label, str(ca.get("__refid"))))
        sel.set_options(options)
        if options:
            sel.value = options[0][1]
            self.switch_ca(int(sel.value))

        # Table
        table = self._table()
        table.cursor_type = "row"
        self.ensure_table_columns()
        self.query_one(Status).set_text("Ready. Press '?' for help.")

    # ---------- DataTable columns ----------
    def ensure_table_columns(self) -> None:
        table = self._table()
        expected = ["#", "Serial", "Subject", "Valid from", "Valid until",
                    "Days", "Revoked", "Signature", "Public Key", "SHA-256", "File"]

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
                table.clear(columns=True)  # newer Textual
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
        # load CRL and certs
        crl_path = (ca.get("crl") or {}).get("path_crl")
        self.revoked_serials = _revoked_serials_set(crl_path)
        self.load_certs()

    def load_certs(self) -> None:
        ca = self.current_ca
        if not ca:
            return
        cert_dir = ca.get("__path_cert")
        paths = scan_cert_paths(cert_dir)
        self.cert_rows = []
        for p in paths:
            try:
                row = row_from_cert(p)
                # revoked status via CRL (serial as int)
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
        q = self.filter_q.lower().strip()
        algo = self.filter_algo.lower()
        keytype = self.filter_keytype.lower()
        status = self.filter_status
        rows = self.cert_rows
        if q:
            rows = [r for r in rows if q in r.subject.lower() or q in r.serial_nox.lower() or q in r.sha256_fingerprint.lower() or q in r.filename.lower()]
        if algo:
            rows = [r for r in rows if r.sig_algo.lower() == algo]
        if keytype:
            rows = [r for r in rows if keytype in r.pubkey_type.lower()]
        if status:
            if status == 'expiring':
                rows = [r for r in rows if 0 < r.days_to_expiry <= 30]
            elif status == 'valid':
                rows = [r for r in rows if r.days_to_expiry > 30]
            elif status == 'expired':
                rows = [r for r in rows if r.days_to_expiry == 0]
        # list revoked first, then by days to expiry
        rows = sorted(rows, key=lambda r: (not r.revoked, r.days_to_expiry))
        return rows

    def refresh_table(self) -> None:
        table = self._table()
        self.ensure_table_columns()
        try:
            table.clear()
        except TypeError:
            while getattr(table, "row_count", 0):
                table.remove_row(0)

        rows = self.filtered_rows()
        for i, r in enumerate(rows, start=1):
            table.add_row(
                str(i),
                r.serial_nox,
                r.subject,
                r.not_before.strftime('%Y-%m-%d'),
                r.not_after.strftime('%Y-%m-%d'),
                str(r.days_to_expiry),
                "yes" if r.revoked else "no",
                r.sig_algo,
                f"{r.pubkey_type}{' '+str(r.pubkey_bits)+' bits' if r.pubkey_bits else ''}",
                r.sha256_fingerprint,
                r.filename,
            )

        if rows:
            try:
                table.move_cursor(row=0, column=0)  # newer Textual
            except Exception:
                try:
                    table.cursor_coordinate = (0, 0)  # older Textual
                except Exception:
                    pass
            try:
                table.focus()
            except Exception:
                pass
            self._show_detail_current_row()

        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        self.query_one(Status).set_text(f"{len(rows)} certificates — CA: {ca_name}")

    # ---------- Actions ----------
    def action_help(self) -> None:
        msg = textwrap.dedent("""
        Keyboard shortcuts
        ------------------
        / : Quick search
        f : Toggle filters
        Enter : Show details for current row
        e : Export current (filtered) list to CSV in cwd
        r : Revoke selected certificate
        u : Unrevoke selected certificate
        F5 : Reload CA
        Tab / Shift+Tab : Move between left/right panes
        q : Quit
        """)
        self.notify(msg, title="Help", severity="information", timeout=8)

    def action_focus_search(self) -> None:
        self.query_one("#inp_q", Input).focus()

    def action_toggle_filters(self) -> None:
        filters = self.query_one("#filters")
        filters.display = ("none" if filters.display != "none" else "block")

    def action_reload(self) -> None:
        # Reload CRL + certs
        ca = self.current_ca
        if ca:
            crl_path = (ca.get("crl") or {}).get("path_crl")
            self.revoked_serials = _revoked_serials_set(crl_path)
        self.load_certs()

    def action_open_detail(self) -> None:
        self._show_detail_current_row()

    def action_export_csv(self) -> None:
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
        table = self._table()
        rows = self.filtered_rows()
        if not rows:
            self.notify("No certificates to operate on.", severity="warning")
            return None
        row_idx = getattr(table, "cursor_row", None)
        if row_idx is None or row_idx < 0 or row_idx >= len(rows):
            row_idx = 0
        return rows[row_idx]

    def action_revoke_current(self) -> None:
        """Revoke the selected certificate and update the CRL."""
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

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        serial = r.serial_nox  # hex (no 0x)
        try:
            revoke(ca_key=ca_key, ca_cert=ca_cert, serial=serial, crl_path=crl_path)
            # Reload CRL + table + details
            self.revoked_serials = _revoked_serials_set(crl_path)
            self.load_certs()
            self.notify(f"Cert {serial} revoked — CRL updated: {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"Revoke failed: {e}", severity="error", timeout=8)

    def action_unrevoke_current(self) -> None:
        """Unrevoke the selected certificate and update the CRL."""
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

        try:
            ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        except Exception as e:
            self.notify(f"Failed to load CA cert (DER): {e}", severity="error", timeout=6)
            return

        serial = r.serial_nox  # hex (no 0x)
        try:
            unrevoke(ca_key=ca_key, ca_cert=ca_cert, serial=serial, crl_path=crl_path)
            # Reload CRL + table + details
            self.revoked_serials = _revoked_serials_set(crl_path)
            self.load_certs()
            self.notify(f"Cert {serial} unrevoked — CRL updated: {crl_path}", severity="success", timeout=6)
        except Exception as e:
            self.notify(f"Unrevoke failed: {e}", severity="error", timeout=8)

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
        elif event.select.id == "sel_algo":
            self.filter_algo = event.value or ""
            self.refresh_table()
        elif event.select.id == "sel_key":
            self.filter_keytype = event.value or ""
            self.refresh_table()
        elif event.select.id == "sel_status":
            self.filter_status = event.value or ""
            self.refresh_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "inp_q":
            self.filter_q = event.value or ""
            self.refresh_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_apply":
            q = self.query_one("#inp_q", Input).value or ""
            self.filter_q = q
            self.refresh_table()
        elif event.button.id == "btn_export":
            self.action_export_csv()
        elif event.button.id == "btn_reload":
            self.action_reload()
        elif event.button.id == "btn_revoke":
            self.action_revoke_current()
        elif event.button.id == "btn_unrevoke":
            self.action_unrevoke_current()

    # --- Auto-update the details panel when the row changes ---
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

    # Universal fallback: intercept arrows when focus is on the table
    def on_key(self, event: events.Key) -> None:
        if self.focused is self._table():
            if event.key in ("up", "down", "pageup", "pagedown", "home", "end"):
                # NOTE: use a tiny positive delay to avoid ZeroDivisionError in some Textual versions
                self.set_timer(0.05, self._show_detail_current_row)

    # ---------- Certificate detail panel ----------
    def show_detail(self, r: CertRow) -> None:
        ca = self.current_ca
        if not ca:
            return
        cert_dir = ca.get("__path_cert")
        cert_path = None
        for p in scan_cert_paths(cert_dir):
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
            cert = _load_certificate(cert_path)
            # revoked status
            try:
                serial_int = int(format(cert.serial_number, "x"), 16)
            except ValueError:
                serial_int = int(cert.serial_number)
            is_revoked = serial_int in self.revoked_serials

            lines: List[str] = []
            lines.append(f"File: {cert_path}")
            lines.append(f"Subject: {cert.subject.rfc4514_string()}")
            lines.append(f"Serial (hex): {format(cert.serial_number, 'x')}")
            lines.append(f"Validity: {cert.not_valid_before} -> {cert.not_valid_after}")
            lines.append(f"Revoked: {'yes' if is_revoked else 'no'}")
            try:
                sig_algo = cert.signature_hash_algorithm.name
            except Exception:
                sig_algo = "unknown"
            lines.append(f"Signature: {sig_algo}")
            pk_type, pk_bits = _get_pubkey_info(cert)
            lines.append(f"Public Key: {pk_type}{' '+str(pk_bits)+' bits' if pk_bits else ''}")
            fp = cert.fingerprint(hashes.SHA256()).hex()
            lines.append(f"SHA-256: {fp}")
            # SAN + KU + EKU (best effort)
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

if __name__ == "__main__":
    ADCSApp().run()

