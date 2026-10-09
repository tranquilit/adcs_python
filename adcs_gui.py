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

All certificate operations are delegated to adcs_actions.py;
commands are implemented separately in adcs_tool.py.
"""
from __future__ import annotations
import os
import sys
import textwrap
import argparse
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Set

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, Container
from textual.widgets import (
    Header, Footer, Static, DataTable, Input, Select, Button, Label
)
from textual.reactive import reactive
from textual import events  # to intercept keys
try:
    from textual import work
except ImportError:
    # Compatibility with Textual releases that expose run_worker() but not the
    # @work decorator yet. The application still gets a background thread.
    def work(*, thread: bool = False, exclusive: bool = False, group: Optional[str] = None):
        def decorator(func):
            def start_worker(self, *args, **kwargs):
                runner = lambda: func(self, *args, **kwargs)
                try:
                    return self.run_worker(
                        runner, thread=thread, exclusive=exclusive, group=group
                    )
                except TypeError:
                    return self.run_worker(
                        runner, thread=thread, exclusive=exclusive
                    )
            return start_worker
        return decorator
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

from adcs_config import load_yaml_conf
from utils_crt import revoked_serials_set, load_certificate_file, parse_certificate_details

from adcs_cert_store import (
    TABLE_HEADER_SORT_KEYS, MAX_ROWS_DEFAULT, CertRow,
    _cert_row_serial_int, _resolve_storage_paths_from_ca,
    _sync_certificate_cache, list_certificate_rows,
    _sort_certificate_rows_in_memory,
    _cached_certificate_details,
    scan_certificate_rows_without_sqlite, filter_certificate_rows_without_sqlite,
)
from adcs_actions import (
    issue_certificate, change_revocation, resign_ca_crl, delete_certificate,
)

# Display-only column layouts (the SQLite sort/filter definitions remain shared
# in adcs_cert_store.py). Keep these headers in sync with the original UI.
FULL_COLUMNS = ["Sel", "#", "Serial", "Subject", "Valid from", "Valid until",
                "Days", "Revoked", "Is CA", "Signature", "Public Key", "SHA-256", "File"]
COMPACT_COLUMNS = ["Sel", "#", "Serial", "Subject", "Valid until", "Days", "Revoked", "Is CA"]
NARROW_COLUMNS = ["Sel", "#", "Serial", "Subject", "Days", "Revoked"]
TINY_COLUMNS = ["Sel", "#", "Subject", "Days", "Revoked"]

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
            result = issue_certificate(
                self.ca, common_name=cn, sans=sans,
                rsa_bits=rsa_bits, valid_days=valid_days, fullchain=False,
            )
            crt_path = result['certificate_path']
            key_path = result['key_path']
        except Exception as e:
            self.parent_app.notify(f"Issue certificate failed: {e}", severity="error", timeout=8)
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
    def __init__(self, *, confadcs_path: str = "/etc/adcs/adcs.yaml", **kwargs) -> None:
        super().__init__(**kwargs)
        self.confadcs_path = confadcs_path

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
    revoked_serials: Set[int] = set()

    # SQLite-backed view state. The query result is cached until search/status,
    # sort, CA contents or CRL state changes, so cursor movement and selection
    # never re-run the database query.
    _cache_available: bool = False
    cert_rows: List[CertRow] = []  # Directly parsed rows only if SQLite is unavailable.
    _certificate_cache_error: Optional[str] = None
    _filtered_rows_cache_key: Optional[tuple] = None
    _filtered_rows_cache: List[CertRow] = []
    _filtered_rows_total: int = 0
    _visible_rows: List[CertRow] = []
    _sort_column: str = "not_before"
    _sort_descending: bool = False

    # Generation counter for asynchronous certificate-cache loads. A result from
    # an older CA/load is ignored if the user switches CA while a worker runs.
    _certificate_load_generation: int = 0
    _certificate_load_in_progress: bool = False

    compact_mode: reactive[bool] = reactive(False)
    details_side_by_side: reactive[bool] = reactive(False)
    _table_density: str = "full"

    filter_q: reactive[str] = reactive("")
    filter_status: reactive[str] = reactive("")
    filter_revocation: reactive[str] = reactive("")

    # Maximum number of rows materialized in the DataTable. 0 means unlimited.
    # The value can be changed at runtime from the filters pane.
    max_rows: reactive[int] = reactive(MAX_ROWS_DEFAULT)

    # Keep-focus support: filename to reselect after refresh. When a row
    # disappears (revocation filter / deletion), also remember the previous
    # viewport so the replacement row stays at roughly the same screen height
    # instead of being auto-scrolled to the bottom of the DataTable.
    _pending_select_filename: Optional[str] = None
    _pending_table_viewport: Optional[tuple[float, int]] = None

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
                    yield Label("Search, Status & Limit", id="lbl_filters")
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
                    yield _mc_select(
                        options=[
                            ("(Revocation: any)", ""),
                            ("Revoked", "revoked"),
                            ("Not revoked", "not_revoked"),
                        ],
                        id="sel_revocation",
                        value="",
                    )
                    yield Label("Max rows (0 = all)", id="lbl_max_rows")
                    yield Input(
                        value=str(MAX_ROWS_DEFAULT),
                        placeholder="Max rows (0 = all)",
                        id="inp_max_rows",
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

    def _remember_table_viewport(self) -> Optional[tuple[float, int]]:
        """Return (scroll_y, cursor_row) for restoring the visual neighborhood."""
        table = self._maybe_table()
        if table is None:
            return None
        try:
            scroll_y = float(getattr(table, "scroll_y", 0) or 0)
        except Exception:
            scroll_y = 0.0
        try:
            cursor_row = int(getattr(table, "cursor_row", 0) or 0)
        except Exception:
            cursor_row = 0
        return (scroll_y, cursor_row)

    def _request_reselect(
        self,
        filename: Optional[str],
        viewport: Optional[tuple[float, int]] = None,
    ) -> None:
        self._pending_select_filename = filename
        # Normal refreshes intentionally clear any old pending viewport. Only
        # callers that are replacing/removing a row opt in to scroll restoration.
        self._pending_table_viewport = viewport

    def _restore_table_viewport(
        self,
        viewport: Optional[tuple[float, int]],
        target_idx: int,
    ) -> None:
        """Restore cursor's previous screen height after a table rebuild.

        DataTable.move_cursor() scrolls just enough to reveal an off-screen row,
        which tends to place it at the bottom. Compensate for any row-index shift
        caused by removed rows so the new focused row stays where the old cursor
        was visually.
        """
        if viewport is None:
            return

        old_scroll_y, old_cursor_row = viewport
        desired_y = max(0.0, old_scroll_y + (target_idx - old_cursor_row))
        table = self._maybe_table()
        if table is None:
            return

        scroll_to = getattr(table, "scroll_to", None)
        if callable(scroll_to):
            try:
                scroll_to(y=desired_y, animate=False, force=True)
                return
            except TypeError:
                try:
                    scroll_to(y=desired_y, animate=False)
                    return
                except TypeError:
                    try:
                        scroll_to(y=desired_y)
                        return
                    except Exception:
                        pass
                except Exception:
                    pass
            except Exception:
                pass

        # Last-resort compatibility path for older Textual versions.
        try:
            table.scroll_y = desired_y
        except Exception:
            pass

    @staticmethod
    def _nearest_surviving_filename(
        visible_order_before: List[str],
        cursor_filename: Optional[str],
        surviving_filenames: Set[str],
    ) -> Optional[str]:
        """Return the closest surviving row to the previous cursor position.

        Prefer the row below the removed cursor (it naturally slides into the same
        visual position). If none survives below, use the nearest row above.
        """
        if not surviving_filenames:
            return None

        if cursor_filename and cursor_filename in surviving_filenames:
            return cursor_filename

        if not visible_order_before:
            return None

        try:
            cursor_idx = visible_order_before.index(cursor_filename)
        except (ValueError, TypeError):
            # The old cursor is unknown; keep a deterministic visible survivor.
            for filename in visible_order_before:
                if filename in surviving_filenames:
                    return filename
            return None

        # Search outward from the old cursor. At equal distance prefer below.
        for distance in range(1, len(visible_order_before) + 1):
            below = cursor_idx + distance
            if below < len(visible_order_before):
                filename = visible_order_before[below]
                if filename in surviving_filenames:
                    return filename

            above = cursor_idx - distance
            if above >= 0:
                filename = visible_order_before[above]
                if filename in surviving_filenames:
                    return filename

        return None

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
        """Return rows already materialized in the DataTable view."""
        return self._visible_rows

    def _get_target_rows(self) -> List[CertRow]:
        if self.selected_filenames:
            rows = self.filtered_rows(apply_limit=False)
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
        sel_revocation = self.query_one("#sel_revocation")
        lbl_max_rows = self.query_one("#lbl_max_rows", Label)
        inp_max_rows = self.query_one("#inp_max_rows", Input)

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
                # In stacked compact mode, scale the details pane with the
                # terminal height. Keep it shallow on short screens, but let it
                # grow when vertical space is available. The detail widget is
                # scrollable, so the lower bound can stay small without losing
                # information.
                pane_height = max(7, min(24, (self.size.height // 2) - 4))
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
            sel_revocation.display = "none" if self.compact_mode else "block"
            # Max rows visibility depends on whether the current result set is
            # actually truncated. refresh_table() updates these two widgets once
            # it knows the matching row count. Keep them hidden in compact mode.
            if self.compact_mode:
                lbl_max_rows.display = "none"
                inp_max_rows.display = "none"
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
            inp_max_rows.styles.margin = 0 if self.compact_mode else (0, 0, 1, 0)
        except Exception:
            pass

        self.ensure_table_columns()
        self.refresh_table()
        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        prefix = "Compact mode — " if self.compact_mode else ""
        if not self._certificate_load_in_progress:
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

        size_changed = getattr(self, "_last_layout_size", None) != (w, h)

        if (
            want_compact != self.compact_mode
            or want_side_by_side != self.details_side_by_side
            or want_density != self._table_density
            or size_changed
        ):
            self.compact_mode = want_compact
            self.details_side_by_side = want_side_by_side
            self._table_density = want_density
            self._last_layout_size = (w, h)
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

        # Reflect the effective startup value (constant or ADCS_MAX_ROWS) in the UI.
        try:
            self.query_one("#inp_max_rows", Input).value = str(self.max_rows)
        except Exception:
            pass

        try:
            self.confadcs = load_yaml_conf(self.confadcs_path,bypass_read_only=True)
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
        if not self._certificate_load_in_progress:
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

    def _display_table_columns(self) -> List[str]:
        """Return visible headers with the sort arrow on the active column."""
        columns = list(self._expected_table_columns())
        arrow = "↓" if self._sort_descending else "↑"
        active_header = next(
            (label for label, key in TABLE_HEADER_SORT_KEYS.items()
             if key == self._sort_column),
            None,
        )
        if active_header in columns:
            columns[columns.index(active_header)] = f"{active_header} {arrow}"
        return columns

    def ensure_table_columns(self, force: bool = False) -> None:
        table = self._table()
        expected = self._expected_table_columns()
        displayed = self._display_table_columns()

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

        if force or current != len(expected):
            try:
                table.clear(columns=True)
            except Exception:
                try:
                    table.clear()
                except Exception:
                    pass
            try:
                table.add_columns(*displayed)
            except Exception:
                for col in displayed:
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

    def _invalidate_filtered_rows_cache(self) -> None:
        self._filtered_rows_cache_key = None
        self._filtered_rows_cache = []
        self._filtered_rows_total = 0

    def _apply_crl_state_without_certificate_reload(
        self,
        revoked_serials: Set[int],
        cursor_filename: Optional[str],
    ) -> None:
        """Apply freshly-read CRL state to the current UI without reloading certs."""
        # Snapshot the current visible layout and viewport before mutating CRL
        # state. If a revocation filter removes the focused row, the replacement
        # row can later be restored at the same screen height.
        viewport_before = self._remember_table_viewport()
        visible_order_before = [row.filename for row in self._visible_rows]
        revoked_before = {row.filename: row.revoked for row in self._visible_rows}

        self.revoked_serials = set(revoked_serials)

        # Update every certificate row that is already materialized in memory.
        # Do not rescan files and do not requery SQLite just to refresh CRL state.
        seen: Set[int] = set()
        for collection in (self._visible_rows, self._filtered_rows_cache, self.cert_rows):
            for row in collection:
                row_id = id(row)
                if row_id in seen:
                    continue
                seen.add(row_id)
                row.revoked = _cert_row_serial_int(row) in self.revoked_serials

        # If an explicit revocation filter is active, rows changed by the action
        # may no longer belong in the current view. Remove those rows locally; do
        # not fetch replacement rows from SQLite until the next normal refresh.
        removed_filenames: Set[str] = set()
        if self.filter_revocation == "revoked":
            kept = []
            for row in self._visible_rows:
                if row.revoked:
                    kept.append(row)
                else:
                    removed_filenames.add(row.filename)
            self._visible_rows = kept
        elif self.filter_revocation == "not_revoked":
            kept = []
            for row in self._visible_rows:
                if not row.revoked:
                    kept.append(row)
                else:
                    removed_filenames.add(row.filename)
            self._visible_rows = kept

        if removed_filenames:
            self._filtered_rows_total = max(
                0, self._filtered_rows_total - len(removed_filenames)
            )
            self.selected_filenames.difference_update(removed_filenames)

        # Revoked sorting is CRL-only. Re-sort the rows already on screen locally
        # rather than issuing another database query.
        if self._sort_column == "revoked":
            self._visible_rows = _sort_certificate_rows_in_memory(
                self._visible_rows, "revoked", self._sort_descending
            )

        # Any future normal refresh must query again because its cached rows were
        # built with the previous CRL state. Keep the current total for this local
        # repaint, however.
        self._filtered_rows_cache_key = None
        self._filtered_rows_cache = []

        # Fast path: if the visible rows are still exactly the same and in the same
        # order, do not clear/rebuild the DataTable. Updating just the Revoked cell
        # preserves focus, scroll position and terminal contents, eliminating the
        # flash seen after revoke/unrevoke. If the Textual version does not support
        # in-place cell updates, or a filter/sort changed the layout, fall back to
        # the normal full repaint.
        if self._refresh_revocation_cells_in_place(
            visible_order_before, revoked_before
        ):
            self._pending_select_filename = None
            self._show_detail_current_row()
            return

        # A revocation filter can make the current row disappear. Do not fall
        # back to row 0: keep the same visual neighborhood by selecting the next
        # surviving row, or the previous one when the cursor was at the bottom.
        surviving_filenames = {row.filename for row in self._visible_rows}
        focus_filename = self._nearest_surviving_filename(
            visible_order_before, cursor_filename, surviving_filenames
        )
        self._request_reselect(focus_filename, viewport=viewport_before)
        self.refresh_table(reuse_visible=True)

    def _certificate_load_is_current(self, generation: int, ca_refid: Any) -> bool:
        current_refid = self.current_ca.get("__refid") if self.current_ca else None
        return (
            generation == self._certificate_load_generation
            and current_refid == ca_refid
        )

    def _update_certificate_load_stage(
        self,
        generation: int,
        ca_refid: Any,
        message: str,
    ) -> None:
        """Show a coarse cache-loading phase before numeric progress is known."""
        if not self._certificate_load_is_current(generation, ca_refid):
            return
        self.query_one(Status).set_text(message)

    def _update_certificate_load_progress(
        self,
        generation: int,
        ca_refid: Any,
        done: int,
        new_total: int,
        certificate_total: int,
    ) -> None:
        """Update only the loading status; keep the certificate grid empty."""
        if not self._certificate_load_is_current(generation, ca_refid):
            return

        # Do not expose a partially synchronized SQLite cache to the DataTable.
        # The table is populated once, by _finish_certificate_load(), after the
        # worker has completely finished synchronizing the database.
        if new_total > 0:
            self.query_one(Status).set_text(
                f"Loading SQLite cache: {done}/{new_total} new certificate(s) "
                f"— {certificate_total} total"
            )
        else:
            self.query_one(Status).set_text(
                f"Checking SQLite cache — {certificate_total} certificate(s)"
            )

    def _finish_certificate_load(
        self,
        generation: int,
        ca_refid: Any,
        cache_error: Optional[str],
        direct_rows: Optional[List[CertRow]],
        direct_error: Optional[str],
    ) -> None:
        """Apply the current SQLite or direct-scan worker result to Textual."""
        if not self._certificate_load_is_current(generation, ca_refid):
            return
        self._certificate_load_in_progress = False
        self._cache_available = cache_error is None
        self._certificate_cache_error = cache_error
        self.cert_rows = direct_rows or []
        self._invalidate_filtered_rows_cache()

        if cache_error:
            self.notify(
                f"SQLite unavailable; using direct certificate scan: {cache_error}",
                severity="warning" if direct_error is None else "error", timeout=8,
            )
            if direct_error:
                self.notify(f"Direct scan also failed: {direct_error}", severity="error", timeout=8)
        self.refresh_table()

    @work(thread=True, exclusive=True, group="certificate-cache-load")
    def _load_certs_worker(
        self,
        generation: int,
        ca_refid: Any,
        certs_dir: str,
        revoked_serials: Set[int],
        force_direct: bool = False,
    ) -> None:
        """Try SQLite, falling back to a single direct scan off the UI thread."""
        cache_error: Optional[str] = None
        direct_rows: Optional[List[CertRow]] = None
        direct_error: Optional[str] = None

        def stage(message: str) -> None:
            self.call_from_thread(
                self._update_certificate_load_stage,
                generation, ca_refid, message,
            )

        def progress(done: int, new_total: int, certificate_total: int) -> None:
            self.call_from_thread(
                self._update_certificate_load_progress,
                generation, ca_refid, done, new_total, certificate_total,
            )

        if not force_direct:
            try:
                _sync_certificate_cache(certs_dir, progress=progress, status=stage)
            except Exception as exc:
                cache_error = str(exc)
        else:
            cache_error = self._certificate_cache_error or "SQLite query failed"

        if cache_error is not None:
            stage("SQLite unavailable; scanning certificate files directly...")
            try:
                direct_rows = scan_certificate_rows_without_sqlite(
                    certs_dir, revoked_serials,
                )
            except Exception as exc:
                direct_error = str(exc)

        self.call_from_thread(
            self._finish_certificate_load, generation, ca_refid,
            cache_error, direct_rows, direct_error,
        )

    def load_certs(self, force_direct: bool = False) -> None:
        ca = self.current_ca
        if not ca:
            return

        certs_dir, _private_dir = self._resolve_storage_paths(ca)
        ca_refid = ca.get("__refid")

        self._visible_rows = []
        self._cache_available = False
        self.cert_rows = []
        if not force_direct:
            self._certificate_cache_error = None
        self._invalidate_filtered_rows_cache()

        # Keep the UI deliberately empty while SQLite is being synchronized.
        # This also clears rows from a previously selected CA/reload instead of
        # leaving stale certificates visible during the background operation.
        table = self._table()
        try:
            table.clear()
        except TypeError:
            while getattr(table, "row_count", 0):
                table.remove_row(0)

        try:
            detail = self.query_one("#detail")
            if hasattr(detail, "clear"):
                detail.clear()
            else:
                detail.update("")
        except Exception:
            pass

        self._certificate_load_generation += 1
        generation = self._certificate_load_generation
        self._certificate_load_in_progress = True

        # This is set before starting the worker so Textual can paint it while
        # SQLite/cache parsing continues in the background.
        self.query_one(Status).set_text(
            "Preparing certificate cache..."
        )

        self._load_certs_worker(
            generation,
            ca_refid,
            certs_dir,
            set(self.revoked_serials),
            force_direct,
        )

    # ---------- Filters & view ----------
    def filtered_rows(self, apply_limit: bool = True) -> List[CertRow]:
        """Use shared SQLite filters, or the shared direct-scan fallback."""
        if not self.current_ca:
            return []
        certs_dir, _private_dir = self._resolve_storage_paths(self.current_ca)
        query_limit = self.max_rows if (apply_limit and self.max_rows > 0) else 0
        cache_key = (
            certs_dir, self.filter_q.lower().strip(), self.filter_status,
            self.filter_revocation, self._sort_column, self._sort_descending,
            query_limit, self._cache_available,
        )
        if self._filtered_rows_cache_key == cache_key:
            return self._filtered_rows_cache
        try:
            kwargs = dict(
                query=self.filter_q, status=self.filter_status,
                revocation=self.filter_revocation, revoked_serials=self.revoked_serials,
                sort_column=self._sort_column, descending=self._sort_descending,
                limit=query_limit,
            )
            if self._cache_available:
                rows, total = list_certificate_rows(certs_dir, **kwargs)
            else:
                rows, total = filter_certificate_rows_without_sqlite(self.cert_rows, **kwargs)
            self._filtered_rows_total = total
            self._filtered_rows_cache_key = cache_key
            self._filtered_rows_cache = rows
            return rows
        except (OSError, sqlite3.Error) as exc:
            self._certificate_cache_error = str(exc)
            self._invalidate_filtered_rows_cache()
            self._filtered_rows_total = 0
            self.notify(
                f"SQLite query failed; switching to direct scan: {exc}",
                severity="warning", timeout=8,
            )
            # Preserve the previous row/viewport across the asynchronous
            # database-to-direct-scan transition whenever possible.
            focus_filename = self._pending_select_filename or self._remember_cursor_filename()
            focus_viewport = self._pending_table_viewport or self._remember_table_viewport()
            self._request_reselect(focus_filename, viewport=focus_viewport)
            self.load_certs(force_direct=True)
            return []

    @staticmethod
    def _mc_cell(value: object, marked: bool = False) -> object:
        """Emphasize marked rows without imposing a color outside the theme."""
        if not marked:
            return value
        return Text(str(value), style="bold")

    def _refresh_revocation_cells_in_place(
        self,
        visible_order_before: List[str],
        revoked_before: Dict[str, bool],
    ) -> bool:
        """Update only visible Revoked cells when the table layout is unchanged.

        Returns True when no full table rebuild is needed. Returns False when row
        membership/order changed or when the installed Textual doesn't expose the
        coordinate-based cell update API.
        """
        rows = self._visible_rows
        if [row.filename for row in rows] != visible_order_before:
            return False

        table = self._table()
        update_cell_at = getattr(table, "update_cell_at", None)
        if not callable(update_cell_at):
            return False

        try:
            if int(getattr(table, "row_count", len(rows))) != len(rows):
                return False
        except Exception:
            return False

        try:
            revoked_col = self._expected_table_columns().index("Revoked")
            coordinate_type = type(table.cursor_coordinate)
        except Exception:
            return False

        for row_idx, row in enumerate(rows):
            previous = revoked_before.get(row.filename)
            if previous is None or previous == row.revoked:
                continue

            selected = row.filename in self.selected_filenames
            value = self._mc_cell("yes" if row.revoked else "no", selected)
            coordinate = coordinate_type(row_idx, revoked_col)
            try:
                update_cell_at(coordinate, value, update_width=False)
            except TypeError:
                # Compatibility with older Textual releases where update_width
                # may not be accepted by update_cell_at().
                try:
                    update_cell_at(coordinate, value)
                except Exception:
                    return False
            except Exception:
                return False

        return True

    def refresh_table(self, reuse_visible: bool = False) -> None:
        """Rebuild the DataTable, optionally reusing rows already in memory."""
        table = self._table()
        self.ensure_table_columns()
        try:
            table.clear()
        except TypeError:
            while getattr(table, "row_count", 0):
                table.remove_row(0)

        if reuse_visible:
            # Used after revoke/unrevoke: only repaint the rows whose CRL state
            # was updated in memory. No filesystem scan and no SQLite query.
            all_rows = list(self._visible_rows)
        else:
            all_rows = self.filtered_rows()
        total = self._filtered_rows_total

        # Max rows stays visible whenever the user is using a non-default
        # limit (including 0 = all). With the default value, only show the
        # control when the matching result set actually exceeds that limit.
        # Compact mode always keeps it hidden.
        try:
            show_max_rows = (
                not self.compact_mode
                and (
                    self.max_rows != MAX_ROWS_DEFAULT
                    or (self.max_rows > 0 and total > self.max_rows)
                )
            )
            self.query_one("#lbl_max_rows", Label).display = (
                "block" if show_max_rows else "none"
            )
            self.query_one("#inp_max_rows", Input).display = (
                "block" if show_max_rows else "none"
            )
        except Exception:
            pass

        # Keep hidden Ctrl+A selections when SQL returned only the visible slice.
        # If the full filtered result fits in memory, stale selections can still
        # be removed exactly as before.
        if total <= len(all_rows):
            visible_set = {r.filename for r in all_rows}
            self.selected_filenames = {
                fn for fn in self.selected_filenames if fn in visible_set
            }

        if self.max_rows <= 0:
            rows = all_rows
        else:
            rows = all_rows[: self.max_rows]
        self._visible_rows = rows

        table_width = self._table_view_width()
        for i, r in enumerate(rows, start=1):
            selected = (r.filename in self.selected_filenames)
            sel_mark = "[X]" if selected else "[ ]"

            subj = r.subject
            serial = r.serial_nox

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
        # Keep any requested viewport restoration until after move_cursor(), since
        # move_cursor() itself may auto-scroll the selected row to the bottom.
        pending_viewport = self._pending_table_viewport
        self._pending_table_viewport = None
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

            # Run after the current refresh/layout pass so DataTable's own cursor
            # auto-scroll has already happened and cannot overwrite our position.
            if pending_viewport is not None:
                try:
                    self.call_after_refresh(
                        self._restore_table_viewport, pending_viewport, target_idx
                    )
                except Exception:
                    self._restore_table_viewport(pending_viewport, target_idx)

            self._show_detail_current_row()

        ca_name = (self.current_ca.get('display_name') if self.current_ca else '-')
        prefix = "Compact mode — " if self.compact_mode else ""
        limit_note = ""
        if total > len(rows):
            limit_note = f" (limited to {len(rows)}/{total})"
        sel_note = f" — selected: {len(self.selected_filenames)}"
        sort_arrow = "↓" if self._sort_descending else "↑"
        sort_note = f" — sort: {self._sort_column} {sort_arrow}"
        if not self._certificate_load_in_progress:
            if self._certificate_cache_error and not self._certificate_load_in_progress:
                self.query_one(Status).set_text(
                    f"Direct scan (SQLite unavailable) — "
                    f"{len(rows)}/{total} certificates{sel_note} — CA: {ca_name}{sort_note}{limit_note}"
                )
            else:
                self.query_one(Status).set_text(
                    f"{prefix}{len(rows)}/{total} certificates{sel_note}"
                    f" — CA: {ca_name}{sort_note}{limit_note}"
                )

    # ---------- Actions ----------
    def action_help(self) -> None:
        msg = textwrap.dedent("""
        Keyboard shortcuts
        ------------------
        / : Quick search
        Click a column header : Sort ascending / descending
        Revocation filter : any / revoked / not revoked
        Max rows : enter a limit in the left pane (0 = all), then press Enter

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
            #self.notify("No certificates to operate on.", severity="warning")
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
        for r in self.filtered_rows(apply_limit=False):
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
        crl_path = (ca.get("crl") or {}).get("path_crl")
        if not crl_path:
            self.notify("Incomplete CA config for revoke: missing crl.path_crl", severity="error", timeout=6)
            return

        targets = self._get_target_rows()
        if not targets:
            return

        failed_serials: List[str] = []
        operation_ok: List[CertRow] = []

        for r in targets:
            try:
                change_revocation(
                    ca, r.serial_nox, revoke_it=True,
                    next_update_hours=self.confadcs['next_update_hours_crl'],
                )
                operation_ok.append(r)
            except Exception:
                failed_serials.append(r.serial_nox)

        # Reload only the CRL. A successful revoke is trusted by the UI only if
        # the serial is actually present in the freshly-read CRL.
        try:
            refreshed_revoked = revoked_serials_set(crl_path)
        except Exception as exc:
            self.notify(
                f"Revoke completed but CRL verification failed: {exc}",
                severity="error",
                timeout=8,
            )
            return

        verified_ok: List[CertRow] = []
        for r in operation_ok:
            if _cert_row_serial_int(r) in refreshed_revoked:
                verified_ok.append(r)
            else:
                failed_serials.append(r.serial_nox)

        self._apply_crl_state_without_certificate_reload(
            refreshed_revoked, cursor_fn
        )

        ok = len(verified_ok)
        fail = len(failed_serials)
        if fail == 0:
            self.notify(f"Revoked: {ok} certificate(s) — CRL verified: {crl_path}", severity="success", timeout=6)
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
        crl_path = (ca.get("crl") or {}).get("path_crl")
        if not crl_path:
            self.notify("Incomplete CA config for unrevoke: missing crl.path_crl", severity="error", timeout=6)
            return

        targets = self._get_target_rows()
        if not targets:
            return

        failed_serials: List[str] = []
        operation_ok: List[CertRow] = []

        for r in targets:
            try:
                change_revocation(
                    ca, r.serial_nox, revoke_it=False,
                    next_update_hours=self.confadcs['next_update_hours_crl'],
                )
                operation_ok.append(r)
            except Exception:
                failed_serials.append(r.serial_nox)

        # Reload only the CRL. A successful unrevoke is trusted by the UI only
        # if the serial is absent from the freshly-read CRL.
        try:
            refreshed_revoked = revoked_serials_set(crl_path)
        except Exception as exc:
            self.notify(
                f"Unrevoke completed but CRL verification failed: {exc}",
                severity="error",
                timeout=8,
            )
            return

        verified_ok: List[CertRow] = []
        for r in operation_ok:
            if _cert_row_serial_int(r) not in refreshed_revoked:
                verified_ok.append(r)
            else:
                failed_serials.append(r.serial_nox)

        self._apply_crl_state_without_certificate_reload(
            refreshed_revoked, cursor_fn
        )

        ok = len(verified_ok)
        fail = len(failed_serials)
        if fail == 0:
            self.notify(f"Unrevoked: {ok} certificate(s) — CRL verified: {crl_path}", severity="success", timeout=6)
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
        crl_path = (ca.get("crl") or {}).get("path_crl")
        try:
            new_num, self.revoked_serials = resign_ca_crl(
                ca, next_update_hours=self.confadcs['next_update_hours_crl'],
                bump_number=True,
            )
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
        viewport_before = self._remember_table_viewport()
        visible_order_before = [row.filename for row in self._visible_rows]

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
        deleted_filenames: Set[str] = set()

        for r in targets:
            if r.is_ca:
                blocked.append(r.filename)
                continue
            if not r.revoked and r.not_after > datetime.now(timezone.utc):
                blocked.append(r.filename)
                continue

            certs_dir, _ = self._resolve_storage_paths(ca)
            cert_path = os.path.join(certs_dir, r.cache_key) if r.cache_key else None
            if not cert_path:
                deleted_fail += 1
                continue

            try:
                n_cert, n_key = delete_certificate(
                    ca, cert_path=cert_path, revoked=r.revoked, expires_at=r.not_after,
                )
                cert_deleted += n_cert
                key_deleted += n_key
                deleted_ok += 1
                if n_cert:
                    deleted_filenames.add(r.filename)
                if r.filename in self.selected_filenames:
                    self.selected_filenames.remove(r.filename)
            except Exception:
                deleted_fail += 1

        # If the cursor row was deleted, focus its closest surviving neighbor
        # instead of letting the subsequent reload select the first row.
        surviving_filenames = set(visible_order_before) - deleted_filenames
        focus_filename = self._nearest_surviving_filename(
            visible_order_before, cursor_fn, surviving_filenames
        )
        self._request_reselect(focus_filename, viewport=viewport_before)
        try:
            self.load_certs()
        except Exception:
            pass

        msg = f"Delete: ok={deleted_ok}, failed={deleted_fail}, blocked={len(blocked)} — moved to .trash. (cert:{cert_deleted}, key:{key_deleted})"
        severity = "success" if (deleted_fail == 0 and not blocked) else ("warning" if deleted_ok > 0 else "error")
        self.notify(msg, severity=severity, timeout=10)

        if blocked:
            self.notify(
                "Blocked (CA certificate or must be revoked/expired): " + ", ".join(blocked[:10]) + ("…" if len(blocked) > 10 else ""),
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
        elif event.select.id == "sel_revocation":
            cursor_fn = self._remember_cursor_filename()
            self.filter_revocation = event.value or ""
            self._request_reselect(cursor_fn)
            self.refresh_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "inp_q":
            cursor_fn = self._remember_cursor_filename()
            self.filter_q = event.value or ""
            self._request_reselect(cursor_fn)
            self.refresh_table()
        elif event.input.id == "inp_max_rows":
            cursor_fn = self._remember_cursor_filename()
            raw_value = (event.value or "").strip()
            try:
                value = int(raw_value)
                if value < 0:
                    raise ValueError
            except ValueError:
                self.notify(
                    "Max rows must be a non-negative integer (0 = all).",
                    severity="warning",
                    timeout=5,
                )
                event.input.value = str(self.max_rows)
                return

            self.max_rows = value
            event.input.value = str(value)
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

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """Sort table data and show the direction arrow in the active header."""
        label_obj = getattr(event, "label", "")
        label = getattr(label_obj, "plain", None) or str(label_obj)

        # The active header itself contains the visual sort marker. Strip it
        # before looking up the logical sort key so repeated clicks still toggle.
        for suffix in (" ↑", " ↓"):
            if label.endswith(suffix):
                label = label[:-len(suffix)]
                break

        sort_column = TABLE_HEADER_SORT_KEYS.get(label)
        if not sort_column:
            return

        cursor_fn = self._remember_cursor_filename()
        if sort_column == self._sort_column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = sort_column
            self._sort_descending = False

        self._invalidate_filtered_rows_cache()
        self._request_reselect(cursor_fn)

        # Recreate only the headers so the arrow moves immediately to the
        # newly selected column / direction. refresh_table() repopulates rows.
        self.ensure_table_columns(force=True)
        self.refresh_table()

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
        cert_path = os.path.join(certs_dir, r.cache_key) if r.cache_key else None
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
            if self._cache_available:
                try:
                    details = _cached_certificate_details(certs_dir, r.cache_key)
                except (KeyError, sqlite3.Error, OSError):
                    details = parse_certificate_details(load_certificate_file(cert_path))
            else:
                details = parse_certificate_details(load_certificate_file(cert_path))

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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ADCS terminal interface (optional Textual UI)")
    parser.add_argument("--confadcs", default="/etc/adcs/adcs.yaml", help="ADCS YAML configuration path")
    args = parser.parse_args(argv)
    ADCSApp(confadcs_path=args.confadcs, ansi_color=True).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
