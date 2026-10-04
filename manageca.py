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
import json
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set, Callable
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

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Your utilities
from adcs_config import load_yaml_conf
from utils_crt import (
    revoke,
    unrevoke,
    resign_crl,
    issue_cert_with_new_key,
    load_certificate_file,
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

MAX_ROWS_DEFAULT = 1000

# Per-CA immutable certificate cache. Certificate files are treated as frozen:
# an existing cache key is never re-read from disk. Increment PARSER_VERSION
# whenever parse_certificate_details() output used by this UI changes.
#
# SQLite files live in the current user's local profile, not beside certificates.
# The filename is the SHA-256 hash of the canonical certificate-directory path.
CERT_CACHE_APP_DIR = "adcs-tui"
CERT_CACHE_SUBDIR = "cert-cache"
CERT_CACHE_SCHEMA_VERSION = 2
CERT_CACHE_PARSER_VERSION = 1

# Sort keys accepted by the SQLite certificate query. Values are SQL fragments
# from a fixed whitelist; user-provided text is never interpolated as SQL.
CERT_CACHE_SORT_COLUMNS = {
    "subject": ("subject COLLATE NOCASE",),
    "not_before": ("not_before",),
    "not_after": ("not_after",),
    "days": ("not_after",),
    "filename": ("filename COLLATE NOCASE",),
    "signature": ("sig_algo COLLATE NOCASE",),
    "public_key": ("pubkey_type COLLATE NOCASE", "COALESCE(pubkey_bits, -1)"),
    "sha256": ("sha256 COLLATE NOCASE",),
    "is_ca": ("is_ca",),
}

TABLE_HEADER_SORT_KEYS = {
    "Serial": "serial",
    "Subject": "subject",
    "Valid from": "not_before",
    "Valid until": "not_after",
    "Days": "days",
    "Revoked": "revoked",
    "Is CA": "is_ca",
    "Signature": "signature",
    "Public Key": "public_key",
    "SHA-256": "sha256",
    "File": "filename",
}

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
    search_text: str = ""
    cache_key: str = ""
    revoked: bool = False  # CRL status
    is_ca: bool = False


def _build_certificate_search_text(details: Dict[str, Any], filename: str) -> str:
    """Build a lower-case search index from certificate-only metadata.

    The index is computed once when the certificate row is loaded so filtering
    remains a cheap substring lookup while typing/searching.
    """
    values: List[str] = []

    def add(value: Any) -> None:
        if value is None:
            return
        value_s = str(value).strip()
        if value_s:
            values.append(value_s)

    add(filename)
    add(details.get("subject"))
    add(details.get("issuer"))
    add(details.get("serial_hex"))
    add(details.get("serial_number"))
    add((details.get("fingerprints") or {}).get("sha256"))

    microsoft = details.get("microsoft") or {}
    template = microsoft.get("template") or {}
    add(template.get("name"))
    add(template.get("oid"))
    add(microsoft.get("object_sid"))

    for item in details.get("san") or []:
        if isinstance(item, dict):
            add(item.get("display"))
            add(item.get("value"))
            add(item.get("oid"))
        else:
            add(item)

    for item in details.get("extended_key_usage") or []:
        if isinstance(item, dict):
            add(item.get("display"))
            add(item.get("oid"))
        else:
            add(item)

    for item in microsoft.get("application_policies") or []:
        if isinstance(item, dict):
            add(item.get("display"))
            add(item.get("oid"))
        else:
            add(item)

    return "\n".join(values).lower()


def _ensure_utc_datetime(value: Any) -> datetime:
    """Convert an ISO/datetime cache value to a timezone-aware datetime."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        dt = datetime.fromisoformat(value)
    else:
        raise ValueError("missing datetime value")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _certificate_details_to_json(details: Dict[str, Any]) -> str:
    """Serialize parse_certificate_details() output for the local UI cache."""
    def default(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    return json.dumps(
        details,
        ensure_ascii=False,
        separators=(",", ":"),
        default=default,
    )


def _certificate_details_from_json(payload: str) -> Dict[str, Any]:
    """Restore cached details, including the two certificate validity dates."""
    details = json.loads(payload)
    for key in ("not_valid_before", "not_valid_after"):
        value = details.get(key)
        if isinstance(value, str) and value:
            try:
                details[key] = datetime.fromisoformat(value)
            except ValueError:
                pass
    return details


def _certificate_cache_path(cert_dir: str) -> str:
    """Return the per-user SQLite cache path for a certificate directory.

    No migration from the former ``<cert_dir>/.cert_cache.sqlite3`` location is
    attempted: an old file there is simply ignored.
    """
    canonical_cert_dir = os.path.realpath(
        os.path.abspath(os.path.expanduser(str(cert_dir)))
    )
    path_hash = hashlib.sha256(
        canonical_cert_dir.encode("utf-8", errors="surrogateescape")
    ).hexdigest()

    data_home = os.environ.get("XDG_DATA_HOME")
    if not data_home:
        data_home = os.path.join(os.path.expanduser("~"), ".local", "share")
    else:
        data_home = os.path.abspath(os.path.expanduser(data_home))

    cache_dir = os.path.join(data_home, CERT_CACHE_APP_DIR, CERT_CACHE_SUBDIR)
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    return os.path.join(cache_dir, path_hash + ".sqlite3")


def _open_certificate_cache(cert_dir: str) -> sqlite3.Connection:
    """Open/create the SQLite cache in the current user's local profile."""
    conn = sqlite3.connect(_certificate_cache_path(cert_dir), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    metadata = {
        str(row["key"]): str(row["value"])
        for row in conn.execute("SELECT key, value FROM metadata")
    }
    expected_schema = str(CERT_CACHE_SCHEMA_VERSION)
    expected_parser = str(CERT_CACHE_PARSER_VERSION)

    if metadata.get("schema_version") != expected_schema:
        # Schema changes are handled by rebuilding the local cache. No migration
        # of existing cache contents is attempted.
        conn.execute("DROP TABLE IF EXISTS certificate_search")
        conn.execute("DROP TABLE IF EXISTS certificates")
        conn.execute("DELETE FROM metadata")
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("schema_version", expected_schema),
        )
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            ("parser_version", expected_parser),
        )
    elif metadata.get("parser_version") != expected_parser:
        # Files are immutable, but the parser/index can evolve between releases.
        # Rebuild both the certificate cache and its FTS index; no migration.
        conn.execute("DROP TABLE IF EXISTS certificate_search")
        conn.execute("DROP TABLE IF EXISTS certificates")
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
            ("parser_version", expected_parser),
        )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS certificates (
            relative_path TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            serial_hex TEXT,
            subject TEXT,
            not_before TEXT,
            not_after TEXT,
            sig_algo TEXT,
            pubkey_type TEXT,
            pubkey_bits INTEGER,
            sha256 TEXT,
            is_ca INTEGER NOT NULL DEFAULT 0,
            search_text TEXT NOT NULL DEFAULT '',
            details_json TEXT,
            parse_error TEXT
        )
        """
    )

    # Fast arbitrary-substring search. The trigram tokenizer indexes every
    # 3-character sequence in search_text, which preserves the current
    # "contains" search semantics without scanning every certificate row.
    # If the local SQLite build lacks FTS5/trigram, opening the cache fails and
    # the existing direct-parsing fallback keeps the TUI functional.
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS certificate_search USING fts5(
            relative_path UNINDEXED,
            search_text,
            tokenize='trigram'
        )
        """
    )

    # Small, persistent B-tree indexes for filtering and sorting. search_text is
    # indexed separately by the FTS5 trigram table above.
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_cert_not_before ON certificates(not_before)",
        "CREATE INDEX IF NOT EXISTS idx_cert_not_after ON certificates(not_after)",
        "CREATE INDEX IF NOT EXISTS idx_cert_subject ON certificates(subject COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS idx_cert_filename ON certificates(filename COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS idx_cert_signature ON certificates(sig_algo COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS idx_cert_public_key ON certificates(pubkey_type COLLATE NOCASE, pubkey_bits)",
        "CREATE INDEX IF NOT EXISTS idx_cert_sha256 ON certificates(sha256 COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_hex COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS idx_cert_is_ca ON certificates(is_ca)",
    ):
        conn.execute(statement)

    conn.commit()
    return conn


def _cache_record_from_certificate(cert_dir: str, path: str) -> Dict[str, Any]:
    """Parse one new immutable certificate and build its persistent cache row."""
    cert = load_certificate_file(path)
    details = parse_certificate_details(cert)
    filename = os.path.basename(path)
    not_before = _ensure_utc_datetime(details.get("not_valid_before"))
    not_after = _ensure_utc_datetime(details.get("not_valid_after"))
    sig = details.get("signature") or {}
    public_key = details.get("public_key") or {}

    return {
        "relative_path": os.path.relpath(path, cert_dir),
        "filename": filename,
        "serial_hex": str(details.get("serial_hex") or format(cert.serial_number, "x")),
        "subject": str(details.get("subject") or ""),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "sig_algo": str(sig.get("hash") or sig.get("display") or "unknown"),
        "pubkey_type": str(public_key.get("type") or "unknown"),
        "pubkey_bits": public_key.get("bits"),
        "sha256": str((details.get("fingerprints") or {}).get("sha256") or ""),
        "is_ca": 1 if bool((details.get("basic_constraints") or {}).get("is_ca")) else 0,
        "search_text": _build_certificate_search_text(details, filename),
        "details_json": _certificate_details_to_json(details),
        "parse_error": None,
    }


def _cache_error_record(cert_dir: str, path: str, exc: Exception) -> Dict[str, Any]:
    filename = os.path.basename(path)
    return {
        "relative_path": os.path.relpath(path, cert_dir),
        "filename": filename,
        "serial_hex": "(error)",
        "subject": "Error: %s" % exc,
        "not_before": "",
        "not_after": "",
        "sig_algo": "-",
        "pubkey_type": "-",
        "pubkey_bits": None,
        "sha256": "-",
        "is_ca": 0,
        "search_text": (filename + "\n" + str(exc)).lower(),
        "details_json": None,
        "parse_error": str(exc),
    }


def _sync_certificate_cache(
    cert_dir: str,
    progress: Optional[Callable[[int, int, int], None]] = None,
    status: Optional[Callable[[str], None]] = None,
) -> Dict[str, int]:
    """Sync the per-CA cache without re-reading an already cached file.

    Certificate files are immutable by design. Therefore:
      * new path     -> parse once and INSERT;
      * cached path  -> keep the SQLite row untouched;
      * missing path -> DELETE from SQLite.

    ``progress(done, new_total, certificate_total)`` is called while new
    certificates are parsed. ``status(message)`` reports the coarse phases
    before the per-certificate counter is available. Both callbacks are optional
    so CLI/non-TUI code can keep using the cache without any UI dependency.

    Filtering, searching and sorting are deliberately handled by
    _query_certificate_cache() after synchronization.
    """
    if status is not None:
        status("Scanning certificate files...")

    paths = scan_cert_paths(cert_dir)
    path_map = {os.path.relpath(path, cert_dir): path for path in paths}
    current_keys = set(path_map)
    certificate_total = len(current_keys)

    if status is not None:
        status(
            f"Found {certificate_total} certificate file(s) — opening SQLite cache..."
        )

    conn = _open_certificate_cache(cert_dir)
    try:
        if status is not None:
            status(
                f"Checking SQLite cache — {certificate_total} certificate file(s) found"
            )

        cached_keys = {
            str(row["relative_path"])
            for row in conn.execute("SELECT relative_path FROM certificates")
        }

        removed = cached_keys - current_keys
        if removed:
            conn.executemany(
                "DELETE FROM certificate_search WHERE relative_path = ?",
                ((key,) for key in removed),
            )
            conn.executemany(
                "DELETE FROM certificates WHERE relative_path = ?",
                ((key,) for key in removed),
            )
            # Keep the normal table and FTS index transactionally consistent.
            conn.commit()

        new_keys = current_keys - cached_keys
        new_total = len(new_keys)
        if progress is not None:
            # The UI keeps the certificate grid empty until synchronization is
            # complete, but it can already show an accurate progress counter.
            progress(0, new_total, certificate_total)

        # Existing keys are deliberately not stat'ed, hashed, opened or parsed.
        for index, key in enumerate(new_keys, start=1):
            path = path_map[key]
            try:
                record = _cache_record_from_certificate(cert_dir, path)
            except Exception as exc:
                record = _cache_error_record(cert_dir, path, exc)

            conn.execute(
                """
                INSERT INTO certificates (
                    relative_path, filename, serial_hex, subject,
                    not_before, not_after, sig_algo, pubkey_type, pubkey_bits,
                    sha256, is_ca, search_text, details_json, parse_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["relative_path"], record["filename"],
                    record["serial_hex"], record["subject"],
                    record["not_before"], record["not_after"],
                    record["sig_algo"], record["pubkey_type"],
                    record["pubkey_bits"], record["sha256"],
                    record["is_ca"], record["search_text"],
                    record["details_json"], record["parse_error"],
                ),
            )

            conn.execute(
                "INSERT INTO certificate_search(relative_path, search_text) VALUES (?, ?)",
                (record["relative_path"], record["search_text"]),
            )

            # Keep commits batched for SQLite/FTS efficiency and restartability.
            # Progress reporting is intentionally independent from commits: the
            # DataTable stays empty until the complete synchronization finishes,
            # so the status counter can advance after every processed certificate.
            publish_batch = (
                index == 1 or index == new_total or index % 25 == 0
            )
            if publish_batch:
                conn.commit()

            if progress is not None:
                progress(index, new_total, certificate_total)

        conn.commit()
        return {
            "total": certificate_total,
            "added": new_total,
            "removed": len(removed),
        }
    finally:
        conn.close()


def _certificate_cache_order_by(sort_column: str, descending: bool) -> str:
    """Return a safe ORDER BY clause for immutable certificate metadata."""
    direction = "DESC" if descending else "ASC"

    if sort_column == "serial" or sort_column == "revoked":
        # Certificate serial numbers may be wider than SQLite's signed 64-bit
        # INTEGER. Numeric order for hexadecimal text is therefore obtained by
        # normalized digit count first, then hexadecimal lexical order.
        terms = (
            "length(ltrim(lower(serial_hex), '0'))",
            "ltrim(lower(serial_hex), '0')",
        )
    else:
        terms = CERT_CACHE_SORT_COLUMNS.get(
            sort_column, CERT_CACHE_SORT_COLUMNS["not_before"]
        )

    ordered = ["%s %s" % (term, direction) for term in terms]
    # Deterministic final tie-breaker regardless of the selected sort.
    ordered.append("relative_path COLLATE NOCASE ASC")
    return " ORDER BY " + ", ".join(ordered)


def _fts5_literal_query(value: str) -> str:
    """Return an FTS5 phrase that searches *value* as literal text.

    Quoting prevents punctuation found in SIDs, OIDs, DNS names, hashes, etc.
    from being interpreted as FTS5 query syntax. Doubling embedded quotes is
    FTS5's escaping rule inside a quoted phrase.
    """
    return '"' + value.replace('"', '""') + '"'


def _query_certificate_cache(
    cert_dir: str,
    query: str = "",
    status: str = "",
    revocation: str = "",
    revoked_serials: Optional[Set[int]] = None,
    sort_column: str = "not_before",
    descending: bool = False,
    limit: int = 0,
) -> tuple[List[Dict[str, Any]], int]:
    """Query lightweight certificate rows directly from SQLite.

    Search, status filtering and immutable-certificate sorts are performed by
    SQLite. Revocation is never persisted in SQLite: when the UI explicitly
    requests ``revoked`` or ``not_revoked``, current CRL serial numbers are
    supplied only as query parameters. ``limit`` limits rows returned to the UI;
    a separate COUNT keeps the full matching total available for the status bar.
    """
    where: List[str] = []
    params: List[Any] = []

    q = (query or "").strip().lower()
    if q:
        if len(q) >= 3:
            where.append(
                "relative_path IN ("
                "SELECT relative_path FROM certificate_search "
                "WHERE search_text MATCH ?"
                ")"
            )
            params.append(_fts5_literal_query(q))
        else:
            where.append("instr(search_text, ?) > 0")
            params.append(q)

    # Preserve the existing UI buckets based on integer days_to_expiry.
    now = datetime.now(timezone.utc)
    cutoff_1d = (now + timedelta(days=1)).isoformat()
    cutoff_31d = (now + timedelta(days=31)).isoformat()
    if status == "expired":
        where.append("not_after < ?")
        params.append(cutoff_1d)
    elif status == "expiring":
        where.append("not_after >= ? AND not_after < ?")
        params.extend((cutoff_1d, cutoff_31d))
    elif status == "valid":
        where.append("not_after >= ?")
        params.append(cutoff_31d)

    # Revocation remains CRL-only. Only explicit revoked/not_revoked filters
    # inject CRL serials into the transient SELECT; nothing is stored in SQLite.
    crl_serials = sorted({
        format(int(serial), "x").lower()
        for serial in (revoked_serials or set())
    })
    if revocation == "revoked":
        if crl_serials:
            placeholders = ",".join("?" for _ in crl_serials)
            where.append(f"serial_hex COLLATE NOCASE IN ({placeholders})")
            params.extend(crl_serials)
        else:
            where.append("0")
    elif revocation == "not_revoked" and crl_serials:
        placeholders = ",".join("?" for _ in crl_serials)
        where.append(f"serial_hex COLLATE NOCASE NOT IN ({placeholders})")
        params.extend(crl_serials)

    where_sql = ""
    if where:
        where_sql = " WHERE " + " AND ".join(where)

    select_sql = """
        SELECT relative_path, filename, serial_hex, subject,
               not_before, not_after, sig_algo, pubkey_type, pubkey_bits,
               sha256, is_ca, parse_error
          FROM certificates
    """ + where_sql
    select_sql += _certificate_cache_order_by(sort_column, descending)

    select_params = list(params)
    if limit > 0:
        select_sql += " LIMIT ?"
        select_params.append(int(limit))

    count_sql = "SELECT COUNT(*) FROM certificates" + where_sql

    conn = sqlite3.connect(_certificate_cache_path(cert_dir), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        total = int(conn.execute(count_sql, params).fetchone()[0])
        rows = [dict(row) for row in conn.execute(select_sql, select_params)]
        return rows, total
    finally:
        conn.close()


def _cert_row_serial_int(row: CertRow) -> int:
    """Return an integer certificate serial, keeping malformed rows sortable."""
    try:
        return int(row.serial_nox, 16)
    except (TypeError, ValueError):
        try:
            return int(row.serial_nox, 10)
        except (TypeError, ValueError):
            return -1


def _sort_certificate_rows_in_memory(
    rows: List[CertRow],
    sort_column: str,
    descending: bool,
) -> List[CertRow]:
    """Fallback sorter used only when the SQLite cache is unavailable.

    Revoked is always an in-memory sort because that state comes from the CRL
    and is intentionally never persisted in the certificate cache.
    """
    if sort_column == "serial":
        key = lambda row: _cert_row_serial_int(row)
    elif sort_column == "subject":
        key = lambda row: row.subject.casefold()
    elif sort_column == "not_after" or sort_column == "days":
        key = lambda row: row.not_after
    elif sort_column == "filename":
        key = lambda row: row.filename.casefold()
    elif sort_column == "signature":
        key = lambda row: row.sig_algo.casefold()
    elif sort_column == "public_key":
        key = lambda row: (row.pubkey_type.casefold(), row.pubkey_bits or -1)
    elif sort_column == "sha256":
        key = lambda row: row.sha256_fingerprint.casefold()
    elif sort_column == "is_ca":
        key = lambda row: row.is_ca
    elif sort_column == "revoked":
        # Ascending intentionally presents revoked certificates first; serial
        # number is the deterministic second key requested by the UI.
        key = lambda row: (0 if row.revoked else 1, _cert_row_serial_int(row))
    else:
        key = lambda row: row.not_before

    return sorted(rows, key=key, reverse=descending)

def _cached_certificate_details(cert_dir: str, cache_key: str) -> Dict[str, Any]:
    """Read parsed details from SQLite; cached files are not reopened."""
    # load_certs() already synchronized/versioned the database. Detail browsing
    # stays read-only and avoids schema work on every cursor movement.
    conn = sqlite3.connect(_certificate_cache_path(cert_dir), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        row = conn.execute(
            "SELECT details_json, parse_error FROM certificates WHERE relative_path = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            raise KeyError(cache_key)
        if row["parse_error"]:
            raise ValueError(str(row["parse_error"]))
        if not row["details_json"]:
            raise ValueError("cached certificate details are missing")
        return _certificate_details_from_json(str(row["details_json"]))
    finally:
        conn.close()


def _row_from_cache_record(record: Dict[str, Any]) -> CertRow:
    """Create a live UI row from lightweight SQLite fields."""
    now = datetime.now(timezone.utc)
    parse_error = record.get("parse_error")

    if parse_error:
        not_before = now
        not_after = now
        filename = str(record.get("filename") or "") + " (ERROR)"
    else:
        not_before = _ensure_utc_datetime(record.get("not_before"))
        not_after = _ensure_utc_datetime(record.get("not_after"))
        filename = str(record.get("filename") or "")

    return CertRow(
        filename=filename,
        serial_nox=str(record.get("serial_hex") or ""),
        subject=str(record.get("subject") or ""),
        not_before=not_before,
        not_after=not_after,
        days_to_expiry=max(0, (not_after - now).days),
        sig_algo=str(record.get("sig_algo") or "-"),
        pubkey_type=str(record.get("pubkey_type") or "-"),
        pubkey_bits=record.get("pubkey_bits"),
        sha256_fingerprint=str(record.get("sha256") or "-"),
        # Cached rows do not carry the full search index in memory; searches
        # are executed directly against SQLite.
        search_text="",
        cache_key=str(record.get("relative_path") or ""),
        revoked=False,
        is_ca=bool(record.get("is_ca")),
    )


def row_from_cert(path: str) -> CertRow:
    """Fallback path used only when the SQLite cache cannot be used."""
    cert = load_certificate_file(path)
    details = parse_certificate_details(cert)
    now = datetime.now(timezone.utc)

    not_before = _ensure_utc_datetime(details.get("not_valid_before"))
    not_after = _ensure_utc_datetime(details.get("not_valid_after"))
    sig = details.get("signature") or {}
    pk = details.get("public_key") or {}
    filename = os.path.basename(path)

    return CertRow(
        filename=filename,
        serial_nox=str(details.get("serial_hex") or format(cert.serial_number, "x")),
        subject=str(details.get("subject") or ""),
        not_before=not_before,
        not_after=not_after,
        days_to_expiry=max(0, (not_after - now).days),
        sig_algo=str(sig.get("hash") or sig.get("display") or "unknown"),
        pubkey_type=str(pk.get("type") or "unknown"),
        pubkey_bits=pk.get("bits"),
        sha256_fingerprint=str((details.get("fingerprints") or {}).get("sha256") or ""),
        search_text=_build_certificate_search_text(details, filename),
        is_ca=bool((details.get("basic_constraints") or {}).get("is_ca")),
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

    # SQLite-backed view state. The query result is cached until search/status,
    # sort, CA contents or CRL state changes, so cursor movement and selection
    # never re-run the database query.
    _cache_available: bool = False
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
            self.confadcs = load_yaml_conf(args.confadcs,bypass_read_only=True)
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
        self._request_reselect(cursor_filename)
        self.refresh_table(reuse_visible=True)

    def _load_direct_certificate_rows(
        self,
        certs_dir: str,
        revoked_serials: Optional[Set[int]] = None,
    ) -> List[CertRow]:
        """Fallback loader used only when the per-CA SQLite cache is unavailable."""
        revoked = self.revoked_serials if revoked_serials is None else revoked_serials
        rows: List[CertRow] = []
        for path in scan_cert_paths(certs_dir):  # utils
            try:
                row = row_from_cert(path)
                row.revoked = _cert_row_serial_int(row) in revoked
                rows.append(row)
            except Exception as exc:
                now = datetime.now(timezone.utc)
                rows.append(CertRow(
                    filename=os.path.basename(path) + " (ERROR)",
                    serial_nox="(error)",
                    subject=f"Error: {exc}",
                    not_before=now, not_after=now,
                    days_to_expiry=0, sig_algo="-",
                    pubkey_type="-", pubkey_bits=None,
                    sha256_fingerprint="-",
                    revoked=False,
                    is_ca=False,
                ))
        return rows

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
        cache_available: bool,
        direct_rows: List[CertRow],
        cache_error: Optional[str],
    ) -> None:
        """Apply a worker result only if it still belongs to the selected CA."""
        if not self._certificate_load_is_current(generation, ca_refid):
            return

        self._certificate_load_in_progress = False
        self._cache_available = cache_available
        self.cert_rows = direct_rows
        self._invalidate_filtered_rows_cache()

        if cache_error:
            self.notify(
                f"Certificate cache unavailable; direct parsing used: {cache_error}",
                severity="warning",
                timeout=6,
            )

        self.refresh_table()

    @work(thread=True, exclusive=True, group="certificate-cache-load")
    def _load_certs_worker(
        self,
        generation: int,
        ca_refid: Any,
        certs_dir: str,
        revoked_serials: Set[int],
    ) -> None:
        """Synchronize/parse certificates off the Textual UI thread."""
        cache_available = False
        direct_rows: List[CertRow] = []
        cache_error: Optional[str] = None

        def stage(message: str) -> None:
            self.call_from_thread(
                self._update_certificate_load_stage,
                generation,
                ca_refid,
                message,
            )

        def progress(done: int, new_total: int, certificate_total: int) -> None:
            self.call_from_thread(
                self._update_certificate_load_progress,
                generation,
                ca_refid,
                done,
                new_total,
                certificate_total,
            )

        try:
            # Synchronization only discovers additions/removals. Existing
            # immutable certificates are never reopened. Rows are fetched by
            # filtered_rows() through one central SQLite query.
            _sync_certificate_cache(
                certs_dir,
                progress=progress,
                status=stage,
            )
            cache_available = True
        except Exception as cache_exc:
            cache_error = str(cache_exc)
            direct_rows = self._load_direct_certificate_rows(
                certs_dir,
                revoked_serials=revoked_serials,
            )

        self.call_from_thread(
            self._finish_certificate_load,
            generation,
            ca_refid,
            cache_available,
            direct_rows,
            cache_error,
        )

    def load_certs(self) -> None:
        ca = self.current_ca
        if not ca:
            return

        certs_dir, _private_dir = self._resolve_storage_paths(ca)
        ca_refid = ca.get("__refid")

        self.cert_rows = []
        self._visible_rows = []
        self._cache_available = False
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
        )

    # ---------- Filters & view ----------
    def filtered_rows(self, apply_limit: bool = True) -> List[CertRow]:
        q = self.filter_q.lower().strip()
        status = self.filter_status
        revocation = self.filter_revocation

        if self._cache_available and self.current_ca:
            certs_dir, _private_dir = self._resolve_storage_paths(self.current_ca)

            # Normal display queries are limited directly by SQLite. Sorting by
            # Revoked without a revocation filter is the exception: Revoked is
            # CRL-only, so preserve the existing global sort in Python.
            query_limit = self.max_rows if (apply_limit and self.max_rows > 0) else 0
            sort_revoked_in_python = (
                self._sort_column == "revoked" and not revocation
            )
            if sort_revoked_in_python:
                query_limit = 0

            cache_key = (
                certs_dir, q, status, revocation,
                self._sort_column, self._sort_descending, query_limit,
                apply_limit, self.max_rows if apply_limit else 0,
            )
            if self._filtered_rows_cache_key == cache_key:
                return self._filtered_rows_cache

            try:
                records, total = _query_certificate_cache(
                    certs_dir,
                    query=q,
                    status=status,
                    revocation=revocation,
                    revoked_serials=self.revoked_serials,
                    sort_column=self._sort_column,
                    descending=self._sort_descending,
                    limit=query_limit,
                )
                rows: List[CertRow] = []
                for record in records:
                    row = _row_from_cache_record(record)
                    if not record.get("parse_error"):
                        row.revoked = (
                            _cert_row_serial_int(row) in self.revoked_serials
                        )
                    rows.append(row)

                if sort_revoked_in_python:
                    rows = _sort_certificate_rows_in_memory(
                        rows, "revoked", self._sort_descending
                    )
                    if apply_limit and self.max_rows > 0:
                        rows = rows[: self.max_rows]

                self._filtered_rows_total = total
                self._filtered_rows_cache_key = cache_key
                self._filtered_rows_cache = rows
                return rows
            except (OSError, sqlite3.Error) as cache_exc:
                self._cache_available = False
                self._invalidate_filtered_rows_cache()
                self.notify(
                    f"Certificate cache query failed; direct parsing used: {cache_exc}",
                    severity="warning",
                    timeout=6,
                )
                self.cert_rows = self._load_direct_certificate_rows(certs_dir)

        rows = list(self.cert_rows)

        if q:
            rows = [r for r in rows if q in r.search_text]

        if status:
            if status == "expiring":
                rows = [r for r in rows if 0 < r.days_to_expiry <= 30]
            elif status == "valid":
                rows = [r for r in rows if r.days_to_expiry > 30]
            elif status == "expired":
                rows = [r for r in rows if r.days_to_expiry == 0]

        if revocation == "revoked":
            rows = [r for r in rows if r.revoked]
        elif revocation == "not_revoked":
            rows = [r for r in rows if not r.revoked]

        rows = _sort_certificate_rows_in_memory(
            rows, self._sort_column, self._sort_descending
        )
        self._filtered_rows_total = len(rows)
        if apply_limit and self.max_rows > 0:
            rows = rows[: self.max_rows]
        return rows

    @staticmethod
    def _mc_cell(value: object, marked: bool = False) -> object:
        """Emphasize marked rows without imposing a color outside the theme."""
        if not marked:
            return value
        return Text(str(value), style="bold")

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
        sort_arrow = "↓" if self._sort_descending else "↑"
        sort_note = f" — sort: {self._sort_column} {sort_arrow}"
        if not self._certificate_load_in_progress:
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

        failed_serials: List[str] = []
        operation_ok: List[CertRow] = []

        for r in targets:
            try:
                revoke(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    serial=r.serial_nox,
                    crl_path=crl_path,
                    next_update_hours=self.confadcs['next_update_hours_crl']
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

        failed_serials: List[str] = []
        operation_ok: List[CertRow] = []

        for r in targets:
            try:
                unrevoke(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    serial=r.serial_nox,
                    crl_path=crl_path,
                    next_update_hours=self.confadcs['next_update_hours_crl']
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
        """Sort table data when a sortable column header is clicked."""
        label_obj = getattr(event, "label", "")
        label = getattr(label_obj, "plain", None) or str(label_obj)
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
        if not cert_path:
            for p in scan_cert_paths(certs_dir):  # fallback without SQLite cache
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
            if r.cache_key:
                try:
                    details = _cached_certificate_details(certs_dir, r.cache_key)
                except (KeyError, sqlite3.Error):
                    # Cache disappeared/became unavailable after load: preserve
                    # functionality by parsing this certificate directly.
                    cert = load_certificate_file(cert_path)
                    details = parse_certificate_details(cert)
            else:
                cert = load_certificate_file(cert_path)
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
