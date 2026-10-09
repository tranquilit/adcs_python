#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Certificate inventory and the shared per-CA SQLite cache.

Used by both the Textual UI and the ``adcs-tool`` commands. A cache stores
immutable certificate metadata; revocation status is always read from the CRL.
"""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set
from utils_crt import load_certificate_file, parse_certificate_details, scan_cert_paths

CERT_EXTS = {".crt", ".pem", ".cer"}
MAX_ROWS_DEFAULT = 1000  # Same initial display limit in GUI and CLI.

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

# Both front ends use the same public ordering vocabulary and validator.
# Aliases exist solely to make the CLI friendlier; every SQL column is fixed.
ORDER_BY_ALIASES = {
    "expiration_date": "not_after",
    "expires": "not_after",
    "valid_until": "not_after",
    "issued": "not_before",
    "issue_date": "not_before",
    "days_to_expiry": "days",
    "file": "filename",
    "serial_number": "serial",
    "fingerprint": "sha256",
}
ORDER_BY_FIELDS = tuple(sorted({
    *CERT_CACHE_SORT_COLUMNS, "serial", "revoked", *ORDER_BY_ALIASES,
}))


def parse_order_by(
    order_by: Optional[str] = None,
    *, sort_column: str = "not_before", descending: bool = False,
) -> List[tuple[str, bool]]:
    """Validate an ORDER BY-style list of whitelisted fields and directions."""
    if not order_by:
        column = ORDER_BY_ALIASES.get(sort_column, sort_column)
        if column not in CERT_CACHE_SORT_COLUMNS and column not in ("serial", "revoked"):
            raise ValueError(f"Unsupported ordering field: {sort_column}")
        return [(column, descending)]
    entries: List[tuple[str, bool]] = []
    for part in order_by.split(","):
        match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z_0-9]*)\s*(ASC|DESC)?\s*", part, re.I)
        if not match:
            raise ValueError(f"Invalid ORDER BY term: {part.strip()!r}")
        name = match.group(1).lower()
        column = ORDER_BY_ALIASES.get(name, name)
        if column not in CERT_CACHE_SORT_COLUMNS and column not in ("serial", "revoked"):
            raise ValueError(
                f"Invalid ORDER BY field {name!r}; allowed: {', '.join(ORDER_BY_FIELDS)}"
            )
        entries.append((column, (match.group(2) or "ASC").upper() == "DESC"))
    return entries


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
    # SQLite FTS5/trigram is required; callers report an explicit error when
    # unavailable rather than maintaining a duplicate file-parsing path.
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


def _certificate_cache_order_by(
    sort_column: str, descending: bool,
    *, order_by: Optional[str] = None,
) -> str:
    """Build an injection-safe SQL ORDER BY from approved expressions only."""
    clauses = []
    for column, reverse in parse_order_by(
        order_by, sort_column=sort_column, descending=descending,
    ):
        direction = "DESC" if reverse else "ASC"
        if column in ("serial", "revoked"):
            # Arbitrary-width hex serials cannot fit in SQLite INTEGER.
            terms = (
                "length(ltrim(lower(serial_hex), '0'))",
                "ltrim(lower(serial_hex), '0')",
            )
        else:
            terms = CERT_CACHE_SORT_COLUMNS[column]
        clauses.extend(f"{term} {direction}" for term in terms)
    clauses.append("relative_path COLLATE NOCASE ASC")
    return " ORDER BY " + ", ".join(clauses)


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
    order_by: Optional[str] = None,
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
    select_sql += _certificate_cache_order_by(
        sort_column, descending, order_by=order_by,
    )

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


def list_certificate_rows(
    cert_dir: str, *, query: str = "", status: str = "",
    revocation: str = "", revoked_serials: Optional[Set[int]] = None,
    sort_column: str = "not_before", descending: bool = False,
    order_by: Optional[str] = None, limit: int = 0,
    synchronize: bool = False,
) -> tuple[List[CertRow], int]:
    """Shared filter/search/sort/limit implementation for CLI and Textual UI.

    Only the immutable certificate index is stored in SQLite. Revocation is
    supplied by the current CRL; if sorting on it, the complete result is
    sorted in memory before limiting to keep the ordering globally correct.
    """
    order_terms = parse_order_by(
        order_by, sort_column=sort_column, descending=descending,
    )
    if status not in ("", "valid", "expiring", "expired"):
        raise ValueError(f"Unsupported status filter: {status}")
    if revocation not in ("", "revoked", "not_revoked"):
        raise ValueError(f"Unsupported revocation filter: {revocation}")
    if limit < 0:
        raise ValueError("limit must be >= 0 (0 = unlimited)")
    if synchronize:
        _sync_certificate_cache(cert_dir)
    contains_revoked_sort = any(col == "revoked" for col, _ in order_terms)
    raw, total = _query_certificate_cache(
        cert_dir, query=query, status=status, revocation=revocation,
        revoked_serials=revoked_serials, sort_column=sort_column,
        descending=descending,
        order_by=(order_by if not contains_revoked_sort else None),
        limit=(0 if contains_revoked_sort else limit),
    )
    crl_serials = revoked_serials or set()
    rows = []
    for record in raw:
        row = _row_from_cache_record(record)
        if not record.get("parse_error"):
            row.revoked = _cert_row_serial_int(row) in crl_serials
        rows.append(row)

    if contains_revoked_sort:
        # Multi-field sorting must be stable: the rightmost ORDER BY term is
        # lowest priority. Do not reimplement this in the Textual event layer.
        for col, reverse in reversed(order_terms):
            rows = _sort_certificate_rows_in_memory(rows, col, reverse)
        if limit > 0:
            rows = rows[:limit]
    return rows, total


def cached_certificate_by_serial(cert_dir: str, serial: str) -> Dict[str, Any]:
    """Return a single certificate record from SQLite by hexadecimal serial."""
    try:
        normalized = format(int(str(serial).strip().removeprefix("0x"), 16), "x")
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal certificate serial: {serial}") from exc
    conn = _open_certificate_cache(cert_dir)
    try:
        matches = [dict(row) for row in conn.execute(
            """SELECT relative_path, filename, serial_hex, subject,
                      not_before, not_after, sig_algo, pubkey_type, pubkey_bits,
                      sha256, is_ca, parse_error, details_json
                 FROM certificates
                WHERE lower(ltrim(serial_hex, '0')) = ?""",
            (normalized,),
        )]
        if not matches:
            raise LookupError(f"Certificate serial not found: {serial}")
        if len(matches) != 1:
            raise LookupError(f"Multiple certificates have serial: {serial}")
        if matches[0].get("parse_error"):
            raise ValueError(f"Certificate cannot be parsed: {matches[0]['parse_error']}")
        return matches[0]
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
    """Sort transient CRL-derived state shared by both interfaces.

    SQLite stores immutable certificate metadata only. Revocation comes from
    the CRL, so sorting by that field must use this shared function.
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


def _resolve_storage_paths_from_ca(ca: Dict[str, Any]) -> tuple[str, str]:
    sp = ca.get("storage_paths", {}) or {}
    certs_dir = sp.get("certs_dir") or sp.get("cert_dir") or ca.get("__path_cert") or "."
    private_dir = sp.get("private_dir") or certs_dir
    return str(certs_dir), str(private_dir)


