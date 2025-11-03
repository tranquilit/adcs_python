import base64
import datetime as dt
import json
import os
import sqlite3
import uuid
import textwrap
import requests  # active HTTP-01 validation
from urllib.parse import urlparse, urljoin

from flask import Blueprint, Response, current_app, g, jsonify, request, make_response

from adcs_config import build_templates_for_policy_response
from callback_loader import load_func
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from utils import format_b64_for_soap, build_adcs_bst_certrep

# jwcrypto for JWS verification
from jwcrypto import jwk as jwk_mod
from jwcrypto import jws as jws_mod
from jwcrypto.common import JWException


acme_api = Blueprint("acme_api", __name__)
# Alias to match the import in app.py
acme_bp = acme_api


# --------------------------- DB & time utilities ---------------------------

def _db():
    url = current_app.confadcs["acme_database_url"]  # e.g.: sqlite:///acme.db
    assert url.startswith("sqlite:///"), "Only sqlite:/// is supported here"
    path = url[len("sqlite:///"):]
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _b64url_nopad(b) -> str:
    """Return base64url without padding.
    Accepts bytes or an already-base64url string (jwcrypto.thumbprint()
    may return a str depending on version)."""
    if isinstance(b, str):
        return b.rstrip("=")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _init_db():
    with _db() as cx:
        cx.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS acme_account (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              caid TEXT NOT NULL,
              template_alias TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'valid',
              contact TEXT,
              kid TEXT UNIQUE,
              jws_jwk TEXT NOT NULL,
              tos_agreed INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS acme_nonce (
              value TEXT PRIMARY KEY,
              caid TEXT NOT NULL,
              template_alias TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS acme_order (
              id INTEGER PRIMARY KEY AUTOINCREMENT,   -- internal PK (INTEGER)
              order_ext_id TEXT UNIQUE,               -- external identifier (UUID.int as text)
              caid TEXT NOT NULL,
              template_alias TEXT NOT NULL,
              account_id INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              identifiers TEXT NOT NULL,
              not_before TEXT,
              not_after  TEXT,
              finalize_url TEXT,
              cert_url TEXT,
              csr_der_b64 TEXT,
              cert_der_b64 TEXT,
              chain_p7_der_b64 TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(account_id) REFERENCES acme_account(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS acme_authz (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              caid TEXT NOT NULL,
              template_alias TEXT NOT NULL,
              order_id INTEGER NOT NULL,              -- internal FK to acme_order.id
              status TEXT NOT NULL DEFAULT 'valid',   -- default bypass (will be 'pending' for http-01)
              identifier TEXT NOT NULL,               -- JSON {type:"dns", value:"..."}
              created_at TEXT NOT NULL,
              -- HTTP-01 challenge columns (added via soft migration if missing)
              challenge_type TEXT,
              challenge_token TEXT,
              challenge_status TEXT,
              challenge_url TEXT,
              key_authorization TEXT,
              validated_at TEXT,
              FOREIGN KEY(order_id) REFERENCES acme_order(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_acme_order_account ON acme_order(account_id);
            CREATE INDEX IF NOT EXISTS idx_acme_order_caid_tpl ON acme_order(caid, template_alias);
            CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authz(order_id);
            CREATE INDEX IF NOT EXISTS idx_acme_authz_caid_tpl ON acme_authz(caid, template_alias);
            """
        )

        # Soft migration if the table exists without the order_ext_id column
        try:
            cx.execute("SELECT order_ext_id FROM acme_order LIMIT 1")
        except sqlite3.OperationalError:
            cx.execute("ALTER TABLE acme_order ADD COLUMN order_ext_id TEXT")
            cx.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_acme_order_order_ext_id ON acme_order(order_ext_id)")

        # Soft migrations for HTTP-01 challenge columns
        try:
            cx.execute(
                "SELECT challenge_type, challenge_token, challenge_status, challenge_url, key_authorization, validated_at FROM acme_authz LIMIT 1"
            )
        except sqlite3.OperationalError:
            cx.execute("ALTER TABLE acme_authz ADD COLUMN challenge_type TEXT")
            cx.execute("ALTER TABLE acme_authz ADD COLUMN challenge_token TEXT")
            cx.execute("ALTER TABLE acme_authz ADD COLUMN challenge_status TEXT")
            cx.execute("ALTER TABLE acme_authz ADD COLUMN challenge_url TEXT")
            cx.execute("ALTER TABLE acme_authz ADD COLUMN key_authorization TEXT")
            cx.execute("ALTER TABLE acme_authz ADD COLUMN validated_at TEXT")
            cx.execute("CREATE INDEX IF NOT EXISTS idx_acme_authz_token ON acme_authz(challenge_token)")


# Register exactly once when the blueprint is attached to the app
@acme_api.record_once
def _on_register(setup_state):
    app = setup_state.app
    with app.app_context():
        _init_db()


# --------------------------------- Helpers -----------------------------------

def _base_path(caid, alias):
    root = request.url_root.rstrip("/")
    return f"{root}/acme/{caid}/{alias}"


def _location(path):
    base = request.url_root.rstrip("/")
    return f"{base}{path}"


def _new_nonce_value():
    return base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")


def _nonce_gc(caid, alias, ttl_seconds=600):
    """Purge nonces older than ttl_seconds for (caid, alias)."""
    cutoff = (dt.datetime.utcnow() - dt.timedelta(seconds=ttl_seconds)).replace(microsecond=0).isoformat() + "Z"
    with _db() as cx:
        cx.execute(
            "DELETE FROM acme_nonce WHERE created_at < ? AND caid = ? AND template_alias = ?",
            (cutoff, caid, alias),
        )


def _issue_nonce(caid, alias):
    _nonce_gc(caid, alias)  # simple GC
    val = _new_nonce_value()
    with _db() as cx:
        cx.execute(
            "INSERT INTO acme_nonce(value, caid, template_alias, created_at) VALUES (?,?,?,?)",
            (val, caid, alias, _now_iso()),
        )
    return val


def _consume_nonce(nonce, caid, alias):
    """Consume the nonce for the pair (caid, alias)."""
    with _db() as cx:
        cur = cx.execute(
            "DELETE FROM acme_nonce WHERE value=? AND caid=? AND template_alias=?",
            (nonce, caid, alias),
        )
    return cur.rowcount == 1


def _std_headers(caid, alias):
    """Required headers for all ACME responses."""
    hdrs = {
        "Replay-Nonce": _issue_nonce(caid, alias),
        "Cache-Control": "no-store",
        "Link": f'<{_base_path(caid, alias)}/directory>;rel="index"',
    }
    return hdrs


def _apply_headers(resp, headers: dict):
    for k, v in headers.items():
        # Use add to avoid overwriting existing Link headers
        if k.lower() == "link":
            resp.headers.add(k, v)
        else:
            resp.headers[k] = v
    return resp


def _error(caid, alias, err_type: str, code: int, detail: str | None = None):
    body = {"type": err_type}
    if detail:
        body["detail"] = detail
    resp = jsonify(body)
    return _apply_headers(resp, _std_headers(caid, alias)), code


def _account_by_kid(kid, caid=None, alias=None):
    with _db() as cx:
        if caid and alias:
            cur = cx.execute(
                "SELECT * FROM acme_account WHERE kid=? AND caid=? AND template_alias=?",
                (kid, caid, alias),
            )
        else:
            cur = cx.execute("SELECT * FROM acme_account WHERE kid=?", (kid,))
        return cur.fetchone()


def _jwk_thumbprint_b64u_from_acc(acc_row) -> str:
    """Return the account JWK thumbprint (RFC7638) in base64url, for keyAuthorization."""
    k = jwk_mod.JWK.from_json(acc_row["jws_jwk"])  # stored jwk JSON
    th = k.thumbprint()  # bytes or str depending on jwcrypto version
    # If jwcrypto returns a str (already b64url), just strip padding; if bytes, b64url-encode
    return _b64url_nopad(th)


def _resolve_template_for_user(caid, alias):
    templates_for_user, _ = build_templates_for_policy_response(
        current_app.confadcs,
        kerberos_user=getattr(g, "kerberos_user", None),
        request=request,
        acme_only=True
    )

    # match alias across several possible keys
    def _match_alias(t, alias_str):
        if not alias_str:
            return False
        # 1) explicit alias
        if t.get("acme_alias") == alias_str:
            return True
        # 2) common_name (your case: "adcswebuser")
        if t.get("common_name") == alias_str:
            return True
        # 3) template_oid.name if present
        toid = t.get("template_oid") or {}
        if toid.get("name") == alias_str:
            return True
        return False

    tpl = next(
        (t for t in templates_for_user
         if t.get("acme_available") and _match_alias(t, alias)),
        None
    )
    if not tpl:
        return None, None

    ca_refs = tpl.get("ca_references") or []
    if not ca_refs:
        return None, None

    # map CA id -> object
    cas_map = {c["id"]: c for c in current_app.confadcs.get("cas_list", [])}
    # must be a CA allowed by the template
    if caid not in cas_map or caid not in ca_refs:
        return None, None

    return tpl, cas_map[caid]


# ---------------------- CSR/SAN cross-checking (ADDED) ----------------------

def _csr_dns_names_from_der(csr_der: bytes) -> set[str]:
    """
    Extract all DNS names from the CSR (SAN.DNSName + optional CN) in lowercase.
    """
    csr = cx509.load_der_x509_csr(csr_der)
    names = set()

    # SAN
    try:
        san = csr.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
        names.update(n.lower() for n in san.get_values_for_type(cx509.DNSName))
    except cx509.ExtensionNotFound:
        pass

    # CN (tolerated for compatibility; tighten if needed)
    try:
        cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for cn_attr in cns:
            cn = (cn_attr.value or "").strip()
            if cn:
                names.add(cn.lower())
    except Exception:
        pass

    return names


def _expected_dns_from_identifiers(identifiers_json: str) -> set[str]:
    """
    Extract expected DNS from the acme_order.identifiers JSON column.
    """
    try:
        idents = json.loads(identifiers_json) or []
    except Exception:
        idents = []
    return {(i.get("value") or "").lower() for i in idents if (i.get("type") or "").lower() == "dns"}


# ------------------------- JWS verification (strict) --------------------------

_ALLOWED_ALGS = {"RS256", "ES256"}


def _json_b64url_decode(b64u: str) -> dict:
    if b64u is None:
        return {}
    try:
        # tolerant padding
        pad = '=' * ((4 - len(b64u) % 4) % 4)
        data = base64.urlsafe_b64decode(b64u + pad)
        return json.loads(data.decode("utf-8")) if data else {}
    except Exception:
        raise ValueError("malformedJWS")


def _verify_jws_and_nonce(caid, alias):
    """
    Verify a flattened JWS JSON (Certbot):
    - Verify signature (RS256/ES256) with jwcrypto
    - Consume the nonce (anti-replay) scoped to the pair (caid, alias)
    - Verify header.url == request.url
    - kid XOR jwk
    Return (env_dict, None) or (None, (type, code, detail?))
    """
    try:
        body = request.get_json(force=True, silent=False)
    except Exception:
        return None, ("malformedJWS", 400, None)

    protected_b64 = body.get("protected")
    payload_b64 = body.get("payload", "")
    signature_b64 = body.get("signature")

    if not (protected_b64 and signature_b64 and payload_b64 is not None):
        return None, ("malformedJWS", 400, "Missing protected/payload/signature fields")

    # Decode & check protected header
    try:
        protected = _json_b64url_decode(protected_b64)
    except ValueError:
        return None, ("malformedJWS", 400, "Cannot decode protected header")

    alg = protected.get("alg")
    url_h = protected.get("url")
    nonce = protected.get("nonce")
    kid = protected.get("kid")
    jwk_json = protected.get("jwk")

    if alg not in _ALLOWED_ALGS:
        return None, ("badSignatureAlgorithm", 400, f"Unsupported alg {alg}")

    # url must match the resource exactly
    if not url_h or url_h != request.url:
        return None, ("urlMismatch", 400, "Header url mismatch with request.url")

    if not nonce or not _consume_nonce(nonce, caid, alias):
        return None, ("badNonce", 400, None)

    # kid XOR jwk
    if bool(kid) == bool(jwk_json):
        return None, ("malformedJWS", 400, "kid XOR jwk must be present")

    # Build a compact JWS token: protected.payload.signature
    token_compact = f"{protected_b64}.{payload_b64}.{signature_b64}"

    # Key resolution
    try:
        if kid:
            acc = _account_by_kid(kid, caid, alias)
            if not acc:
                return None, ("accountDoesNotExist", 400, None)
            key = jwk_mod.JWK.from_json(acc["jws_jwk"])
        else:
            key = jwk_mod.JWK.from_json(json.dumps(jwk_json))
    except Exception:
        return None, ("malformedJWK", 400, None)

    # Signature verification & payload decoding
    try:
        verifier = jws_mod.JWS()
        verifier.deserialize(token_compact)
        verifier.verify(key)  # raises JWException if invalid
        raw_payload = verifier.payload or b""
        payload = json.loads(raw_payload.decode("utf-8")) if raw_payload else {}
    except (JWException, ValueError, json.JSONDecodeError):
        return None, ("badSignature", 400, None)

    return {"payload": payload, "kid": kid, "jwk": (jwk_json if jwk_json else None)}, None


# -------------------------------- Endpoints ----------------------------------

@acme_api.route("/acme/<caid>/<alias>/new-nonce", methods=["HEAD", "POST", "GET"])
def new_nonce(caid, alias):
    # Always return a nonce and Link rel="index" to /directory
    val = _issue_nonce(caid, alias)
    resp = make_response("", 200)
    resp.headers["Replay-Nonce"] = val
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Link"] = f'<{_base_path(caid, alias)}/directory>;rel="index"'
    return resp


@acme_api.route("/acme/<caid>/<alias>/new-account", methods=["POST"])
def new_account(caid, alias):
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    p = env["payload"]
    jwk_in_header = env["jwk"]

    # POST-as-GET (kid present, no jwk)
    if not jwk_in_header:
        kid = env.get("kid")
        if not kid:
            return _error(caid, alias, "accountDoesNotExist", 400)
        acc = _account_by_kid(kid, caid, alias)
        if not acc:
            return _error(caid, alias, "accountDoesNotExist", 400)

        body = {
            "status": acc["status"],
            "contact": (acc["contact"] or "").split(",") if acc["contact"] else [],
            "orders": _location(f"/acme/{caid}/{alias}/account/{acc['id']}/orders"),
        }
        resp = jsonify(body)
        resp.headers["Location"] = acc["kid"]
        return _apply_headers(resp, _std_headers(caid, alias))

    # Account creation (jwk in protected header)
    contact = p.get("contact", [])
    tos_agreed = bool(p.get("termsOfServiceAgreed"))

    with _db() as cx:
        cur = cx.execute(
            """INSERT INTO acme_account(caid, template_alias, status, contact, kid, jws_jwk, tos_agreed, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (caid, alias, "valid", ",".join(contact), "", json.dumps(jwk_in_header), 1 if tos_agreed else 0, _now_iso()),
        )
        acc_id = cur.lastrowid
        kid_url = _location(f"/acme/{caid}/{alias}/account/{acc_id}")
        cx.execute("UPDATE acme_account SET kid=? WHERE id=?", (kid_url, acc_id))

    body = {"status": "valid", "contact": contact, "orders": _location(f"/acme/{caid}/{alias}/account/{acc_id}/orders")}
    resp = jsonify(body)
    resp.headers["Location"] = kid_url
    return _apply_headers(resp, _std_headers(caid, alias)), 201


@acme_api.route("/acme/<caid>/<alias>/new-order", methods=["POST"])
def new_order(caid, alias):
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    acc = _account_by_kid(env.get("kid"), caid, alias)
    if not acc:
        return _error(caid, alias, "accountDoesNotExist", 400)

    p = env["payload"]
    identifiers = p.get("identifiers", [])
    not_before = p.get("notBefore")
    not_after = p.get("notAfter")

    with _db() as cx:
        # 1) create the internal order row
        cur = cx.execute(
            """INSERT INTO acme_order(caid, template_alias, account_id, status, identifiers, not_before, not_after, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (caid, alias, acc["id"], "pending", json.dumps(identifiers), not_before, not_after, _now_iso()),
        )
        internal_order_id = cur.lastrowid

        # 2) generate the external identifier potentially >64 bits
        oid = uuid.uuid4().int
        oid_str = str(oid)

        finalize_url = _location(f"/acme/{caid}/{alias}/finalize/{oid_str}")
        cert_url = _location(f"/acme/{caid}/{alias}/order/{oid_str}/certificate")

        # 3) update the row by internal id (safe) and store order_ext_id
        cx.execute(
            "UPDATE acme_order SET order_ext_id=?, finalize_url=?, cert_url=? WHERE id=?",
            (oid_str, finalize_url, cert_url, internal_order_id)
        )

        # 4) create the Authorizations linked to the internal PK (FK) + HTTP-01 challenge
        authz_urls = []
        for ident in identifiers:
            # By default, http-01 challenge is 'pending'
            token = _b64url_nopad(os.urandom(16))  # 128 bits ~ 22 base64url chars
            cur_a = cx.execute(
                """INSERT INTO acme_authz(
                       caid, template_alias, order_id, status, identifier, created_at,
                       challenge_type, challenge_token, challenge_status, challenge_url
                   )
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (caid, alias, internal_order_id, "pending", json.dumps(ident), _now_iso(),
                 "http-01", token, "pending", ""),
            )
            aid = cur_a.lastrowid
            challenge_api_url = _location(f"/acme/{caid}/{alias}/challenge/{aid}")
            cx.execute("UPDATE acme_authz SET challenge_url=? WHERE id=?", (challenge_api_url, aid))

            authz_urls.append(_location(f"/acme/{caid}/{alias}/authz/{aid}"))

    order_obj = {"status": "pending", "finalize": finalize_url, "identifiers": identifiers, "authorizations": authz_urls}
    resp = jsonify(order_obj)
    resp.headers["Location"] = _location(f"/acme/{caid}/{alias}/order/{oid_str}")
    return _apply_headers(resp, _std_headers(caid, alias)), 201


@acme_api.route("/acme/<caid>/<alias>/account/<int:acc_id>", methods=["POST"])
def get_account(caid, alias, acc_id):
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    with _db() as cx:
        acc = cx.execute(
            "SELECT * FROM acme_account WHERE id=? AND caid=? AND template_alias=?",
            (acc_id, caid, alias),
        ).fetchone()

    if not acc:
        return _error(caid, alias, "accountDoesNotExist", 404)

    body = {
        "status": acc["status"],
        "contact": (acc["contact"] or "").split(",") if acc["contact"] else [],
        "orders": _location(f"/acme/{caid}/{alias}/account/{acc['id']}/orders"),
    }
    resp = jsonify(body)
    resp.headers["Location"] = acc["kid"]
    return _apply_headers(resp, _std_headers(caid, alias))


@acme_api.route("/acme/<caid>/<alias>/order/<oid>", methods=["POST"])
def get_order(caid, alias, oid):
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    with _db() as cx:
        row = cx.execute(
            "SELECT * FROM acme_order WHERE order_ext_id=? AND caid=? AND template_alias=?",
            (str(oid), caid, alias),
        ).fetchone()

        if not row:
            return _error(caid, alias, "orderNotFound", 404)

        authz_rows = cx.execute(
            "SELECT id, status, identifier FROM acme_authz WHERE order_id=? AND caid=? AND template_alias=?",
            (row["id"], caid, alias),
        ).fetchall()

    authorizations = [
        _location(f"/acme/{caid}/{alias}/authz/{r['id']}") for r in authz_rows
    ]

    body = {
        "status": row["status"],
        "finalize": row["finalize_url"],
        "identifiers": json.loads(row["identifiers"]),
    }
    if authorizations:
        body["authorizations"] = authorizations
    if row["status"] == "valid":
        body["certificate"] = _location(f"/acme/{caid}/{alias}/order/{oid}/certificate")

    resp = jsonify(body)
    resp.headers["Location"] = _location(f"/acme/{caid}/{alias}/order/{oid}")
    return _apply_headers(resp, _std_headers(caid, alias))


@acme_api.route("/acme/<caid>/<alias>/authz/<int:aid>", methods=["POST"])
def get_authz(caid, alias, aid):
    """Authorization resource (POST-as-GET). Returns the http-01 challenge."""
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    with _db() as cx:
        r = cx.execute(
            """SELECT status, identifier, challenge_type, challenge_token,
                      challenge_status, challenge_url
               FROM acme_authz
               WHERE id=? AND caid=? AND template_alias=?""",
            (aid, caid, alias),
        ).fetchone()

    if not r:
        return _error(caid, alias, "authorizationNotFound", 404)

    ident = json.loads(r["identifier"])
    body = {
        "status": r["status"],
        "identifier": ident,
        "challenges": [
            {
                "type": r["challenge_type"],       # "http-01"
                "status": r["challenge_status"],   # "pending"/"processing"/"valid"/"invalid"
                "url": r["challenge_url"],         # ACME endpoint to trigger
                "token": r["challenge_token"],     # token to place on client side
            }
        ]
    }
    resp = jsonify(body)
    return _apply_headers(resp, _std_headers(caid, alias))


def _http01_fetch_with_safe_redirects(start_url: str, expected_host: str, timeout=5, max_redirects=5):
    """
    Manually follow HTTP redirects (max_redirects) enforcing:
      - http:// scheme only (no https/file/...)
      - strict host preservation (restricted: same FQDN)
    NOTE: No filtering for "public" IP here since internal network is desired.
    """
    session = requests.Session()
    session.max_redirects = max_redirects
    current = start_url
    for _ in range(max_redirects + 1):
        r = session.get(current, timeout=timeout, allow_redirects=False, headers={"Host": expected_host})
        if r.is_redirect or r.is_permanent_redirect:
            loc = r.headers.get("Location", "")
            if not loc:
                return False, f"redirect without Location from {current}"
            # Build absolute URL
            nxt = urljoin(current, loc)
            p = urlparse(nxt)
            if p.scheme != "http":
                return False, f"redirect to unsupported scheme: {p.scheme}"
            if p.hostname and p.hostname.lower() != expected_host.lower():
                return False, f"redirect to different host: {p.hostname}"
            current = nxt
            continue
        # No redirect: final return
        body = (r.text or "").strip()
        return True, (r.status_code, body)
    return False, "too many redirects"


@acme_api.route("/acme/<caid>/<alias>/challenge/<int:aid>", methods=["POST"])
def trigger_challenge(caid, alias, aid):
    """Trigger active validation of the HTTP-01 challenge for authz <aid>."""
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    acc = _account_by_kid(env.get("kid"), caid, alias)
    if not acc:
        return _error(caid, alias, "accountDoesNotExist", 400)

    with _db() as cx:
        row = cx.execute(
            """SELECT a.id, a.status, a.identifier, a.challenge_type, a.challenge_token,
                      a.challenge_status, a.key_authorization, a.validated_at, a.order_id
               FROM acme_authz a
               WHERE a.id=? AND a.caid=? AND a.template_alias=?""",
            (aid, caid, alias),
        ).fetchone()

        if not row:
            return _error(caid, alias, "authorizationNotFound", 404)
        if row["challenge_type"] != "http-01":
            return _error(caid, alias, "unsupportedChallengeType", 400)

        # Build keyAuthorization = token + "." + base64url(JWK_Thumbprint(SHA-256))
        token = row["challenge_token"]
        th_b64u = _jwk_thumbprint_b64u_from_acc(acc)
        key_auth = f"{token}.{th_b64u}"

        # Mark challenge as processing and store keyAuthorization
        cx.execute(
            "UPDATE acme_authz SET challenge_status=?, key_authorization=? WHERE id=?",
            ("processing", key_auth, aid),
        )

    ident = json.loads(row["identifier"])
    fqdn = ident.get("value") or ""
    if not fqdn:
        return _error(caid, alias, "malformedIdentifier", 400, "Missing FQDN value")

    # HTTP-01: validation over clear HTTP on port 80 with bounded redirects
    http01_url = f"http://{fqdn}/.well-known/acme-challenge/{token}"

    ok = False
    detail = ""
    try:
        fetched, result = _http01_fetch_with_safe_redirects(http01_url, fqdn, timeout=5, max_redirects=5)
        if not fetched:
            detail = str(result)
        else:
            status_code, body = result
            if status_code == 200 and body == key_auth:
                ok = True
            else:
                detail = f"unexpected content or status={status_code}"
    except requests.RequestException as e:
        detail = f"fetch error: {e}"

    with _db() as cx:
        if ok:
            # Challenge validated
            cx.execute(
                "UPDATE acme_authz SET status=?, challenge_status=?, validated_at=? WHERE id=?",
                ("valid", "valid", _now_iso(), aid),
            )

            # If all authz for the order are valid -> order becomes 'ready'
            o = cx.execute("SELECT order_id FROM acme_authz WHERE id=?", (aid,)).fetchone()
            order_id = o["order_id"]
            rest = cx.execute(
                "SELECT COUNT(*) AS nb FROM acme_authz WHERE order_id=? AND status!='valid'",
                (order_id,),
            ).fetchone()
            if rest["nb"] == 0:
                cx.execute("UPDATE acme_order SET status=? WHERE id=?", ("ready", order_id))
        else:
            cx.execute(
                "UPDATE acme_authz SET status=?, challenge_status=? WHERE id=?",
                ("invalid", "invalid", aid),
            )

        r2 = cx.execute(
            """SELECT status, identifier, challenge_type, challenge_token,
                      challenge_status, challenge_url
               FROM acme_authz WHERE id=?""",
            (aid,),
        ).fetchone()

    body = {
        "type": r2["challenge_type"],
        "status": r2["challenge_status"],
        "url": r2["challenge_url"],
        "token": r2["challenge_token"],
    }

    resp = jsonify(body)

    # FIRST apply standard headers (Replay-Nonce, Cache-Control, Link rel="index")
    resp = _apply_headers(resp, _std_headers(caid, alias))

    # THEN add 'Link: rel="up"' (otherwise it gets overwritten)
    authz_url = _location(f"/acme/{caid}/{alias}/authz/{aid}")
    resp.headers.add("Link", f'<{authz_url}>; rel="up"')

    # Add detail on failure (helps client-side debugging)
    if not ok and detail:
        resp = _apply_headers(resp, {"ACME-Validation-Detail": detail})

    return resp


@acme_api.route("/acme/<caid>/<alias>/finalize/<oid>", methods=["POST"])
def finalize(caid, alias, oid):
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        return _error(caid, alias, t, c, d)

    p = env["payload"]
    csr_b64u = p.get("csr")
    if not csr_b64u:
        return _error(caid, alias, "malformedRequest", 400, "Missing csr")

    # Decode CSR
    try:
        pad = '=' * ((4 - len(csr_b64u) % 4) % 4)
        csr_der = base64.urlsafe_b64decode(csr_b64u + pad)
    except Exception:
        return _error(caid, alias, "malformedRequest", 400, "Bad csr (base64url)")

    # Require order to be 'ready' (all authz validated)
    with _db() as cx:
        order_row = cx.execute(
            "SELECT * FROM acme_order WHERE order_ext_id=? AND caid=? AND template_alias=?",
            (str(oid), caid, alias),
        ).fetchone()
    if not order_row:
        return _error(caid, alias, "orderNotFound", 404)

    with _db() as cx:
        cnt = cx.execute(
            "SELECT COUNT(*) AS nb FROM acme_authz WHERE order_id=? AND status!='valid'",
            (order_row["id"],)
        ).fetchone()
    if cnt["nb"] != 0 or order_row["status"] not in ("ready", "valid"):
        return _error(caid, alias, "orderNotReady", 403)

    # Cross-check CSR vs identifiers (DNS): strict set equality
    expected_dns = _expected_dns_from_identifiers(order_row["identifiers"])
    csr_dns = _csr_dns_names_from_der(csr_der)

    if not expected_dns:
        return _error(caid, alias, "rejectedIdentifier", 400, "No expected DNS in order")
    if not csr_dns:
        return _error(caid, alias, "malformedCSR", 400, "CSR contains no DNS (SAN/CN)")

    extra_in_csr = csr_dns - expected_dns
    missing_in_csr = expected_dns - csr_dns

    if extra_in_csr or missing_in_csr:
        resp = jsonify({
            "type": "rejectedIdentifier",
            "detail": "CSR identifiers mismatch",
            "extra": sorted(extra_in_csr),
            "missing": sorted(missing_in_csr),
        })
        return _apply_headers(resp, _std_headers(caid, alias)), 400

    tpl, ca = _resolve_template_for_user(caid, alias)
    if not tpl or not ca:
        return _error(caid, alias, "unauthorized", 403)

    cb = tpl.get("__callback") or {}

    with open(os.path.join(current_app.confadcs['path_list_request_id'], str(oid)), 'wb') as f:
        f.write(csr_der)

    emit_certificate = load_func(cb.get("path"), cb.get("issue"))

    info = {"oid": (tpl.get("template_oid") or {}).get("value"), "name": tpl.get("common_name")}

    req_id = uuid.uuid4().int
    result = emit_certificate(
        csr_der=csr_der,
        request_id=req_id,
        kerberos_user=getattr(g, "kerberos_user", None),
        ca=ca,
        template=tpl,
        info=info,
        app_conf=current_app.confadcs,
        CAID=caid,
        request=request,
        body_part_id=0,
    )

    cert_val = result.get("cert")
    if isinstance(cert_val, cx509.Certificate):
        cert_obj = cert_val
        cert_der = cert_val.public_bytes(serialization.Encoding.DER)
    elif isinstance(cert_val, (bytes, bytearray, memoryview)):
        cert_der = bytes(cert_val)
        cert_obj = cx509.load_der_x509_certificate(cert_der)
    else:
        return Response("Callback(issued) must return 'cert' (x509 or DER bytes)", status=500, content_type="text/plain; charset=utf-8")

    b64_leaf = format_b64_for_soap(cert_der)

    with open(os.path.join(ca['__path_cert'], f"{oid}.pem"), 'w') as f:
        f.write(
            "-----BEGIN CERTIFICATE-----\n" +
            "\n".join(textwrap.wrap(b64_leaf, 64)) +
            "\n-----END CERTIFICATE-----"
        )

    status = str(result.get("status", "")).lower()
    with _db() as cx:
        # re-read the order (already read above, but we want it in the same update transaction)
        order_row = cx.execute(
            "SELECT * FROM acme_order WHERE order_ext_id=? AND caid=? AND template_alias=?",
            (str(oid), caid, alias),
        ).fetchone()
        if not order_row:
            return _error(caid, alias, "orderNotFound", 404)

        if status == "issued":
            cert_val = result.get("cert")
            try:
                if isinstance(cert_val, cx509.Certificate):
                    cert_der = cert_val.public_bytes(ser.Encoding.DER)
                else:
                    cert_der = bytes(cert_val)
                    cx509.load_der_x509_certificate(cert_der)  # sanity check
            except Exception:
                return _error(caid, alias, "serverInternal", 500, "Cannot decode returned certificate DER")

            p7_der = result.get("pkcs7_der")
            if not p7_der:
                ca_key = ca.get("__key_obj")
                ca_cert_der = ca.get("__certificate_der")
                if not (ca_key and ca_cert_der):
                    p7_der = b""
                else:
                    p7_der = build_adcs_bst_certrep(cert_der, ca_cert_der, ca_key, 0)

            cx.execute(
                """UPDATE acme_order
                   SET status=?, csr_der_b64=?, cert_der_b64=?, chain_p7_der_b64=?
                   WHERE id=?""",
                (
                    "valid",
                    base64.b64encode(csr_der).decode(),
                    format_b64_for_soap(cert_der),
                    (format_b64_for_soap(p7_der) if p7_der else None),
                    order_row["id"],
                ),
            )
            order_obj = {"status": "valid", "certificate": _location(f"/acme/{caid}/{alias}/order/{oid}/certificate")}
        elif status in ("pending", "processing"):
            cx.execute(
                "UPDATE acme_order SET status=?, csr_der_b64=? WHERE id=?",
                ("processing", base64.b64encode(csr_der).decode(), order_row["id"]),
            )
            order_obj = {"status": "processing"}
        else:
            cx.execute(
                "UPDATE acme_order SET status=?, csr_der_b64=? WHERE id=?",
                ("invalid", base64.b64encode(csr_der).decode(), order_row["id"]),
            )
            order_obj = {"status": "invalid"}

    resp = jsonify(order_obj)
    resp.headers["Location"] = _location(f"/acme/{caid}/{alias}/order/{oid}")
    return _apply_headers(resp, _std_headers(caid, alias))


@acme_api.route("/acme/<caid>/<alias>/order/<oid>/certificate", methods=["POST"])
def download_cert(caid, alias, oid):
    # Verify JWS + nonce (ACME POST-as-GET)
    env, err = _verify_jws_and_nonce(caid, alias)
    if err:
        t, c, d = err
        r, sc = _error(caid, alias, t, c, d)
        return r, sc

    # Retrieve leaf from DB
    with _db() as cx:
        row = cx.execute(
            "SELECT cert_der_b64 FROM acme_order WHERE order_ext_id=? AND caid=? AND template_alias=?",
            (str(oid), caid, alias),
        ).fetchone()

    if not row or not row["cert_der_b64"]:
        resp = jsonify({"type": "orderNotReady"})
        return _apply_headers(resp, _std_headers(caid, alias)), 404

    # Leaf -> PEM
    try:
        leaf_der = base64.b64decode(row["cert_der_b64"])
        leaf = cx509.load_der_x509_certificate(leaf_der)
        leaf_pem = leaf.public_bytes(ser.Encoding.PEM)
    except Exception:
        return _error(caid, alias, "serverInternal", 500, "cannot decode stored certificate")

    # Issuer PEM (from the CA config used by this template)
    tpl, ca_obj = _resolve_template_for_user(caid, alias)
    if not ca_obj:
        # Unlikely fallback: try via global conf
        ca_obj = next((c for c in current_app.confadcs.get("cas_list") or [] if c.get("id") == caid), None)

    issuer_pem = (ca_obj or {}).get("__certificate_pem")
    if not issuer_pem:
        # Last fallback: return at least the leaf (but Certbot may complain)
        fullchain_bytes = leaf_pem
    else:
        # Concatenate leaf + issuer (intermediate if issued via ICA, root if issued via root)
        fullchain_bytes = leaf_pem + issuer_pem.encode("utf-8")

    # RFC 8555: application/pem-certificate-chain, Link: <...>;rel="up" to issuer if known
    resp = Response(fullchain_bytes, mimetype="application/pem-certificate-chain")
    resp = _apply_headers(resp, _std_headers(caid, alias))

    # Add Link: up if we have issuer URL (handy for some clients)
    issuer_url = (ca_obj or {}).get("urls", {}).get("ca_issuers_http")
    if issuer_url:
        resp.headers.add("Link", f'<{issuer_url}>;rel="up"')

    return resp


@acme_api.route("/acme/<caid>/<alias>/directory", methods=["GET"])
def directory(caid, alias):
    base = _base_path(caid, alias)
    body = {
        "newNonce":   f"{base}/new-nonce",
        "newAccount": f"{base}/new-account",
        "newOrder":   f"{base}/new-order",
        # Optional RFC 8555:
        # "revokeCert": f"{base}/revoke-cert",
        # "keyChange":  f"{base}/key-change",
        # "meta": {"externalAccountRequired": False}
    }
    resp = jsonify(body)
    return _apply_headers(resp, _std_headers(caid, alias))
