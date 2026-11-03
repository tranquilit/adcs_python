"""AD lookup via ldap3 and mandatory Kerberos/GSSAPI Sign or Seal.

Compatible with ldap3 2.9.1: application LDAP messages are signed or
sealed via an isolated RFC 4752 transport implementation. No TLS, Samba
or subprocess. Loaded lazily by utils.search_user_ldap3.
"""

from contextlib import contextmanager, suppress
from copy import deepcopy
import logging
from pathlib import Path
import re
import struct
from tempfile import TemporaryDirectory
from typing import Optional, Union

import gssapi
from ldap3 import (
    ALL_ATTRIBUTES, BASE, DEREF_NEVER, KERBEROS, NONE, SASL, SUBTREE, SYNC,
    Server,
)
from ldap3.utils.conv import escape_filter_chars
from ldap3_gssapi import ProtectedKerberosConnection

log = logging.getLogger(__name__)
DOMAIN_SCOPE_OID = "1.2.840.113556.1.4.1339"


class InvalidKerberosCredentials(Exception):
    """Explicit username/password credentials were rejected by the KDC."""


# MIT krb5 minor status codes, normalized to signed 32-bit integers.
# Do not include KDC_UNREACH, DNS failures or LDAP/GSSAPI bind errors:
# those are infrastructure errors, not a bad password.
_KRB5_CREDENTIAL_REJECTION_CODES = frozenset({
    -1765328383,  # KRB5KDC_ERR_NAME_EXP (account expired)
    -1765328378,  # KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
    -1765328366,  # KRB5KDC_ERR_CLIENT_REVOKED (disabled/locked)
    -1765328363,  # KRB5KDC_ERR_CLIENT_NOTYET
    -1765328361,  # KRB5KDC_ERR_KEY_EXP (password expired)
    -1765328360,  # KRB5KDC_ERR_PREAUTH_FAILED
    -1765328353,  # KRB5KRB_AP_ERR_BAD_INTEGRITY (wrong AS reply key)
    -1765328253,  # KRB5_LIBOS_BADPWDMATCH (password mismatch)
    -1765328174,  # KRB5_PREAUTH_FAILED (generic preauth failure)
})


def _is_credential_rejection(error: gssapi.exceptions.GSSError) -> bool:
    """Recognize KDC credential rejection without parsing localized messages."""
    minor = int(error.min_code) & 0xFFFFFFFF
    if minor >= 0x80000000:
        minor -= 0x100000000
    return minor in _KRB5_CREDENTIAL_REJECTION_CODES


def _dns_name(name: str, field: str) -> str:
    """Accept only DNS names, never LDAP URLs, IP addresses or short names."""
    if not isinstance(name, str):
        raise ValueError(f"{field} must be a DNS domain or FQDN")
    name = name.strip().rstrip(".").lower()
    parts = name.split(".")
    if (len(parts) < 2 or len(name) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in parts
    )):
        raise ValueError(f"{field} must be a DNS domain or FQDN")
    # Numeric dotted IP addresses are not valid Kerberos SPN targets.
    if all(part.isdigit() for part in parts):
        raise ValueError(f"{field} must not be an IP address")
    return name


def _principal(name: str, realm: str):
    if not isinstance(name, str) or not name.strip() or "\x00" in name or "\\" in name:
        raise ValueError("Expected an AD user or Kerberos principal")
    account, at, supplied_realm = name.strip().partition("@")
    if not account or (at and (not supplied_realm or "@" in supplied_realm)):
        raise ValueError("Invalid Kerberos principal")
    domain = _dns_name(supplied_realm, "principal realm") if at else realm.lower()
    if domain != realm.lower():
        raise ValueError("Principal realm differs from requested AD realm")
    return gssapi.Name(
        f"{account}@{realm}", name_type=gssapi.NameType.kerberos_principal,
    )


def _machine_principal(keytab: Path, realm: str):
    """Find unique NAME$@REALM in a FILE keytab (MIT v1 or v2).

    Skips key material, duplicate enctypes/KVNOs and deleted slots. No
    subprocess, no heuristics based on the host's current hostname.
    """
    wanted = realm.encode("ascii")
    found = set()

    with keytab.open("rb", buffering=0) as stream:
        size = stream.seek(0, 2)
        stream.seek(0)
        header = stream.read(2)
        if header not in (b"\x05\x01", b"\x05\x02"):
            raise ValueError("Unsupported or corrupt FILE keytab")
        v1 = header == b"\x05\x01"
        order = "=" if v1 else ">"
        end = size

        def read(n):
            if n < 0 or stream.tell() + n > end:
                raise ValueError("Truncated keytab record")
            data = stream.read(n)
            if len(data) != n:
                raise ValueError("Truncated keytab record")
            return data

        def integer(fmt):
            return struct.unpack(order + fmt, read(struct.calcsize(fmt)))[0]

        def counted():
            return read(integer("H"))

        while stream.tell() < size:
            end = size
            length = integer("i")
            if length == 0:
                break
            end = stream.tell() + abs(length)
            if end > size:
                raise ValueError("Truncated keytab entry")
            if length < 0:
                stream.seek(end)
                continue

            parts = integer("H") - int(v1)
            if parts < 1:
                raise ValueError("Invalid keytab principal")
            entry_realm = counted()
            account = counted()
            for _ in range(parts - 1):
                counted()
            if not v1:
                integer("I")  # name type
            integer("I")  # timestamp
            integer("B")  # KVNO
            integer("H")  # enctype
            key_len = integer("H")
            if not key_len or stream.tell() + key_len > end:
                raise ValueError("Truncated or missing keytab key")
            stream.seek(end)  # skip key bytes, KVNO32 and padding

            if parts == 1 and len(account) > 1 and account.endswith(b"$") and entry_realm == wanted:
                found.add(account)

    if not found:
        raise ValueError(f"No machine principal NAME$@{realm} in {keytab}")
    #if len(found) != 1:
    #    raise ValueError(f"Multiple different machine principals NAME$@{realm} in {keytab}")

    account = next(iter(found))
    # A keytab name component is not a free-form principal string. Escape any
    # delimiter before constructing the GSSAPI kerberos_principal Name.
    for original, escaped in (
        (b"\\", b"\\\\"), (b"/", b"\\/"), (b"@", b"\\@"),
        (b"\x00", b"\\0"), (b"\n", b"\\n"), (b"\t", b"\\t"),
    ):
        account = account.replace(original, escaped)
    return gssapi.Name(account + b"@" + wanted,
                       name_type=gssapi.NameType.kerberos_principal)


@contextmanager
def _kerberos_credentials(userauth, realm, password, bind_user, keytab):
    """Acquire explicit initiator creds, never alter KRB5CCNAME/KRB5_KTNAME."""
    if password is not None:
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a nonempty string")
        name = _principal(bind_user if bind_user is not None else userauth, realm)
        try:
            result = gssapi.raw.acquire_cred_with_password(
                name=name,
                password=password.encode("utf-8"),
                mechs=[gssapi.MechType.kerberos],
                usage="initiate",
            )
        except gssapi.exceptions.GSSError as exc:
            # Only classify an explicit password's KDC rejection here.
            # Errors later in the LDAP/GSSAPI connection remain exceptions.
            if _is_credential_rejection(exc):
                raise InvalidKerberosCredentials from None
            raise
        yield result.creds
        return

    if bind_user is not None:
        raise ValueError("bind_user requires password")
    if not isinstance(keytab, str) or not keytab:
        raise ValueError("keytab must be a path to a FILE keytab")
    path = Path(keytab).resolve(strict=True)
    if not path.is_file():
        raise ValueError("keytab must be a file")
    name = _machine_principal(path, realm)
    with TemporaryDirectory(prefix="ldap3-krb5-") as cache_dir:
        # MIT GSSAPI uses the initiator keytab to acquire a TGT. A per-call
        # ccache prevents leaking into other concurrent user sessions.
        creds = gssapi.Credentials(
            name=name, usage="initiate", mechs=[gssapi.MechType.kerberos],
            store={"client_keytab": f"FILE:{path}",
                   "ccache": f"FILE:{cache_dir}/ccache"},
        )
        yield creds


def _entries(conn, operation):
    result = conn.result or {}
    if result.get("result") != 0:
        raise RuntimeError(f"{operation}: LDAP error {result.get('description')!r} ({result.get('result')})")
    response = conn.response or []
    if any(item.get("type") == "searchResRef" for item in response):
        raise RuntimeError(f"{operation}: LDAP referral refused")
    return [item for item in response if item.get("type") == "searchResEntry"]


def find_user(
    userauth: str,
    ldap_filter: str = "",
    dc_fqdn: Optional[str] = None,
    basedn: Optional[str] = None,
    password: Optional[str] = None,
    bind_user: Optional[str] = None,
    dc_cache_ttl_seconds: float = 300,
    *,
    realm: Optional[str] = None,
    keytab: str = "/etc/krb5.keytab",
    attributes: Optional[Union[list[str], tuple[str, ...]]] = None,
    timeout: int = 10,
    get_dc_fqdn,
) -> Optional[dict]:
    """Find an AD sAMAccountName with SASL Kerberos; return detached LDAP entry or None.

    GSSAPI confidentiality (Seal) is preferred; GSSAPI integrity (Sign)
    is mandatory if Seal is unavailable. TCP/389, no TLS.
    """
    if not isinstance(userauth, str) or not userauth.strip() or "\x00" in userauth:
        raise ValueError("userauth must be an AD account")
    account, sep, user_realm = userauth.strip().partition("@")
    account = account.strip()
    if not account or "\\" in account or (sep and (not user_realm or "@" in user_realm)):
        raise ValueError("Expected sAMAccountName or sAMAccountName@REALM")
    if realm is None:
        if not sep:
            raise ValueError("realm is required for a short userauth")
        realm = user_realm
    domain = _dns_name(realm, "realm")
    if sep and _dns_name(user_realm, "userauth realm") != domain:
        raise ValueError("userauth realm and explicit realm differ")
    if not isinstance(ldap_filter, str):
        raise ValueError("ldap_filter must be a trusted LDAP filter string")
    if basedn is not None and (not isinstance(basedn, str) or not basedn.strip()):
        raise ValueError("basedn must be a nonempty DN")
    if attributes is not None and (
        not isinstance(attributes, (tuple, list)) or
        any(not isinstance(a, str) or not a for a in attributes)
    ):
        raise ValueError("attributes must be a list/tuple of LDAP attributes")
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("timeout must be a positive integer")

    if dc_fqdn is not None:
        dc_fqdn = _dns_name(dc_fqdn, "dc_fqdn")
    realm_name = domain.upper()
    base = basedn or "DC=" + domain.replace(".", ",DC=")
    filter_str = f"(&(sAMAccountName={escape_filter_chars(account)}){ldap_filter})"

    with _kerberos_credentials(userauth.strip(), realm_name, password, bind_user, keytab) as creds:
        host = dc_fqdn or _dns_name(
            get_dc_fqdn(domain, dc_cache_ttl_seconds=dc_cache_ttl_seconds, timeout=timeout),
            "discovered DC",
        )
        server = Server(host, port=389, use_ssl=False, get_info=NONE, connect_timeout=timeout)
        kwargs = dict(
            authentication=SASL,
            client_strategy=SYNC,
            sasl_mechanism=KERBEROS,
            sasl_credentials=(host, None, creds),
            auto_bind=False,
            auto_referrals=False,
            check_names=False,
            read_only=True,
            raise_exceptions=True,
            receive_timeout=timeout,
        )
        conn = ProtectedKerberosConnection(server, **kwargs)
        try:
            conn.open(read_server_info=False)
            if not conn.bind(read_server_info=False) or not conn.bound:
                raise RuntimeError("LDAP SASL/GSSAPI bind failed")
            if getattr(conn, "gssapi_security_layer", None) not in ("sign", "seal"):
                raise RuntimeError("LDAP connection lacks SASL Sign/Seal")
            conn.search(
                search_base=base,
                search_filter=filter_str,
                search_scope=SUBTREE,
                dereference_aliases=DEREF_NEVER,
                attributes=[ALL_ATTRIBUTES] if attributes is None else list(attributes),
                size_limit=2,
                time_limit=timeout,
                controls=[(DOMAIN_SCOPE_OID, True, None)],
            )
            results = _entries(conn, "Search user")
            if not results:
                return None
            if len(results) != 1:
                raise ValueError("More than one user matches sAMAccountName")
            return deepcopy(results[0])
        finally:
            with suppress(Exception):
                conn.unbind()
