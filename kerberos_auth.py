"""Kerberos/SPNEGO authentication and authenticated PAC metadata decoding.

No LDAP or Winbind calls. Optional PAC metadata is best-effort.
"""

import base64
import binascii
import logging
import struct
from datetime import datetime, timedelta, timezone
from itertools import islice

import gssapi
from flask import current_app, g, request

from adcs_logging import get_logger, log_event

logger = get_logger("auth")


# python3-samba provides the native, local NDR decoder for PAC data.
# All authentication methods still work if Samba's Python bindings are absent.
try:
    from samba.dcerpc import krb5pac
    from samba.ndr import ndr_unpack
except (ImportError, OSError):
    krb5pac = None
    ndr_unpack = None

# Claims decoding is optional. Some Samba builds expose the PAC structures
# without exposing the claims NDR bindings.
try:
    from samba.dcerpc import claims as samba_claims
except (ImportError, OSError):
    samba_claims = None


_MAX_PAC_BYTES = 4 * 1024 * 1024
_MAX_PAC_ENTRIES = 16384
_SE_GROUP_ENABLED = 0x00000004
_SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

# MS-PAC buffer numbers are stable across Samba versions. Avoid looking up
# newly added constants at import time on older Debian/Samba installations.
_PAC_BUFFER_NAMES = {
    1: "logon_info",
    2: "credential_info",
    6: "server_checksum",
    7: "kdc_checksum",
    10: "client_info",
    11: "constrained_delegation",
    12: "upn_dns_info",
    13: "client_claims_info",
    14: "device_info",
    15: "device_claims_info",
    16: "ticket_checksum",
    17: "attributes_info",
    18: "requestor_sid",
    19: "full_checksum",
}


def _empty_pac_info():
    """Fresh request-local data for every auth method, even non-Kerberos."""
    return {
        # Account identity (UPN_DNS_INFO and LOGON_INFO).
        "sid": None,
        "sam_name": None,
        "upn": None,
        "dns_domain": None,
        "upn_dns_flags": None,
        "upn_constructed": None,
        "rid": None,
        "domain_sid": None,
        "domain_name": None,
        "logon_server": None,
        "full_name": None,
        # Authorization: only enabled, non-deny-only SIDs are included.
        "groups": None,
        "primary_group_rid": None,
        "extra_sids": None,
        "resource_groups": None,
        "group_count": None,
        # Samba SAM account flags, NOT LDAP userAccountControl bits.
        "account_flags": None,
        "user_flags": None,
        "sub_auth_status": None,
        # Authentication/account history from LOGON_INFO, as seen when the
        # ticket was issued (not live LDAP values).
        "last_logon": None,
        "last_successful_logon": None,
        "last_failed_logon": None,
        "logoff_time": None,
        "kickoff_time": None,
        "password_last_set": None,
        "password_can_change": None,
        "password_must_change": None,
        "logon_count": None,
        "bad_password_count": None,
        "failed_logon_count": None,
        "home_directory": None,
        "home_drive": None,
        "logon_script": None,
        "profile_path": None,
        # Other PAC buffers (present only in some Kerberos tickets).
        "client_name": None,
        "client_auth_time": None,
        "requestor_sid": None,
        "pac_requested": None,
        "pac_given_implicitly": None,
        "pac_attributes_flags": None,
        "delegation_proxy_target": None,
        "delegation_transited_services": None,
        "device_info": None,
        "client_claims_present": None,
        "device_claims_present": None,
        "client_claims": None,
        "device_claims": None,
        "credential_info_present": None,
        "pac_signature_types": None,
        "pac_version": None,
        "pac_size": None,
        "pac_buffer_types": None,
        "pac_buffer_type_ids": None,
    }


def _authenticated_pac_attribute(name, key):
    """Return authenticated PAC bytes only AFTER GSSAPI context completion.

    Unauthenticated GSS name attributes must never be used for authorization.
    """
    try:
        attr = name.attributes[key]
    except (
        AttributeError,
        KeyError,
        TypeError,
        NotImplementedError,
        gssapi.exceptions.GSSError,
    ):
        return None

    if not attr.authenticated or not attr.complete or len(attr.values) != 1:
        return None
    raw = next(iter(attr.values))
    if not isinstance(raw, bytes) or len(raw) > _MAX_PAC_BYTES:
        return None
    return raw


def _populate_upn_dns_info(name, info):
    """Decode PAC_UPN_DNS_INFO (including optional SAM name and SID)."""
    data = _authenticated_pac_attribute(name, "urn:mspac:upn-dns-info")
    if not data or len(data) < 12:
        return

    upn_length, upn_offset, dns_length, dns_offset, flags = struct.unpack_from(
        "<HHHHI", data, 0
    )
    info["upn_dns_flags"] = flags
    info["upn_constructed"] = bool(flags & 0x01)
    with_sam_and_sid = bool(flags & 0x02)
    header_size = 20 if with_sam_and_sid else 12
    if len(data) < header_size:
        return

    def read_utf16(length, offset):
        if length == 0 or length % 2 or offset < header_size:
            return None
        if offset + length > len(data):
            return None
        try:
            return data[offset:offset + length].decode("utf-16-le")
        except UnicodeDecodeError:
            return None

    info["upn"] = read_utf16(upn_length, upn_offset)
    info["dns_domain"] = read_utf16(dns_length, dns_offset)

    if not with_sam_and_sid:
        return
    sam_length, sam_offset, sid_length, sid_offset = struct.unpack_from(
        "<HHHH", data, 12
    )
    info["sam_name"] = read_utf16(sam_length, sam_offset)

    if sid_length < 12 or sid_offset < header_size:
        return
    if sid_offset + sid_length > len(data):
        return
    sid = data[sid_offset:sid_offset + sid_length]
    revision, count = sid[0], sid[1]
    if revision != 1 or not 1 <= count <= 15:
        return
    if sid_length != 8 + 4 * count:
        return
    authority = int.from_bytes(sid[2:8], "big")
    subauths = struct.unpack_from("<" + "I" * count, sid, 8)
    info["sid"] = f"S-{revision}-{authority}" + "".join(
        f"-{value}" for value in subauths
    )


def _valid_sid(value):
    """Convert a Samba dom_sid to a SID string, or None if malformed."""
    if value is None:
        return None
    sid = str(value)
    parts = sid.split("-")
    if len(parts) < 3 or parts[0] != "S" or not all(
        part.isascii() and part.isdecimal() for part in parts[1:]
    ):
        return None
    return sid


def _optional_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _lsa_text(value):
    """Convert a Samba lsa_String or a plain string, never raw bytes."""
    if isinstance(value, str):
        result = value
    else:
        result = getattr(value, "string", None)
    return result if isinstance(result, str) and result else None


def _utf16_name(value):
    """Handle the PAC_LOGON_NAME UTF-16 field on different Samba versions."""
    text = _lsa_text(value)
    if text is not None:
        return text.rstrip("\x00") or None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, (list, tuple)) and len(value) <= 8192:
        try:
            raw = bytes(value)
        except (TypeError, ValueError):
            return None
    else:
        return None
    if not raw or len(raw) % 2:
        return None
    try:
        return raw.decode("utf-16-le").rstrip("\x00") or None
    except UnicodeDecodeError:
        return None


def _nttime_iso8601(value):
    """Convert Windows FILETIME/NTTIME to ISO 8601 UTC; never/unset -> None."""
    ticks = _optional_int(value)
    if ticks is None or ticks <= 0 or ticks >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=ticks // 10
        )
    except (OverflowError, ValueError):
        return None
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _pac_branch(buffer, branch_name):
    """Access a tagged PAC_INFO union across Samba Python wrapper variants."""
    obj = getattr(buffer, "info", None)
    for _ in range(3):
        if obj is None:
            break
        branch = getattr(obj, branch_name, None)
        if branch is not None:
            return branch
        obj = getattr(obj, "info", None)
    return None


def _pac_payload(buffer, branch_name, marker):
    """Dereference optional *_CTR.info wrappers to reach a PAC structure."""
    branch = _pac_branch(buffer, branch_name)
    candidates = [branch, getattr(branch, "info", None)]
    # Older/alternative Samba wrappers can expose the decoded value directly.
    outer = getattr(buffer, "info", None)
    candidates.extend([outer, getattr(outer, "info", None)])
    for obj in candidates:
        if obj is not None and hasattr(obj, marker):
            return obj
    return None


def _enabled_group(entry):
    flags = _optional_int(getattr(entry, "attributes", None))
    return flags is not None and bool(flags & _SE_GROUP_ENABLED) and not bool(
        flags & _SE_GROUP_USE_FOR_DENY_ONLY
    )


def _sid_list_from_rids(domain_sid, entries):
    """Resolve enabled RID+domain SID membership without network requests."""
    results = []
    seen = set()
    if not domain_sid or entries is None:
        return results
    for entry in islice(entries, _MAX_PAC_ENTRIES):
        rid = _optional_int(getattr(entry, "rid", None))
        if _enabled_group(entry) and rid is not None and 0 < rid <= 0xFFFFFFFF:
            sid = f"{domain_sid}-{rid}"
            if sid not in seen:
                seen.add(sid)
                results.append(sid)
    return results


def _sid_list_from_extras(entries):
    results = []
    seen = set()
    for entry in islice((entries or []), _MAX_PAC_ENTRIES):
        if _enabled_group(entry):
            sid = _valid_sid(getattr(entry, "sid", None))
            if sid is not None and sid not in seen:
                seen.add(sid)
                results.append(sid)
    return results


def _unique_sids(*sid_sets):
    combined = []
    seen = set()
    for sids in sid_sets:
        for sid in sids:
            if sid and sid not in seen:
                seen.add(sid)
                combined.append(sid)
                if len(combined) >= _MAX_PAC_ENTRIES:
                    return combined
    return combined


def _populate_logon_metadata(base, domain_sid, extra_sids, info):
    """Read safe fields from netr_SamBaseInfo, never session keys/hashes."""
    info["rid"] = _optional_int(getattr(base, "rid", None))
    info["domain_sid"] = domain_sid
    info["domain_name"] = _lsa_text(getattr(base, "logon_domain", None))
    info["logon_server"] = _lsa_text(getattr(base, "logon_server", None))
    info["primary_group_rid"] = _optional_int(getattr(base, "primary_gid", None))
    info["account_flags"] = _optional_int(getattr(base, "acct_flags", None))
    info["user_flags"] = _optional_int(getattr(base, "user_flags", None))
    info["sub_auth_status"] = _optional_int(getattr(base, "sub_auth_status", None))
    info["last_logon"] = _nttime_iso8601(getattr(base, "logon_time", None))
    info["last_successful_logon"] = _nttime_iso8601(
        getattr(base, "last_successful_logon", None)
    )
    info["last_failed_logon"] = _nttime_iso8601(
        getattr(base, "last_failed_logon", None)
    )
    info["logoff_time"] = _nttime_iso8601(getattr(base, "logoff_time", None))
    info["kickoff_time"] = _nttime_iso8601(getattr(base, "kickoff_time", None))
    info["password_last_set"] = _nttime_iso8601(
        getattr(base, "last_password_change", None)
    )
    info["password_can_change"] = _nttime_iso8601(
        getattr(base, "allow_password_change", None)
    )
    info["password_must_change"] = _nttime_iso8601(
        getattr(base, "force_password_change", None)
    )
    info["logon_count"] = _optional_int(getattr(base, "logon_count", None))
    info["bad_password_count"] = _optional_int(
        getattr(base, "bad_password_count", None)
    )
    info["failed_logon_count"] = _optional_int(
        getattr(base, "failed_logon_count", None)
    )
    info["full_name"] = _lsa_text(getattr(base, "full_name", None))
    info["home_directory"] = _lsa_text(getattr(base, "home_directory", None))
    info["home_drive"] = _lsa_text(getattr(base, "home_drive", None))
    info["logon_script"] = _lsa_text(getattr(base, "logon_script", None))
    info["profile_path"] = _lsa_text(getattr(base, "profile_path", None))
    info["extra_sids"] = extra_sids


def _populate_logon_buffer(buffer, info):
    logon = _pac_payload(buffer, "logon_info", "info3")
    if logon is None:
        return
    info3 = getattr(logon, "info3", None)
    base = getattr(info3, "base", None)
    if base is None:
        return

    domain_sid = _valid_sid(getattr(base, "domain_sid", None))
    rid = _optional_int(getattr(base, "rid", None))
    if info["sid"] is None and domain_sid and rid is not None and rid > 0:
        info["sid"] = f"{domain_sid}-{rid}"
    if info["sam_name"] is None:
        info["sam_name"] = _lsa_text(getattr(base, "account_name", None))

    ordinary = _sid_list_from_rids(
        domain_sid, getattr(getattr(base, "groups", None), "rids", None)
    )
    extras = _sid_list_from_extras(getattr(info3, "sids", None))
    primary_rid = _optional_int(getattr(base, "primary_gid", None))
    primary_sid = (
        f"{domain_sid}-{primary_rid}"
        if domain_sid and primary_rid is not None and 0 < primary_rid <= 0xFFFFFFFF
        else None
    )

    resource_sids = []
    resource = getattr(logon, "resource_groups", None)
    if resource is not None:
        resource_domain_sid = _valid_sid(getattr(resource, "domain_sid", None))
        resource_sids = _sid_list_from_rids(
            resource_domain_sid, getattr(getattr(resource, "groups", None), "rids", None)
        )

    info["groups"] = _unique_sids(
        [primary_sid] if primary_sid else [], ordinary, extras, resource_sids
    )
    info["resource_groups"] = resource_sids
    info["group_count"] = len(info["groups"])
    _populate_logon_metadata(base, domain_sid, extras, info)


def _populate_device_buffer(buffer, info):
    device = _pac_payload(buffer, "device_info", "rid")
    if device is None:
        return
    domain_sid = _valid_sid(getattr(device, "domain_sid", None))
    rid = _optional_int(getattr(device, "rid", None))
    primary_rid = _optional_int(getattr(device, "primary_gid", None))
    primary_sid = (
        f"{domain_sid}-{primary_rid}"
        if domain_sid and primary_rid is not None and 0 < primary_rid <= 0xFFFFFFFF
        else None
    )
    extras = _sid_list_from_extras(getattr(device, "sids", None))
    regular = _sid_list_from_rids(
        domain_sid, getattr(getattr(device, "groups", None), "rids", None)
    )
    resource_groups = []
    for group in islice((getattr(device, "domain_groups", None) or []), _MAX_PAC_ENTRIES):
        domain = _valid_sid(getattr(group, "domain_sid", None))
        memberships = getattr(getattr(group, "groups", None), "rids", None)
        resource_groups.extend(_sid_list_from_rids(domain, memberships))
        if len(resource_groups) >= _MAX_PAC_ENTRIES:
            break
    device_sid = (
        f"{domain_sid}-{rid}"
        if domain_sid and rid is not None and 0 < rid <= 0xFFFFFFFF
        else None
    )
    info["device_info"] = {
        "sid": device_sid,
        "rid": rid,
        "domain_sid": domain_sid,
        "primary_group_rid": primary_rid,
        "extra_sids": extras,
        "resource_groups": _unique_sids(resource_groups),
        "groups": _unique_sids(
            [primary_sid] if primary_sid else [], regular, extras, resource_groups
        ),
    }


def _populate_client_buffer(buffer, info):
    client = _pac_payload(buffer, "logon_name", "logon_time")
    if client is None:
        return
    info["client_name"] = _utf16_name(getattr(client, "account_name", None))
    info["client_auth_time"] = _nttime_iso8601(
        getattr(client, "logon_time", None)
    )


def _populate_attributes_buffer(buffer, info):
    attr = _pac_payload(buffer, "attributes_info", "flags")
    if attr is None:
        return
    flags = _optional_int(getattr(attr, "flags", None))
    info["pac_attributes_flags"] = flags
    if flags is not None:
        info["pac_requested"] = bool(flags & 0x01)
        info["pac_given_implicitly"] = bool(flags & 0x02)


def _populate_requestor_buffer(buffer, info):
    requestor = _pac_payload(buffer, "requester_sid", "sid")
    if requestor is not None:
        info["requestor_sid"] = _valid_sid(getattr(requestor, "sid", None))


def _populate_delegation_buffer(buffer, info):
    delegation = _pac_payload(buffer, "constrained_delegation", "proxy_target")
    if delegation is None:
        return
    info["delegation_proxy_target"] = _lsa_text(
        getattr(delegation, "proxy_target", None)
    )
    services = getattr(delegation, "transited_services", None)
    info["delegation_transited_services"] = [
        name for service in islice((services or []), _MAX_PAC_ENTRIES)
        if (name := _lsa_text(service)) is not None
    ]


def _pac_blob_bytes(value):
    """Read a Samba DATA_BLOB_REM without copying unrelated PAC buffers."""
    for _ in range(4):
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            return raw if len(raw) <= _MAX_PAC_BYTES else None
        if isinstance(value, (list, tuple)):
            try:
                raw = bytes(value)
            except (TypeError, ValueError):
                return None
            return raw if len(raw) <= _MAX_PAC_BYTES else None
        if value is None:
            return None
        value = next(
            (getattr(value, field) for field in ("remaining", "data", "blob")
             if getattr(value, field, None) is not None),
            None,
        )
    return None


def _populate_claims_buffer(buffer, info, branch, key):
    """Decode AD claims if Samba's native NDR decompressor is available.

    Native Samba NDR supports the Microsoft compression types. Unknown claims
    or unsupported Samba versions leave this optional field as None.
    """
    if samba_claims is None or ndr_unpack is None:
        return
    payload = _pac_branch(buffer, branch)
    raw = _pac_blob_bytes(payload)
    if not raw:
        return
    decoded = ndr_unpack(samba_claims.CLAIMS_SET_METADATA_NDR, raw)
    metadata = getattr(getattr(decoded, "claims", None), "metadata", None)
    claim_set_ndr = getattr(metadata, "claims_set", None)
    claim_set = getattr(getattr(claim_set_ndr, "claims", None), "claims", None)
    if claim_set is None:
        return

    type_members = {
        1: ("int64", "claim_int64"),
        2: ("uint64", "claim_uint64"),
        3: ("string", "claim_string"),
        6: ("boolean", "claim_boolean"),
    }
    result = []
    for arr in islice((getattr(claim_set, "claims_arrays", None) or []), 128):
        source_id = _optional_int(getattr(arr, "claims_source_type", None))
        source = {1: "ad", 2: "certificate"}.get(source_id, source_id)
        for entry in islice((getattr(arr, "claim_entries", None) or []), 2048):
            if len(result) >= 2048:
                break
            claim_type = _optional_int(getattr(entry, "type", None))
            mapped = type_members.get(claim_type)
            if mapped is None:
                continue
            type_label, union_member = mapped
            union = getattr(entry, "values", None)
            value_set = getattr(union, union_member, None)
            values = getattr(value_set, "values", None)
            decoded_values = []
            for value in islice((values or []), 1024):
                if type_label == "string":
                    text = _lsa_text(value)
                    if text is not None:
                        decoded_values.append(text)
                elif type_label == "boolean":
                    number = _optional_int(value)
                    if number is not None:
                        decoded_values.append(bool(number))
                else:
                    number = _optional_int(value)
                    if number is not None:
                        decoded_values.append(number)
            claim_id = _lsa_text(getattr(entry, "id", None))
            if claim_id is not None:
                result.append({
                    "id": claim_id,
                    "source": source,
                    "type": type_label,
                    "values": decoded_values,
                })
        if len(result) >= 2048:
            break
    info[key] = result


def _populate_pac_buffers(name, info):
    """Decode optional PAC buffers once with Samba. No LDAP/Winbind I/O.

    A malformed or Samba-version-specific optional buffer never invalidates
    a previously authenticated Kerberos request or other decoded fields.
    """
    if krb5pac is None or ndr_unpack is None:
        return
    raw = _authenticated_pac_attribute(name, "urn:mspac:")
    if not raw:
        return

    try:
        pac = ndr_unpack(krb5pac.PAC_DATA, raw)
        buffers = list(getattr(pac, "buffers", []) or [])
        if len(buffers) > _MAX_PAC_ENTRIES:
            return
    except Exception as exc:
        log_event(
            logger, logging.DEBUG, "pac_decode_failed",
            "PAC decoding unavailable", reason="ndr_decode_failed",
            error_type=type(exc).__name__,
        )
        return

    info["pac_size"] = len(raw)
    info["pac_version"] = _optional_int(getattr(pac, "version", None))
    types = [_optional_int(getattr(buffer, "type", None)) for buffer in buffers]
    info["pac_buffer_type_ids"] = [t for t in types if t is not None]
    info["pac_buffer_types"] = [
        _PAC_BUFFER_NAMES.get(t, f"unknown_{t}")
        for t in info["pac_buffer_type_ids"]
    ]
    present = set(info["pac_buffer_type_ids"])
    info["client_claims_present"] = 13 in present
    info["device_claims_present"] = 15 in present
    info["credential_info_present"] = 2 in present
    info["pac_signature_types"] = {}

    processors = {
        1: _populate_logon_buffer,
        10: _populate_client_buffer,
        11: _populate_delegation_buffer,
        14: _populate_device_buffer,
        17: _populate_attributes_buffer,
        18: _populate_requestor_buffer,
        13: lambda buffer, info: _populate_claims_buffer(
            buffer, info, "client_claims_info", "client_claims"
        ),
        15: lambda buffer, info: _populate_claims_buffer(
            buffer, info, "device_claims_info", "device_claims"
        ),
    }
    signature_members = {
        6: ("server", "srv_cksum"),
        7: ("kdc", "kdc_cksum"),
        16: ("ticket", "ticket_checksum"),
        19: ("full", "full_checksum"),
    }
    for buffer, buffer_type in zip(buffers, types):
        try:
            processor = processors.get(buffer_type)
            if processor is not None:
                processor(buffer, info)
            elif buffer_type in signature_members:
                label, branch = signature_members[buffer_type]
                signature = _pac_payload(buffer, branch, "type")
                if signature is not None:
                    info["pac_signature_types"][label] = _optional_int(
                        getattr(signature, "type", None)
                    )
            # Credential blobs, PAC signatures and raw claim blobs are never
            # copied into Flask g. Only decoded claims and safe metadata are.
        except Exception as exc:
            log_event(
                logger, logging.DEBUG, "pac_buffer_decode_failed",
                "Optional PAC buffer unavailable",
                reason="buffer_decode_failed", pac_buffer_type=buffer_type,
                error_type=type(exc).__name__,
            )


def _pac_info_from_name(initiator_name):
    """Extract available authenticated PAC metadata, with zero LDAP calls."""
    info = _empty_pac_info()
    _populate_upn_dns_info(initiator_name, info)
    _populate_pac_buffers(initiator_name, info)
    return info


def kerberos_authenticate(auth_header):
    if not auth_header or not auth_header.startswith("Negotiate "):
        return None, None
    token_b64 = auth_header[len("Negotiate "):].strip()

    if not token_b64:
        return None, None

    try:
        # HTTP Negotiate transports GSSAPI tokens encoded in Base64.
        token = base64.b64decode(token_b64, validate=True)

        conf = current_app.confadcs

        # Prefer a fixed Kerberos hostname from the configuration.
        # Fall back to the HTTP Host header for compatibility.
        hostname = conf.get("kerberos_hostname")
        if not hostname:
            hostname = request.host.split(":", 1)[0]

        hostname = hostname.lower()

        # hostbased_service "HTTP@hostname" maps to:
        # HTTP/hostname@REALM
        service_name = gssapi.Name(
            f"HTTP@{hostname}",
            name_type=gssapi.NameType.hostbased_service,
        )

        server_creds = gssapi.Credentials(
            name=service_name,
            usage="accept",
        )
        context = gssapi.SecurityContext(
            creds=server_creds,
            usage="accept",
        )

        response_token_raw = context.step(token)

        response_token = None
        if response_token_raw:
            response_token = base64.b64encode(
                response_token_raw
            ).decode("ascii")
        # SPNEGO/GSSAPI can require more than one exchange.
        # Return the server token even if the context is not complete yet.
        if not context.complete:
            return None, response_token

        initiator_name = context.initiator_name

        if initiator_name is None:
            return None, response_token

        user = str(initiator_name)
        # Read the authenticated PAC after Kerberos context completion.
        g.pac_info = _pac_info_from_name(initiator_name)
        # Keep the previous g.sid interface for compatibility.
        g.sid = g.pac_info["sid"]

        return user, response_token
    except (
        gssapi.exceptions.GSSError,
        binascii.Error,
        UnicodeEncodeError,
        ValueError,
    ) as exc:
        log_event(
            logger, logging.DEBUG, "kerberos_auth_error",
            "Kerberos authentication error", outcome="failure",
            reason="kerberos_error", host=request.host, error_type=type(exc).__name__,
        )
        return None, None
