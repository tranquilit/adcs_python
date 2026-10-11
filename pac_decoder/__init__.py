"""Pure-Python, dependency-free Microsoft Privilege Attribute Certificate decoding.

Security contract:
* The caller MUST obtain ``raw_pac`` from an authenticated, complete GSSAPI
  initiator-name attribute **after** the context is established.
* This module does NOT validate Kerberos tickets or PAC signatures.
* No authorization group is emitted from a failed / partial LOGON_INFO decode.
* Claims are decoded atomically with strictly bounded decompression.
"""

from .binary import (
    PACDecodeError, decode_attributes_info, decode_client_info,
    decode_sid, decode_signature_type, decode_upn_dns_info, parse_pac,
)
from .claims import decode_claims_info
from .logon import decode_device_info, decode_logon_info, decode_delegation_info

BUFFER_NAMES = {
    1: "logon_info", 2: "credential_info", 6: "server_checksum",
    7: "kdc_checksum", 10: "client_info", 11: "constrained_delegation",
    12: "upn_dns_info", 13: "client_claims_info", 14: "device_info",
    15: "device_claims_info", 16: "ticket_checksum", 17: "attributes_info",
    18: "requestor_sid", 19: "full_checksum",
}

SIG_NAMES = {6: "server", 7: "kdc", 16: "ticket", 19: "full"}

# Keep these keys/semantics compatible with kerberos_auth._empty_pac_info().
_EMPTY = (
    "sid", "sam_name", "upn", "dns_domain", "upn_dns_flags", "upn_constructed",
    "rid", "domain_sid", "domain_name", "logon_server", "full_name",
    "groups", "primary_group_rid", "extra_sids", "resource_groups",
    "group_count", "account_flags", "user_flags", "sub_auth_status",
    "last_logon", "last_successful_logon", "last_failed_logon",
    "logoff_time", "kickoff_time", "password_last_set",
    "password_can_change", "password_must_change", "logon_count",
    "bad_password_count", "failed_logon_count", "home_directory",
    "home_drive", "logon_script", "profile_path", "client_name",
    "client_auth_time", "requestor_sid", "pac_requested",
    "pac_given_implicitly", "pac_attributes_flags", "delegation_proxy_target",
    "delegation_transited_services", "device_info", "client_claims_present",
    "device_claims_present", "client_claims", "device_claims",
    "credential_info_present", "pac_signature_types", "pac_version",
    "pac_size", "pac_buffer_types", "pac_buffer_type_ids",
)


def empty_pac_info() -> dict:
    return dict.fromkeys(_EMPTY)


def decode_pac(raw_pac: bytes, upn_dns_attribute: bytes | None = None,
               *, errors: list[int] | None = None) -> dict:
    """Decode a previously authenticated raw MS-PAC into the existing field schema.

    Per-buffer decode errors are isolated, and the LOGON_INFO result is
    committed only when the entire NDR structure was decoded. A conflicting
    SID between UPN_DNS_INFO and LOGON_INFO drops all logon-derived fields.
    Duplicate PAC buffer types are ignored after the first occurrence.

    ``upn_dns_attribute`` is optional and must independently be an authenticated
    GSSAPI attribute if supplied; otherwise pass ``None``.
    """
    pac = parse_pac(raw_pac)
    info = empty_pac_info()
    info["pac_size"] = pac.size
    info["pac_version"] = pac.version
    info["pac_buffer_type_ids"] = [buf.type_id for buf in pac.buffers]
    info["pac_buffer_types"] = [
        BUFFER_NAMES.get(buf.type_id, f"unknown_{buf.type_id}")
        for buf in pac.buffers
    ]
    present = set(info["pac_buffer_type_ids"])
    info["client_claims_present"] = 13 in present
    info["device_claims_present"] = 15 in present
    info["credential_info_present"] = 2 in present
    info["pac_signature_types"] = {}

    # UPN from a separate authenticated GSSAPI attribute takes precedence.
    # The inline PAC copy can be used if GSSAPI only exposes urn:mspac:.
    inline = next((b.data for b in pac.buffers if b.type_id == 12), None)
    for upn_blob in ((upn_dns_attribute,) if upn_dns_attribute is not None
                     else ((inline,) if inline is not None else ())):
        try:
            info.update(decode_upn_dns_info(upn_blob))
        except PACDecodeError:
            pass

    seen = set()
    for buf in pac.buffers:
        t = buf.type_id
        if t in seen:
            continue
        seen.add(t)
        try:
            if t == 1:
                logon = decode_logon_info(buf.data)
                # Do not combine group lists with a conflicting account SID.
                if not logon["sid"] or (info["sid"] and info["sid"] != logon["sid"]):
                    if errors is not None:
                        errors.append(1)
                    continue
                prior_upn_sam = info["sam_name"]
                info.update(logon)
                if prior_upn_sam:
                    info["sam_name"] = prior_upn_sam
            elif t == 10:
                info.update(decode_client_info(buf.data))
            elif t == 11:
                info.update(decode_delegation_info(buf.data))
            elif t == 14:
                info["device_info"] = decode_device_info(buf.data)
            elif t == 17:
                info.update(decode_attributes_info(buf.data))
            elif t == 18:
                info["requestor_sid"] = decode_sid(buf.data)
            elif t in SIG_NAMES:
                info["pac_signature_types"][SIG_NAMES[t]] = decode_signature_type(buf.data)
            elif t in (13, 15):
                key = "client_claims" if t == 13 else "device_claims"
                info[key] = decode_claims_info(buf.data)
            # Credentials (2) intentionally remain opaque. Never expose secrets.
        except PACDecodeError:
            if errors is not None:
                errors.append(t)
            # A broken optional buffer doesn't invalidate GSSAPI authentication.
            # Untrusted partial group lists are never committed.
            continue
    return info


__all__ = [
    "PACDecodeError", "parse_pac", "decode_sid", "decode_upn_dns_info",
    "decode_logon_info", "decode_device_info", "decode_delegation_info",
    "decode_pac", "empty_pac_info", "decode_claims_info",
]
