"""Specialized NDR32 decoders for PAC_LOGON_INFO and PAC_DEVICE_INFO."""

from .binary import PACDecodeError, filetime_to_iso, MAX_PAC_ENTRIES
from .ndr import ndr_serialized_pointer

_ENABLED = 0x00000004
_DENY_ONLY = 0x00000010


def _include(flags: int) -> bool:
    return bool(flags & _ENABLED) and not bool(flags & _DENY_ONLY)


def _valid_rid(rid: int) -> bool:
    return 0 < rid <= 0xFFFFFFFF


def _rid_sids(domain_sid: str | None, memberships: list[tuple[int, int]]) -> list[str]:
    if not domain_sid:
        return []
    return [f"{domain_sid}-{rid}" for rid, flags in memberships
            if _valid_rid(rid) and _include(flags)]


def _extra_sids(entries: list[tuple[str | None, int]]) -> list[str]:
    return [sid for sid, flags in entries if sid and _include(flags)]


def _dedupe(*sublists: list[str]) -> list[str]:
    unique = []
    seen = set()
    for sublist in sublists:
        for value in sublist:
            if value not in seen:
                seen.add(value)
                unique.append(value)
                if len(unique) > MAX_PAC_ENTRIES:
                    raise PACDecodeError("too many combined authorization groups")
    return unique


def decode_logon_info(data: bytes) -> dict:
    """Decode KERB_VALIDATION_INFO, returning *no* session keys or secrets.

    Results must only be used for authorization if the enclosing GSSAPI PAC
    attribute was authenticated and this function returned successfully.
    """
    r = ndr_serialized_pointer(data)
    dates = [r.filetime() for _ in range(6)]
    # Deferred Unicode referents: first read the fixed inline headers.
    first_names = [r.unicode_header() for _ in range(6)]
    logon_count, bad_password_count = r.u16(), r.u16()
    rid, primary_gid, group_count, group_ref, user_flags = (
        r.u32(), r.u32(), r.u32(), r.u32(), r.u32()
    )
    r.bytes(16)  # UserSessionKey: intentionally ignored.
    server_name_hdr, domain_name_hdr = r.unicode_header(), r.unicode_header()
    domain_sid_ref = r.u32()
    r.bytes(8)  # LMKey / Reserved1: never expose.
    account_flags = r.u32()
    reserved3 = [r.u32() for _ in range(7)]
    sid_count, extra_ref, resource_domain_ref, resource_count, resource_ref = (
        r.u32(), r.u32(), r.u32(), r.u32(), r.u32()
    )

    # Process deferred referents in NDR declaration order.
    names = [r.unicode_value(h) for h in first_names]
    memberships = r.group_array(group_ref, group_count)
    server_name = r.unicode_value(server_name_hdr)
    domain_name = r.unicode_value(domain_name_hdr)
    domain_sid = r.sid_pointer(domain_sid_ref)
    extra_entries = r.sid_and_attributes_array(extra_ref, sid_count)
    resource_domain_sid = r.sid_pointer(resource_domain_ref)
    resource_entries = r.group_array(resource_ref, resource_count)

    if memberships and not domain_sid:
        raise PACDecodeError("group RIDs without account domain SID")
    if resource_entries and not resource_domain_sid:
        raise PACDecodeError("resource RIDs without resource domain SID")
    if len(r.data) - r.offset > 7:
        raise PACDecodeError("unconsumed LOGON_INFO payload")
    normal_groups = _rid_sids(domain_sid, memberships)
    account_extra = extra_entries[0][0] if rid == 0 and extra_entries else None
    group_extras = extra_entries[1:] if rid == 0 else extra_entries
    extra_sids = _dedupe(_extra_sids(group_extras))
    resource_groups = _dedupe(_rid_sids(resource_domain_sid, resource_entries))
    primary_sid = f"{domain_sid}-{primary_gid}" if domain_sid and _valid_rid(primary_gid) else None
    user_sid = f"{domain_sid}-{rid}" if domain_sid and _valid_rid(rid) else None
    if rid == 0 and extra_entries:
        # MS-PAC 2.5: the first ExtraSids SID identifies a zero-RID account.
        user_sid = account_extra
    groups = _dedupe(
        [primary_sid] if primary_sid else [], normal_groups, extra_sids, resource_groups
    )
    denied = {f"{domain_sid}-{item}" for item, flags in memberships
              if domain_sid and flags & _DENY_ONLY}
    denied.update(sid for sid, flags in group_extras if sid and flags & _DENY_ONLY)
    denied.update(f"{resource_domain_sid}-{item}" for item, flags in resource_entries
                  if resource_domain_sid and flags & _DENY_ONLY)
    groups = [sid for sid in groups if sid not in denied]
    extra_sids = [sid for sid in extra_sids if sid not in denied]
    resource_groups = [sid for sid in resource_groups if sid not in denied]
    results = {
        "sid": user_sid,
        "sam_name": names[0],
        "rid": rid,
        "domain_sid": domain_sid,
        "domain_name": domain_name,
        "logon_server": server_name,
        "full_name": names[1],
        "logon_script": names[2],
        "profile_path": names[3],
        "home_directory": names[4],
        "home_drive": names[5],
        "groups": groups,
        "primary_group_rid": primary_gid,
        "extra_sids": extra_sids,
        "resource_groups": resource_groups,
        "group_count": len(groups),
        "account_flags": account_flags,
        "user_flags": user_flags,
        "sub_auth_status": reserved3[0],
        "last_logon": filetime_to_iso(dates[0]),
        "logoff_time": filetime_to_iso(dates[1]),
        "kickoff_time": filetime_to_iso(dates[2]),
        "password_last_set": filetime_to_iso(dates[3]),
        "password_can_change": filetime_to_iso(dates[4]),
        "password_must_change": filetime_to_iso(dates[5]),
        "last_successful_logon": filetime_to_iso(reserved3[1] | (reserved3[2] << 32)),
        "last_failed_logon": filetime_to_iso(reserved3[3] | (reserved3[4] << 32)),
        "failed_logon_count": reserved3[5],
        "logon_count": logon_count,
        "bad_password_count": bad_password_count,
    }
    return results


def decode_device_info(data: bytes) -> dict:
    """Decode the PAC_DEVICE_INFO account, extra SID and domain-group lists."""
    r = ndr_serialized_pointer(data)
    rid, primary_gid, domain_sid_ref, group_count, group_ref = (
        r.u32(), r.u32(), r.u32(), r.u32(), r.u32()
    )
    sid_count, sid_ref, domain_count, domains_ref = (
        r.u32(), r.u32(), r.u32(), r.u32()
    )
    domain_sid = r.sid_pointer(domain_sid_ref)
    normal = r.group_array(group_ref, group_count)
    extras = r.sid_and_attributes_array(sid_ref, sid_count)
    domains = r.domain_groups_array(domains_ref, domain_count)
    if normal and not domain_sid:
        raise PACDecodeError("device group RIDs without domain SID")
    if any(groups and not sid for sid, groups in domains):
        raise PACDecodeError("device resource RIDs without domain SID")
    if len(r.data) - r.offset > 7:
        raise PACDecodeError("unconsumed DEVICE_INFO payload")
    group_sids = _rid_sids(domain_sid, normal)
    extra_sids = _dedupe(_extra_sids(extras))
    resource_sids = _dedupe(*[_rid_sids(sid, groups) for sid, groups in domains])
    primary_sid = f"{domain_sid}-{primary_gid}" if domain_sid and _valid_rid(primary_gid) else None
    device_sid = f"{domain_sid}-{rid}" if domain_sid and _valid_rid(rid) else None
    return {
        "sid": device_sid,
        "rid": rid,
        "domain_sid": domain_sid,
        "primary_group_rid": primary_gid,
        "extra_sids": extra_sids,
        "resource_groups": resource_sids,
        "groups": _dedupe(
            [primary_sid] if primary_sid else [], group_sids, extra_sids, resource_sids
        ),
    }


def decode_delegation_info(data: bytes) -> dict:
    """Decode the S4U_DELEGATION_INFO target and transited service names."""
    r = ndr_serialized_pointer(data)
    proxy_header = r.unicode_header()
    count, services_ref = r.u32(), r.u32()
    if count > MAX_PAC_ENTRIES:
        raise PACDecodeError("excessive transited services")
    proxy = r.unicode_value(proxy_header)
    if services_ref:
        maximum = r.u32()
        if maximum != count or count > (len(r.data) - r.offset) // 8:
            raise PACDecodeError("invalid transited services array")
        headers = [r.unicode_header() for _ in range(count)]
        services = [r.unicode_value(header) for header in headers]
    elif count:
        raise PACDecodeError("null transited services pointer with nonzero count")
    else:
        services = []
    return {
        "delegation_proxy_target": proxy,
        "delegation_transited_services": [name for name in services if name],
    }
