"""Dependency-free binary primitives for Microsoft MS-PAC.

No Kerberos validation is performed here. Only pass PAC data obtained from an
*authenticated and complete* GSSAPI name attribute.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import struct

MAX_PAC_BYTES = 4 * 1024 * 1024
MAX_PAC_ENTRIES = 16_384
MAX_SID_SUBAUTHS = 15


class PACDecodeError(ValueError):
    """Malformed, truncated or unsupported PAC encoding."""


@dataclass(frozen=True)
class PACBuffer:
    type_id: int
    data: bytes


@dataclass(frozen=True)
class PAC:
    version: int
    size: int
    buffers: tuple[PACBuffer, ...]


def parse_pac(raw: bytes) -> PAC:
    """Validate and extract an MS-PAC PACTYPE (not an ASN.1 wrapper)."""
    if not isinstance(raw, bytes) or not 8 <= len(raw) <= MAX_PAC_BYTES:
        raise PACDecodeError("invalid PAC length or input type")
    n, version = struct.unpack_from("<II", raw)
    if n > MAX_PAC_ENTRIES or n > (len(raw) - 8) // 16:
        raise PACDecodeError("invalid PAC directory size")
    if version != 0:
        raise PACDecodeError("unsupported PAC version")
    directory_end = 8 + 16 * n
    entries = []
    ranges = []
    for i in range(n):
        type_id, size, offset = struct.unpack_from("<IIQ", raw, 8 + 16 * i)
        if offset % 8 or offset < directory_end or offset > len(raw):
            raise PACDecodeError("invalid PAC buffer offset")
        # Avoid arithmetic overflow in languages other than Python, and
        # ensure that slicing cannot silently truncate a buffer.
        if size > len(raw) - offset:
            raise PACDecodeError("PAC buffer exceeds packet")
        if size:
            ranges.append((offset, offset + size))
        entries.append((type_id, offset, size))
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if previous[1] > current[0]:
            raise PACDecodeError("overlapping PAC buffers")
    # Validate every span BEFORE copying. Otherwise many overlapping large
    # spans could allocate gigabytes before the overlap check rejected them.
    buffers = tuple(PACBuffer(t, raw[o:o + n]) for t, o, n in entries)
    return PAC(version=version, size=len(raw), buffers=buffers)


def decode_sid(raw: bytes) -> str:
    """Decode an exact self-relative binary SID, rejecting malformed SIDs."""
    if len(raw) < 12:
        raise PACDecodeError("SID too short")
    revision, count = raw[0], raw[1]
    if revision != 1 or not 1 <= count <= MAX_SID_SUBAUTHS:
        raise PACDecodeError("unsupported SID revision or subauthority count")
    if len(raw) != 8 + count * 4:
        raise PACDecodeError("SID size mismatch")
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack_from("<" + "I" * count, raw, 8)
    return f"S-{revision}-{authority}" + "".join(f"-{n}" for n in subs)


def filetime_to_iso(value: int) -> str | None:
    """Convert Windows FILETIME, including sentinel values used by AD."""
    if not 0 < value < 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        instant = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=value // 10
        )
    except (ValueError, OverflowError):
        return None
    return instant.isoformat(timespec="seconds").replace("+00:00", "Z")


def decode_upn_dns_info(data: bytes) -> dict:
    """UPN_DNS_INFO, including optional SAM and SID (PAC buffer type 12)."""
    if not isinstance(data, bytes) or len(data) < 12:
        raise PACDecodeError("truncated or invalid UPN_DNS_INFO")
    upn_length, upn_offset, dns_length, dns_offset, flags = struct.unpack_from(
        "<HHHHI", data
    )
    extended = bool(flags & 0x2)
    header_size = 20 if extended else 12
    if len(data) < header_size:
        raise PACDecodeError("truncated extended UPN_DNS_INFO")

    def read_text(length: int, offset: int) -> str | None:
        if not length:
            return None
        if length & 1 or offset < header_size or length > len(data) - offset:
            raise PACDecodeError("invalid UPN_DNS_INFO UTF-16 span")
        try:
            return data[offset:offset + length].decode("utf-16-le") or None
        except UnicodeDecodeError as exc:
            raise PACDecodeError("invalid UPN_DNS_INFO UTF-16") from exc

    result = {
        "upn": read_text(upn_length, upn_offset),
        "dns_domain": read_text(dns_length, dns_offset),
        "upn_dns_flags": flags,
        "upn_constructed": bool(flags & 1),
        "sam_name": None,
        "sid": None,
    }
    if extended:
        sam_length, sam_offset, sid_length, sid_offset = struct.unpack_from(
            "<HHHH", data, 12
        )
        result["sam_name"] = read_text(sam_length, sam_offset)
        if sid_length:
            if sid_offset < header_size or sid_length > len(data) - sid_offset:
                raise PACDecodeError("invalid UPN_DNS_INFO SID span")
            result["sid"] = decode_sid(data[sid_offset:sid_offset + sid_length])
    return result


def decode_client_info(data: bytes) -> dict:
    if len(data) < 10:
        raise PACDecodeError("truncated PAC_CLIENT_INFO")
    filetime, length = struct.unpack_from("<QH", data)
    if length & 1 or length > len(data) - 10:
        raise PACDecodeError("invalid client name length")
    try:
        name = data[10:10 + length].decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError as exc:
        raise PACDecodeError("invalid client name UTF-16") from exc
    return {"client_name": name or None, "client_auth_time": filetime_to_iso(filetime)}


def decode_attributes_info(data: bytes) -> dict:
    if len(data) < 8:
        raise PACDecodeError("truncated PAC_ATTRIBUTES_INFO")
    nbits = struct.unpack_from("<I", data)[0]
    # Future bits can be stored, but cap untrusted values and their allocation.
    if nbits > 256:
        raise PACDecodeError("unsupported PAC flag length")
    needed = ((nbits + 31) // 32) * 4
    if needed > len(data) - 4:
        raise PACDecodeError("truncated PAC_ATTRIBUTES_INFO flags")
    flags = int.from_bytes(data[4:4 + needed], "little")
    if nbits:
        flags &= (1 << nbits) - 1
    return {
        "pac_attributes_flags": flags,
        "pac_requested": bool(flags & 1),
        "pac_given_implicitly": bool(flags & 2),
    }


def decode_signature_type(data: bytes) -> int:
    if len(data) < 4:
        raise PACDecodeError("truncated PAC_SIGNATURE_DATA")
    # The documented checksum types are signed Kerberos type identifiers.
    return struct.unpack_from("<i", data)[0]
