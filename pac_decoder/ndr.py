"""Small, strictly bounded NDR32 reader for MS-PAC structures.

This is *not* a generic DCE/RPC unmarshalling implementation. Only the
pointer/array/string forms used by PAC_LOGON_INFO and PAC_DEVICE_INFO are
supported. Incoming lengths are bounded before allocation or iteration.
"""

import struct
from .binary import PACDecodeError, MAX_PAC_ENTRIES, MAX_SID_SUBAUTHS


class NDRReader:
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.offset = 0

    def align(self, n: int) -> None:
        self.offset = (self.offset + n - 1) & ~(n - 1)
        if self.offset > len(self.data):
            raise PACDecodeError("NDR alignment exceeds buffer")

    def bytes(self, size: int, alignment: int = 1) -> bytes:
        self.align(alignment)
        if size < 0 or size > len(self.data) - self.offset:
            raise PACDecodeError("truncated NDR payload")
        result = bytes(self.data[self.offset:self.offset + size])
        self.offset += size
        return result

    def u16(self) -> int:
        return struct.unpack("<H", self.bytes(2, 2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.bytes(4, 4))[0]

    def filetime(self) -> int:
        # FILETIME is a pair of 32-bit members: use 4-byte NDR alignment.
        low = self.u32()
        return low | (self.u32() << 32)

    def unicode_header(self) -> tuple[int, int, int]:
        length, max_length, referent = self.u16(), self.u16(), self.u32()
        if length & 1 or max_length & 1 or length > max_length:
            raise PACDecodeError("invalid RPC_UNICODE_STRING length")
        if length and not referent:
            raise PACDecodeError("nonempty null RPC_UNICODE_STRING")
        return length, max_length, referent

    def unicode_value(self, header: tuple[int, int, int]) -> str | None:
        length, max_length, referent = header
        if not referent:
            return None
        maximum, offset, actual = self.u32(), self.u32(), self.u32()
        if offset > maximum or actual > maximum - offset:
            raise PACDecodeError("invalid NDR string conformance")
        if maximum > len(self.data) // 2 or actual > len(self.data) // 2:
            raise PACDecodeError("oversized NDR string")
        if length > actual * 2 or length > max_length:
            raise PACDecodeError("NDR string length mismatch")
        raw = self.bytes(actual * 2, 2)
        try:
            return raw[:length].decode("utf-16-le").rstrip("\x00") or None
        except UnicodeDecodeError as exc:
            raise PACDecodeError("invalid NDR Unicode string") from exc

    def group_array(self, referent: int, count: int) -> list[tuple[int, int]]:
        if count > MAX_PAC_ENTRIES:
            raise PACDecodeError("excessive PAC group count")
        if not referent:
            if count:
                raise PACDecodeError("null PAC group pointer with nonzero count")
            return []
        n = self.u32()  # NDR conformant array max_count
        if n != count or count > (len(self.data) - self.offset) // 8:
            raise PACDecodeError("invalid PAC group array count")
        return [(self.u32(), self.u32()) for _ in range(count)]

    def sid(self) -> str:
        # RPC_SID contains a conformant array of subauthorities.
        max_count = self.u32()
        revision, count = self.bytes(2)
        authority = int.from_bytes(self.bytes(6), "big")
        if revision != 1 or not 1 <= count <= MAX_SID_SUBAUTHS or max_count != count:
            raise PACDecodeError("invalid NDR RPC_SID")
        parts = [self.u32() for _ in range(count)]
        return f"S-{revision}-{authority}" + "".join(f"-{x}" for x in parts)

    def sid_pointer(self, referent: int) -> str | None:
        return self.sid() if referent else None

    def sid_and_attributes_array(self, referent: int, count: int) -> list[tuple[str | None, int]]:
        if count > MAX_PAC_ENTRIES:
            raise PACDecodeError("excessive extra SID count")
        if not referent:
            if count:
                raise PACDecodeError("null ExtraSids pointer with nonzero count")
            return []
        maximum = self.u32()
        if maximum != count or count > (len(self.data) - self.offset) // 8:
            raise PACDecodeError("invalid ExtraSids array count")
        # Embedded SID pointers are deferred until all structure members are read.
        entries = [(self.u32(), self.u32()) for _ in range(count)]
        if any(not ptr for ptr, _ in entries):
            raise PACDecodeError("null SID in ExtraSids array")
        return [(self.sid_pointer(ptr), flags) for ptr, flags in entries]

    def domain_groups_array(
        self, referent: int, count: int
    ) -> list[tuple[str | None, list[tuple[int, int]]]]:
        if count > MAX_PAC_ENTRIES:
            raise PACDecodeError("excessive domain group count")
        if not referent:
            if count:
                raise PACDecodeError("null domain group pointer with nonzero count")
            return []
        maximum = self.u32()
        if maximum != count or count > (len(self.data) - self.offset) // 12:
            raise PACDecodeError("invalid domain group array count")
        entries = [(self.u32(), self.u32(), self.u32()) for _ in range(count)]
        # Nested referents are serialized after the conformant array body.
        return [
            (self.sid_pointer(sid_ref), self.group_array(group_ref, n))
            for sid_ref, n, group_ref in entries
        ]


def ndr_serialized_pointer(data: bytes) -> NDRReader:
    """Extract a Microsoft NDR32 type-serialization envelope and root pointer."""
    if len(data) < 20 or data[:4] != b"\x01\x10\x08\x00":
        raise PACDecodeError("unsupported NDR type-serialization header")
    object_length = struct.unpack_from("<I", data, 8)[0]
    if object_length < 4 or object_length > len(data) - 16:
        raise PACDecodeError("invalid NDR object length")
    reader = NDRReader(data[16:16 + object_length])
    if not reader.u32():
        raise PACDecodeError("null NDR root pointer")
    return reader
