"""Bounded MS-XCA decompression using only the Python standard library.

Algorithms: NONE (0), LZNT1 (2), XPRESS/LZ77 (3), XPRESS_HUFF (4).
The caller must provide the expected output size from CLAIMS_SET_METADATA.
See SOURCES.md for Microsoft algorithm descriptions and test-vector sources.
"""
import struct
from .binary import PACDecodeError, MAX_PAC_BYTES

MAX_CLAIMS_BYTES = 4 * 1024 * 1024


class _Input:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.pos:
            raise PACDecodeError("truncated compressed claims")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack('<H', self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack('<I', self.read(4))[0]


def _match(out: bytearray, distance: int, length: int, limit: int,
           window_start: int = 0) -> None:
    if distance < 1 or distance > len(out) - window_start:
        raise PACDecodeError("invalid compression back-reference")
    if length < 3 or length > limit - len(out):
        raise PACDecodeError("decompressed claims exceed expected size")
    # Repeat a bounded period instead of a byte-at-a-time loop. This preserves
    # overlapping LZ references without allocating more than the output limit.
    period = bytes(out[len(out) - distance:])
    if length <= distance:
        out.extend(period[:length])
    else:
        repetitions, remainder = divmod(length, distance)
        out.extend(period * repetitions)
        out.extend(period[:remainder])


def _lznt1(data: bytes, expected: int) -> bytes:
    src, out = _Input(data), bytearray()
    while src.pos < len(data):
        header = src.u16()
        if header == 0:
            if any(data[src.pos:]):
                raise PACDecodeError("nonzero data after LZNT1 terminator")
            break
        if header & 0x7000 != 0x3000:
            raise PACDecodeError("invalid LZNT1 chunk signature")
        chunk = _Input(src.read((header & 0x0FFF) + 1))
        start = len(out)
        limit = min(expected, start + 4096)
        if not header & 0x8000:
            if len(chunk.data) > limit - len(out):
                raise PACDecodeError("oversized uncompressed LZNT1 chunk")
            out.extend(chunk.data)
            continue
        while chunk.pos < len(chunk.data):
            flags = chunk.u8()
            for bit in range(8):
                if chunk.pos == len(chunk.data):
                    break
                if flags & (1 << bit):
                    token = chunk.u16()
                    shift, mask = 12, 0x0FFF
                    position = len(out) - start - 1
                    while position >= 16:
                        mask >>= 1
                        shift -= 1
                        position >>= 1
                    _match(out, (token >> shift) + 1, (token & mask) + 3,
                           limit, start)
                else:
                    if len(out) >= limit:
                        raise PACDecodeError("oversized LZNT1 chunk")
                    out.append(chunk.u8())
    return bytes(out)


def _xpress(data: bytes, expected: int) -> bytes:
    src, out = _Input(data), bytearray()
    flags = bits = 0
    pending_nibble = None
    while len(out) < expected:
        if bits == 0:
            flags, bits = src.u32(), 32
        bits -= 1
        if not flags & (1 << bits):
            out.append(src.u8())
            continue
        token = src.u16()
        distance, length = (token >> 3) + 1, token & 7
        if length == 7:
            if pending_nibble is None:
                packed = src.u8()
                length, pending_nibble = packed & 15, packed >> 4
            else:
                length, pending_nibble = pending_nibble, None
            if length == 15:
                length = src.u8()
                if length == 255:
                    length = src.u16()
                    if length == 0:
                        length = src.u32()
                    if length < 22:
                        raise PACDecodeError("invalid extended XPRESS length")
                    length -= 22
                length += 15
            length += 7
        _match(out, distance, length + 3, expected)
    # Some encoders append an empty all-one flag word on a 32-token boundary.
    # No arbitrary trailing bytes are accepted.
    if src.pos != len(data):
        if not (bits == 0 and data[src.pos:] == b'\xff' * 4):
            raise PACDecodeError("trailing XPRESS input")
    return bytes(out)


class _Bits:
    """MS-XCA's two-word look-ahead, sharing input with long match lengths."""
    def __init__(self, src: _Input):
        self.src = src
        self.register = (src.u16() << 16) | src.u16()
        self.extra = 16

    def take(self, count: int) -> int:
        if not 0 <= count <= 15:
            raise PACDecodeError("invalid Huffman bit count")
        value = self.register >> (32 - count) if count else 0
        self.register = (self.register << count) & 0xFFFFFFFF
        self.extra -= count
        if self.extra < 0:
            self.register |= self.src.u16() << -self.extra
            self.extra += 16
        return value


def _huffman_table(raw: bytes):
    lengths = [n for byte in raw for n in (byte & 15, byte >> 4)]
    # A complete 15-bit decoding table has a fixed, input-independent size.
    table = []
    for length in range(1, 16):
        for symbol, nbits in enumerate(lengths):
            if nbits != length:
                continue
            count = 1 << (15 - length)
            if count > 32768 - len(table):
                raise PACDecodeError("oversubscribed Huffman tree")
            table.extend([symbol] * count)
    if len(table) != 32768:
        raise PACDecodeError("incomplete Huffman tree")
    return lengths, table


def _xpress_huff(data: bytes, expected: int) -> bytes:
    src, out = _Input(data), bytearray()
    while len(out) < expected:
        lengths, table = _huffman_table(src.read(256))
        bits = _Bits(src)
        block_end = min(expected, len(out) + 65536)
        while len(out) < block_end:
            symbol = table[bits.register >> 17]
            bits.take(lengths[symbol])
            if symbol < 256:
                out.append(symbol)
                continue
            code = symbol - 256
            distance_bits, length = code >> 4, code & 15
            if length == 15:
                length = src.u8()
                if length == 255:
                    length = src.u16()
                    # The MS-XCA encoder defines the 32-bit escape as well.
                    if length == 0:
                        length = src.u32()
                    if length < 15:
                        raise PACDecodeError("invalid extended Huffman length")
                    length -= 15
                length += 15
            distance = (1 << distance_bits) + bits.take(distance_bits)
            _match(out, distance, length + 3, expected)
        # Intermediate blocks finish at >= 64 KiB. The next block starts at
        # the current byte cursor, after the two look-ahead words. Matches may
        # extend a block beyond 64 KiB, but never the declared total size.
    # EOF can remain in the bit register. No further symbol is required by
    # the format, but reject a second, unaccounted compressed input stream.
    if src.pos != len(data):
        symbol = table[bits.register >> 17]
        if symbol != 256:
            raise PACDecodeError("missing Huffman end marker")
        bits.take(lengths[symbol])
        if src.pos != len(data):
            raise PACDecodeError("trailing Huffman input")
    return bytes(out)


def decompress_claims(data: bytes, format_id: int, expected_size: int) -> bytes:
    """Return exactly expected_size bytes or raise PACDecodeError.

    Size checks happen before output allocation. This is a decoder, not an
    authentication function; never use its result to trust an unsigned PAC.
    """
    if (not isinstance(data, bytes) or len(data) > MAX_PAC_BYTES
            or type(expected_size) is not int
            or not 0 <= expected_size <= MAX_CLAIMS_BYTES):
        raise PACDecodeError("invalid claims decompression size")
    if format_id == 0:
        result = data
    elif format_id == 2:
        result = _lznt1(data, expected_size)
    elif format_id == 3:
        result = _xpress(data, expected_size)
    elif format_id == 4:
        result = _xpress_huff(data, expected_size)
    else:
        raise PACDecodeError("unsupported claims compression format")
    if len(result) != expected_size:
        raise PACDecodeError("claims decompression size mismatch")
    return result
