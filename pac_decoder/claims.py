"""MS-ADTS CLAIMS_SET_METADATA and CLAIMS_SET, bounded NDR32 decoding.

No claims are returned unless the complete structure, including deferred
pointers and every value, was decoded successfully. No cryptography here.
"""
import struct
from .binary import PACDecodeError, MAX_PAC_ENTRIES, MAX_PAC_BYTES
from .ndr import ndr_serialized_pointer
from .compression import decompress_claims, MAX_CLAIMS_BYTES

_TYPE_NAMES = {1: 'int64', 2: 'uint64', 3: 'string', 6: 'boolean'}
_SOURCE_NAMES = {1: 'ad', 2: 'certificate'}


def _array(r, pointer: int, count: int, *, bound=MAX_PAC_ENTRIES) -> bool:
    if not 0 <= count <= bound:
        raise PACDecodeError('excessive claims array count')
    if not pointer:
        if count:
            raise PACDecodeError('nonempty null claims array')
        return False
    if r.u32() != count:
        raise PACDecodeError('claims conformance count mismatch')
    return True


def _blob(r, pointer: int, count: int, *, bound=MAX_CLAIMS_BYTES) -> bytes:
    return r.bytes(count) if _array(r, pointer, count, bound=bound) else b''


def _string(r) -> str:
    maximum, offset, actual = r.u32(), r.u32(), r.u32()
    if (not actual or offset != 0 or actual > maximum
            or maximum > MAX_CLAIMS_BYTES // 2):
        raise PACDecodeError('invalid claims string bounds')
    raw = r.bytes(actual * 2, 2)
    if raw[-2:] != b'\0\0':
        raise PACDecodeError('unterminated claims string')
    try:
        result = raw[:-2].decode('utf-16-le')
    except UnicodeDecodeError as exc:
        raise PACDecodeError('invalid UTF-16 claim') from exc
    if '\0' in result:
        raise PACDecodeError('embedded NUL in claim string')
    return result


def _finish(r) -> None:
    # NDR serialization can end with up to seven arbitrary alignment bytes.
    if len(r.data) - r.offset > 7:
        raise PACDecodeError('unconsumed claims payload')


def decode_claims_set(data: bytes) -> list[dict]:
    """Return source-tagged claim arrays from a serialized CLAIMS_SET."""
    if not isinstance(data, bytes) or len(data) > MAX_CLAIMS_BYTES:
        raise PACDecodeError('invalid claims input')
    r = ndr_serialized_pointer(data)
    count, arrays_ptr = r.u32(), r.u32()
    r.u16()  # usReservedType: MUST be ignored by clients.
    reserved_size, reserved_ptr = r.u32(), r.u32()
    arrays = []
    total_entries = total_values = 0
    if _array(r, arrays_ptr, count):
        headers = [(r.u16(), r.u32(), r.u32()) for _ in range(count)]
        for source, claim_count, entries_ptr in headers:
            total_entries += claim_count
            if total_entries > MAX_PAC_ENTRIES:
                raise PACDecodeError('excessive total claims count')
            entries = []
            if _array(r, entries_ptr, claim_count):
                fixed = []
                for _ in range(claim_count):
                    id_ptr, typ, discriminant = r.u32(), r.u16(), r.u16()
                    if typ != discriminant or typ not in _TYPE_NAMES:
                        raise PACDecodeError('unsupported claims union')
                    n, value_ptr = r.u32(), r.u32()
                    total_values += n
                    if not id_ptr or not n or total_values > MAX_PAC_ENTRIES:
                        raise PACDecodeError('invalid claim identifier/value count')
                    fixed.append((typ, n, value_ptr))
                for typ, n, value_ptr in fixed:
                    identifier = _string(r)
                    if not identifier:
                        raise PACDecodeError('empty claim identifier')
                    if not _array(r, value_ptr, n):
                        raise PACDecodeError('null claim value array')
                    if typ == 3:
                        refs = [r.u32() for _ in range(n)]
                        if not all(refs):
                            raise PACDecodeError('null claim string pointer')
                        values = [_string(r) for _ in refs]
                    else:
                        raw = r.bytes(n * 8, 8)
                        values = list(struct.unpack('<' + ('q' if typ == 1 else 'Q') * n, raw))
                        if typ == 6:
                            if any(value not in (0, 1) for value in values):
                                raise PACDecodeError('invalid boolean claim value')
                            values = [bool(value) for value in values]
                    entries.append({'id': identifier, 'type': _TYPE_NAMES[typ],
                                    'type_id': typ, 'values': values})
            arrays.append({'source': _SOURCE_NAMES.get(source, 'unknown'),
                           'source_id': source, 'claims': entries})
    _blob(r, reserved_ptr, reserved_size)
    _finish(r)
    return arrays


def decode_claims_info(data: bytes) -> dict:
    """Decode PAC buffers 13/15 (serialized CLAIMS_SET_METADATA).

    Shape: {compression_format, uncompressed_size, arrays: [{source,
    source_id, claims: [{id, type, type_id, values}]}]}. Unknown source IDs are
    preserved numerically, never mislabeled as AD or certificate claims.
    """
    if not isinstance(data, bytes) or len(data) > MAX_PAC_BYTES:
        raise PACDecodeError('invalid claims metadata input')
    r = ndr_serialized_pointer(data)
    size, claims_ptr, compression = r.u32(), r.u32(), r.u16()
    uncompressed_size = r.u32()
    r.u16()
    reserved_size, reserved_ptr = r.u32(), r.u32()
    if not claims_ptr or size == 0:
        raise PACDecodeError('missing encoded CLAIMS_SET')
    compressed = _blob(r, claims_ptr, size, bound=MAX_PAC_BYTES)
    _blob(r, reserved_ptr, reserved_size)
    _finish(r)
    plain = decompress_claims(compressed, compression, uncompressed_size)
    arrays = decode_claims_set(plain)
    return {'compression_format': compression,
            'uncompressed_size': uncompressed_size, 'arrays': arrays}
