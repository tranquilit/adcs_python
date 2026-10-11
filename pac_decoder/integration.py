"""Drop-in bridge using the application's original authenticated GSSAPI helper."""
import logging
from . import decode_pac, empty_pac_info, decode_upn_dns_info, PACDecodeError

_LOG = logging.getLogger('adcs.pac_python')


def _legacy_claims_format(decoded):
    """Adapt the new structured decoder to the original Samba-compatible API.

    Old kerberos_auth.py exposes a *flat list* of {id, source, type, values}.
    Unknown source IDs remain integers, never labeled as Active Directory.
    Reject a malformed/unbounded conversion as unavailable, rather than
    silently publishing a partial authorization-relevant claim list.
    """
    if decoded is None:
        return None
    if not isinstance(decoded, dict):
        return None
    arrays = decoded.get('arrays')
    if not isinstance(arrays, list) or len(arrays) > 128:
        return None
    output = []
    for group in arrays:
        if not isinstance(group, dict):
            return None
        source_id = group.get('source_id')
        entries = group.get('claims')
        if not isinstance(source_id, int) or not isinstance(entries, list):
            return None
        source = {1: 'ad', 2: 'certificate'}.get(source_id, source_id)
        for claim in entries:
            if not isinstance(claim, dict) or len(output) >= 2048:
                return None
            claim_id, typ, values = (claim.get('id'), claim.get('type'),
                                     claim.get('values'))
            if not isinstance(claim_id, str) or not claim_id:
                return None
            if typ not in ('int64', 'uint64', 'string', 'boolean'):
                return None
            if not isinstance(values, list) or len(values) > 1024:
                return None
            output.append({
                'id': claim_id, 'source': source, 'type': typ,
                'values': values,
            })
    return output


def pac_info_from_name(initiator_name, *, authenticated_attribute,
                       empty_factory=empty_pac_info) -> dict:
    """Only consume attributes already validated by the application's helper.

    The caller must run this after GSSAPI has completed authentication. This
    bridge deliberately does not import Flask, gssapi, Samba or any RPC client.
    It never fetches LDAP data and never reads identity from HTTP headers.
    """
    info = empty_pac_info()
    original_empty = empty_factory()
    if not isinstance(original_empty, dict):
        raise TypeError('_empty_pac_info must return a dictionary')
    info.update(original_empty)
    raw = upn = None
    try:
        raw = authenticated_attribute(initiator_name, 'urn:mspac:')
    except Exception:
        _LOG.warning('pac_python attribute_unavailable kind=pac')
    try:
        upn = authenticated_attribute(initiator_name, 'urn:mspac:upn-dns-info')
    except Exception:
        _LOG.warning('pac_python attribute_unavailable kind=upn')
    if raw is not None:
        errors = []
        try:
            info.update(decode_pac(raw, upn_dns_attribute=upn, errors=errors))
            # Expose the original flat claims list at g.pac_info for existing
            # callbacks. Internal decode_claims_info() remains structured.
            for field in ('client_claims', 'device_claims'):
                if info[field] is not None:
                    info[field] = _legacy_claims_format(info[field])
                    if info[field] is None:
                        _LOG.warning('pac_python claims_conversion_failed kind=%s', field)
        except PACDecodeError:
            _LOG.warning('pac_python decode_failed kind=pac')
        except Exception as exc:
            _LOG.warning('pac_python unexpected_decode_error kind=pac type=%s',
                         type(exc).__name__)
        for type_id in errors:
            # Only a bounded numeric buffer type is logged; no SID/name/PAC.
            _LOG.warning('pac_python buffer_unavailable type=%d', type_id)
    if upn is not None and info.get('upn') is None:
        try:
            candidate = decode_upn_dns_info(upn)
            if not (info.get('sid') and candidate.get('sid')
                    and info['sid'] != candidate['sid']):
                for key, value in candidate.items():
                    if info.get(key) is None:
                        info[key] = value
        except PACDecodeError:
            _LOG.warning('pac_python decode_failed kind=upn')
        except Exception as exc:
            _LOG.warning('pac_python unexpected_decode_error kind=upn type=%s',
                         type(exc).__name__)
    return info
