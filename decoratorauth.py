import base64
import binascii
import logging
import struct
import gssapi
from flask import request, Response, g
from flask import current_app
from functools import wraps
from callback_loader import load_func
from defusedxml import ElementTree as ET
from adcs_logging import get_logger, log_event
from utils import is_client_certificate_valid_for_ca_reference


logger = get_logger("auth")


try:
    from samba.dcerpc import krb5pac
    from samba.ndr import ndr_unpack
except (ImportError, OSError):
    krb5pac = None
    ndr_unpack = None


_MAX_PAC_BYTES = 4 * 1024 * 1024
_SE_GROUP_ENABLED = 0x00000004
_SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010


def _empty_pac_info():
    """A fresh per-request dictionary, including for non-Kerberos requests."""
    return {
        "sid": None,
        "sam_name": None,
        "upn": None,
        "dns_domain": None,
        "groups": None,
    }


def _authenticated_pac_attribute(name, key):
    """Return an authenticated PAC name attribute as bytes, if exposed.

    Access these attributes only after SecurityContext.complete is True.
    Never trust unauthenticated GSSAPI name attributes as authorization data.
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
    """Decode PAC_UPN_DNS_INFO; SID and SAM extension is optional."""
    data = _authenticated_pac_attribute(name, "urn:mspac:upn-dns-info")
    if not data or len(data) < 12:
        return

    upn_length, upn_offset, dns_length, dns_offset, flags = struct.unpack_from(
        "<HHHHI", data, 0
    )
    has_sam_and_sid = bool(flags & 0x02)
    header_size = 20 if has_sam_and_sid else 12
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

    if not has_sam_and_sid:
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


def _valid_sid(sid):
    """Convert a Samba dom_sid to a conventional SID string, if valid."""
    if sid is None:
        return None
    text = str(sid)
    parts = text.split("-")
    if len(parts) < 3 or parts[0] != "S" or not all(
        part.isascii() and part.isdecimal() for part in parts[1:]
    ):
        return None
    return text


def _populate_logon_info(name, info):
    """Decode PAC_LOGON_INFO from the authenticated full PAC using Samba NDR.

    Includes domain groups, primary group, resource-domain groups, and extra
    enabled authorization SIDs. A genuine empty list means LOGON_INFO was
    decoded but contained no usable groups; None means it was unavailable.
    """
    if krb5pac is None or ndr_unpack is None:
        return

    # The urn:mspac: attribute is the complete PAC, not just LOGON_INFO.
    # ndr_unpack(PAC_DATA, ...) handles the PAC buffer offsets and NDR headers.
    raw_pac = _authenticated_pac_attribute(name, "urn:mspac:")
    if not raw_pac:
        return

    try:
        pac = ndr_unpack(krb5pac.PAC_DATA, raw_pac)
        for pac_buffer in pac.buffers:
            if pac_buffer.type != krb5pac.PAC_TYPE_LOGON_INFO:
                continue

            # Samba's Python PAC_BUFFER.info is the decoded type-specific
            # structure; for LOGON_INFO, .info is PAC_LOGON_INFO itself.
            logon = pac_buffer.info.info
            if logon is None:
                return
            info3 = logon.info3
            base = info3.base
            domain_sid = _valid_sid(base.domain_sid)

            if info["sid"] is None and domain_sid and base.rid:
                info["sid"] = f"{domain_sid}-{int(base.rid)}"
            if info["sam_name"] is None:
                info["sam_name"] = getattr(base.account_name, "string", None)

            groups = []
            seen = set()

            def add_sid(sid):
                sid = _valid_sid(sid)
                if sid and sid not in seen:
                    seen.add(sid)
                    groups.append(sid)

            def add_rid(sid_prefix, rid):
                if sid_prefix and rid is not None and 0 < int(rid) <= 0xFFFFFFFF:
                    add_sid(f"{sid_prefix}-{int(rid)}")

            def enabled(entry):
                # Do not expose disabled / deny-only entries as groups for
                # positive authorization decisions.
                attributes = int(entry.attributes)
                return bool(attributes & _SE_GROUP_ENABLED) and not bool(
                    attributes & _SE_GROUP_USE_FOR_DENY_ONLY
                )

            # The primary group can be absent from the ordinary groups array.
            add_rid(domain_sid, base.primary_gid)
            for entry in (base.groups.rids or []):
                if enabled(entry):
                    add_rid(domain_sid, entry.rid)

            # Extra SIDs can represent forest-trust groups or SIDHistory.
            for entry in (info3.sids or []):
                if enabled(entry):
                    add_sid(entry.sid)

            # Cross-domain / resource group SIDs use their own domain prefix.
            resource = logon.resource_groups
            if resource is not None:
                resource_domain_sid = _valid_sid(resource.domain_sid)
                for entry in (resource.groups.rids or []):
                    if enabled(entry):
                        add_rid(resource_domain_sid, entry.rid)

            info["groups"] = groups
            return
    except Exception as exc:
        # PAC decoding is optional metadata; never turn a successful GSSAPI
        # authentication into a 500 error if a PAC buffer cannot be decoded.
        log_event(
            logger, logging.DEBUG, "pac_logon_info_decode_failed",
            "PAC LOGON_INFO decoding unavailable",
            reason="ndr_decode_failed", error_type=type(exc).__name__,
        )


def _pac_info_from_name(initiator_name):
    """Extract available PAC identity and group information, with no LDAP."""
    info = _empty_pac_info()
    _populate_upn_dns_info(initiator_name, info)
    _populate_logon_info(initiator_name, info)
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
        g.pac_info = _pac_info_from_name(initiator_name)

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


def _unauthorized(response_token=None):
    if response_token:
        authenticate_header = "Negotiate " + response_token
    else:
        authenticate_header = "Negotiate"

    return Response(
        "Unauthorized",
        401,
        {
            "WWW-Authenticate": authenticate_header
        },
    )

def _extract_username_password_from_soap(raw):
    if not raw:
        return '', ''

    xml_text = raw.decode('utf-8', errors='replace')
    if 'Username' not in xml_text:
        return '', ''

    NS = {
        'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    }

    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ET.DefusedXmlException):
        return '', ''

    username_el = root.find('.//o:Username', NS)
    password_el = root.find('.//o:Password', NS)

    username = username_el.text if username_el is not None and username_el.text else ''
    password = password_el.text if password_el is not None and password_el.text else ''
    return username, password


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.pac_info = _empty_pac_info()
        conf = current_app.confadcs
        auth_header = request.headers.get('Authorization')
        user = None
        response_token = None
        auth_method = None
        attempted_methods = []
        username_xml = ''
        password_xml = ''

        auth_kerberos = bool(conf.get("auth_kerberos", False))
        auth_tls = bool(conf.get("auth_tls", False))
        auth_username_password = bool(conf.get("auth_username_password", False))

        MAX_SOAP_BYTES = 2 * 1024 * 1024
        raw = request.data or b""
        if len(raw) > MAX_SOAP_BYTES:
            log_event(
                logger, logging.WARNING, "authentication_failed",
                "Authentication request rejected",
                outcome="failure", reason="request_too_large", bytes=len(raw),
            )
            return _unauthorized()

        # TLS client-certificate authentication is accepted only when enabled
        # in adcs.yaml. If it is disabled, X-Ssl-* headers are ignored here and
        # cannot bypass Kerberos or username/password authentication.
        x_ssl_client_sha1 = request.headers.get('X-Ssl-Client-Sha1') if auth_tls else None
        if x_ssl_client_sha1:
            attempted_methods.append('tls')

            x509_cas = [
                ca for ca in (conf.get("cas_list") or [])
                if any(
                    (entry.get("method") or "").strip().lower() == "x509"
                    for entry in (ca.get("auth_methods") or [])
                )
            ]

            if not x509_cas:
                log_event(
                    logger, logging.WARNING, "authentication_failed",
                    "TLS authentication rejected",
                    outcome="failure", reason="no_x509_ca_configured", method="tls",
                )
                return Response("Forbidden", 403)

            x_ssl_client_cert = request.headers.get('X-Ssl-Client-Cert')
            if not is_client_certificate_valid_for_ca_reference(
                x_ssl_client_cert,
                x509_cas,
            ):
                log_event(
                    logger, logging.WARNING, "authentication_failed",
                    "TLS client certificate rejected",
                    outcome="failure", reason="invalid_client_certificate",
                    method="tls", certificate_fingerprint=x_ssl_client_sha1,
                )
                return _unauthorized()

            auth_method = 'tls'

        # Kerberos is tried only when enabled and TLS did not already authenticate
        # the request.
        if not auth_method and auth_kerberos and auth_header:
            attempted_methods.append('kerberos')
            user, response_token = kerberos_authenticate(auth_header)
            if user:
                auth_method = 'kerberos'
            elif response_token:
                # GSSAPI/SPNEGO may require an intermediate token to be sent
                # back to the client before authentication can complete.
                return _unauthorized(response_token)

        # Username/password authentication is tried only when enabled. The
        # callback path still lives under auth.callback in adcs.yaml.
        if not auth_method and auth_username_password:
            attempted_methods.append('username_password')
            auth_callback = conf.get("auth_callbacks") or {}
            if auth_callback.get('path') and auth_callback.get('func'):
                username_xml, password_xml = _extract_username_password_from_soap(raw)
                try:
                    auth_func = load_func(auth_callback['path'], auth_callback['func'])
                    user = auth_func(username=username_xml, password=password_xml)
                except Exception as exc:
                    log_event(
                        logger, logging.ERROR, "callback_exception",
                        "Authentication callback raised an exception",
                        outcome="failure", reason="python_exception", exc_info=True,
                        stage="authentication",
                        callback_path=auth_callback.get('path'),
                        callback_func=auth_callback.get('func'),
                        username=username_xml,
                        error_type=type(exc).__name__,
                    )
                    raise
                if user:
                    auth_method = 'username_password'

        if not auth_method:
            credentials_supplied = bool(
                auth_header
                or x_ssl_client_sha1
                or username_xml
                or password_xml
            )

            if credentials_supplied:
                log_event(
                    logger, logging.WARNING, "authentication_failed",
                    "Authentication failed",
                    outcome="failure", reason="no_method_succeeded",
                    attempted_methods=attempted_methods or ["none"],
                    username=username_xml or None,
                    authorization_header_present=bool(auth_header),
                    tls_certificate_present=bool(x_ssl_client_sha1),
                    enabled_kerberos=auth_kerberos,
                    enabled_tls=auth_tls,
                    enabled_username_password=auth_username_password,
                )
            else:
                # The first Kerberos/SPNEGO request commonly has no credentials
                # and is answered with a 401 challenge. This is protocol flow,
                # not an authentication failure worth warning on.
                log_event(
                    logger, logging.DEBUG, "authentication_challenge",
                    "Authentication challenge sent",
                    reason="no_credentials",
                    enabled_kerberos=auth_kerberos,
                    enabled_tls=auth_tls,
                    enabled_username_password=auth_username_password,
                )
            return _unauthorized()

        # Keep the transport method separate from the effective method.
        # Authentication callbacks may set g.auth_method themselves (for
        # example to a custom token method); otherwise preserve the historical
        # transport method as the effective method.
        g.username = user
        g.auth_transport_method = auth_method
        if not getattr(g, "auth_method", None):
            g.auth_method = auth_method

        if auth_method == 'tls':
            log_event(
                logger, logging.INFO, "authentication_succeeded",
                "TLS authentication succeeded",
                outcome="success", method="tls",
                certificate_fingerprint=x_ssl_client_sha1,
            )
        else:
            log_event(
                logger, logging.INFO, "authentication_succeeded",
                "Authentication succeeded",
                outcome="success", method=auth_method,
            )

        headers = {'WWW-Authenticate': 'Negotiate ' + response_token} if response_token else {}
        resp = f(*args, **kwargs)
        if isinstance(resp, Response):
            resp.headers.update(headers)
            return resp
        return Response(resp, headers=headers)

    return decorated_function