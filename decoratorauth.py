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


def _sid_from_pac(initiator_name):
    """Return the account SID from an authenticated Kerberos PAC, if exposed."""
    try:
        # RFC 6680 GSS name attribute (MIT Kerberos / Heimdal support varies).
        info = initiator_name.attributes["urn:mspac:upn-dns-info"]
    except (KeyError, TypeError, NotImplementedError, gssapi.exceptions.GSSError):
        return None

    if not info.authenticated or not info.complete or len(info.values) != 1:
        return None

    data = next(iter(info.values))
    # MS-PAC UPN_DNS_INFO: 12-byte base header, 20-byte extended header.
    if not isinstance(data, bytes) or len(data) < 20:
        return None

    flags = struct.unpack_from("<I", data, 8)[0]
    if not flags & 0x02:  # PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID
        return None

    sid_length, sid_offset = struct.unpack_from("<HH", data, 16)
    if sid_length < 12 or sid_offset < 20 or sid_offset + sid_length > len(data):
        return None

    sid = data[sid_offset:sid_offset + sid_length]
    revision, count = sid[0], sid[1]
    if revision != 1 or not 1 <= count <= 15:
        return None
    if sid_length != 8 + 4 * count:
        return None

    authority = int.from_bytes(sid[2:8], "big")
    subauths = struct.unpack_from("<" + "I" * count, sid, 8)
    return f"S-{revision}-{authority}" + "".join(
        f"-{value}" for value in subauths
    )


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
        # The PAC is read only after successful Kerberos authentication.
        g.sid = _sid_from_pac(initiator_name)

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
        conf = current_app.confadcs
        auth_header = request.headers.get('Authorization')
        g.sid = None
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