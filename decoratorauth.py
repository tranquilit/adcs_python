"""Flask authentication decorator (TLS, Kerberos, username/password)."""

import logging
from functools import wraps

from defusedxml import ElementTree as ET
from flask import Response, current_app, g, request

from adcs_logging import get_logger, log_event
from callback_loader import load_func
from kerberos_auth import _empty_pac_info, kerberos_authenticate
from utils import is_client_certificate_valid_for_ca_reference


logger = get_logger("auth")


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