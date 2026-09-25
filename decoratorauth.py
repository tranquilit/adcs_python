import kerberos
from flask import request, Response, g
from flask import current_app
from functools import wraps
from callback_loader import load_func
from defusedxml import ElementTree as ET
from adcs_logging import get_logger, safe_log_value


logger = get_logger("auth")


def kerberos_authenticate(auth_header):
    if not auth_header or not auth_header.startswith("Negotiate "):
        return None, None

    token = auth_header[len("Negotiate "):]
    context = None
    try:
        service = "HTTP@" + request.host.split(":")[0].lower()
        try:
            rc, context = kerberos.authGSSServerInit(service)
        except kerberos.GSSError:
            rc, context = kerberos.authGSSServerInit(service.lower())
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None, None

        rc = kerberos.authGSSServerStep(context, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            user = kerberos.authGSSServerUserName(context)
            response_token = kerberos.authGSSServerResponse(context)
            return user, response_token
        return None, None
    except kerberos.GSSError as exc:
        logger.debug(
            "event=kerberos_auth_error host=%s error=%s",
            safe_log_value(request.host),
            safe_log_value(exc),
        )
        return None, None
    finally:
        if context is not None:
            try:
                kerberos.authGSSServerClean(context)
            except Exception:
                pass


def _unauthorized():
    return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})


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
            logger.warning(
                "event=auth_failed reason=request_too_large bytes=%d",
                len(raw),
            )
            return _unauthorized()

        # TLS client-certificate authentication is accepted only when enabled
        # in adcs.yaml. If it is disabled, X-Ssl-* headers are ignored here and
        # cannot bypass Kerberos or username/password authentication.
        x_ssl_client_sha1 = request.headers.get('X-Ssl-Client-Sha1') if auth_tls else None
        if x_ssl_client_sha1:
            attempted_methods.append('tls')
            if request.headers.get('X-Ssl-Authenticated') != "SUCCESS":
                logger.warning(
                    "event=auth_failed method=tls reason=client_certificate_not_verified fingerprint=%s",
                    safe_log_value(x_ssl_client_sha1, max_length=128),
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
                    logger.error(
                        "event=auth_callback_failed callback_path=%s callback_func=%s username=%s error_type=%s",
                        safe_log_value(auth_callback.get('path')),
                        safe_log_value(auth_callback.get('func')),
                        safe_log_value(username_xml, max_length=256),
                        type(exc).__name__,
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
                logger.warning(
                    "event=auth_failed reason=no_method_succeeded attempted=%s username=%s authorization_header=%s tls_certificate=%s enabled_kerberos=%s enabled_tls=%s enabled_username_password=%s",
                    safe_log_value(','.join(attempted_methods) or 'none'),
                    safe_log_value(username_xml, max_length=256),
                    bool(auth_header),
                    bool(x_ssl_client_sha1),
                    auth_kerberos,
                    auth_tls,
                    auth_username_password,
                )
            else:
                # The first Kerberos/SPNEGO request commonly has no credentials
                # and is answered with a 401 challenge. This is protocol flow,
                # not an authentication failure worth warning on.
                logger.debug(
                    "event=auth_challenge reason=no_credentials enabled_kerberos=%s enabled_tls=%s enabled_username_password=%s",
                    auth_kerberos,
                    auth_tls,
                    auth_username_password,
                )
            return _unauthorized()

        # For TLS auth, keep g.username as None: the template callbacks already
        # resolve and validate the client certificate from X-Ssl-* headers.
        g.username = user
        g.auth_method = auth_method

        if auth_method == 'tls':
            logger.info(
                "event=auth_success method=tls certificate_fingerprint=%s",
                safe_log_value(x_ssl_client_sha1, max_length=128),
            )
        else:
            logger.info("event=auth_success method=%s", safe_log_value(auth_method))

        headers = {'WWW-Authenticate': 'Negotiate ' + response_token} if response_token else {}
        resp = f(*args, **kwargs)
        if isinstance(resp, Response):
            resp.headers.update(headers)
            return resp
        return Response(resp, headers=headers)

    return decorated_function