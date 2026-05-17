import kerberos
from flask import request, Response, g
from flask import current_app
from functools import wraps
from callback_loader import load_func
import xml.etree.ElementTree as ET

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
    except kerberos.GSSError:
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
    except ET.ParseError:
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

        auth_kerberos = bool(conf.get("auth_kerberos", False))
        auth_tls = bool(conf.get("auth_tls", False))
        auth_username_password = bool(conf.get("auth_username_password", False))

        MAX_SOAP_BYTES = 2 * 1024 * 1024
        raw = request.data or b""
        if len(raw) > MAX_SOAP_BYTES:
            return _unauthorized()

        # TLS client-certificate authentication is accepted only when enabled
        # in adcs.yaml. If it is disabled, X-Ssl-* headers are ignored here and
        # cannot bypass Kerberos or username/password authentication.
        x_ssl_client_sha1 = request.headers.get('X-Ssl-Client-Sha1') if auth_tls else None
        if x_ssl_client_sha1:
            if request.headers.get('X-Ssl-Authenticated') != "SUCCESS":
                return _unauthorized()
            auth_method = 'tls'

        # Kerberos is tried only when enabled and TLS did not already authenticate
        # the request.
        if not auth_method and auth_kerberos and auth_header:
            user, response_token = kerberos_authenticate(auth_header)
            if user:
                auth_method = 'kerberos'

        # Username/password authentication is tried only when enabled. The
        # callback path still lives under auth.callback in adcs.yaml.
        if not auth_method and auth_username_password:
            auth_callback = conf.get("auth_callbacks") or {}
            if auth_callback.get('path') and auth_callback.get('func'):
                username_xml, password_xml = _extract_username_password_from_soap(raw)
                auth_func = load_func(auth_callback['path'], auth_callback['func'])
                user = auth_func(username=username_xml, password=password_xml)
                if user:
                    auth_method = 'username_password'

        if not auth_method:
            return _unauthorized()

        # For TLS auth, keep g.username as None: the template callbacks already
        # resolve and validate the client certificate from X-Ssl-* headers.
        g.username = user
        g.auth_method = auth_method

        headers = {'WWW-Authenticate': 'Negotiate ' + response_token} if response_token else {}
        resp = f(*args, **kwargs)
        if isinstance(resp, Response):
            resp.headers.update(headers)
            return resp
        return Response(resp, headers=headers)
    return decorated_function

