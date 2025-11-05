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
        service = "HTTP@" + request.host.split(":")[0]
        rc, context = kerberos.authGSSServerInit(service)
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


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        user = None
        response_token=None
        x_ssl_client_sha1 = request.headers.get('X-Ssl-Client-Sha1', None)

        MAX_SOAP_BYTES = 2 * 1024 * 1024  
        raw = request.data or b""
        if len(raw) > MAX_SOAP_BYTES: 
            return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})

        xml_text = request.data.decode('utf-8')
        NS = {
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
        }
        root = ET.fromstring(xml_text)
        
        username_el = root.find('.//o:Username', NS)
        password_el = root.find('.//o:Password', NS)

        if username_el != None:    
            username_xml = username_el.text
        else: 
            username_xml = ''

        if password_el != None:
            password_xml = password_el.text
        else: 
            password_xml = ''

        if not auth_header and (not username_xml) and (not x_ssl_client_sha1):
            return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})

        user = None
        if current_app.confadcs["auth_kerberos"] and (not x_ssl_client_sha1) :
            user, response_token = kerberos_authenticate(auth_header)
        if not user and (not x_ssl_client_sha1):
            auth_func = load_func(current_app.confadcs["auth_callbacks"]['path'], current_app.confadcs["auth_callbacks"]['func'])
            r = auth_func(username=username_xml,password=password_xml) 
            user = r

        if (not user) and (not x_ssl_client_sha1):
            return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})

        g.kerberos_user = user
        if response_token:
            headers = {'WWW-Authenticate': 'Negotiate ' + response_token} if response_token else {}
        else:
            headers = {}
        resp = f(*args, **kwargs)
        if isinstance(resp, Response):
            resp.headers.update(headers)
            return resp
        return Response(resp, headers=headers)
    return decorated_function

