import kerberos
from flask import request, Response, g
from functools import wraps


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


def kerberos_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})

        user, response_token = kerberos_authenticate(auth_header)
        if not user:
            return Response("Unauthorized", 401, {'WWW-Authenticate': 'Negotiate'})

        g.kerberos_user = user
        headers = {'WWW-Authenticate': 'Negotiate ' + response_token} if response_token else {}
        resp = f(*args, **kwargs)
        if isinstance(resp, Response):
            resp.headers.update(headers)
            return resp
        return Response(resp, headers=headers)
    return decorated_function

