import requests
import kerberos
from flask import Flask, request, Response, g
from functools import wraps


def kerberos_authenticate(auth_header):
    if not auth_header or not auth_header.startswith("Negotiate "):
        return None, None

    token = auth_header[len("Negotiate "):]
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
    except kerberos.GSSError as e:
        raise
        return None, None

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
        response = f(*args, **kwargs)
        if isinstance(response, Response):
            response.headers.update(headers)
            return response
        return Response(response, headers=headers)
    return decorated_function


