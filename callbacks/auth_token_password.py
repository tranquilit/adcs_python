from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import g
from utils import search_user_ldap3, get_default_realm
import yaml


def check_auth(username=None, password=None):
    if not password:
        return False

    with open("/etc/adcs/token.yaml", "r") as f:
        config = yaml.safe_load(f)

    serializer = URLSafeTimedSerializer(
        config["security"]["secret_key"],
        salt=config["security"]["token_salt"]
    )

    try:
        payload = serializer.loads(
            password,
            max_age=config["security"]["token_max_age"]
        )

        issued_for = payload.get("issued_for")
        if not issued_for:
            return False

        g.token = payload
        g.auth_method = "token"

        return issued_for

    except SignatureExpired:
        return False

    except BadSignature:
        if not isinstance(username, str) or not username.strip():
            return False

        username = username.strip()
        realm = get_default_realm().upper()

        if "@" in username:
            user, domain = username.split("@", 1)

            if not user or domain.upper() != realm:
                return False
        else:
            user = username

        username = f"{user}@{realm}"

        r = search_user_ldap3(
            userauth=username,
            password=password
        )

        return username if r else False
