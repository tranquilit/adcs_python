#!/usr/bin/env python3

import yaml
from itsdangerous import URLSafeTimedSerializer

with open("/etc/adcs/token.yaml") as f:
    config = yaml.safe_load(f)

serializer = URLSafeTimedSerializer(
    config["security"]["secret_key"],
    salt=config["security"]["token_salt"],
)

payload = {
    "name": input("fqdn: "),
    "issued_for": input("login username : "),
}

print(serializer.dumps(payload))
