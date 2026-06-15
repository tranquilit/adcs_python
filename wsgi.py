import os
from app import init_app

application = init_app(
    os.environ.get("ADCS_CONF", "/etc/adcs/adcs.yaml")
)