"""Kerberos/SPNEGO authentication with authenticated PAC metadata.

PAC decoding uses a dependency-free Python implementation. This module still
requires the application's existing GSSAPI bindings for ticket authentication.
"""

import base64
import binascii
import logging
import sys
from pathlib import Path

import gssapi
from flask import current_app, g, request

from adcs_logging import get_logger, log_event

# The submodule has a src/ layout, and is not a Debian Python package.
_DECODER_SRC = Path(__file__).resolve().parent / "vendor/py-mspack-decoder/src"
if not (_DECODER_SRC / "pac_decoder/__init__.py").is_file():
    raise RuntimeError("Missing PAC decoder submodule: git submodule update --init --recursive")
sys.path.insert(0, str(_DECODER_SRC))

from pac_decoder import PACDecodeError
from pac_decoder.gssapi_helpers import PACAttributeError, decode_completed_context

logger = get_logger("auth")

def _empty_pac_info():
    """Fresh request-local data for every auth method, even non-Kerberos."""
    return {
        # Account identity (UPN_DNS_INFO and LOGON_INFO).
        "sid": None,
        "sam_name": None,
        "upn": None,
        "dns_domain": None,
        "upn_dns_flags": None,
        "upn_constructed": None,
        "rid": None,
        "domain_sid": None,
        "domain_name": None,
        "logon_server": None,
        "full_name": None,
        # Authorization: only enabled, non-deny-only SIDs are included.
        "groups": None,
        "primary_group_rid": None,
        "extra_sids": None,
        "resource_groups": None,
        "group_count": None,
        # SAM account flags, NOT LDAP userAccountControl bits.
        "account_flags": None,
        "user_flags": None,
        "sub_auth_status": None,
        # Authentication/account history from LOGON_INFO, as seen when the
        # ticket was issued (not live LDAP values).
        "last_logon": None,
        "last_successful_logon": None,
        "last_failed_logon": None,
        "logoff_time": None,
        "kickoff_time": None,
        "password_last_set": None,
        "password_can_change": None,
        "password_must_change": None,
        "logon_count": None,
        "bad_password_count": None,
        "failed_logon_count": None,
        "home_directory": None,
        "home_drive": None,
        "logon_script": None,
        "profile_path": None,
        # Other PAC buffers (present only in some Kerberos tickets).
        "client_name": None,
        "client_auth_time": None,
        "requestor_sid": None,
        "pac_requested": None,
        "pac_given_implicitly": None,
        "pac_attributes_flags": None,
        "delegation_proxy_target": None,
        "delegation_transited_services": None,
        "device_info": None,
        "client_claims_present": None,
        "device_claims_present": None,
        "client_claims": None,
        "device_claims": None,
        "credential_info_present": None,
        "pac_signature_types": None,
        "pac_version": None,
        "pac_size": None,
        "pac_buffer_types": None,
        "pac_buffer_type_ids": None,
    }


def _pac_info_from_context(context):
    """Read the authenticated PAC using the decoder's GSSAPI integration."""
    try:
        return decode_completed_context(context)
    except (PACAttributeError, PACDecodeError) as exc:
        logger.warning("PAC unavailable or invalid: %s", type(exc).__name__)
        return _empty_pac_info()


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

        # Only accept a completed Kerberos mechanism (never NTLM or another GSS mechanism).
        if context.mech != gssapi.MechType.kerberos:
            return None, response_token

        initiator_name = context.initiator_name

        if initiator_name is None:
            return None, response_token

        user = str(initiator_name)
        # Read the authenticated PAC after Kerberos context completion.
        g.pac_info = _pac_info_from_context(context)
        # Keep the previous g.sid interface for compatibility.
        g.sid = g.pac_info["sid"]

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
