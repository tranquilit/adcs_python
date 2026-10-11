"""Kerberos/SPNEGO authentication with authenticated PAC metadata.

PAC decoding uses a dependency-free Python implementation. This module still
requires the application's existing GSSAPI bindings for ticket authentication.
"""

import base64
import binascii
import logging

import gssapi
from flask import current_app, g, request

from adcs_logging import get_logger, log_event

logger = get_logger("auth")

_MAX_PAC_BYTES = 4 * 1024 * 1024

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


def _authenticated_pac_attribute(name, key):
    """Return authenticated PAC bytes only AFTER GSSAPI context completion.

    Unauthenticated GSS name attributes must never be used for authorization.
    """
    try:
        attr = name.attributes[key]
    except (
        AttributeError,
        KeyError,
        TypeError,
        NotImplementedError,
        gssapi.exceptions.GSSError,
    ):
        return None

    if not attr.authenticated or not attr.complete or len(attr.values) != 1:
        return None
    raw = next(iter(attr.values))
    if not isinstance(raw, bytes) or len(raw) > _MAX_PAC_BYTES:
        return None
    return raw


def _pac_info_from_name(initiator_name):
    """PAC decoding only; GSSAPI remains unchanged."""
    from pac_decoder.integration import pac_info_from_name
    return pac_info_from_name(
        initiator_name,
        authenticated_attribute=_authenticated_pac_attribute,
        empty_factory=_empty_pac_info,
    )


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

        initiator_name = context.initiator_name

        if initiator_name is None:
            return None, response_token

        user = str(initiator_name)
        # Read the authenticated PAC after Kerberos context completion.
        g.pac_info = _pac_info_from_name(initiator_name)
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
