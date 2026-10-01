#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, Response, g
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import argparse
import logging
import uuid
import base64
import textwrap
from defusedxml import ElementTree as ET  # anti-XXE / billion-laughs

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization

from decoratorauth import auth_required

from utils import (
    format_b64_for_soap,
    exct_csr_from_cmc,
    build_adcs_bst_pkiresponse,
    build_adcs_bst_pkiresponse_issued,
    build_ws_trust_response,
    build_get_policies_response,
    build_ces_response,
    build_ket_response
)

from adcs_config import load_yaml_conf, build_templates_for_policy_response, _call_callback_with_params
from callback_loader import load_func
from tpm_support import verify_tpm_for_template
from adcs_logging import (
    configure_logging,
    get_logger,
    install_request_logging,
    log_event,
    set_enrollment_request_id,
)


# ------------- SOAP parsing security -------------
MAX_SOAP_BYTES = 2 * 1024 * 1024  # 2 MiB: hard limit to avoid OOM

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

install_request_logging(app)

logger = get_logger("app")
cep_logger = get_logger("cep")
ces_logger = get_logger("ces")
issuance_logger = get_logger("issuance")


def init_app(confadcs="/etc/adcs/adcs.yaml"):
    """
    Initialize the Flask application.

    Used by:
      - python3 app.py          -> direct launch with Waitress by default
      - Gunicorn via wsgi.py    -> application = init_app(...)
      - uWSGI via wsgi.py       -> application = init_app(...)
    """
    app.confadcs = load_yaml_conf(confadcs)
    configure_logging(app, app.confadcs)
    os.makedirs(app.confadcs['path_list_request_id'], exist_ok=True)

    decls = app.confadcs.get("__template_decls__") or []
    log_event(
        logger, logging.INFO, "config_loaded", "Configuration loaded",
        outcome="success", file=confadcs, template_declarations=len(decls),
        cas=len(app.confadcs.get("cas_list") or []),
    )

    return app


def _https_base_url():
    host_url = request.host_url.rsplit('/', 1)[0]
    return host_url.replace("http://", "https://")


def _ca_allows_auth_method(ca: dict, auth_method: str) -> bool:
    method_map = {
        "kerberos": "kerberos",
        "username_password": "username_password",
        "tls": "x509",
    }

    requested_method = method_map.get(auth_method)
    if not requested_method:
        return False

    auth_entries = ca.get("auth_methods")

    # Keep CES aligned with CEP default: when no CA-specific policy is defined,
    # DEFAULT_AUTH_METHODS is Kerberos-only.
    if not auth_entries:
        auth_entries = [
            {"method": "kerberos", "renewal_only": False},
        ]

    for entry in auth_entries:
        method = (entry.get("method") or "").strip().lower()
        if method == requested_method:
            return True

    return False


# ---------------- Endpoints ----------------

@app.route('/CEP', methods=['POST', 'GET'])
@app.route('/ADPolicyProvider_CEP_Kerberos/service.svc/CEP', methods=['POST', 'GET'])
@app.route('/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP', methods=['POST', 'GET'])
@app.route('/KeyBasedRenewal_ADPolicyProvider_CEP_Certificate/service.svc/CEP', methods=['POST', 'GET'])
@auth_required
def cep_service():
    host_url = request.host_url.rsplit('/', 1)[0]
    raw = request.data or b""

    if len(raw) > MAX_SOAP_BYTES:
        log_event(
            cep_logger, logging.WARNING, "cep_request_rejected",
            "CEP request rejected", outcome="failure", reason="request_too_large",
            bytes=len(raw),
        )
        return Response("Request too large", status=413, content_type="text/plain; charset=utf-8")

    try:
        xml_data = raw.decode('utf-8', errors='replace')
    except Exception as exc:
        log_event(
            cep_logger, logging.WARNING, "cep_request_rejected",
            "CEP request rejected", outcome="failure", reason="invalid_encoding",
            error_type=type(exc).__name__,
        )
        return Response("Invalid encoding", status=400, content_type="text/plain; charset=utf-8")

    log_event(
        cep_logger, logging.DEBUG, "cep_policy_request", "CEP policy request received",
        bytes=len(raw),
    )

    rst_xml = xml_data
    uuid_request = ''

    if rst_xml:
        try:
            root = ET.fromstring(rst_xml)
            namespaces = {
                's': 'http://www.w3.org/2003/05/soap-envelope',
                'a': 'http://www.w3.org/2005/08/addressing'
            }
            message_id_elem = root.find('.//a:MessageID', namespaces)
            uuid_request = message_id_elem.text.replace("urn:uuid:", "") if message_id_elem is not None else ''
        except Exception as exc:
            # Continue: CEP can generate a response without correlation if parsing fails.
            uuid_request = ''
            log_event(
                cep_logger, logging.WARNING, "cep_message_id_parse_failed",
                "CEP MessageID could not be parsed", outcome="failure",
                reason="invalid_message_id", error_type=type(exc).__name__,
            )

    uuid_random = str(uuid.uuid4())
    relates_to = uuid_request or uuid_random

    # User resolution for CEP, same as for CES.
    username = g.username

    # Build templates + OIDs for THIS CEP response, user-dependent.
    try:
        templates_for_user, oids_for_user = build_templates_for_policy_response(
            app.confadcs,
            username=username,
            request=request,
            auth_method=getattr(g, "auth_method", None)
        )
    except Exception as exc:
        log_event(
            cep_logger, logging.ERROR, "cep_policy_build_failed",
            "CEP policy build failed", outcome="failure", reason="python_exception",
            exc_info=True, error_type=type(exc).__name__,
        )
        raise

    # Keep an in-memory index, optional, no longer required by CES.
    app.confadcs['templates_by_template_oid_value'] = {
        (t.get("template_oid") or {}).get("value"): t for t in templates_for_user
    }

    try:
        response_xml = build_get_policies_response(
            uuid_request=relates_to,
            uuid_random=uuid_random,
            hosturl=host_url.replace('http://', 'https://') + ':' + request.headers.get('X-Forwarded-Port', '443'),
            policyid=app.confadcs['policyid'],
            policyfriendlyname=app.confadcs['policyfriendlyname'],
            next_update_hours=app.confadcs['next_update_hours'],
            cas=app.confadcs['cas_list'],
            templates=templates_for_user,
            oids=oids_for_user,
        )
    except Exception as exc:
        log_event(
            cep_logger, logging.ERROR, "cep_policy_response_failed",
            "CEP policy response build failed", outcome="failure", reason="python_exception",
            exc_info=True, soap_message_id=relates_to, error_type=type(exc).__name__,
        )
        raise

    log_event(
        cep_logger, logging.INFO, "cep_policy_response", "CEP policy response built",
        outcome="success", soap_message_id=relates_to,
        templates=len(templates_for_user), oids=len(oids_for_user),
        cas=len(app.confadcs.get('cas_list') or []),
    )

    return Response(response_xml, content_type='application/soap+xml')


CHALLENGE_RESPONSE = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#CHALLENGERESPONSE"


def _parse_enrollment_request_id(value) -> int:
    """Validate an ADCS protocol RequestID without changing its semantics.

    Server-generated RequestIDs are UUID integers (at most 128 bits). Client
    values are accepted only in the same non-negative decimal range so they remain
    safe for filenames and SOC correlation.
    """
    text = str(value or "").strip()
    if not text or not text.isdigit() or len(text) > 39:
        raise ValueError("Invalid enrollment RequestID")
    request_id = int(text, 10)
    if request_id < 0 or request_id >= (1 << 128):
        raise ValueError("Invalid enrollment RequestID")
    return request_id


def extract_challenge_response_and_request_id(xml_data: str):
    ns = {
        "s": "http://www.w3.org/2003/05/soap-envelope",
        "wst": "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
        "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "auth": "http://schemas.xmlsoap.org/ws/2006/12/authorization",
    }

    root = ET.fromstring(xml_data)

    challenge_response = ""
    token = root.find(".//wsse:BinarySecurityToken", ns)

    if token is not None and token.get("ValueType") == CHALLENGE_RESPONSE:
        challenge_response = "".join((token.text or "").split())

    request_id = root.findtext(
        './/auth:ContextItem[@Name="RequestID"]/auth:Value',
        namespaces=ns
    )

    if request_id:
        request_id = _parse_enrollment_request_id(request_id)

    return {
        "is_challenge_response": challenge_response != "",
        "challenge_response": challenge_response.replace('&#xD;', '').replace('\n', ''),
        "request_id": request_id,
    }


@app.route('/CES/<CAID>', methods=['POST'])
@auth_required
def ces_service(CAID):
    raw = request.data or b""

    if len(raw) > MAX_SOAP_BYTES:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="request_too_large",
            ca_id=CAID, bytes=len(raw),
        )
        return Response("Request too large", status=413, content_type="text/plain; charset=utf-8")

    try:
        rst_xml = raw.decode('utf-8', errors='replace')
    except Exception as exc:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="invalid_encoding",
            ca_id=CAID, error_type=type(exc).__name__,
        )
        return Response("Invalid encoding", status=400, content_type="text/plain; charset=utf-8")

    # Get request UUID, optional.
    try:
        root = ET.fromstring(rst_xml)
    except Exception as exc:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="invalid_soap",
            ca_id=CAID, error_type=type(exc).__name__,
        )
        return Response("Bad SOAP: cannot parse XML", status=400, content_type="text/plain; charset=utf-8")

    namespaces = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'a': 'http://www.w3.org/2005/08/addressing',
        "wst": "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    }

    message_id_elem = root.find('.//a:MessageID', namespaces)
    message_id_text = (message_id_elem.text or "").strip() if message_id_elem is not None else ""
    if not message_id_text:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="missing_message_id",
            ca_id=CAID,
        )
        return Response("Missing WS-Addressing MessageID", status=400, content_type="text/plain; charset=utf-8")
    uuid_request = message_id_text.removeprefix("urn:uuid:")

    log_event(
        ces_logger, logging.DEBUG, "ces_request", "CES request received",
        ca_id=CAID, soap_message_id=uuid_request, bytes=len(raw),
    )

    ca_match = [u for u in app.confadcs['cas_list'] if u['id'] == CAID]
    if not ca_match:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="ca_not_found",
            ca_id=CAID,
        )
        return Response("CAID not found", 403)

    transport_auth_method = getattr(
        g, "auth_transport_method", getattr(g, "auth_method", None)
    )
    if not _ca_allows_auth_method(ca_match[0], transport_auth_method):
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="auth_method_not_allowed",
            ca_id=CAID, method=transport_auth_method,
        )
        return Response(
            "Authentication method %s is not allowed for CA %s" %
            (transport_auth_method, CAID),
            403,
        )

    if root.find(".//wst:RequestKET", namespaces) is not None:
        try:
            response_xml = build_ket_response(
                uuid_request=uuid_request,
                uuid_random=str(uuid.uuid4()),
                ket_cert_der=ca_match[0]['__ket_certificate_b64']
            )
        except Exception as exc:
            log_event(
                ces_logger, logging.ERROR, "ket_response_failed",
                "KET response build failed", outcome="failure", reason="python_exception",
                exc_info=True, ca_id=CAID, error_type=type(exc).__name__,
            )
            raise

        log_event(
            ces_logger, logging.INFO, "ket_response", "KET response built",
            outcome="success", ca_id=CAID,
        )
        return Response(response_xml, content_type='application/soap+xml')

    try:
        challenge = extract_challenge_response_and_request_id(rst_xml)
    except (TypeError, ValueError) as exc:
        log_event(
            ces_logger, logging.WARNING, "ces_request_rejected",
            "CES request rejected", outcome="failure", reason="invalid_challenge_request_id",
            ca_id=CAID, error_type=type(exc).__name__,
        )
        return Response("Invalid TPM challenge RequestID", status=400, content_type="text/plain; charset=utf-8")

    req_id_elem = root.find(
        ".//enr:RequestID",
        {"enr": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"}
    )

    enr_request_id = None
    if req_id_elem is not None and (req_id_elem.text or "").strip():
        try:
            enr_request_id = _parse_enrollment_request_id(req_id_elem.text)
        except (TypeError, ValueError) as exc:
            log_event(
                ces_logger, logging.WARNING, "ces_request_rejected",
                "CES request rejected", outcome="failure", reason="invalid_enrollment_request_id",
                ca_id=CAID, error_type=type(exc).__name__,
            )
            return Response("Invalid enrollment RequestID", status=400, content_type="text/plain; charset=utf-8")

    if challenge['is_challenge_response']:
        if challenge['request_id'] is None:
            log_event(
                ces_logger, logging.WARNING, "tpm_challenge_rejected",
                "TPM challenge response rejected", outcome="failure", reason="missing_request_id",
                ca_id=CAID,
            )
            return Response(
                "Missing ContextItem RequestID for TPM challenge response",
                content_type="text/plain; charset=utf-8",
                status=400,
            )

        if enr_request_id is not None and enr_request_id != challenge['request_id']:
            log_event(
                ces_logger, logging.WARNING, "tpm_challenge_rejected",
                "TPM challenge response rejected", outcome="failure", reason="request_id_mismatch",
                ca_id=CAID, enrollment_request_id=enr_request_id,
                challenge_request_id=challenge['request_id'],
            )
            return Response(
                "Mismatched RequestID between enr:RequestID and challenge-response ContextItem",
                content_type="text/plain; charset=utf-8",
                status=400,
            )

    if enr_request_id is not None:
        request_id = enr_request_id
        p7_path = os.path.join(app.confadcs['path_list_request_id'], str(request_id))

        if not os.path.isfile(p7_path):
            log_event(
                ces_logger, logging.ERROR, "pending_request_missing",
                "Pending enrollment request state is missing", outcome="failure",
                reason="pending_state_missing", ca_id=CAID, enrollment_request_id=request_id,
            )
            return Response(
                'File %s not foud in path_list_request_id' % str(request_id),
                content_type="application/soap+xml; charset=utf-8",
                status=500
            )

        try:
            with open(p7_path, 'rb') as f:
                p7_der = f.read()
        except Exception as exc:
            log_event(
                ces_logger, logging.ERROR, "pending_request_read_failed",
                "Pending enrollment request state could not be read", outcome="failure",
                reason="python_exception", exc_info=True, ca_id=CAID,
                enrollment_request_id=request_id, error_type=type(exc).__name__,
            )
            raise

    elif challenge['is_challenge_response']:
        request_id = challenge['request_id']
        p7_path = os.path.join(app.confadcs['path_list_request_id'], str(request_id))

        if not os.path.isfile(p7_path):
            log_event(
                ces_logger, logging.ERROR, "pending_request_missing",
                "Pending enrollment request state is missing", outcome="failure",
                reason="pending_state_missing", ca_id=CAID, enrollment_request_id=request_id,
            )
            return Response(
                'File %s not foud in path_list_request_id' % str(request_id),
                content_type="application/soap+xml; charset=utf-8",
                status=500
            )

        try:
            with open(p7_path, 'rb') as f:
                p7_der = f.read()
        except Exception as exc:
            log_event(
                ces_logger, logging.ERROR, "pending_request_read_failed",
                "Pending enrollment request state could not be read", outcome="failure",
                reason="python_exception", exc_info=True, ca_id=CAID,
                enrollment_request_id=request_id, error_type=type(exc).__name__,
            )
            raise

    else:
        ns_wsse = {
            'wsse': "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        }

        try:
            bst_node = root.find('.//wsse:BinarySecurityToken', ns_wsse)
            p7_der = base64.b64decode(bst_node.text)
            request_id = uuid.uuid4().int
        except Exception as exc:
            log_event(
                ces_logger, logging.ERROR, "cmc_payload_extract_failed",
                "CMC payload extraction failed", outcome="failure", reason="python_exception",
                exc_info=True, ca_id=CAID, error_type=type(exc).__name__,
            )
            raise

    # From this point on, every log record automatically carries the existing
    # ADCS enrollment RequestID is exposed as requestId in the structured
    # event object. The separate HTTP correlation ID remains correlationId.
    set_enrollment_request_id(request_id)

    try:
        csr_der, body_part_id, info = exct_csr_from_cmc(p7_der)
    except Exception as exc:
        log_event(
            ces_logger, logging.ERROR, "cmc_parse_failed", "CMC parsing failed",
            outcome="failure", reason="python_exception", exc_info=True, ca_id=CAID,
            enrollment_request_id=request_id, error_type=type(exc).__name__,
        )
        raise

    username = g.username

    # Rebuild templates for this CES request.
    try:
        templates_for_user, _ = build_templates_for_policy_response(
            app.confadcs,
            username=username,
            request=request,
            auth_method=getattr(g, "auth_method", None)
        )
    except Exception as exc:
        log_event(
            ces_logger, logging.ERROR, "ces_template_build_failed",
            "CES template policy build failed", outcome="failure", reason="python_exception",
            exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
            error_type=type(exc).__name__,
        )
        raise

    tmap = {
        (t.get("template_oid") or {}).get("value"): t for t in templates_for_user
    }

    tmap_name = {
        t.get("common_name"): t for t in templates_for_user
    }

    if info.get('oid'):
        tpl = tmap.get(info.get('oid'))
    else:
        tpl = tmap_name.get(info.get('name'))

    if not tpl:
        log_event(
            ces_logger, logging.INFO, "enrollment_rejected", "Enrollment rejected",
            outcome="failure", reason="invalid_template", ca_id=CAID,
            enrollment_request_id=request_id, template_oid=info.get('oid'),
            template_name=info.get('name'),
        )
        return Response("The requested template is not valid", 403)

    if not tpl['permissions']['enroll']:
        log_event(
            ces_logger, logging.INFO, "enrollment_rejected", "Enrollment rejected",
            outcome="failure", reason="enroll_not_permitted", ca_id=CAID,
            enrollment_request_id=request_id, template=tpl.get('common_name'),
        )
        return Response("You do not have permission to enroll on this template", 403)

    dict_id_ca = {u['id']: u for u in app.confadcs['cas_list']}
    ca = dict_id_ca.get(CAID)

    if not ca:
        log_event(
            ces_logger, logging.INFO, "enrollment_rejected", "Enrollment rejected",
            outcome="failure", reason="ca_not_found", ca_id=CAID,
            enrollment_request_id=request_id,
        )
        return Response("CAID not found", 403)

    if ca.get("__refid") not in set(tpl.get("__ca_refids") or []):
        log_event(
            ces_logger, logging.INFO, "enrollment_rejected", "Enrollment rejected",
            outcome="failure", reason="template_ca_mismatch", ca_id=CAID,
            enrollment_request_id=request_id,
            template=(tpl.get('template_oid') or {}).get('value'),
        )
        return Response(
            '%s not in ca_references for template %s' %
            (CAID, tpl['template_oid']['value']),
            403,
        )

    cb = (tpl.get("__callback") if tpl else (app.confadcs.get("__default_callback"))) or {}
    cb_path = cb.get("path")
    cb_issue = cb.get("issue")

    try:
        emit_certificate = load_func(cb_path, cb_issue)
    except Exception as exc:
        log_event(
            issuance_logger, logging.ERROR, "callback_exception",
            "Certificate callback could not be loaded",
            outcome="failure", reason="callback_load_failed", exc_info=True,
            stage="issuance", ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'), callback_path=cb_path,
            callback_func=cb_issue, error_type=type(exc).__name__,
        )
        raise

    log_event(
        issuance_logger, logging.INFO, "enrollment_requested",
        "Certificate enrollment requested",
        ca_id=CAID, enrollment_request_id=request_id,
        template=tpl.get('common_name'),
        template_oid=(tpl.get('template_oid') or {}).get('value'),
        tpm_challenge_response_present=bool(challenge['is_challenge_response']),
        body_part_id=body_part_id,
    )

    ces_uri = f"{_https_base_url()}/CES/{CAID}"

    try:
        if challenge['is_challenge_response']:
            tpm_result = verify_tpm_for_template(
                csr_der=csr_der,
                challenge_response_der=base64.b64decode(
                    challenge["challenge_response"],
                    validate=True,
                ),
                template=tpl,
                request_id=request_id,
                ca=ca,
                pending_dir=app.confadcs["tpm_pending_dir"],
                pending_challenge_max_age_seconds=app.confadcs["tpm_pending_challenge_max_age_seconds"],
            )
        else:
            tpm_result = verify_tpm_for_template(
                csr_der=csr_der,
                cmc_der=p7_der,
                template=tpl,
                request_id=request_id,
                ca=ca,
                pending_dir=app.confadcs["tpm_pending_dir"],
                pending_challenge_max_age_seconds=app.confadcs["tpm_pending_challenge_max_age_seconds"],
            )
    except Exception as exc:
        log_event(
            issuance_logger, logging.ERROR, "tpm_attestation_failed",
            "TPM attestation failed",
            outcome="failure", reason="verification_exception", exc_info=True,
            ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'), error_type=type(exc).__name__,
        )
        raise

    if tpm_result.get("status") == "pending":
        status_text = "Waiting for processing"

        log_event(
            issuance_logger, logging.INFO, "certificate_pending",
            "Certificate enrollment is pending TPM challenge completion",
            outcome="unknown", reason="tpm_challenge",
            ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'),
        )

        try:
            xml_body, http_code = build_ws_trust_response(
                pkcs7_der=tpm_result["challenge_pkcs7_der"],
                relates_to=f"urn:uuid:{uuid_request}",
                request_id=int(tpm_result.get("request_id", request_id)),
                ces_uri=ces_uri,
                status="pending",
                disposition_message=status_text,
                lang="en-US",
            )
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_response_failed",
                "Certificate response build failed", outcome="failure", reason="python_exception",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), status="pending", stage="tpm_challenge",
                error_type=type(exc).__name__,
            )
            raise

        response = Response(
            xml_body.decode("utf-8"),
            content_type="application/soap+xml; charset=utf-8",
            status=http_code
        )

        try:
            with open(os.path.join(app.confadcs['path_list_request_id'], str(request_id)), 'wb') as f:
                f.write(p7_der)
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_issue_failed",
                "Certificate issuance failed", outcome="failure", reason="pending_state_store_failed",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), stage="tpm_challenge",
                error_type=type(exc).__name__,
            )
            raise

        return response

    try:
        result = _call_callback_with_params(
            emit_certificate,
            params=cb.get("params"),
            csr_der=csr_der,
            request_id=request_id,
            username=username,
            ca=ca,
            template=tpl,
            info=info,
            app_conf=app.confadcs,
            CAID=CAID,
            request=request,
            auth_method=getattr(g, "auth_method", None),
            body_part_id=body_part_id,
            p7_der=p7_der,
            tpm_result=tpm_result
        )
    except Exception as exc:
        log_event(
            issuance_logger, logging.ERROR, "callback_exception",
            "Certificate issuance callback raised an exception",
            outcome="failure", reason="python_exception", exc_info=True,
            stage="issuance", ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'), callback_path=cb_path,
            callback_func=cb_issue, error_type=type(exc).__name__,
        )
        raise

    if not isinstance(result, dict):
        log_event(
            issuance_logger, logging.ERROR, "certificate_issue_failed",
            "Certificate callback returned an invalid result", outcome="failure",
            reason="invalid_callback_result", ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'), result_type=type(result).__name__,
        )
        return Response(
            "Certificate callback must return a mapping",
            status=500,
            content_type="text/plain; charset=utf-8",
        )

    status = str(result.get("status", "")).lower()

    if status == "unsupported_auth":
        log_event(
            issuance_logger, logging.INFO, "certificate_denied",
            "Certificate enrollment denied",
            outcome="failure", reason="unsupported_auth",
            ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'),
            detail=result.get("status_text") or "Unsupported authentication method",
        )
        return Response(
            result.get("status_text") or "Unsupported authentication method",
            status=401,
            headers={"WWW-Authenticate": result.get("www_authenticate", "Negotiate")},
        )

    csr_path = os.path.join(ca['__path_csr'], f"{request_id}.pem")

    if not os.path.isfile(csr_path):
        pem_csr = (
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "\n".join(textwrap.wrap(format_b64_for_soap(csr_der), 64)) +
            "\n-----END CERTIFICATE REQUEST-----"
        )

        try:
            os.makedirs(ca['__path_csr'], exist_ok=True)
            with open(csr_path, 'w') as f:
                f.write(pem_csr)
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_issue_failed",
                "Certificate issuance failed", outcome="failure", reason="csr_store_failed",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), error_type=type(exc).__name__,
            )
            raise

    ces_uri = f"{_https_base_url()}/CES/{CAID}"

    pkcs7_der = result.get("pkcs7_der")

    if status != 'pending':
        p7_path = os.path.join(app.confadcs['path_list_request_id'], str(request_id))
        if os.path.exists(p7_path):
            try:
                os.remove(p7_path)
            except Exception as exc:
                log_event(
                    issuance_logger, logging.ERROR, "certificate_issue_failed",
                    "Certificate issuance failed", outcome="failure",
                    reason="pending_state_cleanup_failed", exc_info=True, ca_id=CAID,
                    enrollment_request_id=request_id, template=tpl.get('common_name'),
                    error_type=type(exc).__name__,
                )
                raise
    else:
        try:
            with open(os.path.join(app.confadcs['path_list_request_id'], str(request_id)), 'wb') as f:
                f.write(p7_der)
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_issue_failed",
                "Certificate issuance failed", outcome="failure", reason="pending_state_store_failed",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), stage="callback_pending",
                error_type=type(exc).__name__,
            )
            raise

    if status in ("pending", "denied"):
        status_text = (
            result.get("status_text") or
            ("Waiting for processing" if status == "pending" else "Denied")
        )

        if status == "pending":
            log_event(
                issuance_logger, logging.INFO, "certificate_pending",
                "Certificate enrollment is pending",
                outcome="unknown", reason="callback_pending",
                ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), detail=status_text,
            )
        else:
            log_event(
                issuance_logger, logging.INFO, "certificate_denied",
                "Certificate enrollment denied",
                outcome="failure", reason="callback_denied",
                ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), detail=status_text,
                error_code=result.get("error_code", -2146877420),
            )

        try:
            if not pkcs7_der:
                pkcs7_der = build_adcs_bst_pkiresponse(
                    ca_der=ca["__certificate_der"],
                    ca_key=ca["__key_obj"],
                    request_id=request_id,
                    status=status,
                    status_text=status_text,
                    body_part_id=body_part_id
                )

            xml_body, http_code = build_ws_trust_response(
                pkcs7_der=pkcs7_der,
                relates_to=f"urn:uuid:{uuid_request}",
                request_id=request_id,
                ces_uri=ces_uri,
                status=status,
                disposition_message=status_text if status == "pending" else None,
                reason_text=status_text if status == "denied" else None,
                error_code=result.get("error_code", -2146877420),
                invalid_request=True,
                lang="en-US",
            )
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_response_failed",
                "Certificate response build failed", outcome="failure", reason="python_exception",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), status=status, error_type=type(exc).__name__,
            )
            raise

        return Response(
            xml_body.decode("utf-8"),
            content_type="application/soap+xml; charset=utf-8",
            status=http_code
        )

    elif status == "issued":
        cert_val = result.get("cert")

        if isinstance(cert_val, cx509.Certificate):
            cert_obj = cert_val
            cert_der = cert_val.public_bytes(serialization.Encoding.DER)

        elif isinstance(cert_val, (bytes, bytearray, memoryview)):
            cert_der = bytes(cert_val)
            try:
                cert_obj = cx509.load_der_x509_certificate(cert_der)
            except Exception as exc:
                log_event(
                    issuance_logger, logging.ERROR, "certificate_issue_failed",
                    "Certificate callback returned an invalid certificate", outcome="failure",
                    reason="invalid_callback_certificate", exc_info=True, ca_id=CAID,
                    enrollment_request_id=request_id, template=tpl.get('common_name'),
                    error_type=type(exc).__name__,
                )
                raise

        else:
            log_event(
                issuance_logger, logging.ERROR, "certificate_issue_failed",
                "Certificate callback did not return a certificate", outcome="failure",
                reason="callback_missing_certificate", ca_id=CAID,
                enrollment_request_id=request_id, template=tpl.get('common_name'),
            )
            return Response(
                "Callback(issued) must return 'cert' (x509 or DER bytes)",
                status=500,
                content_type="text/plain; charset=utf-8"
            )

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/2524682a-9587-4ac1-8adf-7e8094baa321
        if not pkcs7_der:
            try:
                pkcs7_der = build_adcs_bst_pkiresponse_issued(
                    cert_der,
                    ca["__certificate_der"],
                    ca["__key_obj"],
                    body_part_id
                )
            except Exception as exc:
                log_event(
                    issuance_logger, logging.ERROR, "certificate_issue_failed",
                    "Certificate issuance failed", outcome="failure", reason="pkcs7_build_failed",
                    exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                    template=tpl.get('common_name'), error_type=type(exc).__name__,
                )
                raise

        b64_p7 = format_b64_for_soap(pkcs7_der)
        b64_leaf = format_b64_for_soap(cert_der)

        try:
            os.makedirs(ca['__path_cert'], exist_ok=True)
            with open(os.path.join(ca['__path_cert'], f"{request_id}.pem"), 'w') as f:
                f.write(
                    "-----BEGIN CERTIFICATE-----\n" +
                    "\n".join(textwrap.wrap(b64_leaf, 64)) +
                    "\n-----END CERTIFICATE-----"
                )
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_issue_failed",
                "Certificate issuance failed", outcome="failure", reason="certificate_store_failed",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), error_type=type(exc).__name__,
            )
            raise

        log_event(
            issuance_logger, logging.INFO, "certificate_issued",
            "Certificate issued",
            outcome="success", ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'),
            serial=format(cert_obj.serial_number, "X"),
            subject=cert_obj.subject.rfc4514_string(),
            issuer=cert_obj.issuer.rfc4514_string(),
            certificate_fingerprint_sha256=cert_obj.fingerprint(hashes.SHA256()).hex(),
            tpm_used=bool(tpm_result.get("used")),
            tpm_attestation_valid=bool(tpm_result.get("attestation_valid")),
            tpm_ek_cert_sha256=tpm_result.get("ek_cert_sha256"),
            tpm_ek_public_key_identity_sha256=tpm_result.get("ek_public_key_identity_sha256"),
        )

        try:
            response_xml = build_ces_response(
                uuid_request=uuid_request,
                uuid_random=str(uuid.uuid4()),
                p7b_der=b64_p7,
                leaf_der=b64_leaf,
                body_part_id=body_part_id,
            )
        except Exception as exc:
            log_event(
                issuance_logger, logging.ERROR, "certificate_response_failed",
                "Certificate response build failed", outcome="failure", reason="python_exception",
                exc_info=True, ca_id=CAID, enrollment_request_id=request_id,
                template=tpl.get('common_name'), status="issued",
                serial=format(cert_obj.serial_number, "X"), error_type=type(exc).__name__,
            )
            raise

        return Response(response_xml, content_type='application/soap+xml')

    else:
        log_event(
            issuance_logger, logging.ERROR, "certificate_issue_failed",
            "Certificate callback returned an unknown status",
            outcome="failure", reason="unknown_callback_status",
            ca_id=CAID, enrollment_request_id=request_id,
            template=tpl.get('common_name'), status=status,
        )
        return Response(
            f"Unknown callback status '{status}'",
            status=500,
            content_type="text/plain; charset=utf-8"
        )


# ---------------- Main ----------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--confadcs",
        default="/etc/adcs/adcs.yaml",
        help="Path to the adcs.yaml file"
    )

    parser.add_argument(
        "--server",
        choices=["waitress", "flask"],
        default="waitress",
        help="Server to use when launching app.py directly. Default: waitress"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind. Default: 127.0.0.1"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind. Default: 8080"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=8,
        help="Number of Waitress threads. Default: 8"
    )

    args = parser.parse_args()

    init_app(args.confadcs)

    if args.server == "waitress":
        from waitress import serve

        serve(
            app,
            host=args.host,
            port=args.port,
            threads=args.threads,
            trusted_proxy="127.0.0.1",
            trusted_proxy_count=1,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-port",
            },
            clear_untrusted_proxy_headers=True,
        )

    else:
        app.run(
            host=args.host,
            port=args.port
        )