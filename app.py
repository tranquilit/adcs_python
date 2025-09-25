#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, Response, g
from waitress import serve
import os
import uuid
import base64
import textwrap
import hashlib
import datetime
from defusedxml import ElementTree as ET  # anti-XXE / billion-laughs

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from decoratorauth import auth_required

from utils import (
    build_adcs_bst_certrep,
    format_b64_for_soap,
    exct_csr_from_cmc,
    search_user,
    validate_csr,
    build_adcs_bst_pkiresponse,
    build_ws_trust_response,
    build_get_policies_response,
    build_ces_response
)

from adcs_config import load_yaml_conf, build_templates_for_policy_response
from callback_loader import load_func

# ------------- SOAP parsing security -------------
MAX_SOAP_BYTES = 2 * 1024 * 1024  # 2 MiB: hard limit to avoid OOM

app = Flask(__name__)

def _https_base_url():

    host_url = request.host_url.rsplit('/', 1)[0]
    return host_url.replace("http://", "https://")


# ---------------- Endpoints ----------------

@app.route('/CEP', methods=['POST', 'GET'])
@auth_required
def cep_service():
    host_url = request.host_url.rsplit('/', 1)[0]
    raw = request.data or b""
    if len(raw) > MAX_SOAP_BYTES:
        return Response("Request too large", status=413, content_type="text/plain; charset=utf-8")
    try:
        xml_data = raw.decode('utf-8', errors='replace')
    except Exception:
        return Response("Invalid encoding", status=400, content_type="text/plain; charset=utf-8")
    print(f"[CEP] Request from {g.kerberos_user} (len={len(raw)} bytes)")

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
        except Exception:
            # Continue: CEP can generate a response without correlation if parsing fails
            uuid_request = ''

    uuid_random = str(uuid.uuid4())
    relates_to = uuid_request or uuid_random

    # User resolution for CEP (same as for CES)
    kerberos_user = g.kerberos_user

    # Build templates + OIDs for THIS CEP response (user-dependent)
    templates_for_user, oids_for_user = build_templates_for_policy_response(
        app.confadcs,
        kerberos_user=kerberos_user,
        request=request
    )

    # Keep an in-memory index (optional, no longer required by CES)
    app.confadcs['templates_by_template_oid_value'] = {
        (t.get("template_oid") or {}).get("value"): t for t in templates_for_user
    }

    response_xml = build_get_policies_response(
        uuid_request=relates_to,
        uuid_random=uuid_random,
        hosturl=host_url.replace('http://', 'https://'),
        policyid=app.confadcs['policyid'],
        next_update_hours=app.confadcs['next_update_hours'],
        cas=app.confadcs['cas_list'],
        templates=templates_for_user,   # static extensions already materialized
        oids=oids_for_user,             # OIDs registry for policyOIDReference / oIDReference
    )
    return Response(response_xml, content_type='application/soap+xml')


@app.route('/CES/<CAID>', methods=['POST'])
@auth_required
def ces_service(CAID):
    raw = request.data or b""
    if len(raw) > MAX_SOAP_BYTES:
        return Response("Request too large", status=413, content_type="text/plain; charset=utf-8")
    try:
        rst_xml = raw.decode('utf-8', errors='replace')
    except Exception:
        return Response("Invalid encoding", status=400, content_type="text/plain; charset=utf-8")

    # --- Get request UUID (optional)
    try:
        root = ET.fromstring(rst_xml)
    except Exception:
        return Response("Bad SOAP: cannot parse XML", status=400, content_type="text/plain; charset=utf-8")

    namespaces = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'a': 'http://www.w3.org/2005/08/addressing'
    }
    message_id_elem = root.find('.//a:MessageID', namespaces)
    uuid_request = message_id_elem.text.replace("urn:uuid:", "")


    req_id_elem = root.find(".//enr:RequestID", {"enr": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"})
    if req_id_elem is not None and (req_id_elem.text or "").strip():
        request_id = int(req_id_elem.text.strip())
        with open (os.path.join(app.confadcs['path_list_request_id'],str(request_id)) ,'rb') as f:
            p7_der = f.read()
    else:
        ns_wsse = {'wsse': "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"}
        bst_node = root.find('.//wsse:BinarySecurityToken', ns_wsse)
        p7_der = base64.b64decode(bst_node.text)
        request_id = uuid.uuid4().int
        with open (os.path.join(app.confadcs['path_list_request_id'],str(request_id)) ,'wb') as f:
            f.write(p7_der)

    csr_der, body_part_id, info = exct_csr_from_cmc(p7_der)

    kerberos_user = g.kerberos_user

    # --- IMPORTANT: (re)build templates FOR THIS CES request
    templates_for_user, _ = build_templates_for_policy_response(
        app.confadcs,
        kerberos_user=kerberos_user,
        request=request
    )

    tmap = { (t.get("template_oid") or {}).get("value"): t for t in templates_for_user }
    tmap_name = { t.get("common_name") : t for t in templates_for_user }

    if info.get('oid'):
        tpl = tmap.get(info.get('oid'))
    else:
        tpl = tmap_name.get(info.get('name'))
    if not CAID in tpl['ca_references']:
        return Response('%s not in ca_references for template %s' % (CAID, tpl['template_oid']['value']) , 403)        
    dict_id_ca = {u['id'] : u for u in app.confadcs['cas_list']}

    ca = dict_id_ca[CAID]

    cb = (tpl.get("__callback") if tpl else (app.confadcs.get("__default_callback"))) or {}
    cb_path = cb.get("path")
    cb_issue = cb.get("issue")

    emit_certificate = load_func(cb_path, cb_issue)


    result = emit_certificate(
        csr_der=csr_der,
        request_id=request_id,
        kerberos_user=kerberos_user,
        ca=ca,
        template=tpl,
        info=info,
        app_conf=app.confadcs,
        CAID=CAID,
        request=request
    )

    csr_path = os.path.join(ca['__path_csr'], f"{request_id}.pem")
    if not os.path.isfile(csr_path) :
        os.makedirs(ca['__path_csr'], exist_ok=True)
        pem_csr = (
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "\n".join(textwrap.wrap(format_b64_for_soap(csr_der), 64)) +
            "\n-----END CERTIFICATE REQUEST-----"
        )

        with open(csr_path, 'w') as f:
            f.write(pem_csr)
    
    status = str(result["status"]).lower()


    ces_uri = f"{_https_base_url()}/CES/{CAID}"
    if status in ("pending", "denied"):

        status_text = (result.get("status_text") or
                       ("Waiting for processing" if status == "pending" else "Denied"))
    

        pkcs7_der = build_adcs_bst_pkiresponse(
            ca_der=ca["__certificate_der"],
            ca_key=ca["__key_obj"],
            request_id=request_id,
            status=status,              # "pending" ou "denied"
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
            lang="fr-FR",
        )
    
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
            cert_obj = cx509.load_der_x509_certificate(cert_der)
        else:
            return Response("Callback(issued) must return 'cert' (x509 or DER bytes)", status=500, content_type="text/plain; charset=utf-8")

        ##https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/2524682a-9587-4ac1-8adf-7e8094baa321
        p7b_der = build_adcs_bst_certrep(
            cert_der,
            ca["__certificate_der"],
            ca["__key_obj"],
            body_part_id
        )

        b64_p7 = format_b64_for_soap(p7b_der)
        b64_leaf = format_b64_for_soap(cert_der)


        os.makedirs(ca['__path_cert'], exist_ok=True)
        with open(os.path.join(ca['__path_cert'], f"{request_id}.pem"), 'w') as f:
            f.write(
                "-----BEGIN CERTIFICATE-----\n" +
                "\n".join(textwrap.wrap(b64_leaf, 64)) +
                "\n-----END CERTIFICATE-----"
            )

        response_xml = build_ces_response(
            uuid_request=uuid_request,
            uuid_random=str(uuid.uuid4()),
            p7b_der=b64_p7,
            leaf_der=b64_leaf,
            body_part_id=body_part_id,
        )
        
        return Response(response_xml, content_type='application/soap+xml')

    else:
        return Response(f"Unknown callback status '{status}'", status=500, content_type="text/plain; charset=utf-8")


# ---------------- Main ----------------

if __name__ == '__main__':
    app.confadcs = load_yaml_conf("adcs.yaml")
    decls = app.confadcs.get("__template_decls__") or []
    print("Loaded config with", len(decls), "template declaration(s).")
    #app.run(host='127.0.0.1', port=8080)
    serve(app, host="127.0.0.1", port=8080)




