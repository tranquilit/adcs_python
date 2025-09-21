#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, Response, g
import os
import uuid
import base64
import textwrap
import hashlib
import datetime
from defusedxml import ElementTree as ET  # anti-XXE / billion-laughs

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from decoratorkrb import kerberos_auth_required

from utils import (
    build_adcs_bst_certrep,
    format_b64_for_soap,
    exct_csr_from_cmc,
    search_user,
    validate_csr,              # CSR validation
)

from adcs_config import load_yaml_conf, build_templates_for_policy_response
from callback_loader import load_func

# ------------- SOAP parsing security -------------
MAX_SOAP_BYTES = 2 * 1024 * 1024  # 2 MiB: hard limit to avoid OOM

app = Flask(__name__)

# ---------------- Endpoints ----------------

@app.route('/ADPolicyProvider_CEP_Kerberos/service.svc/CEP', methods=['POST', 'GET'])
@kerberos_auth_required
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
    try:
        samdbr, entry = search_user(kerberos_user)
    except Exception:
        samdbr, entry = None, {}

    # Build templates + OIDs for THIS CEP response (user-dependent)
    templates_for_user, oids_for_user = build_templates_for_policy_response(
        app.confadcs,
        kerberos_user=kerberos_user,
        samdb=samdbr,
        sam_entry=entry,
    )

    # Keep an in-memory index (optional, no longer required by CES)
    app.confadcs['templates_by_template_oid_value'] = {
        (t.get("template_oid") or {}).get("value"): t for t in templates_for_user
    }

    response_xml = app.confadcs['tpl_cep'].render(
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


@app.route('/<CANAME>-ADCS-CA_CES_Kerberos/service.svc/CES', methods=['POST'])
@kerberos_auth_required
def ces_service(CANAME):
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
    uuid_request = message_id_elem.text.replace("urn:uuid:", "") if message_id_elem is not None else ''

    # --- If pending request
    request_id = None
    root = ET.fromstring(rst_xml)
    request_id_elem = root.find(".//enr:RequestID", { "enr": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"})
    if request_id_elem is not None:
        request_id = request_id_elem.text
        print('pending request %s' % str(request_id))
    
    # --- Retrieve PKCS#7 (BinarySecurityToken)
    ns_wsse = {'wsse': "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"}
    bst_node = root.find('.//wsse:BinarySecurityToken', ns_wsse)
    if bst_node is None or not (bst_node.text or '').strip():
        return Response("Missing BinarySecurityToken", status=400, content_type="text/plain; charset=utf-8")

    try:
        p7_der = base64.b64decode(bst_node.text)
    except Exception:
        return Response("BinarySecurityToken is not base64", status=400, content_type="text/plain; charset=utf-8")

    # --- CMC -> extract CSR + info (incl. template OID)
    try:
        csr_der, body_part_id, info = exct_csr_from_cmc(p7_der)
    except Exception as e:
        return Response(f"Cannot extract CSR from CMC: {e}", status=400, content_type="text/plain; charset=utf-8")

    body_part_id =  int(str(int(datetime.datetime.utcnow().timestamp())) + str(int(hashlib.sha256(csr_der).hexdigest(), 16)))

    # --- CSR validation (signature algo, key, etc.)
    try:
        csr_obj = cx509.load_der_x509_csr(csr_der)
    except Exception:
        return Response("Invalid CSR: cannot decode DER", status=400, content_type="text/plain; charset=utf-8")

    try:
        validate_csr(csr_obj)
    except Exception as e:
        return Response(f"Invalid CSR: {e}", status=400, content_type="text/plain; charset=utf-8")

    # --- User resolution (for callbacks)
    kerberos_user = g.kerberos_user
    try:
        samdbr, entry = search_user(kerberos_user)
    except Exception:
        samdbr, entry = None, {}

    # --- IMPORTANT: (re)build templates FOR THIS CES request
    templates_for_user, _ = build_templates_for_policy_response(
        app.confadcs,
        kerberos_user=kerberos_user,
        samdb=samdbr,
        sam_entry=entry,
    )
    tmap = { (t.get("template_oid") or {}).get("value"): t for t in templates_for_user }

    # --- Resolve template from OID found in CSR
    tpl = tmap.get(info.get('oid'))
    if tpl is None:
        return Response("Unknown template OID", status=400, content_type="text/plain; charset=utf-8")

    # --- Pick target CA referenced by template (first in list), else default CA
    ca_ref_ids = tpl.get("__ca_refids", [])
    if ca_ref_ids:
        ca = app.confadcs["cas_by_refid"].get(ca_ref_ids[0], app.confadcs['default_ca'])
    else:
        ca = app.confadcs['default_ca']

    # --- Save CSR (optional, handy for debug/forensics)
    sha256_hex = hashlib.sha256(csr_der).hexdigest()
    os.makedirs(ca['__path_csr'], exist_ok=True)
    pem_csr = (
        "-----BEGIN CERTIFICATE REQUEST-----\n" +
        "\n".join(textwrap.wrap(format_b64_for_soap(csr_der), 64)) +
        "\n-----END CERTIFICATE REQUEST-----"
    )
    with open(os.path.join(ca['__path_csr'], f"{body_part_id}.pem"), 'w') as f:
        f.write(pem_csr)

    # --- Call emission callback (mandatory in 100% callback mode)
    cb = tpl.get("__callback") or {}
    cb_path = cb.get("path")
    cb_issue = cb.get("issue")
    if not (cb_path and cb_issue):
        return Response("Template callback missing 'path'/'issue'", status=500, content_type="text/plain; charset=utf-8")

    emit_certificate = load_func(cb_path, cb_issue)
    result = emit_certificate(
        csr_der=csr_der,
        kerberos_user=kerberos_user,
        samdb=samdbr,
        sam_entry=entry,
        ca=ca,
        template=tpl,
        info=info,
        app_conf=app.confadcs,
        CANAME=CANAME,
    )

    # --- Result: x509.Certificate or DER bytes
    if isinstance(result, cx509.Certificate):
        cert_obj = result
        cert_der = result.public_bytes(serialization.Encoding.DER)
    elif isinstance(result, (bytes, bytearray, memoryview)):
        cert_der = bytes(result)
        cert_obj = cx509.load_der_x509_certificate(cert_der)
    else:
        return Response("Callback must return x509.Certificate or DER bytes", status=500, content_type="text/plain; charset=utf-8")

#    from utils import build_adcs_bst_pkiresponse_pending  # ← au lieu de build_adcs_cmc_pending
#    from utils import build_ws_trust_pending_response
#    
#    pkcs7_der = build_adcs_bst_pkiresponse_pending(
#        ca_der=ca["__certificate_der"],         # cert DER qui signe (CA/service)
#        ca_key=ca["__key_obj"],                  # clé privée correspondante
#        request_id=82,                           # même ID que dans la réponse SOAP
#        status_text="En attente de traitement",  # message affiché par Windows
#        body_part_id=1,                          # par défaut 1 (ok)
#    )
#    
#    xml_rstrc = build_ws_trust_pending_response(
#        pkcs7_der=pkcs7_der,
#        relates_to=f"urn:uuid:{uuid_request}",
#        request_id=82,  # doit matcher le pendToken / request_id du PKIResponse
#        ces_uri="https://testadcs.ad.tranquil.it/Test%20Intermediate%20CA-ADCS-CA_CES_Kerberos/service.svc/CES",
#    )
#     
#
#    # 3) Retourner/servir le XML (bytes UTF-8)
#    print(xml_rstrc.decode("utf-8"))
#    return Response(xml_rstrc.decode("utf-8"), content_type='application/soap+xml')
#

    # --- Build PKCS#7 (BST) signed by the CA (behavior "like ADCS")

    p7b_der = build_adcs_bst_certrep(
        cert_der,
        ca["__certificate_der"],
        ca["__key_obj"],
        body_part_id
    )

    b64_p7 = format_b64_for_soap(p7b_der)
    b64_leaf = format_b64_for_soap(cert_der)

    # --- Save cert
    os.makedirs(ca['__path_cert'], exist_ok=True)
    with open(os.path.join(ca['__path_cert'], f"{body_part_id}.pem"), 'w') as f:
        f.write(
            "-----BEGIN CERTIFICATE-----\n" +
            "\n".join(textwrap.wrap(b64_leaf, 64)) +
            "\n-----END CERTIFICATE-----"
        )

    response_xml = app.confadcs['tpl_ces'].render(
        uuid_request=uuid_request or str(uuid.uuid4()),
        uuid_random=str(uuid.uuid4()),
        p7b_der=b64_p7,
        leaf_der=b64_leaf,
        body_part_id=body_part_id
    )
    return Response(response_xml, content_type='application/soap+xml')

# ---------------- Main ----------------

if __name__ == '__main__':
    app.confadcs = load_yaml_conf("adcs.yaml")
    decls = app.confadcs.get("__template_decls__") or []
    print("Loaded config with", len(decls), "template declaration(s).")
    app.run(host='127.0.0.1', port=8080)


