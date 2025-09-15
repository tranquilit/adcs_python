from flask import Flask, request, Response, g
import os
import uuid
import base64
import configparser
import textwrap
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from jinja2 import Template
from utils import CertificateTemplate,SMIMECapabilities,SMIMECapability,NtdsAttr,NtdsCASecurityExt,build_adcs_bst_certrep,format_b64_for_soap
from utils import exct_csr_from_cmc,search_user

from asn1crypto import x509 as a_x509, core as a_core

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import (
    NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID,
    ObjectIdentifier as CObjectIdentifier
)
from decorator import kerberos_auth_required

app = Flask(__name__)

@app.route('/ADPolicyProvider_CEP_Kerberos/service.svc/CEP', methods=['POST', 'GET'])
@kerberos_auth_required
def cep_service():
    host_url = request.host_url.rsplit('/', 1)[0]
    xml_data = request.data.decode('utf-8')
    print(f"[CEP] Request from {g.kerberos_user}:\n{xml_data}")

    rst_xml = xml_data
    if rst_xml:
        root = ET.fromstring(rst_xml)
        namespaces = {
            's': 'http://www.w3.org/2003/05/soap-envelope',
            'a': 'http://www.w3.org/2005/08/addressing'
        }
        message_id_elem = root.find('.//a:MessageID', namespaces)
        uuid_request = message_id_elem.text.replace("urn:uuid:", "") if message_id_elem is not None else ''
    else:
        uuid_request = ''

    response_xml = app.confadcs['tpl_adpolicyprovider'].render(    uuid_request=uuid_request,
                                  uuid_random=str(uuid.uuid4()),
                                  hosturl=host_url.replace('http://', 'https://'),
                                  ca_certificate=app.confadcs['ca_certificate'].replace('\n', ''),
                                  policyid = app.confadcs['policyid']
                              )

    return Response(response_xml, content_type='application/soap+xml')

@app.route('/caflask-ADCS-CA_CES_Kerberos/service.svc/CES', methods=['POST'])
@kerberos_auth_required
def ces_service():
    rst_xml = request.data.decode('utf-8')

    root = ET.fromstring(rst_xml)
    namespaces = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'a': 'http://www.w3.org/2005/08/addressing'
    }
    message_id_elem = root.find('.//a:MessageID', namespaces)
    uuid_request = message_id_elem.text.replace("urn:uuid:", "") if message_id_elem is not None else ''

    ns = {'wsse': "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"}
    p7_b64 = ET.fromstring(rst_xml).find('.//wsse:BinarySecurityToken', ns).text
    p7_der = base64.b64decode(p7_b64)

    csr_der, body_part_id, info = exct_csr_from_cmc(p7_der)

    sha256_hex = hashlib.sha256(csr_der).hexdigest()

    with open(os.path.join(app.confadcs['path_csr'],str(sha256_hex) + '.pem'),'w') as f :
        f.write("-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(textwrap.wrap(format_b64_for_soap(csr_der), 64)) + "\n-----END CERTIFICATE REQUEST-----")

    ca_cert_pem = base64.b64decode(app.confadcs['ca_certificate'])
    ca_key_pem  = base64.b64decode(app.confadcs['ca_pem'])

    samdbr,entry = search_user(g.kerberos_user)
    sid = samdbr.schema_format_value("objectSID", entry["objectSID"][0])
    sr = cx509.random_serial_number()
    leaf = issue_cert(csr_der, 
                      ca_cert_pem, ca_key_pem,cn=g.kerberos_user,
                      crl_http_url = app.confadcs['crl_http_url'],
                      ca_issuers_http_url = app.confadcs['ca_issuers_http_url'],
                      sid_bytes = sid,
                      info_csr=info,
                      sr=sr)

    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    p7b_der = build_adcs_bst_certrep(leaf_der, ca_cert_pem, app.confadcs['ca_key_load'], body_part_id)
    b64_leaf=format_b64_for_soap(p7b_der)

    with open(os.path.join(app.confadcs['path_cert'],str(sr) + '.pem'),'w') as f :
        f.write("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64_leaf, 64)) + "\n-----END CERTIFICATE-----")

    response_xml = app.confadcs['tpl_adcs_ca_ces_Kerberos_service_svc_CES'].render(    uuid_request=uuid_request,
                                  uuid_random=str(uuid.uuid4()),
                                  p7b_der=b64_leaf,
                                  leaf_der = format_b64_for_soap(leaf_der),
                                  body_part_id=body_part_id
                              )



    return Response(response_xml, content_type='application/soap+xml')
def issue_cert(csr_der: bytes, ca_cert_der: bytes, ca_key_der: bytes, cn: str, crl_http_url: str,ca_issuers_http_url: str,sid_bytes: bytes, info_csr=None, entry_ad = None, sr = None) -> cx509.Certificate:
    csr_obj  = cx509.load_der_x509_csr(csr_der)
    ca_cert  = cx509.load_der_x509_certificate(ca_cert_der)
    ca_key   = serialization.load_der_private_key(ca_key_der, password=None)
    now = datetime.utcnow() - timedelta(minutes=5)

    #subject = csr_obj.subject if csr_obj.subject.rdns else cx509.Name([
    #    cx509.NameAttribute(NameOID.COMMON_NAME, cn )
    #])

    subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn )])

    san_ext = None
    eku_ext = None
    ku_ext  = None

    #TODO SECURITY check if the values allow
    #TODO retrieve values from the ad, depending on the template define the authorized values.

    for ext in csr_obj.extensions:
        if isinstance(ext.value, cx509.SubjectAlternativeName):
            san_ext = ext.value
        elif isinstance(ext.value, cx509.ExtendedKeyUsage):
            eku_ext = ext.value
        elif isinstance(ext.value, cx509.KeyUsage):
            ku_ext = ext.value

    if san_ext is None:
        san_ext = cx509.SubjectAlternativeName([])
    if eku_ext is None:
        eku_ext = cx509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    if ku_ext is None:
        ku_ext = cx509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        )

    cdp = cx509.CRLDistributionPoints([
        cx509.DistributionPoint(
            full_name=[cx509.UniformResourceIdentifier(crl_http_url)],
            relative_name=None, reasons=None, crl_issuer=None
        )
    ])
    aia = cx509.AuthorityInformationAccess([
        cx509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            cx509.UniformResourceIdentifier(ca_issuers_http_url)
        )
    ])

    template_id_oid = info_csr['oid']
    template_major  = info_csr['major']
    template_minor  = info_csr['minor']

    cert_template_der = CertificateTemplate({
        "template_id":   template_id_oid,
        "major_version": template_major,
        "minor_version": template_minor,
    }).dump()

    policies = a_x509.CertificatePolicies()
    for oid in [
        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
        ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string,
        "1.3.6.1.4.1.311.10.3.4",
    ]:
        policies.append(a_x509.PolicyInformation({"policy_identifier": oid}))
    app_policies_der = policies.dump()

    smime_caps = SMIMECapabilities([
        SMIMECapability({"capability_id": "1.2.840.113549.3.2", "parameters": a_core.Integer(128)}),
        SMIMECapability({"capability_id": "1.2.840.113549.3.4", "parameters": a_core.Integer(128)}),
        SMIMECapability({"capability_id": "1.3.14.3.2.7"}),
        SMIMECapability({"capability_id": "1.2.840.113549.3.7"}),
    ])
    smime_der = smime_caps.dump()

    ntds_attr = NtdsAttr({
        "attr_id":     "1.3.6.1.4.1.311.25.2.1",
        "attr_values": [a_core.OctetString(sid_bytes)],
    })
    ntds_der = NtdsCASecurityExt([ntds_attr]).dump()
    if not sr :
        sr = cx509.random_serial_number()
    builder = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr_obj.public_key())
        .serial_number(sr)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(ku_ext, critical=True)
        .add_extension(eku_ext, critical=False)
        .add_extension(san_ext, critical=False)
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(csr_obj.public_key()), critical=False)
        .add_extension(cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .add_extension(cdp, critical=False)
        .add_extension(aia, critical=False)
        .add_extension(cx509.UnrecognizedExtension(CObjectIdentifier("1.3.6.1.4.1.311.21.7"),  cert_template_der), critical=False)
        .add_extension(cx509.UnrecognizedExtension(CObjectIdentifier("1.3.6.1.4.1.311.21.10"), app_policies_der),  critical=False)
        .add_extension(cx509.UnrecognizedExtension(CObjectIdentifier("1.2.840.113549.1.9.15"), smime_der),         critical=False)
        .add_extension(cx509.UnrecognizedExtension(CObjectIdentifier("1.3.6.1.4.1.311.25.2"),  ntds_der),          critical=False)
    )

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert

 
if __name__ == '__main__':


    confadcs={}

    config = configparser.ConfigParser()
    config.read("config.ini", encoding="utf-8")
    
    path_ca_cert = config.get("global", "ca_certificate_path")
    path_ca_key = config.get("global", "ca_key_path")

    confadcs['crl_http_url']        = config.get("global", "crl_http_url")
    confadcs['ca_issuers_http_url'] = config.get("global", "ca_issuers_http_url")
    confadcs['policyid'] = config.get("global", "policyid")
    confadcs['path_cert'] = config.get("global", "path_cert")
    confadcs['path_csr'] = config.get("global", "path_csr")

    with open(path_ca_cert, 'r') as f:
        confadcs['ca_certificate'] = (
            f.read().split('-----')[2]
            .strip()
        )

    with open(path_ca_key, 'r') as f:
        ca_pem = (
            f.read().split('-----')[2]
            .strip()
        )

    confadcs['ca_pem'] = ca_pem
    
    with open("template/GetPoliciesResponse.xml", "r", encoding="utf-8") as f:
        confadcs['tpl_adpolicyprovider'] = Template(f.read())
    
    with open("template/ADCS-CA_CES_Kerberos_service.svc_CES.xml", "r", encoding="utf-8") as f:
        confadcs['tpl_adcs_ca_ces_Kerberos_service_svc_CES'] = Template(f.read())
    
    with open(path_ca_key, "rb") as f:
        confadcs['ca_key_load'] = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    app.confadcs=confadcs
    app.run(host='127.0.0.1', port=8080)

