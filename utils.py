from asn1crypto import csr
from asn1crypto import cms as a_cms, x509 as a_x509, core as a_core
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
import base64

OID_MS_CERT_TEMPLATE_NAME = '1.3.6.1.4.1.311.20.2'
OID_MS_CERT_TEMPLATE_INFO = '1.3.6.1.4.1.311.21.7'

class _TaggedCertificationRequest(a_cms.Sequence):
    _fields = [
        ("bodyPartID", a_cms.Integer),
        ("certificationRequest", csr.CertificationRequest),
    ]

class _CertReqMsg(a_core.Any):
    pass

class _ORM(a_core.Any):
    pass

class _TaggedRequest(a_cms.Choice):
    _alternatives = [
        ("tcr", _TaggedCertificationRequest, {"implicit": 0}),
        ("crm", _CertReqMsg,               {"implicit": 1}),
        ("orm", _ORM,                      {"implicit": 2}),
    ]

class _TaggedRequests(a_cms.SequenceOf):
    _child_spec = _TaggedRequest


class _Controls(a_cms.SequenceOf):
    _child_spec = a_core.Any

class _TaggedContentInfos(a_cms.SequenceOf):
    _child_spec = a_core.Any

class _OtherMsgs(a_cms.SequenceOf):
    _child_spec = a_core.Any

class PKIData(a_cms.Sequence):
    _fields = [
        ("controlSequence", _Controls),
        ("reqSequence", _TaggedRequests),
        ("cmsSequence", _TaggedContentInfos),
        ("otherMsgSequence", _OtherMsgs),
    ]

class CertificateTemplate(a_core.Sequence):
    _fields = [
        ("template_id",   a_core.ObjectIdentifier),
        ("major_version", a_core.Integer),
        ("minor_version", a_core.Integer),
    ]

class SMIMECapability(a_core.Sequence):
    _fields = [("capability_id", a_core.ObjectIdentifier),
               ("parameters",    a_core.Any, {"optional": True})]

class SMIMECapabilities(a_core.SequenceOf):
    _child_spec = SMIMECapability

class NtdsAttr(a_core.Sequence):
    _fields = [("attr_id",     a_core.ObjectIdentifier),
               ("attr_values", a_core.SetOf, {"spec": a_core.OctetString})]

class NtdsCASecurityExt(a_core.SequenceOf):
    _child_spec = NtdsAttr

class PKIStatusInfo(a_core.Sequence):
    _fields = [('status', a_core.Integer),
               ('status_string', a_core.SequenceOf, {'spec': a_core.UTF8String, 'optional': True}),
               ('fail_info', a_core.BitString, {'optional': True})]

class CertOrEncCert(a_core.Choice):
    _alternatives = [('certificate', a_x509.Certificate),
                     ('encrypted_cert', a_core.Any)]

class CertifiedKeyPair(a_core.Sequence):
    _fields = [('cert_or_enc_cert', CertOrEncCert),
               ('private_key', a_core.Any, {'optional': True}),
               ('publication_info', a_core.Any, {'optional': True})]

class CertResponse(a_core.Sequence):
    _fields = [('cert_req_id', a_core.Integer),
               ('status', PKIStatusInfo),
               ('certified_key_pair', CertifiedKeyPair, {'optional': True}),
               ('rsp_info', a_core.OctetString, {'optional': True})]

class CertRepMessage(a_core.Sequence):
    _fields = [('ca_pubs', a_core.SequenceOf, {'spec': a_x509.Certificate, 'optional': True}),
               ('response', a_core.SequenceOf, {'spec': CertResponse})]

class _PKIDataRelax(a_core.Sequence):
    _fields = [
        ('controlSequence', a_core.SequenceOf, {'spec': a_core.Any, 'optional': True}),
        ('reqSequence',     a_core.SequenceOf, {'spec': a_core.Any, 'optional': True}),
        ('cmsSequence',     a_core.SequenceOf, {'spec': a_core.Any, 'optional': True}),
        ('otherMsgSequence',a_core.SequenceOf, {'spec': a_core.Any, 'optional': True}),
    ]

class _TCRRelax(a_core.Sequence):
    _fields = [
        ('bodyPartID', a_core.Integer),
        ('certificationRequest', csr.CertificationRequest),
    ]


class _SeqOfCSR(a_core.SequenceOf):
    _child_spec = csr.CertificationRequest


class _MsCertTemplateInfo(a_core.Sequence):
    _fields = [
        ('templateID',   a_core.ObjectIdentifier),
        ('majorVersion', a_core.Integer, {'optional': True}),
        ('minorVersion', a_core.Integer, {'optional': True}),
    ]


def _der_wrap_sequence(contents: bytes) -> bytes:
    n = len(contents)
    if n < 128:
        return b'\x30' + bytes([n]) + contents
    lb = []
    x = n
    while x:
        lb.append(x & 0xff)
        x >>= 8
    lb.reverse()
    return b'\x30' + bytes([0x80 | len(lb)]) + bytes(lb) + contents


def _parse_template_from_csr_bytes(csr_der: bytes) -> dict:

    tpl = {"name": None, "oid": None, "major": None, "minor": None}

    csr_obj = csr.CertificationRequest.load(csr_der)
    cri = csr_obj['certification_request_info']

    for attr in cri['attributes']:
        if attr['type'].dotted != '1.2.840.113549.1.9.14':
            continue

        for val in attr['values']:
            exts = a_x509.Extensions.load(val.dump()) if not isinstance(val, a_x509.Extensions) else val
            for ext in exts:
                ext_oid = ext['extn_id'].dotted
                inner_der = ext['extn_value'].parsed.dump()

                if ext_oid == OID_MS_CERT_TEMPLATE_NAME:
                    name = None
                    for typ in (a_core.BMPString, a_core.UTF8String, a_core.PrintableString, a_core.TeletexString):
                        try:
                            name = typ.load(inner_der).native
                            break
                        except Exception:
                            pass
                    if name is None:
                        try:
                            name = bytes(inner_der).decode('utf-16-le')
                        except Exception:
                            pass
                    tpl['name'] = name

                elif ext_oid == OID_MS_CERT_TEMPLATE_INFO:
                    info = _MsCertTemplateInfo.load(inner_der)
                    tpl['oid'] = info['templateID'].dotted
                    if info['majorVersion'].native is not None:
                        tpl['major'] = int(info['majorVersion'].native)
                    if info['minorVersion'].native is not None:
                        tpl['minor'] = int(info['minorVersion'].native)


    return tpl

def exct_csr_from_cmc(p7_der: bytes) -> tuple[bytes, int, dict]:
    ci = a_cms.ContentInfo.load(p7_der)
    if ci["content_type"].native != "signed_data":
        raise ValueError("ContentInfo.content_type != signed_data")

    sd = ci["content"] 
    eci = sd["encap_content_info"]

    if eci["content"] is None:
        raise ValueError("SignedData without encapsulated content (detached)")

    pki_octets: bytes = eci["content"].native

    try:
        pkidata_relax = _PKIDataRelax.load(pki_octets)
        if pkidata_relax['reqSequence'] is not None:
            for any_item in pkidata_relax['reqSequence']:
                try:
                    wrapped = _der_wrap_sequence(any_item.contents)
                    tcr = _TCRRelax.load(wrapped)
                    csr_obj = tcr['certificationRequest']
                    body_part_id = int(tcr['bodyPartID'].native)
                    csr_bytes = csr_obj.dump()
                    template_info = _parse_template_from_csr_bytes(csr_bytes)
                    return csr_bytes, body_part_id, template_info
                except Exception:
                    continue
    except Exception:
        pass

    try:
        seq = _SeqOfCSR.load(pki_octets)
        if len(seq) >= 1:
            csr_bytes = seq[0].dump()
            body_part_id = 0
            template_info = _parse_template_from_csr_bytes(csr_bytes)
            return csr_bytes, body_part_id, template_info
    except Exception:
        pass

    try:
        csr_obj = csr.CertificationRequest.load(pki_octets)
        csr_bytes = csr_obj.dump()
        body_part_id = 0
        template_info = _parse_template_from_csr_bytes(csr_bytes)
        return csr_bytes, body_part_id, template_info
    except Exception:
        pass

    ct = eci['content_type'].dotted if eci['content_type'] is not None else 'unknown'
    raise ValueError(
    f"Unable to extract a CSR: no TCR, no simplePKIRequest, nor a direct CSR. "
    f"EncapContentInfo.content_type={ct}"
    )

def _tbs_signed_attrs(attrs: a_cms.CMSAttributes) -> bytes:
    der = attrs.dump()
    return (b"\x31" + der[1:]) if der and der[0] == 0xA0 else der

def build_adcs_bst_certrep(child_der: bytes, ca_der: bytes, ca_key, cert_req_id: int) -> bytes:

    leaf_cert = a_x509.Certificate.load(child_der)
    ca_cert   = a_x509.Certificate.load(ca_der)

    status = PKIStatusInfo({'status': 0})
    ckp = CertifiedKeyPair({'cert_or_enc_cert': ('certificate', leaf_cert)})
    cert_resp = CertResponse({'cert_req_id': cert_req_id, 'status': status, 'certified_key_pair': ckp})
    certrep = CertRepMessage({'response': [cert_resp]})
    certrep_der = certrep.dump()

    encap_content_info = a_cms.EncapsulatedContentInfo({
        'content_type': a_cms.ContentType('1.3.6.1.5.5.7.12.2'),
        'content': a_cms.ParsableOctetString(certrep_der),
    })

    signed_attrs = a_cms.CMSAttributes([
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.3', 'values': [a_cms.ContentType('1.3.6.1.5.5.7.12.2')]}),
        a_cms.CMSAttribute({'type': '1.2.840.113549.1.9.4', 'values': [hashlib.sha256(certrep_der).digest()]}),
    ])


    to_be_signed = _tbs_signed_attrs(signed_attrs)

    signature = ca_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())
    digest_alg = a_cms.DigestAlgorithm({'algorithm': 'sha256'})
    signer_info = a_cms.SignerInfo({
        'version': 'v1',
        'sid': a_cms.SignerIdentifier({
            'issuer_and_serial_number': a_cms.IssuerAndSerialNumber({
                'issuer': ca_cert.issuer,
                'serial_number': ca_cert.serial_number,
            })
        }),
        'digest_algorithm': a_cms.DigestAlgorithm({'algorithm': 'sha256'}),
        'signed_attrs': signed_attrs,
        'signature_algorithm': a_cms.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature': signature,
    })

    signature = ca_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())
    signer_info['signature'] = signature

    signed_data = a_cms.SignedData({
        'version': 3,
        'digest_algorithms': [digest_alg],
        'encap_content_info': encap_content_info,
        'certificates': [ca_cert, leaf_cert],
        'signer_infos': [signer_info],
    })

    content_info = a_cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})
    return content_info.dump()

def format_b64_for_soap(data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    return b64

