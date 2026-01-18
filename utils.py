#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from xml.dom import minidom

from asn1crypto import csr
from asn1crypto import cms as a_cms, x509 as a_x509, core as a_core

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa,
    ec,
    ed25519,
    ed448,
)
from cryptography.x509.oid import ObjectIdentifier as CObjectIdentifier

# Samba / AD lookup (used by search_user)
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.net import Net
from samba.dcerpc import nbt

# pyasn1 for minimal CMC/PKIResponse structures
from pyasn1.type import univ, namedtype, namedval, char, useful, constraint
from pyasn1.codec.der.encoder import encode as der_encode


# -----------------------------------------------------------------------------
# Useful OIDs
# -----------------------------------------------------------------------------
OID_MS_CERT_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2"
OID_MS_CERT_TEMPLATE_INFO = "1.3.6.1.4.1.311.21.7"

# For PKIResponse (PKIResponse + CMCStatusInfo)
OID_ID_CCT_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3"  # eContentType for PKIResponse
OID_ID_CMC_STATUS_INFO = "1.3.6.1.5.5.7.7.1"     # id-cmc-statusInfo


# -----------------------------------------------------------------------------
# ASN.1 structures (CMC/PKIData, NTDS CA Security, etc.)
# -----------------------------------------------------------------------------

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
        ("crm", _CertReqMsg, {"implicit": 1}),
        ("orm", _ORM, {"implicit": 2}),
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
        ("template_id", a_core.ObjectIdentifier),
        ("major_version", a_core.Integer),
        ("minor_version", a_core.Integer),
    ]


class SMIMECapability(a_core.Sequence):
    _fields = [
        ("capability_id", a_core.ObjectIdentifier),
        ("parameters", a_core.Any, {"optional": True}),
    ]


class SMIMECapabilities(a_core.SequenceOf):
    _child_spec = SMIMECapability


class NtdsAttr(a_core.Sequence):
    _fields = [
        ("attr_id", a_core.ObjectIdentifier),
        ("attr_values", a_core.SetOf, {"spec": a_core.OctetString}),
    ]


class NtdsCASecurityExt(a_core.SequenceOf):
    _child_spec = NtdsAttr


class PKIStatusInfo(a_core.Sequence):
    _fields = [
        ("status", a_core.Integer),
        ("status_string", a_core.SequenceOf, {"spec": a_core.UTF8String, "optional": True}),
        ("fail_info", a_core.BitString, {"optional": True}),
    ]


class CertOrEncCert(a_core.Choice):
    _alternatives = [
        ("certificate", a_x509.Certificate),
        ("encrypted_cert", a_core.Any),
    ]


class CertifiedKeyPair(a_core.Sequence):
    _fields = [
        ("cert_or_enc_cert", CertOrEncCert),
        ("private_key", a_core.Any, {"optional": True}),
        ("publication_info", a_core.Any, {"optional": True}),
    ]


class CertResponse(a_core.Sequence):
    _fields = [
        ("cert_req_id", a_core.Integer),
        ("status", PKIStatusInfo),
        ("certified_key_pair", CertifiedKeyPair, {"optional": True}),
        ("rsp_info", a_core.OctetString, {"optional": True}),
    ]


class CertRepMessage(a_core.Sequence):
    _fields = [
        ("ca_pubs", a_core.SequenceOf, {"spec": a_x509.Certificate, "optional": True}),
        ("response", a_core.SequenceOf, {"spec": CertResponse}),
    ]


class _PKIDataRelax(a_core.Sequence):
    _fields = [
        ("controlSequence", a_core.SequenceOf, {"spec": a_core.Any, "optional": True}),
        ("reqSequence", a_core.SequenceOf, {"spec": a_core.Any, "optional": True}),
        ("cmsSequence", a_core.SequenceOf, {"spec": a_core.Any, "optional": True}),
        ("otherMsgSequence", a_core.SequenceOf, {"spec": a_core.Any, "optional": True}),
    ]


class _TCRRelax(a_core.Sequence):
    _fields = [
        ("bodyPartID", a_core.Integer),
        ("certificationRequest", csr.CertificationRequest),
    ]


class _SeqOfCSR(a_core.SequenceOf):
    _child_spec = csr.CertificationRequest


class _MsCertTemplateInfo(a_core.Sequence):
    _fields = [
        ("templateID", a_core.ObjectIdentifier),
        ("majorVersion", a_core.Integer, {"optional": True}),
        ("minorVersion", a_core.Integer, {"optional": True}),
    ]


# -----------------------------------------------------------------------------
# Small ASN.1 helpers
# -----------------------------------------------------------------------------

def _der_wrap_sequence(contents: bytes) -> bytes:
    """Wrap raw SEQUENCE contents with DER SEQUENCE header."""
    n = len(contents)
    if n < 128:
        return b"\x30" + bytes([n]) + contents
    lb = []
    x = n
    while x:
        lb.append(x & 0xFF)
        x >>= 8
    lb.reverse()
    return b"\x30" + bytes([0x80 | len(lb)]) + bytes(lb) + contents


# -----------------------------------------------------------------------------
# CSR parsing (extract CSR from CMC/PKIData and parse MS template)
# -----------------------------------------------------------------------------

def _parse_template_from_csr_bytes(csr_der: bytes) -> dict:
    """
    Return {"name","oid","major","minor"} if present in Microsoft Template
    (both Template Name and Template Info).
    """
    tpl = {"name": None, "oid": None, "major": None, "minor": None}

    csr_obj = csr.CertificationRequest.load(csr_der)
    cri = csr_obj["certification_request_info"]

    for attr in cri["attributes"]:
        # extensionRequest (1.2.840.113549.1.9.14)
        if attr["type"].dotted != "1.2.840.113549.1.9.14":
            continue

        for val in attr["values"]:
            exts = a_x509.Extensions.load(val.dump()) if not isinstance(val, a_x509.Extensions) else val
            for ext in exts:
                ext_oid = ext["extn_id"].dotted
                inner_der = ext["extn_value"].parsed.dump()

                if ext_oid == OID_MS_CERT_TEMPLATE_NAME:
                    # Try multiple string types; fallback on UTF-16-LE decode
                    name = None
                    for typ in (
                        a_core.BMPString,
                        a_core.UTF8String,
                        a_core.PrintableString,
                        a_core.TeletexString,
                    ):
                        try:
                            name = typ.load(inner_der).native
                            break
                        except Exception:
                            pass
                    if name is None:
                        try:
                            name = bytes(inner_der).decode("utf-16-le")
                        except Exception:
                            pass
                    tpl["name"] = name

                elif ext_oid == OID_MS_CERT_TEMPLATE_INFO:
                    info = _MsCertTemplateInfo.load(inner_der)
                    tpl["oid"] = info["templateID"].dotted
                    if info["majorVersion"].native is not None:
                        tpl["major"] = int(info["majorVersion"].native)
                    if info["minorVersion"].native is not None:
                        tpl["minor"] = int(info["minorVersion"].native)

    return tpl


MS_TPL_NAME_OID = "1.3.6.1.4.1.311.20.2"
MS_TPL_V2_OID = "1.3.6.1.4.1.311.21.7"
EXT_REQ_OID = "1.2.840.113549.1.9.14"  # extensionRequest

def _decode_ms_template_value(data: bytes) :
    """Try to decode the template value (often BMPString/UTF16)."""
    # 1) Generic ASN.1 attempt
    try:
        anyv = a_core.Asn1Value.load(data)
        if isinstance(anyv.native, str):
            return anyv.native
        if isinstance(anyv, a_core.OctetString):
            inner = anyv.native if isinstance(anyv.native, (bytes, bytearray)) else anyv.contents
            try:
                inner_any = a_core.Asn1Value.load(inner)
                if isinstance(inner_any.native, str):
                    return inner_any.native
            except Exception:
                pass
    except Exception:
        pass
    # 2) Fallback encodings
    for enc in ("utf-16-be", "utf-16-le", "utf-8", "latin1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return None


def extract_ms_template_from_csr_der(csr_der: bytes):
    """
    Extract Microsoft template from a CSR (DER).
    Returns {"name": str|None, "oid": str|None}.
    Looks for both direct attributes and extensionRequest.
    """
    req = csr.CertificationRequest.load(csr_der)
    cri = req["certification_request_info"]
    attrs = cri["attributes"]

    tpl_name: Optional[str] = None
    tpl_oid: Optional[str] = None

    for attr in attrs:
        dotted = attr["type"].dotted

        # Direct attribute: template name
        if dotted == MS_TPL_NAME_OID and tpl_name is None:
            try:
                tpl_name = _decode_ms_template_value(attr["values"][0].contents)
            except Exception:
                pass

        # Direct attribute: template v2 OID
        if dotted == MS_TPL_V2_OID and tpl_oid is None:
            try:
                seq = a_core.Sequence.load(attr["values"][0].contents)
                tpl_oid = seq[0].native
            except Exception:
                pass

        # extensionRequest -> Extensions
        if dotted == EXT_REQ_OID:
            val0 = attr["values"][0]
            exts = getattr(val0, "parsed", val0)
            if isinstance(exts, a_x509.Extensions):
                for ext in exts:
                    ext_oid = ext["extn_id"].dotted
                    ev = ext["extn_value"]

                    if ext_oid == MS_TPL_V2_OID and tpl_oid is None:
                        parsed = getattr(ev, "parsed", None)
                        if parsed is not None:
                            try:
                                tpl_oid = parsed[0].native
                            except Exception:
                                pass
                        else:
                            data = ev.native if isinstance(ev.native, (bytes, bytearray)) else ev.contents
                            try:
                                seq = a_core.Sequence.load(data)
                                tpl_oid = seq[0].native
                            except Exception:
                                pass

                    if ext_oid == MS_TPL_NAME_OID and tpl_name is None:
                        data = ev.native if isinstance(ev.native, (bytes, bytearray)) else ev.contents
                        tpl_name = _decode_ms_template_value(data)

    return {"name": tpl_name, "oid": tpl_oid}


def exct_csr_from_cmc(p7_der: bytes):
    """
    Try, in this order, to extract a CSR and its bodyPartID from a wrapped CMC
    (PKIData in SignedData), then fall back to simplePKIRequest or direct CSR.
    Returns (csr_der, body_part_id, template_info_dict).
    """
    try:
        ci = a_cms.ContentInfo.load(p7_der)
        if ci["content_type"].native != "signed_data":
            raise ValueError("ContentInfo.content_type != signed_data")

        sd = ci["content"]
        eci = sd["encap_content_info"]

        if eci["content"] is None:
            raise ValueError("SignedData without encapsulated content (detached)")

        pki_octets: bytes = eci["content"].native

        # 1) PKIData -> look for TaggedCertificationRequest
        try:
            pkidata_relax = _PKIDataRelax.load(pki_octets)
            if pkidata_relax["reqSequence"] is not None:
                for any_item in pkidata_relax["reqSequence"]:
                    try:
                        wrapped = _der_wrap_sequence(any_item.contents)
                        tcr = _TCRRelax.load(wrapped)
                        csr_obj = tcr["certificationRequest"]
                        body_part_id = int(tcr["bodyPartID"].native)
                        csr_bytes = csr_obj.dump()
                        template_info = _parse_template_from_csr_bytes(csr_bytes)
                        return csr_bytes, body_part_id, template_info
                    except Exception:
                        continue
        except Exception:
            pass

        # 2) simplePKIRequest (SEQUENCE OF CSR)
        try:
            seq = _SeqOfCSR.load(pki_octets)
            if len(seq) >= 1:
                csr_bytes = seq[0].dump()
                body_part_id = 0
                template_info = _parse_template_from_csr_bytes(csr_bytes)
                return csr_bytes, body_part_id, template_info
        except Exception:
            pass

        # 3) direct content = CSR
        try:
            csr_obj = csr.CertificationRequest.load(pki_octets)
            csr_bytes = csr_obj.dump()
            body_part_id = 0
            template_info = _parse_template_from_csr_bytes(csr_bytes)
            return csr_bytes, body_part_id, template_info
        except Exception:
            pass

        ct = eci["content_type"].dotted if eci["content_type"] is not None else "unknown"
        raise ValueError(
            "Unable to extract a CSR: no TCR, no simplePKIRequest, nor a direct CSR. "
            f"EncapContentInfo.content_type={ct}"
        )
    except Exception:
        # Ultimate fallback: some clients send just a “naked” CSR
        direct = csr.CertificationRequest.load(p7_der)
        csr_bytes = direct.dump()
        return csr_bytes, 0, extract_ms_template_from_csr_der(csr_bytes)


# -----------------------------------------------------------------------------
# CSR validation (explicit signature verification)
# -----------------------------------------------------------------------------

class CSRValidationError(ValueError):
    pass


def validate_csr(csr_obj: cx509.CertificateSigningRequest) -> None:
    """
    Validate a CSR:
      - explicit signature verification (RSASSA-PKCS1v1_5, ECDSA, or EdDSA)
      - acceptable public key (RSA>=2048 & e>=65537 odd; EC P-256/384/521; Ed25519/Ed448 ok)
    Raise CSRValidationError if invalid.
    """
    pub = csr_obj.public_key()

    # 1) Explicit signature verification
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            hash_algo = csr_obj.signature_hash_algorithm
            pub.verify(
                csr_obj.signature,
                csr_obj.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                hash_algo,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            hash_algo = csr_obj.signature_hash_algorithm
            pub.verify(
                csr_obj.signature,
                csr_obj.tbs_certrequest_bytes,
                ec.ECDSA(hash_algo),
            )
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(csr_obj.signature, csr_obj.tbs_certrequest_bytes)
        elif isinstance(pub, ed448.Ed448PublicKey):
            pub.verify(csr_obj.signature, csr_obj.tbs_certrequest_bytes)
        else:
            raise CSRValidationError("Unsupported public key type (only RSA, ECDSA, Ed25519, Ed448)")
    except Exception as e:
        raise CSRValidationError(f"CSR signature verification failed: {e}")

    # 2) Public key constraints
    if isinstance(pub, rsa.RSAPublicKey):
        key_size = pub.key_size
        if key_size < 2048:
            raise CSRValidationError(f"RSA key too small: {key_size} bits (min 2048)")
        try:
            e = pub.public_numbers().e
            if e < 65537 or e % 2 == 0:
                raise CSRValidationError(f"RSA public exponent not acceptable: {e} (must be odd >= 65537)")
        except Exception:
            raise CSRValidationError("Unable to read RSA public exponent")
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        curve = getattr(pub.curve, "name", str(pub.curve)).lower()
        allowed = {"secp256r1", "prime256v1", "secp384r1", "secp521r1"}
        if curve not in allowed:
            raise CSRValidationError(f"EC curve not allowed: {curve} (allowed: P-256/384/521)")
    # Ed25519/Ed448: no additional constraints


# -----------------------------------------------------------------------------
# BST / PKCS#7 (CES-like responses as in ADCS)
# -----------------------------------------------------------------------------

def _tbs_signed_attrs(attrs: a_cms.CMSAttributes) -> bytes:
    """
    Return the SET (tag 0x31) of the attributes for PKCS#7 signature.
    """
    der = attrs.dump()
    return (b"\x31" + der[1:]) if der and der[0] == 0xA0 else der


def build_adcs_bst_certrep(child_der: bytes, ca_der: bytes, ca_key, cert_req_id: int) -> bytes:
    """
    Build a CMS SignedData response containing a CertRepMessage,
    signed by the CA (behavior similar to ADCS).
    """
    leaf_cert = a_x509.Certificate.load(child_der)
    ca_cert = a_x509.Certificate.load(ca_der)

    status = PKIStatusInfo({"status": 0})
    ckp = CertifiedKeyPair({"cert_or_enc_cert": ("certificate", leaf_cert)})
    cert_resp = CertResponse({"cert_req_id": cert_req_id, "status": status, "certified_key_pair": ckp})
    certrep = CertRepMessage({"response": [cert_resp]})
    certrep_der = certrep.dump()

    encap_content_info = a_cms.EncapsulatedContentInfo(
        {
            "content_type": a_cms.ContentType("1.3.6.1.5.5.7.12.2"),
            "content": a_cms.ParsableOctetString(certrep_der),
        }
    )

    certificates = [ca_cert, leaf_cert]


    digest_algorithms = []
    signer_infos = []

    if ca_key is not None:
        signed_attrs = a_cms.CMSAttributes(
            [
                a_cms.CMSAttribute(
                    {
                        "type": "1.2.840.113549.1.9.3",
                        "values": [a_cms.ContentType("1.3.6.1.5.5.7.12.2")],
                    }
                ),
                a_cms.CMSAttribute(
                    {
                        "type": "1.2.840.113549.1.9.4",
                        "values": [hashlib.sha256(certrep_der).digest()],
                    }
                ),
            ]
        )

        to_be_signed = _tbs_signed_attrs(signed_attrs)

        digest_alg = a_cms.DigestAlgorithm({"algorithm": "sha256"})
        signature = ca_key.sign(
            to_be_signed,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        signer_info = a_cms.SignerInfo(
            {
                "version": "v1",
                "sid": a_cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": a_cms.IssuerAndSerialNumber(
                            {
                                "issuer": ca_cert.issuer,
                                "serial_number": ca_cert.serial_number,
                            }
                        )
                    }
                ),
                "digest_algorithm": a_cms.DigestAlgorithm({"algorithm": "sha256"}),
                "signed_attrs": signed_attrs,
                "signature_algorithm": a_cms.SignedDigestAlgorithm(
                    {"algorithm": "sha256_rsa"}
                ),
                "signature": signature,
            }
        )

        digest_algorithms = [digest_alg]
        signer_infos = [signer_info]

    signed_data = a_cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": digest_algorithms,
            "encap_content_info": encap_content_info,
            "certificates": certificates,
            "signer_infos": signer_infos,
        }
    )

    content_info = a_cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )
    return content_info.dump()


# -----------------------------------------------------------------------------
# PKIResponse (pending/denied) builders and CMS wrapper
# -----------------------------------------------------------------------------

class BodyPartID(univ.Integer):
    """BodyPartID ::= INTEGER (0..4294967295)"""
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, 4294967295)


class BodyPartList(univ.SequenceOf):
    componentType = BodyPartID()


class CMCStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('success', 0), ('failed', 2), ('pending', 3), ('noSupport', 4),
        ('confirmRequired', 5), ('popRequired', 6), ('partial', 7),
    )


class CMCFailInfo(univ.Integer):
    pass


class PendInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pendToken', univ.OctetString()),
        namedtype.NamedType('pendTime', useful.GeneralizedTime()),
    )


class OtherInfo(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('failInfo', CMCFailInfo()),
        namedtype.NamedType('pendInfo', PendInfo()),
    )


class CMCStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cMCStatus', CMCStatus()),
        namedtype.NamedType('bodyList', BodyPartList()),
        namedtype.OptionalNamedType('statusString', char.UTF8String()),
        namedtype.OptionalNamedType('otherInfo', OtherInfo()),
    )


class AttributeValue(univ.Any):
    pass


class AttributeValues(univ.SetOf):
    componentType = AttributeValue()


class TaggedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', AttributeValues()),
    )


class TaggedAttributeSeq(univ.SequenceOf):
    componentType = TaggedAttribute()


class TaggedContentInfo(univ.Sequence):
    pass  # unused


class TaggedContentInfoSeq(univ.SequenceOf):
    componentType = TaggedContentInfo()


class OtherMsg(univ.Sequence):
    pass


class OtherMsgSeq(univ.SequenceOf):
    componentType = OtherMsg()


class PKIResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlSequence', TaggedAttributeSeq()),
        namedtype.NamedType('cmsSequence', TaggedContentInfoSeq()),
        namedtype.NamedType('otherMsgSequence', OtherMsgSeq()),
    )


def _build_pkiresponse_pending_der(
    request_id: int,
    status_text: str = "Pending",
    body_part_id: int = 1
) -> bytes:
    """Build a minimal PKIResponse with CMCStatusInfo(pending)."""
    csi = CMCStatusInfo()
    csi.setComponentByName('cMCStatus', 3)  # pending

    bl = BodyPartList()
    bl.append(BodyPartID(body_part_id))
    csi.setComponentByName('bodyList', bl)

    if status_text:
        csi.setComponentByName('statusString', char.UTF8String(status_text))

    pend = PendInfo()
    pend.setComponentByName('pendToken', univ.OctetString(str(request_id).encode('ascii')))
    pend.setComponentByName('pendTime', useful.GeneralizedTime(datetime.now(timezone.utc).strftime('%Y%m%d%H%M%SZ')))
    oi = OtherInfo()
    oi.setComponentByName('pendInfo', pend)
    csi.setComponentByName('otherInfo', oi)

    ta = TaggedAttribute()
    ta.setComponentByName('bodyPartID', BodyPartID(body_part_id))
    ta.setComponentByName('attrType', univ.ObjectIdentifier(OID_ID_CMC_STATUS_INFO))
    avs = AttributeValues()
    avs.append(AttributeValue(der_encode(csi)))
    ta.setComponentByName('attrValues', avs)

    controls = TaggedAttributeSeq()
    controls.append(ta)

    resp = PKIResponse()
    resp.setComponentByName('controlSequence', controls)
    resp.setComponentByName('cmsSequence', TaggedContentInfoSeq())
    resp.setComponentByName('otherMsgSequence', OtherMsgSeq())

    return der_encode(resp)


def _build_pkiresponse_denied_der(
    status_text: str = "Denied by administrator",
    body_part_id: int = 1
) -> bytes:
    """Build a minimal PKIResponse with CMCStatusInfo(failed)."""
    csi = CMCStatusInfo()
    csi.setComponentByName('cMCStatus', 2)  # failed

    bl = BodyPartList()
    bl.append(BodyPartID(body_part_id))
    csi.setComponentByName('bodyList', bl)

    if status_text:
        csi.setComponentByName('statusString', char.UTF8String(status_text))

    ta = TaggedAttribute()
    ta.setComponentByName('bodyPartID', BodyPartID(body_part_id))
    ta.setComponentByName('attrType', univ.ObjectIdentifier(OID_ID_CMC_STATUS_INFO))
    avs = AttributeValues()
    avs.append(AttributeValue(der_encode(csi)))
    ta.setComponentByName('attrValues', avs)

    controls = TaggedAttributeSeq()
    controls.append(ta)

    resp = PKIResponse()
    resp.setComponentByName('controlSequence', controls)
    resp.setComponentByName('cmsSequence', TaggedContentInfoSeq())
    resp.setComponentByName('otherMsgSequence', OtherMsgSeq())

    return der_encode(resp)


def build_adcs_bst_pkiresponse(
    ca_der: bytes,
    ca_key,
    request_id: int,
    status: str = "pending",
    status_text: str = "Pending",
    body_part_id: int = 1
) -> bytes:
    """
    Build a CMS SignedData containing a PKIResponse (Windows/ADCS-ready).
    - eContentType = 1.3.6.1.5.5.7.12.3
    - SignedAttributes = content-type(12.3) + message-digest(SHA256(PKIResponse))
    Parameters:
      - status: "pending" or "denied" (aliases: "failed", "refused")
    """
    signer_cert = a_x509.Certificate.load(ca_der)

    st = (status or "").strip().lower()
    if st in ("pending", "pend", "p"):
        pkiresp_der = _build_pkiresponse_pending_der(
            request_id=request_id,
            status_text=status_text,
            body_part_id=body_part_id,
        )
    elif st in ("denied", "failed", "refused", "fail"):
        pkiresp_der = _build_pkiresponse_denied_der(
            status_text=status_text,
            body_part_id=body_part_id,
        )
    else:
        raise ValueError(f"Unsupported PKIResponse status: {status!r} (expected: 'pending' or 'denied')")

    encap_content_info = a_cms.EncapsulatedContentInfo(
        {
            "content_type": a_cms.ContentType(OID_ID_CCT_PKI_RESPONSE),
            "content": a_cms.ParsableOctetString(pkiresp_der),
        }
    )

    signed_attrs = a_cms.CMSAttributes(
        [
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.3", "values": [a_cms.ContentType(OID_ID_CCT_PKI_RESPONSE)]}),
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.4", "values": [hashlib.sha256(pkiresp_der).digest()]}),
        ]
    )
    to_be_signed = _tbs_signed_attrs(signed_attrs)

    signer_info = a_cms.SignerInfo(
        {
            "version": "v1",
            "sid": a_cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": a_cms.IssuerAndSerialNumber(
                        {"issuer": signer_cert.issuer, "serial_number": signer_cert.serial_number}
                    )
                }
            ),
            "digest_algorithm": a_cms.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": a_cms.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature": b"",
        }
    )
    if ca_key:
        sig = ca_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        sig = b''

    signer_info["signature"] = sig

    sd = a_cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [a_cms.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": encap_content_info,
            "certificates": [signer_cert],
            "signer_infos": [signer_info],
        }
    )
    ci = a_cms.ContentInfo({"content_type": "signed_data", "content": sd})
    return ci.dump()


# -----------------------------------------------------------------------------
# Utility encoding (Base64 helpers)
# -----------------------------------------------------------------------------

def format_b64_for_soap(data: bytes) -> str:
    """Base64-encode bytes for inclusion into SOAP text nodes."""
    return base64.b64encode(data).decode("ascii")


def _wrap_b64(data: bytes, line_len: int = 64, with_crlf: bool = True) -> str:
    """
    Base64-encode bytes and optionally wrap lines to a fixed length.
    If with_crlf is True, lines are joined using CRLF (\r\n).
    """
    s = base64.b64encode(data).decode("ascii")
    if not line_len:
        return s
    lines = [s[i:i + line_len] for i in range(0, len(s), line_len)]
    sep = "\r\n" if with_crlf else "\n"
    return sep.join(lines)


# -----------------------------------------------------------------------------
# WS-Trust (Enrollment) response builder
# -----------------------------------------------------------------------------

def build_ws_trust_response(
    pkcs7_der: bytes,
    relates_to: str,
    request_id: int,
    ces_uri: str,
    *,
    status: str = "pending",  # "pending" | "denied"/"failed"/"fail"/"refused"
    disposition_message: str = "Pending",
    reason_text: str = "Denied by administrator",
    error_code: int = -2146877420,
    invalid_request: bool = True,
    lang: str = "fr-FR",
    token_type: str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
    activity_correlation_id: str = "3fd81603-cf85-48d8-945d-990e2a7a5673",
    activity_id: str = "00000000-0000-0000-0000-000000000000",
    wrap_b64_lines: bool = True,
):
    """
    Build a WS-Trust response:
      - status="pending"  -> RSTRC (success), returns (xml_bytes, 200)
      - status in {"denied","failed","fail","refused"} -> SOAP Fault (CertificateEnrollmentWSDetailFault), returns (xml_bytes, 500)
    """
    import base64
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import QName

    NS = {
        "s":  "http://www.w3.org/2003/05/soap-envelope",
        "a":  "http://www.w3.org/2005/08/addressing",
        "wst":"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
        "wss":"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "msdiag": "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
        "msenroll": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment",
        "xsd": "http://www.w3.org/2001/XMLSchema",
        "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    }
    for p, uri in NS.items():
        ET.register_namespace(p, uri)

    def _wrap_b64_crlf(data: bytes, line_len: int = 64) -> str:
        s = base64.b64encode(data).decode("ascii")
        if not line_len:
            return s
        return "\r\n".join(s[i:i+line_len] for i in range(0, len(s), line_len))

    st = (status or "").strip().lower()
    is_pending = st in ("pending", "pend", "p")
    is_failed = st in ("denied", "failed", "fail", "refused")

    if is_pending:
        # ----- RSTRC (HTTP 200) -----
        senv = ET.Element(QName(NS["s"], "Envelope"))

        header = ET.SubElement(senv, QName(NS["s"], "Header"))
        a_action = ET.SubElement(header, QName(NS["a"], "Action"), {QName(NS["s"], "mustUnderstand"): "1"})
        a_action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
        a_rel = ET.SubElement(header, QName(NS["a"], "RelatesTo")); a_rel.text = relates_to
        activity = ET.SubElement(header, QName(NS["msdiag"], "ActivityId"), {"CorrelationId": activity_correlation_id})
        activity.text = activity_id

        body = ET.SubElement(senv, QName(NS["s"], "Body"))
        rstrc = ET.SubElement(body, QName(NS["wst"], "RequestSecurityTokenResponseCollection"))
        rstr = ET.SubElement(rstrc, QName(NS["wst"], "RequestSecurityTokenResponse"))

        tokentype = ET.SubElement(rstr, QName(NS["wst"], "TokenType"))
        tokentype.text = token_type

        disp = ET.SubElement(rstr, QName(NS["msenroll"], "DispositionMessage"), {"{http://www.w3.org/XML/1998/namespace}lang": lang})
        disp.text = disposition_message

        bst = ET.SubElement(
            rstr,
            QName(NS["wss"], "BinarySecurityToken"),
            {"ValueType": f"{NS['wss']}#PKCS7", "EncodingType": f"{NS['wss']}#base64binary"},
        )
        bst.text = _wrap_b64_crlf(pkcs7_der) if wrap_b64_lines else base64.b64encode(pkcs7_der).decode("ascii")

        req_tok = ET.SubElement(rstr, QName(NS["wst"], "RequestedSecurityToken"))
        str_el = ET.SubElement(req_tok, QName(NS["wss"], "SecurityTokenReference"))
        ET.SubElement(str_el, QName(NS["wss"], "Reference"), {"URI": ces_uri})

        req_id = ET.SubElement(rstr, QName(NS["msenroll"], "RequestID")); req_id.text = str(request_id)

        return ET.tostring(senv, encoding="utf-8", xml_declaration=True, method="xml"), 200

    elif is_failed:
        # ----- SOAP Fault (HTTP 500): CertificateEnrollmentWSDetailFault -----
        senv = ET.Element(QName(NS["s"], "Envelope"))

        header = ET.SubElement(senv, QName(NS["s"], "Header"))
        a_action = ET.SubElement(header, QName(NS["a"], "Action"), {QName(NS["s"], "mustUnderstand"): "1"})
        a_action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RequestSecurityTokenCertificateEnrollmentWSDetailFault"
        a_rel = ET.SubElement(header, QName(NS["a"], "RelatesTo")); a_rel.text = relates_to
        activity = ET.SubElement(header, QName(NS["msdiag"], "ActivityId"), {"CorrelationId": activity_correlation_id})
        activity.text = activity_id

        body = ET.SubElement(senv, QName(NS["s"], "Body"))
        fault = ET.SubElement(body, QName(NS["s"], "Fault"))

        code = ET.SubElement(fault, QName(NS["s"], "Code"))
        ET.SubElement(code, QName(NS["s"], "Value")).text = "s:Receiver"

        reason = ET.SubElement(fault, QName(NS["s"], "Reason"))
        ET.SubElement(reason, QName(NS["s"], "Text"), {"{http://www.w3.org/XML/1998/namespace}lang": lang}).text = reason_text

        detail = ET.SubElement(fault, QName(NS["s"], "Detail"))
        cert_detail = ET.SubElement(
            detail,
            QName(NS["msenroll"], "CertificateEnrollmentWSDetail"),
            {"xmlns:xsd": NS["xsd"], "xmlns:xsi": NS["xsi"]},
        )

        b64 = _wrap_b64_crlf(pkcs7_der) if wrap_b64_lines else base64.b64encode(pkcs7_der).decode("ascii")
        ET.SubElement(cert_detail, QName(NS["msenroll"], "BinaryResponse")).text = b64
        ET.SubElement(cert_detail, QName(NS["msenroll"], "ErrorCode")).text = str(int(error_code))
        ET.SubElement(cert_detail, QName(NS["msenroll"], "InvalidRequest")).text = "true" if invalid_request else "false"
        ET.SubElement(cert_detail, QName(NS["msenroll"], "RequestID")).text = str(request_id)

        return ET.tostring(senv, encoding="utf-8", xml_declaration=True, method="xml"), 500

    else:
        raise ValueError(f"Unsupported status '{status}': use 'pending' or 'denied'")


# -----------------------------------------------------------------------------
# Active Directory user resolution (SAMBA/LDAP)
# -----------------------------------------------------------------------------

def search_user(userauth: str,ldap_filter='',dc_fqdn=None,basedn=None,password=None):
    """
    Resolve the SAM/LDAP entry for the Kerberos user 'user@REALM'.
    Returns (SamDB, entry) if found.
    """
    lp = LoadParm()
    lp.load_default()

    creds = Credentials()
    creds.guess(lp)
    if not password:
        creds.set_kerberos_state(True)
        creds.set_machine_account(lp)
    else:
        creds.set_username(userauth.split('@')[0])
        creds.set_password(password)

    realm = lp.get("realm")
    if not dc_fqdn:
        net = Net(creds=creds, lp=lp)
        flags = nbt.NBT_SERVER_LDAP
        dc_info = net.finddc(domain=realm, flags=flags)
        dc_fqdn = str(dc_info.pdc_dns_name)

    ldap_url = f"ldap://{dc_fqdn}"

    samdbr = SamDB(url=ldap_url, credentials=creds, lp=lp)
    if not basedn:
        if "@" in userauth:
            basedn = "DC=" + userauth.split("@")[1].replace(".", ",DC=")
        else:
            basedn = samdbr.get_default_basedn()
        
    ldap_filter = "(&(samAccountName=%s)%s)" % (userauth.split("@")[0],ldap_filter)

    res = samdbr.search(
        base=basedn,
        scope=2,
        expression=ldap_filter
    )

    for entry in res:
        return samdbr, entry


# -----------------------------------------------------------------------------
# Static extensions (EKU/KU/AppPolicies/TemplateInfo) applied to the cert
# -----------------------------------------------------------------------------

def _apply_static_extensions(builder: cx509.CertificateBuilder, template: dict) -> cx509.CertificateBuilder:
    """
    Re-read static extensions already materialized in the template (field __der)
    and re-apply them to x509.CertificateBuilder, typing EKU/KU when possible.
    Extensions marked dynamic (__der=None) are ignored here.
    """
    EKU_OID = "2.5.29.37"
    KU_OID = "2.5.29.15"

    src = template.get("__all_required_extensions") or template.get("required_extensions") or []
    for ext in src:
        der = ext.get("__der")
        if der is None:
            continue  # dynamic (e.g., NTDS) -> handled elsewhere
        oid = ext.get("oid")
        critical = bool(ext.get("critical", False))

        if oid == EKU_OID:
            try:
                eku_asn1 = a_x509.ExtKeyUsageSyntax.load(der)
                oids = [cx509.ObjectIdentifier(str(x)) for x in eku_asn1]
                eku = cx509.ExtendedKeyUsage(oids)
                builder = builder.add_extension(eku, critical=critical)
            except Exception:
                builder = builder.add_extension(
                    cx509.UnrecognizedExtension(CObjectIdentifier(oid), der),
                    critical=critical,
                )

        elif oid == KU_OID:
            try:
                bits = a_core.BitString.load(der).native
                bits += [False] * (9 - len(bits))
                ku = cx509.KeyUsage(
                    digital_signature=bits[0],
                    content_commitment=bits[1],
                    key_encipherment=bits[2],
                    data_encipherment=bits[3],
                    key_agreement=bits[4],
                    key_cert_sign=bits[5],
                    crl_sign=bits[6],
                    encipher_only=bits[7],
                    decipher_only=bits[8],
                )
                builder = builder.add_extension(ku, critical=critical)
            except Exception:
                builder = builder.add_extension(
                    cx509.UnrecognizedExtension(CObjectIdentifier(oid), der),
                    critical=True,
                )
        else:
            # AppPolicies (1.3.6.1.4.1.311.21.10), TemplateInfo (1.3.6.1.4.1.311.21.7), etc.
            builder = builder.add_extension(
                cx509.UnrecognizedExtension(CObjectIdentifier(oid), der),
                critical=critical,
            )

    return builder


# -----------------------------------------------------------------------------
# Enrollment Policy (GetPolicies) XML helpers and response
# -----------------------------------------------------------------------------

NS_EP = {
    "s":   "http://www.w3.org/2003/05/soap-envelope",
    "a":   "http://www.w3.org/2005/08/addressing",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "ep":  "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy",
    "diag":"http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
}
# Register once
ET.register_namespace('s',   NS_EP["s"])
ET.register_namespace('a',   NS_EP["a"])
ET.register_namespace('xsi', NS_EP["xsi"])
ET.register_namespace('xsd', NS_EP["xsd"])
ET.register_namespace('ep',  NS_EP["ep"])
ET.register_namespace('',    NS_EP["diag"])  # optional: limit prefix creation on ActivityId

_TRUE = "true"
_FALSE = "false"

def tbool(v: bool) -> str:
    return _TRUE if bool(v) else _FALSE

def text(elem, value):
    elem.text = "" if value is None else str(value)
    return elem

def set_xsi_nil(elem, is_nil: bool):
    elem.set(f"{{{NS_EP['xsi']}}}nil", _TRUE if is_nil else _FALSE)
    return elem

def prettify(xml_bytes: bytes) -> str:
    parsed = minidom.parseString(xml_bytes)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

def build_get_policies_response(
    uuid_request: str,
    uuid_random: str,
    hosturl: str,
    policyid: str,
    next_update_hours: int,
    cas: list,
    templates: list,
    oids: list,
) -> str:
    # --- helpers for dynamic OID refs ---
    def _to_int_or_none(x):
        try:
            return int(str(x))
        except Exception:
            return None

    def _next_free_refid(oids_list: list) -> int:
        used = set()
        for oo in oids_list:
            v = oo.get("__refid") or oo.get("oIDReferenceID") or oo.get("refid")
            iv = _to_int_or_none(v)
            if iv is not None:
                used.add(iv)
        return (max(used) + 1) if used else 1

    def _find_oid_refid(oids_list: list, value: str, group: int, default_name: str):
        for oo in oids_list:
            if (
                str(oo.get("value")) == value
                and str(oo.get("group")) == str(group)
                and str(oo.get("default_name")) == default_name
            ):
                return oo.get("__refid")
        return None

    def _ensure_oid(oids_list: list, value: str, group: int, default_name: str, refid: int | None = None) -> int:
        existing = _find_oid_refid(oids_list, value, group, default_name)
        if existing is not None:
            return int(existing)

        if refid is None:
            refid = _next_free_refid(oids_list)

        oids_list.append({
            "value": value,
            "group": group,
            "__refid": refid,
            "default_name": default_name,
        })
        return refid

    # --- ECDSA/ECDH curves mapping by minimalKeyLength ---
    # Note: ECC uses 256/384/521. If you pass 512 we map to 521.
    ECDSA_CURVES = {
        256: {"value": "1.2.840.10045.3.1.7", "group": 3, "default_name": "ECDSA_P256"},
        384: {"value": "1.3.132.0.34",       "group": 3, "default_name": "ECDSA_P384"},
        521: {"value": "1.3.132.0.35",       "group": 3, "default_name": "ECDSA_P521"},
    }
    ECDH_CURVES = {
        256: {"value": "1.2.840.10045.3.1.7", "group": 3, "default_name": "ECDH_P256"},
        384: {"value": "1.3.132.0.34",       "group": 3, "default_name": "ECDH_P384"},
        521: {"value": "1.3.132.0.35",       "group": 3, "default_name": "ECDH_P521"},
    }

    # --- Supported algorithms (RSA/DSA are single OID entries) ---
    ALGO_OIDS = {
        "rsa": {"value": "1.2.840.113549.1.1.1", "group": 3, "default_name": "RSA"},
        "dsa": {"value": "1.2.840.10040.4.1",    "group": 3, "default_name": "DSA"},
        # ecc handled separately via curves + minimalKeyLength (+ keySpec for ECDH)
    }

    # --- Hash algorithms OIDs (for hashAlgorithmOIDReference) ---
    # group=1 matches what ADCS emits for hash OIDs in XCEP responses
    HASH_OIDS = {
        "SHA1":   {"value": "1.3.14.3.2.26",            "group": 1, "default_name": "SHA1"},
        "SHA256": {"value": "2.16.840.1.101.3.4.2.1",   "group": 1, "default_name": "SHA256"},
        "SHA384": {"value": "2.16.840.1.101.3.4.2.2",   "group": 1, "default_name": "SHA384"},
        "SHA512": {"value": "2.16.840.1.101.3.4.2.3",   "group": 1, "default_name": "SHA512"},
    }

    # map algo_key -> allocated refid (reuse same refid across templates)
    # (algo_key = "rsa", "dsa", or "ecdsa:256"/"ecdh:256"/...)
    algo_refids: dict[str, int] = {}

    # <s:Envelope>
    env = ET.Element(ET.QName(NS_EP['s'], 'Envelope'))

    # <s:Header>
    hdr = ET.SubElement(env, ET.QName(NS_EP['s'], 'Header'))
    action = ET.SubElement(hdr, ET.QName(NS_EP['a'], 'Action'), {ET.QName(NS_EP['s'], 'mustUnderstand'): "1"})
    action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"

    relates = ET.SubElement(hdr, ET.QName(NS_EP['a'], 'RelatesTo'))
    relates.text = f"urn:uuid:{uuid_request}"

    # ActivityId (Diagnostics ns) — keep it in diag ns like ADCS
    act = ET.SubElement(
        hdr,
        "ActivityId",
        {"CorrelationId": str(uuid_random), "xmlns": NS_EP["diag"]},
    )
    act.text = "00000000-0000-0000-0000-000000000000"

    # <s:Body>
    body = ET.SubElement(env, ET.QName(NS_EP['s'], 'Body'))
    body.set('xmlns:xsi', NS_EP['xsi'])
    body.set('xmlns:xsd', NS_EP['xsd'])

    # <ep:GetPoliciesResponse>
    gpr = ET.SubElement(body, ET.QName(NS_EP['ep'], 'GetPoliciesResponse'))

    # <response>
    response = ET.SubElement(gpr, ET.QName(NS_EP['ep'], 'response'))

    text(ET.SubElement(response, ET.QName(NS_EP['ep'], 'policyID')), policyid)
    ET.SubElement(response, ET.QName(NS_EP['ep'], 'policyFriendlyName'))
    text(ET.SubElement(response, ET.QName(NS_EP['ep'], 'nextUpdateHours')), next_update_hours)

    pol_not_changed = ET.SubElement(response, ET.QName(NS_EP['ep'], 'policiesNotChanged'))
    set_xsi_nil(pol_not_changed, True)

    policies = ET.SubElement(response, ET.QName(NS_EP['ep'], 'policies'))

    # --- templates -> policies/policy ---
    dict_ca_allowed = {}
    for t in templates:
        if t['permissions']['enroll']:
            for c in t['ca_references']:
                dict_ca_allowed[c] = None
        policy = ET.SubElement(policies, ET.QName(NS_EP['ep'], 'policy'))
        text(ET.SubElement(policy, ET.QName(NS_EP['ep'], 'policyOIDReference')), t["__policy_oid_reference"])

        cAs = ET.SubElement(policy, ET.QName(NS_EP['ep'], 'cAs'))
        ca_refids = t.get("__ca_refids") or []
        if ca_refids:
            for refid in ca_refids:
                text(ET.SubElement(cAs, ET.QName(NS_EP['ep'], 'cAReference')), refid)
        else:
            text(ET.SubElement(cAs, ET.QName(NS_EP['ep'], 'cAReference')), cas[0]["__refid"])

        attrs = ET.SubElement(policy, ET.QName(NS_EP['ep'], 'attributes'))
        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'commonName')), t["common_name"])
        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'policySchema')), t["policy_schema"])

        cert_valid = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'certificateValidity'))
        text(ET.SubElement(cert_valid, ET.QName(NS_EP['ep'], 'validityPeriodSeconds')), t["validity"]["validity_seconds"])
        text(ET.SubElement(cert_valid, ET.QName(NS_EP['ep'], 'renewalPeriodSeconds')), t["validity"]["renewal_seconds"])

        perm = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'permission'))
        text(ET.SubElement(perm, ET.QName(NS_EP['ep'], 'enroll')), tbool(t["permissions"]["enroll"]))
        text(ET.SubElement(perm, ET.QName(NS_EP['ep'], 'autoEnroll')), tbool(t["permissions"]["auto_enroll"]))

        pka = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'privateKeyAttributes'))
        text(ET.SubElement(pka, ET.QName(NS_EP['ep'], 'minimalKeyLength')), t["private_key_attributes"]["minimal_key_length"])
        text(ET.SubElement(pka, ET.QName(NS_EP['ep'], 'keySpec')), t["private_key_attributes"]["key_spec"])

        kup = ET.SubElement(pka, ET.QName(NS_EP['ep'], 'keyUsageProperty'))
        set_xsi_nil(kup, True)

        pk_perms = ET.SubElement(pka, ET.QName(NS_EP['ep'], 'permissions'))
        set_xsi_nil(pk_perms, True)

        # --- algorithmOIDReference (RSA/ECDSA/ECDH/DSA) ---
        algo = (t.get("private_key_attributes", {}).get("algorithm") or "").strip().lower()

        # Decide EC signature vs key-exchange:
        # - If algo explicitly "ecdh" => ECDH
        # - If algo is "ecdsa" => ECDSA (but if keySpec indicates key exchange, switch to ECDH to mimic ADCS template behavior)
        # - Otherwise keep existing behavior
        key_spec = _to_int_or_none(t.get("private_key_attributes", {}).get("key_spec"))
        ec_mode = None  # "ecdsa" or "ecdh"
        if algo == "ecdh":
            ec_mode = "ecdh"
        elif algo == "ecdsa":
            # ADCS templates: keySpec=1 typically means key exchange, keySpec=2 means signature
            if key_spec == 1:
                ec_mode = "ecdh"
            else:
                ec_mode = "ecdsa"

        if ec_mode in ("ecdsa", "ecdh"):
            bits = _to_int_or_none(t.get("private_key_attributes", {}).get("minimal_key_length"))
            if bits == 512:
                bits = 521  # tolerate "512" for P-521
            if bits not in (256, 384, 521):
                raise ValueError(f"Unsupported EC minimalKeyLength={bits}. Expected 256/384/521 (or 512->521).")

            meta = (ECDH_CURVES if ec_mode == "ecdh" else ECDSA_CURVES)[bits]
            algo_key = f"{ec_mode}:{bits}"

            if algo_key not in algo_refids:
                existing = _find_oid_refid(oids, meta["value"], meta["group"], meta["default_name"])
                if existing is not None:
                    algo_refids[algo_key] = int(existing)
                else:
                    algo_refids[algo_key] = _ensure_oid(
                        oids,
                        meta["value"],
                        meta["group"],
                        meta["default_name"],
                        refid=_next_free_refid(oids),
                    )

            refid = algo_refids[algo_key]
            alg_el = ET.SubElement(pka, ET.QName(NS_EP["ep"], "algorithmOIDReference"))
            alg_el.text = str(refid)

        elif algo in ALGO_OIDS:
            meta = ALGO_OIDS[algo]
            algo_key = algo

            if algo_key not in algo_refids:
                existing = _find_oid_refid(oids, meta["value"], meta["group"], meta["default_name"])
                if existing is not None:
                    algo_refids[algo_key] = int(existing)
                else:
                    algo_refids[algo_key] = _ensure_oid(
                        oids,
                        meta["value"],
                        meta["group"],
                        meta["default_name"],
                        refid=_next_free_refid(oids),
                    )

            refid = algo_refids[algo_key]
            alg_el = ET.SubElement(pka, ET.QName(NS_EP["ep"], "algorithmOIDReference"))
            alg_el.text = str(refid)

        else:
            # default / existing behavior
            alg_el = ET.SubElement(pka, ET.QName(NS_EP['ep'], 'algorithmOIDReference'))
            alg_ref = t["private_key_attributes"].get("algorithm_oid_reference")
            set_xsi_nil(alg_el, False if alg_ref else True)
            if alg_ref:
                alg_el.text = str(alg_ref)

        cp = ET.SubElement(pka, ET.QName(NS_EP['ep'], 'cryptoProviders'))
        for prov in t["private_key_attributes"].get("crypto_providers", []):
            text(ET.SubElement(cp, ET.QName(NS_EP['ep'], 'provider')), prov)

        rev = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'revision'))
        text(ET.SubElement(rev, ET.QName(NS_EP['ep'], 'majorRevision')), t["revision"]["major"])
        text(ET.SubElement(rev, ET.QName(NS_EP['ep'], 'minorRevision')), t["revision"]["minor"])

        sup = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'supersededPolicies'))
        set_xsi_nil(sup, True)

        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'privateKeyFlags')), t["flags"]["private_key_flags"])
        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'subjectNameFlags')), t["flags"]["subject_name_flags"])
        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'enrollmentFlags')), t["flags"]["enrollment_flags"])
        text(ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'generalFlags')), t["flags"]["general_flags"])

        # --- hashAlgorithmOIDReference (optional) ---
        # priority:
        #   1) t["hash_algorithm"] (ex: "SHA256") -> allocate OID + set ref
        #   2) fallback: t["flags"]["hash_algorithm_oid_reference"] (existing behavior)
        desired_hash = (t.get("hash_algorithm") or t.get("flags", {}).get("hash_algorithm") or "").strip()
        hash_ref = None

        if desired_hash:
            key = desired_hash.upper()
            if key not in HASH_OIDS:
                raise ValueError(f"Unsupported hash_algorithm='{desired_hash}'. Expected one of {', '.join(HASH_OIDS.keys())}")

            meta = HASH_OIDS[key]
            existing = _find_oid_refid(oids, meta["value"], meta["group"], meta["default_name"])
            if existing is not None:
                hash_ref = int(existing)
            else:
                hash_ref = _ensure_oid(
                    oids,
                    meta["value"],
                    meta["group"],
                    meta["default_name"],
                    refid=_next_free_refid(oids),
                )

            # keep it also in flags for traceability/debug
            t.setdefault("flags", {})["hash_algorithm_oid_reference"] = hash_ref
        else:
            hash_ref = t.get("flags", {}).get("hash_algorithm_oid_reference")

        hash_alg = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'hashAlgorithmOIDReference'))
        if not hash_ref:
            set_xsi_nil(hash_alg, False if hash_ref else True)
        if hash_ref:
            hash_alg.text = str(hash_ref)

        ra_req = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'rARequirements'))
        set_xsi_nil(ra_req, True)

        kaa = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'keyArchivalAttributes'))
        set_xsi_nil(kaa, True)

        exts = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'extensions'))
        for ext in t.get("required_extensions", []):
            e = ET.SubElement(exts, ET.QName(NS_EP['ep'], 'extension'))
            text(ET.SubElement(e, ET.QName(NS_EP['ep'], 'oIDReference')), ext["__oid_reference"])
            text(ET.SubElement(e, ET.QName(NS_EP['ep'], 'critical')), tbool(ext["critical"]))
            text(ET.SubElement(e, ET.QName(NS_EP['ep'], 'value')), ext["value_b64"])

    ep_cas = ET.SubElement(gpr, ET.QName(NS_EP['ep'], 'cAs'))

    AUTH_MAP = {
        "anonymous": 1,
        "kerberos": 2,
        "username_password": 4,
        "x509": 8,
    }

    DEFAULT_AUTH_METHODS = [
        {"method": "kerberos", "renewal_only": False},
#        {"method": "username_password", "renewal_only": False},
#        {"method": "x509", "renewal_only": False},
    ]
    
    priority = 1 
    
    for ca in cas:
        ca_el = ET.SubElement(ep_cas, ET.QName(NS_EP['ep'], 'cA'))
        uris = ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'uris'))
    
        auth_entries = ca.get("auth_methods") or DEFAULT_AUTH_METHODS
        seen = set()
    
        for entry in auth_entries:
            method = (entry.get("method") or "").strip().lower()
            renewal_only = bool(entry.get("renewal_only", False))
    
            if method not in AUTH_MAP:
                raise ValueError(f"Unknown auth method '{method}' for CA '{ca.get('id', '?')}'")

            auth_type = AUTH_MAP[method]

            if auth_type in seen:
                continue
            seen.add(auth_type)

            cauri = ET.SubElement(uris, ET.QName(NS_EP['ep'], 'cAURI'))
            text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'clientAuthentication')), auth_type)
            text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'uri')), f"{hosturl}{ca['__ces_path']}")
            text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'priority')), priority)
            text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'renewalOnly')), "true" if renewal_only else "false")
            priority += 1

        text(ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'certificate')), ca["__certificate_b64"])
        text(ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'enrollPermission')), tbool(bool(ca['id'] in dict_ca_allowed)))
        text(ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'cAReferenceID')), ca["__refid"])


    # --- oIDs ---
    ep_oids = ET.SubElement(gpr, ET.QName(NS_EP['ep'], 'oIDs'))
    for o in oids:
        oe = ET.SubElement(ep_oids, ET.QName(NS_EP['ep'], 'oID'))
        text(ET.SubElement(oe, ET.QName(NS_EP['ep'], 'value')), o["value"])
        text(ET.SubElement(oe, ET.QName(NS_EP['ep'], 'group')), o["group"])
        text(ET.SubElement(oe, ET.QName(NS_EP['ep'], 'oIDReferenceID')), o["__refid"])
        text(ET.SubElement(oe, ET.QName(NS_EP['ep'], 'defaultName')), o["default_name"])

    raw = ET.tostring(env, encoding="utf-8", xml_declaration=True)
    return prettify(raw)


# -----------------------------------------------------------------------------
# CES response (Issued) builder
# -----------------------------------------------------------------------------

NS_CES = {
    "s":    "http://www.w3.org/2003/05/soap-envelope",
    "a":    "http://www.w3.org/2005/08/addressing",
    "diag": "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
    "wst":  "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "ep":   "http://schemas.microsoft.com/windows/pki/2009/01/enrollment",
}
ET.register_namespace('s',    NS_CES['s'])
ET.register_namespace('a',    NS_CES['a'])
ET.register_namespace('wst',  NS_CES['wst'])
ET.register_namespace('wsse', NS_CES['wsse'])
ET.register_namespace('ep',   NS_CES['ep'])

def _txt(elem, value):
    elem.text = "" if value is None else str(value)
    return elem

def _prettify(xml_bytes: bytes) -> str:
    return minidom.parseString(xml_bytes).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

def build_ces_response(uuid_request: str, uuid_random: str, p7b_der: str, leaf_der: str, body_part_id: str) -> str:
    env = ET.Element(ET.QName(NS_CES['s'], 'Envelope'))

    hdr = ET.SubElement(env, ET.QName(NS_CES['s'], 'Header'))
    action = ET.SubElement(hdr, ET.QName(NS_CES['a'], 'Action'), {ET.QName(NS_CES['s'], 'mustUnderstand'): "1"})
    _txt(action, "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep")

    relates = ET.SubElement(hdr, ET.QName(NS_CES['a'], 'RelatesTo'))
    _txt(relates, f"urn:uuid:{uuid_request}")

    act = ET.SubElement(hdr, ET.QName(NS_CES['diag'], 'ActivityId'), {"CorrelationId": str(uuid_random)})
    _txt(act, "00000000-0000-0000-0000-000000000000")

    body = ET.SubElement(env, ET.QName(NS_CES['s'], 'Body'))

    rstrc = ET.SubElement(body, ET.QName(NS_CES['wst'], 'RequestSecurityTokenResponseCollection'))
    rstr = ET.SubElement(rstrc, ET.QName(NS_CES['wst'], 'RequestSecurityTokenResponse'))

    tok_type = ET.SubElement(rstr, ET.QName(NS_CES['wst'], 'TokenType'))
    _txt(tok_type, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")

    disp = ET.SubElement(rstr, ET.QName(NS_CES['ep'], 'DispositionMessage'))
    disp.set('xml:lang', 'en-US')
    _txt(disp, "Issued")

    bst_p7b = ET.SubElement(
        rstr, ET.QName(NS_CES['wsse'], 'BinarySecurityToken'),
        {
            "ValueType":    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7",
            "EncodingType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary",
        }
    )
    _txt(bst_p7b, p7b_der)

    req_tok = ET.SubElement(rstr, ET.QName(NS_CES['wst'], 'RequestedSecurityToken'))

    bst_leaf = ET.SubElement(
        req_tok, ET.QName(NS_CES['wsse'], 'BinarySecurityToken'),
        {
            "ValueType":    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
            "EncodingType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary",
        }
    )
    _txt(bst_leaf, leaf_der)

    req_id = ET.SubElement(rstr, ET.QName(NS_CES['ep'], 'RequestID'))
    _txt(req_id, body_part_id)

    raw = ET.tostring(env, encoding="utf-8", xml_declaration=True)
    return _prettify(raw)
