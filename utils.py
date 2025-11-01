#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import os
import ipaddress
import glob
from typing import Tuple, Iterable, List, Optional, Dict, Any, Set
from datetime import datetime, timezone, timedelta
import xml.etree.ElementTree as ET
from xml.dom import minidom

from asn1crypto import csr
from asn1crypto import cms as a_cms, x509 as a_x509, core as a_core

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa,
    ec,
    ed25519,
    ed448,
    dsa,
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

def _decode_ms_template_value(data: bytes) -> Optional[str]:
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


def extract_ms_template_from_csr_der(csr_der: bytes) -> Dict[str, Optional[str]]:
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


def exct_csr_from_cmc(p7_der: bytes) -> Tuple[bytes, int, dict]:
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

    signed_attrs = a_cms.CMSAttributes(
        [
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.3", "values": [a_cms.ContentType("1.3.6.1.5.5.7.12.2")]}),
            a_cms.CMSAttribute({"type": "1.2.840.113549.1.9.4", "values": [hashlib.sha256(certrep_der).digest()]}),
        ]
    )

    to_be_signed = _tbs_signed_attrs(signed_attrs)

    digest_alg = a_cms.DigestAlgorithm({"algorithm": "sha256"})
    signer_info = a_cms.SignerInfo(
        {
            "version": "v1",
            "sid": a_cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": a_cms.IssuerAndSerialNumber(
                        {"issuer": ca_cert.issuer, "serial_number": ca_cert.serial_number}
                    )
                }
            ),
            "digest_algorithm": a_cms.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": a_cms.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature": b"",  # filled after
        }
    )

    signature = ca_key.sign(to_be_signed, padding.PKCS1v15(), hashes.SHA256())
    signer_info["signature"] = signature

    signed_data = a_cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_alg],
            "encap_content_info": encap_content_info,
            "certificates": [ca_cert, leaf_cert],
            "signer_infos": [signer_info],
        }
    )

    content_info = a_cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
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

def search_user(userauth: str):
    """
    Resolve the SAM/LDAP entry for the Kerberos user 'user@REALM'.
    Returns (SamDB, entry) if found.
    """
    lp = LoadParm()
    lp.load_default()

    creds = Credentials()
    creds.guess(lp)
    creds.set_kerberos_state(True)
    creds.set_machine_account(lp)

    realm = lp.get("realm")
    net = Net(creds=creds, lp=lp)
    flags = nbt.NBT_SERVER_LDAP
    dc_info = net.finddc(domain=realm, flags=flags)
    dc_fqdn = str(dc_info.pdc_dns_name)

    ldap_url = f"ldap://{dc_fqdn}"

    samdbr = SamDB(url=ldap_url, credentials=creds, lp=lp)

    res = samdbr.search(
        base="DC=" + userauth.split("@")[1].replace(".", ",DC="),
        scope=2,
        expression="(samAccountName=%s)" % userauth.split("@")[0],
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
    # <s:Envelope>
    env = ET.Element(ET.QName(NS_EP['s'], 'Envelope'))

    # <s:Header>
    hdr = ET.SubElement(env, ET.QName(NS_EP['s'], 'Header'))
    action = ET.SubElement(hdr, ET.QName(NS_EP['a'], 'Action'), {ET.QName(NS_EP['s'], 'mustUnderstand'): "1"})
    action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"

    relates = ET.SubElement(hdr, ET.QName(NS_EP['a'], 'RelatesTo'))
    relates.text = f"urn:uuid:{uuid_request}"

    # ActivityId (Diagnostics ns)
    act = ET.SubElement(hdr, ET.QName(NS_EP['diag'], 'ActivityId'), {"CorrelationId": str(uuid_random)})
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
    for t in templates:
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

        alg = ET.SubElement(pka, ET.QName(NS_EP['ep'], 'algorithmOIDReference'))
        alg_ref = t["private_key_attributes"].get("algorithm_oid_reference")
        set_xsi_nil(alg, False if alg_ref else True)
        if alg_ref:
            alg.text = str(alg_ref)

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

        hash_alg = ET.SubElement(attrs, ET.QName(NS_EP['ep'], 'hashAlgorithmOIDReference'))
        hash_ref = t["flags"].get("hash_algorithm_oid_reference")
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

    # --- cAs (response) ---
    ep_cas = ET.SubElement(gpr, ET.QName(NS_EP['ep'], 'cAs'))
    for i, ca in enumerate(cas, start=1):
        ca_el = ET.SubElement(ep_cas, ET.QName(NS_EP['ep'], 'cA'))
        uris = ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'uris'))
        cauri = ET.SubElement(uris, ET.QName(NS_EP['ep'], 'cAURI'))
        text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'clientAuthentication')), 2)
        text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'uri')), f"{hosturl}{ca['__ces_path']}")
        text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'priority')), i)
        text(ET.SubElement(cauri, ET.QName(NS_EP['ep'], 'renewalOnly')), "false")

        text(ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'certificate')), ca["__certificate_b64"])
        text(ET.SubElement(ca_el, ET.QName(NS_EP['ep'], 'enrollPermission')), tbool(ca["enroll_permission"]))
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


# -----------------------------------------------------------------------------
# CRL helpers and persistent CRLNumber sidecar
# -----------------------------------------------------------------------------

def _load_existing_crl(path: str):
    """Load an existing CRL (PEM or DER). Returns None if missing."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        try:
            return cx509.load_pem_x509_crl(data)
        except Exception:
            return cx509.load_der_x509_crl(data)
    except FileNotFoundError:
        return None


def _iter_revoked(crl) -> List[cx509.RevokedCertificate]:
    """Iterate revoked entries across cryptography versions."""
    if not crl:
        return []
    try:
        return list(crl)
    except Exception:
        rc = getattr(crl, "revoked_certificates", None)
        return list(rc) if rc else []


def _read_crl_number_from_obj(crl) -> Optional[int]:
    """Try to read CRLNumber from a CRL object."""
    if not crl:
        return None
    try:
        ext = crl.extensions.get_extension_for_oid(cx509.ExtensionOID.CRL_NUMBER).value
        return int(ext.crl_number)
    except Exception:
        pass
    try:
        for ext in crl.extensions:
            if getattr(ext, "oid", None) == cx509.ExtensionOID.CRL_NUMBER:
                try:
                    return int(ext.value.crl_number)
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _crlnum_sidecar_path(crl_path: str) -> str:
    return crl_path + ".num"


def _read_sidecar_num(path: str) -> Optional[int]:
    try:
        with open(path, "rt", encoding="utf-8") as f:
            return int(f.read().strip(), 10)
    except Exception:
        return None


def _write_sidecar_num(path: str, num: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wt", encoding="utf-8") as f:
        f.write(str(int(num)))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic on POSIX


def _next_crl_number_persistent(crl_path: str, crl, bump: bool = True) -> int:
    """
    Compute the next CRLNumber using a sidecar file (persistent across restarts).
    If bump=False, return the current value without incrementing.
    """
    sidecar = _crlnum_sidecar_path(crl_path)
    sc = _read_sidecar_num(sidecar)
    cur = _read_crl_number_from_obj(crl)

    if not bump:
        return sc if sc is not None else (cur if cur is not None else 1)

    if sc is not None:
        nxt = sc + 1
    elif cur is not None:
        nxt = cur + 1
    else:
        nxt = 1
    _write_sidecar_num(sidecar, nxt)
    return nxt


def _serial_to_int(serial) -> int:
    """Parse a serial that may be hex-string ('0x...') or decimal-string."""
    if isinstance(serial, str):
        s = serial.strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        try:
            return int(s, 16)
        except ValueError:
            return int(s, 10)
    return int(serial)


def _add_aki_if_absent(builder, ca_key):
    """Add AKI from issuer public key if not already present."""
    try:
        builder.extensions.get_extension_for_class(cx509.AuthorityKeyIdentifier)
    except Exception:
        try:
            aki = cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
            builder = builder.add_extension(aki, critical=False)
        except Exception:
            pass
    return builder


def _select_algo(hash_name: str):
    """Select a HashAlgorithm object by name, defaulting to SHA-256."""
    algo = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
        "sha1":   hashes.SHA1,
    }.get(hash_name.lower(), hashes.SHA256)
    return algo()


def _write_crl_file(crl_path: str, pem_bytes: bytes) -> None:
    """Write a PEM CRL to disk safely (create dirs, fsync, replace)."""
    dirn = os.path.dirname(crl_path) or "."
    os.makedirs(dirn, exist_ok=True)
    with open(crl_path, "wb") as f:
        f.write(pem_bytes)
        f.flush()
        os.fsync(f.fileno())


# -----------------------------------------------------------------------------
# CRL operations: revoke / unrevoke / resign
# -----------------------------------------------------------------------------

def revoke(ca_key, ca_cert: cx509.Certificate, serial, crl_path: str, next_update_hours: int = 8) -> None:
    """Add a revoked entry for `serial` and write a new CRL."""
    serial_int = _serial_to_int(serial)

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    crl_number = _next_crl_number_persistent(crl_path, old_crl, bump=True)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    # Reuse extensions (except CRL_NUMBER) from the previous CRL if present
    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass

    builder = builder.add_extension(cx509.CRLNumber(crl_number), critical=False)

    # Reinstate all previous revoked certs except the one being (re)added
    for rc in _iter_revoked(old_crl):
        if rc.serial_number == serial_int:
            continue
        builder = builder.add_revoked_certificate(rc)

    rcb = (
        cx509.RevokedCertificateBuilder()
        .serial_number(serial_int)
        .revocation_date(now)
        .add_extension(cx509.CRLReason(cx509.ReasonFlags.unspecified), critical=False)
    ).build()
    builder = builder.add_revoked_certificate(rcb)

    builder = _add_aki_if_absent(builder, ca_key)

    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)


def unrevoke(ca_key, ca_cert: cx509.Certificate, serial, crl_path: str, next_update_hours: int = 8) -> None:
    """Remove a revoked entry for `serial` and write a new CRL."""
    serial_int = _serial_to_int(serial)

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    if not old_crl:
        raise FileNotFoundError(f"CRL not found at '{crl_path}' — nothing to remove.")

    crl_number = _next_crl_number_persistent(crl_path, old_crl, bump=True)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass

    builder = builder.add_extension(cx509.CRLNumber(crl_number), critical=False)

    # Reinstate all previous revoked certs except the one being removed
    for rc in _iter_revoked(old_crl):
        if rc.serial_number == serial_int:
            continue
        builder = builder.add_revoked_certificate(rc)

    builder = _add_aki_if_absent(builder, ca_key)

    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)


def resign_crl(
    ca_key,
    ca_cert: cx509.Certificate,
    crl_path: str,
    *,
    next_update_hours: int = 8,
    bump_number: bool = True,
    hash_name: str = "sha256",
) -> int:
    """
    Re-sign the CRL even if nothing changed (bump CRLNumber and refresh dates).
    Returns the new CRLNumber.
    """
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=int(next_update_hours))

    old_crl = _load_existing_crl(crl_path)
    revoked_list = _iter_revoked(old_crl)  # may be empty and that's OK

    new_num = _next_crl_number_persistent(crl_path, old_crl, bump=bump_number)

    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    if old_crl is not None:
        for ext in old_crl.extensions:
            if ext.oid == cx509.ExtensionOID.CRL_NUMBER:
                continue
            try:
                builder = builder.add_extension(ext.value, ext.critical)
            except Exception:
                pass  # be tolerant across versions/values

    builder = builder.add_extension(cx509.CRLNumber(int(new_num)), critical=False)

    for rc in revoked_list:
        try:
            builder = builder.add_revoked_certificate(rc)
        except Exception:
            try:
                minimal = (
                    cx509.RevokedCertificateBuilder()
                    .serial_number(rc.serial_number)
                    .revocation_date(rc.revocation_date)
                    .build()
                )
                builder = builder.add_revoked_certificate(minimal)
            except Exception:
                pass

    builder = _add_aki_if_absent(builder, ca_key)

    algo = _select_algo(hash_name)
    new_crl = builder.sign(private_key=ca_key, algorithm=algo)
    pem_bytes = new_crl.public_bytes(encoding=serialization.Encoding.PEM)
    _write_crl_file(crl_path, pem_bytes)

    # Optional sanity check
    try:
        written = _load_existing_crl(crl_path)
        ext = written.extensions.get_extension_for_oid(cx509.ExtensionOID.CRL_NUMBER).value
        assert int(ext.crl_number) == int(new_num)
    except Exception:
        pass

    return int(new_num)


# -----------------------------------------------------------------------------
# Certificate issuance (new keypair + end-entity certificate)
# -----------------------------------------------------------------------------

def _coerce_san(s: str) -> cx509.GeneralName:
    s = (s or "").strip()
    if not s:
        raise ValueError("Empty SAN")
    try:
        return cx509.IPAddress(ipaddress.ip_address(s))
    except ValueError:
        return cx509.DNSName(s)


def _dedup_sans(strings: Iterable[str]) -> List[cx509.GeneralName]:
    out: List[cx509.GeneralName] = []
    seen = set()
    for s in strings or []:
        try:
            gn = _coerce_san(s)
        except ValueError:
            continue
        key = ("IP", str(gn.value)) if isinstance(gn, cx509.IPAddress) else ("DNS", gn.value.lower())
        if key not in seen:
            out.append(gn)
            seen.add(key)
    return out


def issue_cert_with_new_key(
    *,
    ca: Dict[str, Any],                     # "__certificate_der": bytes, "__key_obj": private key
    common_name: str,
    subject_sans: Iterable[str] = (),
    validity_seconds: int = 365 * 24 * 3600,
    backdate_seconds: int = 300,
    key_type: str = "rsa",                  # "rsa" | "ec" | "ed25519" | "ed448"
    rsa_key_size: int = 2048,
    ec_curve: str = "secp256r1",            # "secp384r1", "secp521r1", "secp256k1"
    key_export_password: Optional[bytes] = None,
) -> Tuple[cx509.Certificate, Any, bytes, bytes]:
    """Generate a new keypair, issue an end-entity certificate, and return (cert_obj, privkey_obj, cert_pem, key_pem)."""

    # Generate subject key
    key_type_l = (key_type or "rsa").lower()
    if key_type_l == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=int(rsa_key_size))
    elif key_type_l == "ec":
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1(),
        }
        curve = curve_map.get((ec_curve or "secp256r1").lower(), ec.SECP256R1())
        priv = ec.generate_private_key(curve)
    elif key_type_l == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    elif key_type_l == "ed448":
        priv = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unknown key_type: {key_type}")

    pub = priv.public_key()

    # CA material
    ca_cert = cx509.load_der_x509_certificate(ca["__certificate_der"])
    ca_key = ca["__key_obj"]

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(seconds=int(backdate_seconds))
    not_after = not_before + timedelta(seconds=int(validity_seconds))

    # Build certificate
    builder = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )

    # AKI
    try:
        builder = builder.add_extension(
            cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    except Exception:
        pass

    # AIA / CDP from config
    urls = ca.get("urls", {}) or {}
    if urls.get("ca_issuers_http"):
        builder = builder.add_extension(
            cx509.AuthorityInformationAccess([
                cx509.AccessDescription(
                    cx509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                    cx509.UniformResourceIdentifier(urls["ca_issuers_http"]),
                )
            ]),
            critical=False,
        )
    if urls.get("crl_http"):
        builder = builder.add_extension(
            cx509.CRLDistributionPoints([
                cx509.DistributionPoint(
                    full_name=[cx509.UniformResourceIdentifier(urls["crl_http"])],
                    relative_name=None, reasons=None, crl_issuer=None
                )
            ]),
            critical=False,
        )

    # SAN
    if subject_sans:
        sans = _dedup_sans(subject_sans)
        if sans:
            builder = builder.add_extension(cx509.SubjectAlternativeName(sans), critical=False)

    # Sign
    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = builder.sign(private_key=ca_key, algorithm=None)
    else:
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Export PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    if key_export_password:
        encryption = serialization.BestAvailableEncryption(key_export_password)
    else:
        encryption = serialization.NoEncryption()

    key_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    return cert, priv, cert_pem, key_pem


# -----------------------------------------------------------------------------
# Certificate file helpers (parsing and discovery)
# -----------------------------------------------------------------------------

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"
_CERT_EXTS = {".crt", ".pem", ".cer"}

def is_pem_blob(data: bytes) -> bool:
    return _PEM_BEGIN in data and _PEM_END in data

def load_certificate_file(path: str) -> cx509.Certificate:
    """Load a certificate from a file (PEM, DER, or raw base64 DER)."""
    with open(path, "rb") as f:
        data = f.read()
    if not is_pem_blob(data):
        # Try direct DER
        try:
            return cx509.load_der_x509_certificate(data)
        except Exception:
            # Often DER is base64 without headers
            try:
                der = base64.b64decode(data)
                return cx509.load_der_x509_certificate(der)
            except Exception as e:
                raise ValueError(f"File not recognized as X.509 certificate: {os.path.basename(path)}: {e}")
    return cx509.load_pem_x509_certificate(data)

def get_public_key_info(cert: cx509.Certificate) -> Tuple[str, Optional[int]]:
    """Return ('RSA', bits) | ('EC(name)', None) | ('DSA', bits) | (class_name, None)."""
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return ("RSA", pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        try:
            name = pk.curve.name
        except Exception:
            name = pk.curve.__class__.__name__
        return (f"EC({name})", None)
    if isinstance(pk, dsa.DSAPublicKey):
        return ("DSA", pk.key_size)
    return (pk.__class__.__name__, None)

def scan_cert_paths(cert_dir: str) -> List[str]:
    """Return a sorted list of certificate file paths in `cert_dir` (recursive)."""
    files: List[str] = []
    for ext in _CERT_EXTS:
        files.extend(glob.glob(os.path.join(cert_dir, f"**/*{ext}"), recursive=True))
    return sorted(set(files))

def revoked_serials_set(crl_path: Optional[str]) -> Set[int]:
    """Return the set of revoked serial numbers (as ints) from the CRL at `crl_path`."""
    if not crl_path:
        return set()
    crl = _load_existing_crl(crl_path)
    if not crl:
        return set()
    return {rc.serial_number for rc in _iter_revoked(crl)}

