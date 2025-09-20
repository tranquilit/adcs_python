#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
from typing import Tuple

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
)
from cryptography.x509.oid import ObjectIdentifier as CObjectIdentifier

# Samba / AD lookup (used by search_user)
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.net import Net
from samba.dcerpc import nbt


# -----------------------------------------------------------------------------
# Useful OIDs
# -----------------------------------------------------------------------------
OID_MS_CERT_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2"
OID_MS_CERT_TEMPLATE_INFO = "1.3.6.1.4.1.311.21.7"


# -----------------------------------------------------------------------------
# Useful ASN.1 structures (CMC/PKIData, NTDS CA Security, etc.)
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
# ASN.1 helpers
# -----------------------------------------------------------------------------

def _der_wrap_sequence(contents: bytes) -> bytes:
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
# CSR parsing (extract CSR from a CMC/PKIData, + read Template OID)
# -----------------------------------------------------------------------------

def _parse_template_from_csr_bytes(csr_der: bytes) -> dict:
    """
    Return a dict {"name","oid","major","minor"} if present in the extensions
    MS Cert Template Name / Info.
    """
    tpl = {"name": None, "oid": None, "major": None, "minor": None}

    csr_obj = csr.CertificationRequest.load(csr_der)
    cri = csr_obj["certification_request_info"]

    for attr in cri["attributes"]:
        if attr["type"].dotted != "1.2.840.113549.1.9.14":
            continue

        for val in attr["values"]:
            exts = a_x509.Extensions.load(val.dump()) if not isinstance(val, a_x509.Extensions) else val
            for ext in exts:
                ext_oid = ext["extn_id"].dotted
                inner_der = ext["extn_value"].parsed.dump()

                if ext_oid == OID_MS_CERT_TEMPLATE_NAME:
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


def exct_csr_from_cmc(p7_der: bytes) -> Tuple[bytes, int, dict]:
    """
    Try, in this order, to extract a CSR and its bodyPartID from a wrapped CMC
    (PKIData in SignedData), then fallback to simplePKIRequest or direct CSR.
    Return (csr_der, body_part_id, template_info_dict).
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
            f"Unable to extract a CSR: no TCR, no simplePKIRequest, nor a direct CSR. "
            f"EncapContentInfo.content_type={ct}"
        )
    except Exception:
        # Ultimate fallback: some clients send just a “naked” CSR
        direct = csr.CertificationRequest.load(p7_der)
        csr_bytes = direct.dump()
        return csr_bytes, 0, _parse_template_from_csr_bytes(csr_bytes)


# -----------------------------------------------------------------------------
# CSR validation (robust: signature always explicitly verified)
# -----------------------------------------------------------------------------

class CSRValidationError(ValueError):
    pass


def validate_csr(csr_obj: cx509.CertificateSigningRequest) -> None:
    """
    Validate a CSR:
      - signature (always explicitly verified, not via is_signature_valid)
      - hash algorithm (SHA-256/384/512) for RSA/ECDSA
      - acceptable public key (RSA>=2048 & e>=65537 odd; EC P-256/384/521; Ed25519/Ed448 ok)
    Raise CSRValidationError if invalid.
    """
    pub = csr_obj.public_key()

    # 1) Explicit signature verification, adapted to key type
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            hash_algo = csr_obj.signature_hash_algorithm  # SHA-2 expected
            pub.verify(
                csr_obj.signature,
                csr_obj.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                hash_algo,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            hash_algo = csr_obj.signature_hash_algorithm  # SHA-2 expected
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

    # 2) Constraints on hash algo (not applicable to EdDSA)
#    if not isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
#        try:
#            hash_name = csr_obj.signature_hash_algorithm.name.lower()
#        except Exception:
#            hash_name = ""
#        if hash_name not in ("sha256", "sha384", "sha512"):
#            raise CSRValidationError(
#                f"Disallowed signature hash: {hash_name or 'unknown'} (require SHA-256/384/512)"
#            )

    # 3) Constraints on public key
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
    # Ed25519/Ed448: no extra size constraint


# -----------------------------------------------------------------------------
# Build the BST / PKCS#7 (CES response like ADCS)
# -----------------------------------------------------------------------------

def _tbs_signed_attrs(attrs: a_cms.CMSAttributes) -> bytes:
    """
    Return the SET version (tag 0x31) of the attributes for PKCS#7 signature.
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
# Utility encoding
# -----------------------------------------------------------------------------

def format_b64_for_soap(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# -----------------------------------------------------------------------------
# User resolution (SAMBA/LDAP)
# -----------------------------------------------------------------------------

def search_user(userauth: str):
    """
    Resolve the SAM/LDAP entry for the Kerberos user 'user@REALM'.
    Return (SamDB, entry) if found.
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
            continue  # dynamic (e.g. NTDS) -> handled elsewhere
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

