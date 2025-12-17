from datetime import datetime, timedelta
from typing import Iterable, Optional, Dict, Any
from asn1crypto import core as a_core
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import (
    ExtensionOID,
    NameOID,
    AuthorityInformationAccessOID,
    ObjectIdentifier as CObjectIdentifier,
)

from cryptography.x509.extensions import ExtensionNotFound

# As before
from utils import NtdsAttr, NtdsCASecurityExt,search_user
from utils import _apply_static_extensions
import hashlib


# ---------- helpers (optional) ----------
def _is_member_of(sam_entry: dict, groups: Iterable[str]) -> bool:
    member_of = sam_entry.get("memberOf") or []
    for raw in member_of:
        dn = raw.decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        for frag in groups:
            if frag.lower() in dn.lower():
                return True
    return False


# ============================================================
# 1) Template definition for CEP (dynamic per user)
# ============================================================

template_oid           = "1.3.6.1.4.1.311.21.8.999.1"
template_name          = "adcswebuser"
template_major_version = 100
template_minor_version = 3
auto_enroll            = True

def define_template(*, app_conf, kerberos_user=None , request=None):
    validity_seconds = 31536000       # 1 year
    renewal_seconds = 3628800         # 42 days
    auto_enroll = True

    # if ssl auth
    XSslClientSha1 = request.headers.get('X-Ssl-Client-Sha1', None)
    XSslAuthenticated = request.headers.get('X-Ssl-Authenticated', None)
    XSslClientDn = request.headers.get('X-Ssl-Client-Dn', None)

    if kerberos_user :
       username = kerberos_user
    else:
       username = XSslClientDn.split('=',1)[1] 
    samdbr, sam_entry = search_user(username)

    # Example: special group = duration x2
    if _is_member_of(sam_entry or {}, ["CN=PKI-LongLived"]):
        validity_seconds *= 2
        renewal_seconds *= 2
        
    return {
    # MS-XCEP Attributes/commonName: friendly/unique name of the policy item returned by CEP/XCEP
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
    "common_name": template_name,

    "template_oid": {
        # AD CS template OID (msPKI-Cert-Template-OID)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4849b1d6-b6bf-405c-8e9c-28ede1874efa
        "value": template_oid,

        # Template display/name you expose in your policy (often maps to template CN/displayName in AD CS)
        # MS-CRTD (certificate template structures overview)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4c6950e4-1dc2-4ae3-98c3-b8919bb73822
        "name": template_name,

        # Template schema version (msPKI-Template-Schema-Version)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/bf5bd40c-0d4d-44bd-870e-8a6bdea3ca88
        "major_version": template_major_version,

        # Template minor revision (msPKI-Template-Minor-Revision)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3c315531-7cb0-44de-afb9-5c6f9a8aea49
        "minor_version": template_minor_version,
    },

    # MS-XCEP CAReferenceCollection: references to issuing CAs exposed by the policy
    # CAReferenceCollection: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/95baab3d-2f0b-42ad-897a-26565c5f723f
    # CA (cAReferenceID):    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/158e7965-8a82-4729-8271-00aa59e140fe
    "ca_references": ["ca1-inter"],

    # MS-XCEP Attributes/policySchema: policy schema version used by the CEP/XCEP response
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
    "policy_schema": 2,

    "revision": {
        # MS-XCEP Attributes/revision (Revision.majorRevision/minorRevision)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/fc1bb552-591f-45bc-9b18-67e1fb20b394
        "major": template_major_version,

        # MS-XCEP Attributes/revision (minorRevision)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/fc1bb552-591f-45bc-9b18-67e1fb20b394
        "minor": template_minor_version,
    },

    "validity": {
        # MS-XCEP Attributes/certificateValidity.validityPeriodSeconds
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/97bc077a-8f4b-4ab4-b78e-6b312a7642f9
        "validity_seconds": validity_seconds,

        # MS-XCEP Attributes/certificateValidity.renewalPeriodSeconds
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/97bc077a-8f4b-4ab4-b78e-6b312a7642f9
        "renewal_seconds": renewal_seconds,
    },

    "permissions": {
        # MS-XCEP Attributes/permission.enroll: whether enrollment is permitted
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cc5a0298-fd6b-41f1-a700-dad9f8e95842
        "enroll": True,

        # MS-XCEP Attributes/permission.autoEnroll: whether auto-enrollment is permitted
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cc5a0298-fd6b-41f1-a700-dad9f8e95842
        "auto_enroll": auto_enroll,
    },

    "flags": {
        # MS-XCEP Attributes: privateKeyFlags / subjectNameFlags / enrollmentFlags / generalFlags (bitmasks)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
        #
        # AD CS “template in AD” equivalents:
        # - msPKI-Private-Key-Flag      https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
        # - msPKI-Certificate-Name-Flag https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
        # - msPKI-Enrollment-Flag       https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1

        "private_key_flags": {
            # MS-XCEP privateKeyFlags: allow the private key to be exported
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
            "exportable_key": True,
        },

        "subject_name_flags": {
            # MS-XCEP subjectNameFlags: request/require CA-populated SAN entries from directory attributes
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063

            "add_dns_to_san": True,               # require/add DNS in SAN (from directory)
            "add_upn_to_san": True,               # require/add UPN in SAN (from directory)
            "add_email_to_san": True,             # require/add email in SAN (from directory)

            "subject_require_directory_path": True,  # subject must include directory path
            "subject_require_email": True,           # subject must include email attribute
            "subject_require_common_name": False,    # subject must include CN (disabled here)
            "subject_dns_as_cn": False,              # use DNS as CN in subject (disabled here)

            "enrollee_supplies_subject": False,      # CSR subject is supplied by the enrollee (disabled)
            "enrollee_supplies_san": False,          # CSR SAN is supplied by the enrollee (disabled)
            "old_cert_supplies_subject_and_alt_name": False,  # renewal reuses old subject+SAN (disabled)

            "add_domain_dns_to_san": False,          # require/add root domain DNS in SAN (disabled)
            "add_spn_to_san": False,                 # require/add SPN in SAN (disabled)
            "add_directory_guid_to_san": False,      # require/add directory GUID in SAN (disabled)
        },

        "enrollment_flags": {
            # MS-XCEP enrollmentFlags: enrollment behavior (publish, auto-enroll, pending, etc.)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063

            "include_symmetric_algorithms": True,     # include symmetric algorithms (S/MIME-related)
            "publish_to_ds": True,                    # publish issued cert to directory
            "auto_enrollment": auto_enroll,           # allow auto-enrollment
            "user_interaction_required": False,       # require user interaction/consent (disabled)
            "pend_all_requests": False,               # all requests go pending (disabled)
            "publish_to_kra_container": False,        # publish to KRA container (disabled)
            "auto_enrollment_check_user_ds_certificate": False,  # block auto-enroll if valid cert exists (disabled)
            "previous_approval_validate_reenrollment": False,    # validate reenrollment with previous approval (disabled)
            "add_ocsp_nocheck": False,                # add id-pkix-ocsp-nocheck (disabled)
            "enable_key_reuse_on_nt_token_keyset_storage_full": False,  # allow key reuse if token storage full (disabled)
            "no_revocation_info_in_issued_certs": False,         # omit revocation info (disabled)
            "include_basic_constraints_for_ee_certs": False,     # include basic constraints for end-entity (disabled)
            "allow_enroll_on_behalf_of": False,       # allow enroll-on-behalf-of (disabled)
            "allow_previous_approval_keybasedrenewal_validate_reenroll": False,  # key-based renewal behavior (disabled)
            "issuance_policies_from_request": False,   # take issuance policies from CSR (disabled)
            "skip_auto_renewal": False,               # disable auto-renewal (disabled)
            "remove_invalid_certificate_from_personal_store": False,  # cleanup invalid certs (disabled)
        },

        "general_flags": {
            # MS-XCEP generalFlags: general template flags (machine/CA/cross-CA)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
            #
            # Processing semantics: MS-WCCE Certificate.Template.flags
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/c07fc301-a7c1-4a61-ba91-142b751ad114
            "machine_type": False,  # machine template
            "ca_type": False,       # CA request template
            "cross_ca": False,      # cross-cert template
        },
    },

    "private_key_attributes": {
        # MS-XCEP PrivateKeyAttributes: key generation requirements sent by CEP/XCEP
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cf7610a9-26cb-4172-a4c5-895066acf191
        "minimal_key_length": 2048,          # minimalKeyLength (in bits)
        "key_spec": 1,                       # keySpec (default key spec semantics are described in MS-WCCE)
        "algorithm_oid_reference": None,      # algorithmOIDReference (reference into the OID table in XCEP)

        "crypto_providers": [
            # MS-XCEP CryptoProviders: list of CSP/KSP provider names allowed for key generation
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/808caee4-e016-4f9e-ad0a-076ce83c86c7
            "Microsoft Software Key Storage Provider",
            "Microsoft Platform Crypto Provider",
            "Microsoft Enhanced Cryptographic Provider v1.0",
            "Microsoft Base Cryptographic Provider v1.0",
        ],

        # Smartcard example (optional):
        # "crypto_providers": [
        #     "Microsoft Smart Card Key Storage Provider",
        #     "Microsoft Base Smart Card Crypto Provider"
        # ],
    },

    # MS-XCEP ExtensionCollection: list of X.509 extensions carried by the policy
    # ExtensionCollection: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/678f2712-a333-461a-be63-9ada81af81e7
    # Extension:           https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/1ba4cfe2-d0fc-4446-bb70-eca2c28810ce
    "required_extensions": [
        {
            # Microsoft Certificate Template Information extension (1.3.6.1.4.1.311.21.7)
            # MS-WCCE szOID_CERTIFICATE_TEMPLATE
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf
            "oid": "1.3.6.1.4.1.311.21.7",
            "critical": False,
            "template_info": {
                # Template OID carried in the extension
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf
                "oid": template_oid,
                "major_version": template_major_version,
                "minor_version": template_minor_version,
            },
        },
        {
            # Extended Key Usage (EKU) extension (2.5.29.37)
            # MS-WCCE pKIExtendedKeyUsage (server constructs EKU from template attributes)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/1c1d7aaa-281b-48f2-babc-1bc42dd3ed37
            "oid": "2.5.29.37",
            "critical": False,
            "eku_oids": [
                "1.3.6.1.5.5.7.3.2",        # id-kp-clientAuth
                "1.3.6.1.4.1.311.10.3.4",   # Microsoft EFS
            ],
        },
        {
            # Key Usage extension (2.5.29.15)
            # MS-WCCE pKIKeyUsage (server constructs keyUsage from template attributes)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/98626a7c-31eb-46f4-9c44-3cfb29e6c823
            "oid": "2.5.29.15",
            "critical": True,
            "key_usage": {
                "digital_signature": True,     # digitalSignature
                "content_commitment": False,   # nonRepudiation/contentCommitment
                "key_encipherment": True,      # keyEncipherment
                "data_encipherment": False,    # dataEncipherment
                "key_agreement": False,        # keyAgreement
                "key_cert_sign": False,        # keyCertSign
                "crl_sign": False,             # cRLSign
                "encipher_only": False,        # encipherOnly
                "decipher_only": False,        # decipherOnly
            },
        },
        {
            # Microsoft Certificate Application Policy extension (1.3.6.1.4.1.311.21.10)
            # MS-WCCE (application policy encoding/behavior)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/160b96b1-c431-457a-8eed-27c11873f378
            "oid": "1.3.6.1.4.1.311.21.10",
            "critical": False,
            "app_policies": [
                "1.3.6.1.5.5.7.3.2",        # ClientAuth
                "1.3.6.1.4.1.311.10.3.4",   # EFS
            ],
        },
    ],
}


# =======================================
# 2) Certificate issuance (CES callback)
# =======================================
def emit_certificate(
    *,
    csr_der: Optional[bytes],
    request_id: Optional[int],
    kerberos_user: str,
    ca: dict,
    template: Optional[dict],
    info: dict,
    app_conf: dict,
    CAID,
    request,
    body_part_id
) -> Dict[str, Any]:

    # if ssl auth
    XSslClientSha1 = request.headers.get('X-Ssl-Client-Sha1', None)
    XSslAuthenticated = request.headers.get('X-Ssl-Authenticated', None)
    XSslClientDn = request.headers.get('X-Ssl-Client-Dn', None)

    if kerberos_user :
       username = kerberos_user
    else:
       username = XSslClientDn.split('=',1)[1] 
    samdbr, sam_entry = search_user(username)

    denied = False
    must_pending = False

    if denied:
        return {
            "status": "denied",
            "status_text": "denied",
        }
    

    if must_pending:
        return {
            "status": "pending",
            "status_text": "Awaiting manual validation",
        }

    csr = cx509.load_der_x509_csr(csr_der)
    ca_cert = cx509.load_der_x509_certificate(ca["__certificate_der"])
    now = datetime.utcnow() - timedelta(minutes=5)

    UPN_OID = CObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
    try:
        san = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except ExtensionNotFound :
        san = []
    
    list_upn_in_csr = []
    for name in san:
        if isinstance(name, cx509.OtherName) and name.type_id == UPN_OID:
            data = name.value
            if data[0] != 0x0c:
                raise ValueError("bad ASN.1 type")
            length = data[1]
            list_upn_in_csr.append(data[2:2 + length].decode("utf-8"))


    
    # CN = sAMAccountName
    cn = (sam_entry.get("sAMAccountName") or [b"user"])[0].decode("utf-8", "ignore")
    validity_seconds = (template or {}).get("validity", {}).get("validity_seconds") or 31536000

    builder = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(seconds=int(validity_seconds)))
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
    )

    # AIA/CDP from CA
    if ca.get("urls", {}).get("ca_issuers_http"):
        aia = cx509.AuthorityInformationAccess([
            cx509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                cx509.UniformResourceIdentifier(ca["urls"]["ca_issuers_http"])
            )
        ])
        builder = builder.add_extension(aia, critical=False)
    if ca.get("urls", {}).get("crl_http"):
        cdp = cx509.CRLDistributionPoints([
            cx509.DistributionPoint(
                full_name=[cx509.UniformResourceIdentifier(ca["urls"]["crl_http"])],
                relative_name=None, reasons=None, crl_issuer=None
            )
        ])
        builder = builder.add_extension(cdp, critical=False)

    # ✅ Apply static template extensions (EKU/KU/AppPolicies/TemplateInfo)
    builder = _apply_static_extensions(builder, template)

    # ➕ dynamic NTDS (SID)
    sid_bytes = samdbr.schema_format_value("objectSID", sam_entry["objectSID"][0])
    ntds_der = NtdsCASecurityExt([
        NtdsAttr({
            "attr_id": "1.3.6.1.4.1.311.25.2.1",  # ObjectSid
            "attr_values": [a_core.OctetString(sid_bytes)],
        })
    ]).dump()
    builder = builder.add_extension(
        cx509.UnrecognizedExtension(CObjectIdentifier("1.3.6.1.4.1.311.25.2"), ntds_der),
        critical=False
    )

    # (2) sign according to CA key type
    priv = ca["__key_obj"]
    if isinstance(priv, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = builder.sign(private_key=priv, algorithm=None)
    else:
        cert = builder.sign(private_key=priv, algorithm=hashes.SHA256())


    return {
        "status": "issued",
        "cert": cert,
    }

