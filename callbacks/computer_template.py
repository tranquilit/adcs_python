from datetime import datetime, timedelta
from typing import Iterable, Optional, Dict, Any
from asn1crypto import core as a_core
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448  # (2) sign according to key type
from cryptography.x509.oid import (
    NameOID,
    AuthorityInformationAccessOID,
    ObjectIdentifier as CObjectIdentifier,
)

# helpers/structs already present in your project
from utils import NtdsAttr, NtdsCASecurityExt, search_user
from utils import _apply_static_extensions
import hashlib

def _b(entry: dict, attr: str, default: str = "") -> str:
    vals = entry.get(attr) or []
    if not vals:
        return default
    v = vals[0]
    return v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v)




# ============================================================
# 1) Template definition for CEP (dynamic per user)
# ============================================================

template_oid           = "1.3.6.1.4.1.311.21.8.999.3"
template_name          = "adcswebcomputer"
template_major_version = 100
template_minor_version = 3
auto_enroll            = True

def define_template(*, app_conf, username=None, request=None):
    validity_seconds = 31536000       # 1 year
    renewal_seconds = 3628800         # 42 days
    auto_enroll = True

    # if ssl auth
    XSslClientSha1 = request.headers.get('X-Ssl-Client-Sha1', None)
    XSslAuthenticated = request.headers.get('X-Ssl-Authenticated', None)
    XSslClientDn = request.headers.get('X-Ssl-Client-Dn', None)
    XSslClientCert = request.headers.get('X-Ssl-Client-Cert', None)

    if username:
        username = username
    else:
        username = XSslClientDn.split('=', 1)[1]

    return {
        # MS-XCEP Attributes/commonName: friendly/unique name of a CertificateEnrollmentPolicy within a GetPoliciesResponse
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
        "common_name": template_name,

        "template_oid": {
            # MS-CRTD msPKI-Cert-Template-OID: the template OID
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4849b1d6-b6bf-405c-8e9c-28ede1874efa
            "value": template_oid,

            # MS-CRTD (template structures overview): template name/display name you expose
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4c6950e4-1dc2-4ae3-98c3-b8919bb73822
            "name": template_name,

            # MS-CRTD msPKI-Template-Schema-Version: template schema version (1..4)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/bf5bd40c-0d4d-44bd-870e-8a6bdea3ca88
            "major_version": template_major_version,

            # MS-CRTD msPKI-Template-Minor-Revision: template minor revision (0..0x7fffffff)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3c315531-7cb0-44de-afb9-5c6f9a8aea49
            "minor_version": template_minor_version,
        },

        # MS-XCEP CAReferenceCollection: references to issuing CAs returned by the policy response
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/95baab3d-2f0b-42ad-897a-26565c5f723f
        "ca_references": ["ca1-inter"],

        # MS-XCEP Attributes/policySchema: schema version for the policy object (SHOULD be 1,2,3)
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
        "policy_schema": 3,

        "revision": {
            # MS-XCEP Revision/majorRevision: populated from MS-CRTD "revision" attribute
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/fc1bb552-591f-45bc-9b18-67e1fb20b394
            "major": template_major_version,

            # MS-XCEP Revision/minorRevision: populated from MS-CRTD msPKI-Template-Minor-Revision
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/fc1bb552-591f-45bc-9b18-67e1fb20b394
            "minor": template_minor_version,
        },

        "validity": {
            # MS-XCEP CertificateValidity/validityPeriodSeconds: expected certificate validity (seconds)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/97bc077a-8f4b-4ab4-b78e-6b312a7642f9
            "validity_seconds": validity_seconds,

            # MS-XCEP CertificateValidity/renewalPeriodSeconds: recommended renewal window (seconds)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/97bc077a-8f4b-4ab4-b78e-6b312a7642f9
            "renewal_seconds": renewal_seconds,
        },

        "permissions": {
            # MS-XCEP EnrollmentPermission/enroll: requester has permission to enroll
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cc5a0298-fd6b-41f1-a700-dad9f8e95842
            "enroll": True,

            # MS-XCEP EnrollmentPermission/autoEnroll: requester has permission to auto-enroll
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cc5a0298-fd6b-41f1-a700-dad9f8e95842
            "auto_enroll": auto_enroll,
        },

        # FLAGS: booleans only
        # NOTE: Added missing keys (set to False) so compiled results remain unchanged.
        "flags": {
            "private_key_flags": {
                # --- Existing (unchanged intent) ---
                "exportable_key": False,

                # --- Missing keys added (all False => no mask change) ---
                "archive_private_key": False,                   # Archive private key (KRA)
                "protect_private_key": False,                   # Strong private key protection prompt/policy
                "require_alternate_signature_algorithm": False, # Require alternate signature algorithm/format
                "require_same_key_renewal": False,              # Renew using same key
                "use_legacy_provider": False,                   # Force legacy provider (CSP) behavior

                # TPM Key Attestation (AD CS)
                "attest_preferred": False,                      # Prefer TPM key attestation (if client can)
                "attest_required": False,                       # Require TPM key attestation (fail if not)
                "attestation_without_policy": False,            # Attest but do not add issuance policy OID
                "attest_none": False,                           # Explicit "none" (readability only)

                # EK trust model (AD CS)
                "ek_trust_on_use": False,                       # Trust-on-use / credentials-based
                "ek_validate_cert": False,                      # Validate EK certificate chain (EKCert)
                "ek_validate_key": False,                       # Validate EK public key (EKPub allowlist)

                # Windows Hello
                "hello_logon_key": False,                       # Windows Hello for Business logon key
            },

            "subject_name_flags": {
                # --- Existing (unchanged intent) ---
                "add_dns_to_san": True,               # require/add DNS in SAN (directory-sourced)
                "subject_dns_as_cn": True,            # use DNS as CN in Subject (when applicable)
                "enrollee_supplies_subject": False,   # enrollee supplies Subject in CSR
                "enrollee_supplies_san": False,       # enrollee supplies SAN in CSR
                "old_cert_supplies_subject_and_alt_name": False,  # renewal reuses old Subject+SAN
                "add_domain_dns_to_san": False,       # require/add root domain DNS in SAN
                "add_spn_to_san": False,              # require/add SPN in SAN
                "add_directory_guid_to_san": False,   # require/add directory GUID (objectGUID) in SAN
                "add_upn_to_san": False,              # require/add UPN in SAN
                "add_email_to_san": False,            # require/add email in SAN
                "subject_require_email": False,       # require email attribute in Subject
                "subject_require_common_name": False, # require CN in Subject
                "subject_require_directory_path": False, # require directory path in Subject

                # --- Missing keys added (all False => no mask change) ---
                # (Nothing else missing from the catalog for this family)
            },

            "enrollment_flags": {
                # --- Existing (unchanged intent) ---
                "include_symmetric_algorithms": True,     # CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
                "publish_to_ds": True,                    # CT_FLAG_PUBLISH_TO_DS
                "auto_enrollment": auto_enroll,           # CT_FLAG_AUTO_ENROLLMENT
                "user_interaction_required": False,       # CT_FLAG_USER_INTERACTION_REQUIRED
                "pend_all_requests": False,               # CT_FLAG_PEND_ALL_REQUESTS
                "publish_to_kra_container": False,        # CT_FLAG_PUBLISH_TO_KRA_CONTAINER
                "auto_enrollment_check_user_ds_certificate": False,  # CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
                "previous_approval_validate_reenrollment": False,    # CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT
                "add_ocsp_nocheck": False,                # CT_FLAG_ADD_OCSP_NOCHECK
                "enable_key_reuse_on_nt_token_keyset_storage_full": False,  # CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL
                "no_revocation_info_in_issued_certs": False,         # CT_FLAG_NO_REVOCATION_INFO_IN_ISSUED_CERTS
                "include_basic_constraints_for_ee_certs": False,     # CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS
                "allow_enroll_on_behalf_of": False,       # CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF
                "allow_previous_approval_keybasedrenewal_validate_reenroll": False,  # CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLL
                "issuance_policies_from_request": False,   # CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST
                "skip_auto_renewal": False,               # CT_FLAG_SKIP_AUTO_RENEWAL
                "remove_invalid_certificate_from_personal_store": False,  # CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE

                # --- Missing keys added (all False => no mask change) ---
                "do_not_include_sid_extension": False,    # Alias for no_security_extension (same bit)
                "no_security_extension": False,           # Do not include security extension (SID mapping ext) in issued cert
            },

            "general_flags": {
                # --- Existing (unchanged intent) ---
                "machine_type": True,  # CT_FLAG_MACHINE_TYPE: machine enrollment template
                "ca_type": False,      # CT_FLAG_IS_CA: CA request template
                "cross_ca": False,     # CT_FLAG_IS_CROSS_CA: cross-cert template

                # --- Missing keys added (all False => no mask change) ---
                "is_ca": False,                        # Alias for ca_type (same bit)
                "auto_enrollment": False,              # General auto-enrollment flag
                "add_template_name": False,            # Add template name extension
                "do_not_persist_in_db": False,         # Do not persist in CA DB
                "is_default": False,                   # Template marked default
                "is_modified": False,                  # Template marked modified

                # Reserved/MUST ignore (kept for completeness)
                "add_email_reserved_ignore": False,
                "publish_to_ds_reserved_ignore": False,
                "exportable_key_reserved_ignore": False,
            },
        },

        "hash_algorithm": "sha256",

        "private_key_attributes": {
            "algorithm": "ecdsa",  # rsa available

            # MS-XCEP PrivateKeyAttributes: private key generation requirements advertised by the policy
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cf7610a9-26cb-4172-a4c5-895066acf191
            "minimal_key_length": 256,  # minimalKeyLength (bits) (2048 if rsa)

            # MS-CRTD pKIDefaultKeySpec: allowed values for default key spec (AT_KEYEXCHANGE/AT_SIGNATURE)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ee5d75a7-8416-4a92-b708-ee8f6e8baffb
            "key_spec": 2,  # 2 If ECDSA   1 IF ECDH

            "crypto_providers": [
                # MS-XCEP CryptoProviders: list of allowed CSP/KSP provider names
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/808caee4-e016-4f9e-ad0a-076ce83c86c7
                "Microsoft Platform Crypto Provider",
                "Microsoft Software Key Storage Provider",
            ],
        },

        # Static extensions (re-applied at issuance)
        "required_extensions": [
            {  # Certificate Template Information
                # MS-WCCE szOID_CERTIFICATE_TEMPLATE: OID 1.3.6.1.4.1.311.21.7 (critical SHOULD be FALSE)
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf
                "oid": "1.3.6.1.4.1.311.21.7",
                "critical": False,
                "template_info": {
                    # TemplateID maps to MS-CRTD msPKI-Cert-Template-OID
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4849b1d6-b6bf-405c-8e9c-28ede1874efa
                    "oid": template_oid,

                    # MS-WCCE szOID_CERTIFICATE_TEMPLATE: major/minor template version carried in the extension
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf
                    "major_version": template_major_version,
                    "minor_version": template_minor_version,
                },
            },
            {  # EKU: ClientAuth + Secure Email + EFS
                # MS-WCCE pKIExtendedKeyUsage: server MUST add EKU OIDs specified by the template
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/1c1d7aaa-281b-48f2-babc-1bc42dd3ed37
                "oid": "2.5.29.37",
                "critical": False,
                "eku_oids": [
                    "1.3.6.1.5.5.7.3.2",        # id-kp-clientAuth
                    "1.3.6.1.5.5.7.3.4",        # id-kp-emailProtection (Secure Email)
                    "1.3.6.1.4.1.311.10.3.4",   # Microsoft EFS
                ],
            },
            {  # KeyUsage
                # MS-WCCE pKIKeyUsage: server SHOULD build Key Usage from the template attribute
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/98626a7c-31eb-46f4-9c44-3cfb29e6c823
                "oid": "2.5.29.15",
                "critical": True,
                "key_usage": {
                    "digital_signature": True,     # digitalSignature
                    "content_commitment": False,   # nonRepudiation/contentCommitment
                    "key_encipherment": False,     # keyEncipherment
                    "data_encipherment": False,    # dataEncipherment
                    "key_agreement": False,        # keyAgreement  False if ECDSA True If ECDH
                    "key_cert_sign": False,        # keyCertSign
                    "crl_sign": False,             # cRLSign
                    "encipher_only": False,        # encipherOnly
                    "decipher_only": False,        # decipherOnly
                },
            },
            {  # Application Policies
                # MS-WCCE: Certificate Application Policy Extension (OID 1.3.6.1.4.1.311.21.10)
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/160b96b1-c431-457a-8eed-27c11873f378
                "oid": "1.3.6.1.4.1.311.21.10",
                "critical": False,
                "app_policies": [
                    "1.3.6.1.5.5.7.3.2",        # ClientAuth
                    "1.3.6.1.4.1.311.10.3.4",   # Microsoft EFS
                ],
            },
        ],
    }


# ======================
# 2) Certificate issuance
# ======================
def emit_certificate(
    *,
    csr_der: Optional[bytes],
    request_id: Optional[int],
    username: str,
    ca: dict,
    template: Optional[dict],
    info: dict,
    app_conf: dict,
    CAID,
    request = None,
    body_part_id = None
) -> Dict[str, Any]:

    # if ssl auth
    XSslClientSha1 = request.headers.get('X-Ssl-Client-Sha1', None)
    XSslAuthenticated = request.headers.get('X-Ssl-Authenticated', None)
    XSslClientDn = request.headers.get('X-Ssl-Client-Dn', None)
    XSslClientCert = request.headers.get('X-Ssl-Client-Cert', None)

    if username :
       username = username
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

    # ✅ static template extensions (EKU/KU/AppPolicies/TemplateInfo)
    builder = _apply_static_extensions(builder, template)

    dns_host = _b(sam_entry or {}, "dNSHostName", "")
    raw_sam = _b(sam_entry or {}, "sAMAccountName", "")
    hostname = raw_sam[:-1] if raw_sam.endswith("$") else raw_sam


    cn = dns_host or hostname or "computer"

    # Dynamic SAN DNS (de-dup)
    names = []
    seen = set()
    for n in (dns_host, hostname):
        if n and n not in seen:
            names.append(cx509.DNSName(n))
            seen.add(n)
    if names:
        builder = builder.add_extension(cx509.SubjectAlternativeName(names), critical=False)

    # ➕ dynamic NTDS (SID) (1.3.6.1.4.1.311.25.2 / ...2.1)
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

