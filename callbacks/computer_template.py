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

def define_template(*, app_conf, kerberos_user=None , request=None):
    validity_seconds = 31536000       # 1 year
    renewal_seconds = 3628800         # 42 days
    auto_enroll = True

    samdbr, sam_entry = search_user(kerberos_user)

    return {
        "common_name": template_name,
        "template_oid": {
            "value": template_oid,
            "name":  template_name,
            "major_version": template_major_version,
            "minor_version": template_minor_version,
        },
        "ca_references": ["ca1-inter"],

        "policy_schema": 2,
        "revision": {"major": template_major_version, "minor": template_minor_version},
        "validity": {"validity_seconds": validity_seconds, "renewal_seconds": renewal_seconds},
        "permissions": {"enroll": True, "auto_enroll": auto_enroll},

        # ⚙️ FLAGS: booleans only
        "flags": {
            "private_key_flags": {
                "exportable_key": True,
            },
            "subject_name_flags": {
                "add_dns_to_san": True,
                "subject_dns_as_cn": True,
                "enrollee_supplies_subject": False,
                "enrollee_supplies_san": False,
                "old_cert_supplies_subject_and_alt_name": False,
                "add_domain_dns_to_san": False,
                "add_spn_to_san": False,
                "add_directory_guid_to_san": False,
                "add_upn_to_san": False,
                "add_email_to_san": False,
                "subject_require_email": False,
                "subject_require_common_name": False,
                "subject_require_directory_path": False,
            },
            "enrollment_flags": {
                "include_symmetric_algorithms": True,
                "publish_to_ds": True,
                "auto_enrollment": auto_enroll,
                "user_interaction_required": False,
                "pend_all_requests": False,
                "publish_to_kra_container": False,
                "auto_enrollment_check_user_ds_certificate": False,
                "previous_approval_validate_reenrollment": False,
                "add_ocsp_nocheck": False,
                "enable_key_reuse_on_nt_token_keyset_storage_full": False,
                "no_revocation_info_in_issued_certs": False,
                "include_basic_constraints_for_ee_certs": False,
                "allow_enroll_on_behalf_of": False,
                "allow_previous_approval_keybasedrenewal_validate_reenroll": False,
                "issuance_policies_from_request": False,
                "skip_auto_renewal": False,
                "remove_invalid_certificate_from_personal_store": False,
            },
            "general_flags": {
                "machine_type": True,
                "ca_type": False,
                "cross_ca": False,
            },
        },

        "private_key_attributes": {
            "minimal_key_length": 2048,
            "key_spec": 1,  # 1 = AT_KEYEXCHANGE
            "algorithm_oid_reference": None,
            "crypto_providers": [
                "Microsoft Software Key Storage Provider",
                "Microsoft Platform Crypto Provider",
                "Microsoft Enhanced Cryptographic Provider v1.0",
                "Microsoft Base Cryptographic Provider v1.0",
            ],
        },

        # Static extensions (re-applied at issuance)
        "required_extensions": [
            {  # Certificate Template Information
                "oid": "1.3.6.1.4.1.311.21.7",
                "critical": False,
                "template_info": {
                    "oid": template_oid,
                    "major_version": template_major_version,
                    "minor_version": template_minor_version,
                },
            },
            {  # EKU: ClientAuth + Secure Email + EFS
                "oid": "2.5.29.37",
                "critical": False,
                "eku_oids": [
                    "1.3.6.1.5.5.7.3.2",
                    "1.3.6.1.5.5.7.3.4",
                    "1.3.6.1.4.1.311.10.3.4",
                ],
            },
            {  # KeyUsage
                "oid": "2.5.29.15",
                "critical": True,
                "key_usage": {
                    "digital_signature": True,
                    "content_commitment": False,
                    "key_encipherment": True,
                    "data_encipherment": False,
                    "key_agreement": False,
                    "key_cert_sign": False,
                    "crl_sign": False,
                    "encipher_only": False,
                    "decipher_only": False,
                },
            },
            {  # Application Policies
                "oid": "1.3.6.1.4.1.311.21.10",
                "critical": False,
                "app_policies": [
                    "1.3.6.1.5.5.7.3.2",
                    "1.3.6.1.4.1.311.10.3.4",
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
    kerberos_user: str,
    ca: dict,
    template: Optional[dict],
    info: dict,
    app_conf: dict,
    CAID,
    request = None,
    body_part_id = None
) -> Dict[str, Any]:

    samdbr, sam_entry = search_user(kerberos_user)

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

