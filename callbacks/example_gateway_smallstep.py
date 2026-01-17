from typing import Iterable, Optional, Dict, Any
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization as crypto_serialization
from utils import search_user
import requests
import json
import base64
import subprocess

template_oid           = "1.3.6.1.4.1.311.21.8.999.3"
template_name          = "adcswebcomputer"
template_major_version = 100
template_minor_version = 3
caref = 'ca1-inter'

auto_enroll            = True

def define_template(*, app_conf, username=None , request=None):
    validity_seconds = 31536000       # 1 year
    renewal_seconds = 3628800         # 42 days
    auto_enroll = True


    # if ssl auth
    XSslClientSha1 = request.headers.get('X-Ssl-Client-Sha1', None)
    XSslAuthenticated = request.headers.get('X-Ssl-Authenticated', None)
    XSslClientDn = request.headers.get('X-Ssl-Client-Dn', None)

    if username :
       username = username
    else:
       username = XSslClientDn.split('=',1)[1]

    return {
        "common_name": template_name,
        "template_oid": {
            "value": template_oid,
            "name":  template_name,
            "major_version": template_major_version,
            "minor_version": template_minor_version,
        },
        "ca_references": [caref],

        "policy_schema": 2,
        "revision": {"major": template_major_version, "minor": template_minor_version},
        "validity": {"validity_seconds": validity_seconds, "renewal_seconds": renewal_seconds},
        "permissions": {"enroll": True, "auto_enroll": auto_enroll},

        "flags": {
            "private_key_flags": {
                "exportable_key": True,

                # Added missing flags (all False => no behavior/mask change)
                "archive_private_key": False,                   # Archive the private key (KRA)
                "protect_private_key": False,                   # Strong private key protection
                "require_alternate_signature_algorithm": False, # Require alternate signature algorithm
                "require_same_key_renewal": False,              # Require same key on renewal
                "use_legacy_provider": False,                   # Use legacy provider (CSP)

                # TPM Key Attestation (AD CS)
                "attest_preferred": False,                      # Prefer key attestation if client can
                "attest_required": False,                       # Require key attestation
                "attestation_without_policy": False,            # Attest but do not add issuance policy
                "attest_none": False,                           # Explicit none (readability)

                # EK trust model (AD CS)
                "ek_trust_on_use": False,                       # EK trust on first use / credentials
                "ek_validate_cert": False,                      # Validate EK certificate (EKCert)
                "ek_validate_key": False,                       # Validate EK public key (allowlist)

                # Windows Hello
                "hello_logon_key": False,                       # Windows Hello for Business logon key
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

                # Added missing flags (all False => no behavior/mask change)
                "no_security_extension": False,           # Do not include security extension
                "do_not_include_sid_extension": False,    # Alias of no_security_extension (same bit)
            },
            "general_flags": {
                "machine_type": True,
                "ca_type": False,
                "cross_ca": False,

                # Added missing flags (all False => no behavior/mask change)
                "is_ca": False,                        # Alias for ca_type
                "auto_enrollment": False,              # General auto-enrollment flag
                "add_template_name": False,            # Add template name extension
                "do_not_persist_in_db": False,         # Do not persist in CA DB
                "is_default": False,                   # Template marked default
                "is_modified": False,                  # Template marked modified

                # Reserved/MUST ignore (kept for completeness/decoding)
                "add_email_reserved_ignore": False,
                "publish_to_ds_reserved_ignore": False,
                "exportable_key_reserved_ignore": False,
            },
        },

        "private_key_attributes": {
            "minimal_key_length": 3072,
            "key_spec": 1,
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
 #                   "1.3.6.1.5.5.7.3.4",
 #                   "1.3.6.1.4.1.311.10.3.4",
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
    username: str,
    ca: dict,
    template: Optional[dict],
    info: dict,
    app_conf: dict,
    CAID,
    request = None,
    body_part_id = None
) -> Dict[str, Any]:


    ca_url="https://ca.mydomain.lan"
    root_pem_path="/root/roots.pem"
    provisioner="x5c"
    x5c_cert_path='/etc/step-ca/certs/idra-token-signer.crt'
    x5c_key_path="/etc/step-ca/secrets/idra-token-signer.key"
    step_bin = "step"

    csr      = cx509.load_der_x509_csr(csr_der)
    csr_pem = csr.public_bytes(crypto_serialization.Encoding.PEM).decode("utf-8")


    TEMPLATE_OID = [u for u in template['__all_required_extensions'] if u['oid'] == "1.3.6.1.4.1.311.21.7"][0]['value_b64']
    samdbr, sam_entry = search_user(username)

    #MS_SID = samdbr.schema_format_value("objectSID", sam_entry["objectSID"][0]).decode('utf-8')

    cn = sam_entry["sAMAccountName"][0].decode("utf-8", "ignore")

    sans=[]


    template_vars = {
        "msTemplateInfoB64": TEMPLATE_OID,
    }


    ott = _step_ca_token_x5c(
        step_bin=step_bin,
        ca_url=ca_url,
        root_pem_path=root_pem_path,
        provisioner=provisioner,
        subject=cn,
        sans=sans,
        x5c_cert_path=x5c_cert_path,
        x5c_key_path=x5c_key_path,
        template_vars=template_vars,
    )



    r = requests.post(
        ca_url +  "/sign",
        json={
            "csr": csr_pem,
            "ott": ott,
            "templateData": template_vars
            },
        verify=root_pem_path,
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()

    certdata = data["crt"]
    cert = cx509.load_pem_x509_certificate(certdata.encode("ascii"))

    return {
        "status": "issued",
        "cert": cert,
    }


def _step_ca_token_x5c(
    *,
    step_bin: str,
    ca_url: str,
    root_pem_path: str,
    provisioner: str,
    subject: str,
    sans,
    x5c_cert_path: str,
    x5c_key_path: str,
    template_vars: Dict[str, str],
) -> str:


    cmd = [
        step_bin, "ca", "token", subject,
        "--ca-url", ca_url,
        "--root", root_pem_path,
        "--provisioner", provisioner,
        "--x5c-cert", x5c_cert_path,
        "--x5c-key", x5c_key_path,
    ]
    for san in sans:
        cmd += ["--san", san]

    for k, v in template_vars.items():
        cmd += ["--set", f"{k}={v}"]


    return subprocess.check_output(cmd, text=True).strip()
