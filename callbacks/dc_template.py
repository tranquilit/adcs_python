import sys
import argparse
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set

import os
import re
import uuid

from asn1crypto import core as a_core
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import (
    NameOID,
    AuthorityInformationAccessOID,
    ExtensionOID,
    ObjectIdentifier as CObjectIdentifier,
)

from utils import search_user
from utils import _apply_static_extensions
import base64
import json
import textwrap



def _guid_to_ad_bytes_le(val) -> bytes:
    if val is None:
        raise ValueError("objectGUID manquant")

    if isinstance(val, (list, tuple)) and val:
        val = val[0]

    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if len(b) != 16:
            raise ValueError("objectGUID bytes doit faire 16 octets")
        return b

    s = str(val).strip().strip("{}")
    return uuid.UUID(s).bytes_le


# ============================================================
# Template definition for CEP (DC)
# ============================================================

template_oid           = "1.3.6.1.4.1.311.21.8.777.3"
template_name          = "dc"
template_major_version = 100
template_minor_version = 3
auto_enroll            = True

def define_template(*, app_conf, username=None, request=None):

    validity_seconds = 31536000       # 1 year
    renewal_seconds  = 3628800        # 42 days

    username = username

    if not username:
        return

    r = search_user(username,"(userAccountControl:1.2.840.113556.1.4.803:=8192)")
    if not r:
        return

    samdbr, sam_entry = r


    return {
        "common_name": template_name,

        "template_oid": {
            "value": template_oid,
            "name": template_name,
            "major_version": template_major_version,
            "minor_version": template_minor_version,
        },

        "ca_references": ["ca1-inter"],
        "policy_schema": 3,

        "revision": {
            "major": template_major_version,
            "minor": template_minor_version,
        },

        "validity": {
            "validity_seconds": validity_seconds,
            "renewal_seconds": renewal_seconds,
        },

        "permissions": {
            "enroll": True,
            "auto_enroll": auto_enroll,
        },

        "flags": {
            "private_key_flags": {
                "exportable_key": False,
            },

            "subject_name_flags": {
                "add_dns_to_san": True,
                "subject_dns_as_cn": True,
                "enrollee_supplies_subject": False,
                "enrollee_supplies_san": False,
                "old_cert_supplies_subject_and_alt_name": False,
                "add_domain_dns_to_san": False,
                "add_spn_to_san": False,

                "add_directory_guid_to_san": True,

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
            "minimal_key_length": 4096,
            "key_spec": 1,
            "algorithm_oid_reference": None,

            "crypto_providers": [
                "Microsoft Software Key Storage Provider",
                "Microsoft Platform Crypto Provider",
            ],
        },

        # Static extensions (re-applied at issuance via _apply_static_extensions)
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
            {  # EKU: clientAuth + serverAuth + pkInitKDC
                "oid": "2.5.29.37",
                "critical": False,
                "eku_oids": [
                    "1.3.6.1.5.5.7.3.2",  # id-kp-clientAuth
                    "1.3.6.1.5.5.7.3.1",  # id-kp-serverAuth
                    "1.3.6.1.5.2.3.5",    # pkInitKDC
                ],
            },
            {
                "oid": "2.5.29.15",
                "critical": False,
                "key_usage": {
                    "digital_signature": True,
                    "content_commitment": True,
                    "key_encipherment": True,
                    "data_encipherment": False,
                    "key_agreement": False,
                    "key_cert_sign": False,
                    "crl_sign": False,
                    "encipher_only": False,
                    "decipher_only": False,
                },
            },
            {
                "oid": "1.3.6.1.4.1.311.21.10",
                "critical": False,
                "app_policies": [
                    "1.3.6.1.5.5.7.3.2",  # ClientAuth
                    "1.3.6.1.5.5.7.3.1",  # ServerAuth
                    "1.3.6.1.5.2.3.5",    # pkInitKDC
                ],
            },
        ],
    }


# ============================================================
# 2) Certificate issuance (DC)
# ============================================================


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
    request=None,
    body_part_id=None,
    **kwargs
) -> Dict[str, Any]:

    r = search_user(username,"(userAccountControl:1.2.840.113556.1.4.803:=8192)")
    samdbr, sam_entry = r
    if not r:
        return {
            "status": "denied",
            "status_text": "denied",
        }


    csr = cx509.load_der_x509_csr(csr_der)
    ca_cert = cx509.load_der_x509_certificate(ca["__certificate_der"])
    now = datetime.utcnow() - timedelta(minutes=5)

    raw_sam = sam_entry["sAMAccountName"][0].decode('utf-8').lower()
    realm = username.split('$@')[1].lower()
    dc_fqdn = raw_sam.replace('$','') + '.' + realm
    objectGUID = sam_entry["objectGUID"][0]

    dc_guid_ad_bytes_le = _guid_to_ad_bytes_le(objectGUID)

    validity_seconds = (template or {}).get("validity", {}).get("validity_seconds") or 31536000

    builder = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, dc_fqdn)]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(seconds=int(validity_seconds)))
        .add_extension(cx509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
    )

    # authorityKeyIdentifier = keyid,issuer
    try:
        issuer_ski = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        aki = cx509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski)
    except cx509.ExtensionNotFound:
        aki = cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    if ca.get("urls", {}).get("ca_issuers_http"):
        aia = cx509.AuthorityInformationAccess([
            cx509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                cx509.UniformResourceIdentifier(ca["urls"]["ca_issuers_http"]),
            )
        ])
        builder = builder.add_extension(aia, critical=False)

    crl_url = (
        ca.get("urls", {}).get("crl_http")
    )

    builder = builder.add_extension(
        cx509.CRLDistributionPoints([
            cx509.DistributionPoint(
                full_name=[cx509.UniformResourceIdentifier(crl_url)],
                relative_name=None, reasons=None, crl_issuer=None,
            )
        ]),
        critical=False,
    )

    # basicConstraints=CA:FALSE (comme usr_cert_mskdc)
    builder = builder.add_extension(cx509.BasicConstraints(ca=False, path_length=None), critical=False)

    # ✅ static template extensions (EKU/KU/AppPolicies/TemplateInfo)
    builder = _apply_static_extensions(builder, template)

    san_items: List[cx509.GeneralName] = []
    seen: Set[str] = set()

    def _k(gn: cx509.GeneralName) -> str:
        if isinstance(gn, cx509.DNSName):
            return f"dns:{gn.value.lower()}"
        if isinstance(gn, cx509.OtherName):
            return f"other:{gn.type_id.dotted_string}:{gn.value.hex()}"
        return repr(gn)

    dns_gn = cx509.DNSName(realm)
    kk = _k(dns_gn)
    if kk not in seen:
        san_items.append(dns_gn)
        seen.add(kk)

    dns_gn = cx509.DNSName(dc_fqdn)
    kk = _k(dns_gn)
    if kk not in seen:
        san_items.append(dns_gn)
        seen.add(kk)

    msadguid_der = a_core.OctetString(dc_guid_ad_bytes_le).dump()
    on = cx509.OtherName(CObjectIdentifier("1.3.6.1.4.1.311.25.1"), msadguid_der)
    kk = _k(on)
    if kk not in seen:
        san_items.append(on)
        seen.add(kk)

    builder = builder.add_extension(cx509.SubjectAlternativeName(san_items), critical=False)

    priv = ca["__key_obj"]
    if isinstance(priv, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = builder.sign(private_key=priv, algorithm=None)
    else:
        cert = builder.sign(private_key=priv, algorithm=hashes.SHA512())

    return {
        "status": "issued",
        "cert": cert,
    }

