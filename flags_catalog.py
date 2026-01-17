# Full XCEP flags catalog with "friendly" names.
# Usage:
#   from flags_catalog import FLAG_CATALOG, flags_from_bools
#   mask = flags_from_bools(template["flags"]["subject_name_flags"], FLAG_CATALOG["subject_name_flags"])

from typing import Dict

# Ref (XCEP): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
# Note: For several fields, XCEP reuses AD CS template flags (MS-CRTD). In practice, you want the MS-CRTD bit values.

FLAG_CATALOG: Dict[str, Dict[str, int]] = {
    # <privateKeyFlags> (XCEP) maps to msPKI-Private-Key-Flag (MS-CRTD)
    "private_key_flags": {
        # Instructs the client to archive the private key.
        "archive_private_key": 0x00000001,
        # Allow the private key to be exported.
        "exportable_key":      0x00000010,
        # Protect the private key (prompt/strong protection depending on local config).
        "protect_private_key": 0x00000020,

        # Other classic msPKI-Private-Key-Flag bits
        "require_alternate_signature_algorithm": 0x00000040,
        "require_same_key_renewal":              0x00000080,
        "use_legacy_provider":                   0x00000100,

        # TPM Key Attestation (AD CS)
        "attest_preferred":            0x00001000,
        "attest_required":             0x00002000,
        "attestation_without_policy":  0x00004000,
        "attest_none":                 0x00000000,  # readability

        # EK trust model (AD CS)
        "ek_trust_on_use":   0x00000200,  # credentials / TOFU
        "ek_validate_cert":  0x00000400,  # EKCert chain
        "ek_validate_key":   0x00000800,  # EKPub allowlist

        # Windows Hello
        "hello_logon_key":   0x00200000,
    },

    # <subjectNameFlags> (XCEP) maps to msPKI-Certificate-Name-Flag (MS-CRTD)
    # Note: SPN/UPN — if SPN/UPN required, the CA actually adds the UPN (see MS-WCCE).
    "subject_name_flags": {
        # The client supplies the Subject in the CSR
        "enrollee_supplies_subject":              0x00000001,
        # On renewal, reuse Subject + SAN from the old cert
        "old_cert_supplies_subject_and_alt_name": 0x00000008,
        # The client supplies SAN (Subject Alternative Name) in the CSR
        "enrollee_supplies_san":                  0x00010000,

        # Requirements on the CA side to populate SAN from directory:
        "add_domain_dns_to_san":      0x00400000,  # root domain DNS  (FIXED)
        "add_spn_to_san":             0x00800000,  # SPN             (FIXED)
        "add_directory_guid_to_san":  0x01000000,  # objectGUID
        "add_upn_to_san":             0x02000000,  # UPN
        "add_email_to_san":           0x04000000,  # e-mail
        "add_dns_to_san":             0x08000000,  # dNSHostName / DNS

        # Subject constraints (CN/DNS/email/AD path)
        "subject_dns_as_cn":               0x10000000,
        "subject_require_email":           0x20000000,
        "subject_require_common_name":     0x40000000,
        "subject_require_directory_path":  0x80000000,
    },

    # <enrollmentFlags> (XCEP) maps to msPKI-Enrollment-Flag (MS-CRTD)
    "enrollment_flags": {
        "include_symmetric_algorithms":                              0x00000001,  # S/MIME ext (RFC4262)
        "pend_all_requests":                                         0x00000002,  # all requests pending
        "publish_to_kra_container":                                  0x00000004,  # publish to KRA container
        "publish_to_ds":                                             0x00000008,  # append to userCertificate in AD
        "auto_enrollment_check_user_ds_certificate":                 0x00000010,  # no auto-enroll if valid cert exists
        "auto_enrollment":                                           0x00000020,  # allow auto-enrollment
        "previous_approval_validate_reenrollment":                   0x00000040,  # sign renewal with old key
        "user_interaction_required":                                 0x00000100,  # user consent required
        "remove_invalid_certificate_from_personal_store":            0x00000400,  # clean expired certs from store
        "allow_enroll_on_behalf_of":                                 0x00000800,  # EOBO
        "add_ocsp_nocheck":                                          0x00001000,  # id-pkix-ocsp-nocheck
        "enable_key_reuse_on_nt_token_keyset_storage_full":          0x00002000,  # reuse key if card full
        "no_revocation_info_in_issued_certs":                        0x00004000,  # no revocation info in cert
        "include_basic_constraints_for_ee_certs":                    0x00008000,  # Basic Constraints for EE
        "allow_previous_approval_keybasedrenewal_validate_reenroll": 0x00010000,  # ignore Enroll on key renewal
        "issuance_policies_from_request":                            0x00020000,  # issuance policies from CSR
        "skip_auto_renewal":                                         0x00040000,  # no auto-renewal
        "no_security_extension":                                     0x00080000,  # do NOT include 1.3.6.1.4.1.311.25.2

        # alias (same bit) – handy depending on wording
        "do_not_include_sid_extension":                              0x00080000,
    },

    # <generalFlags> (XCEP) maps to the template "flags" attribute (MS-CRTD)
    "general_flags": {
        # Reserved (MUST ignore) but sometimes seen in the wild; keep to decode masks
        "add_email_reserved_ignore":         0x00000002,
        "publish_to_ds_reserved_ignore":     0x00000008,
        "exportable_key_reserved_ignore":    0x00000010,

        # Active bits
        "auto_enrollment":      0x00000020,
        "machine_type":         0x00000040,  # machine template
        "ca_type":              0x00000080,  # CA request
        "is_ca":                0x00000080,  # alias
        "add_template_name":    0x00000200,
        "cross_ca":             0x00000800,  # cross-cert
        "do_not_persist_in_db": 0x00001000,
        "is_default":           0x00010000,
        "is_modified":          0x00020000,
    },
}



