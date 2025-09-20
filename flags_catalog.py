# flags_catalog.py
# Full XCEP flags catalog with "friendly" names.
# Usage:
#   from flags_catalog import FLAG_CATALOG, flags_from_bools
#   mask = flags_from_bools(template["flags"]["subject_name_flags"], FLAG_CATALOG["subject_name_flags"])

from typing import Dict


# --- Full catalog (XCEP) -----------------------------------------------

FLAG_CATALOG: Dict[str, Dict[str, int]] = {
    # MS-XCEP <privateKeyFlags>: bitwise OR of these 3 values
    # Ref: MS-XCEP Attributes – privateKeyFlags
    "private_key_flags": {
        # Instructs the client to archive the private key.
        "archive_private_key": 0x00000001,
        # Allow the private key to be exported.
        "exportable_key":      0x00000010,
        # Protect the private key (user/strong protection prompt depending on local config).
        "protect_private_key": 0x00000020,
    },

    # <subjectNameFlags> (XCEP) — official values (certenroll.h)
    # Note: SPN/UPN — if SPN/UPN required, the CA actually adds the UPN (see MS-WCCE).
    "subject_name_flags": {
        # The client supplies the Subject in the CSR
        "enrollee_supplies_subject":                 0x00000001,
        # On renewal, reuse Subject + SAN from the old cert
        "old_cert_supplies_subject_and_alt_name":    0x00000008,
        # The client supplies SAN (Subject Alternative Name) in the CSR
        "enrollee_supplies_san":                     0x00010000,

        # Requirements on the CA side to populate SAN from directory:
        "add_domain_dns_to_san":                     0x00040000,  # root domain DNS
        "add_spn_to_san":                            0x00080000,  # SPN -> the CA will use the effective UPN
        "add_directory_guid_to_san":                 0x01000000,  # objectGUID
        "add_upn_to_san":                            0x02000000,  # UPN
        "add_email_to_san":                          0x04000000,  # e-mail
        "add_dns_to_san":                            0x08000000,  # dNSHostName / DNS

        # Subject constraints (CN/DNS/email/AD path)
        "subject_dns_as_cn":                         0x10000000,
        "subject_require_email":                     0x20000000,
        "subject_require_common_name":               0x40000000,
        "subject_require_directory_path":            0x80000000,
    },

    # <enrollmentFlags> (XCEP) — full MS-CRTD catalog
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
        "add_ocsp_nocheck":                                          0x00001000,  # id-pkix-ocsp-nocheck, no CRL/OCSP
        "enable_key_reuse_on_nt_token_keyset_storage_full":          0x00002000,  # reuse key if card full
        "no_revocation_info_in_issued_certs":                        0x00004000,  # no revocation info in cert
        "include_basic_constraints_for_ee_certs":                    0x00008000,  # Basic Constraints for EE
        "allow_previous_approval_keybasedrenewal_validate_reenroll": 0x00010000,  # ignore Enroll on key renewal
        "issuance_policies_from_request":                            0x00020000,  # issuance policies from CSR
        "skip_auto_renewal":                                         0x00040000,  # no auto-renewal
        "no_security_extension":                                     0x00080000,  # do NOT include 1.3.6.1.4.1.311.25.2
    },

    # <generalFlags> (XCEP) — only these 3 flags are defined, rest is reserved on XCEP side
    "general_flags": {
        "machine_type": 0x00000040,  # machine template
        "ca_type":      0x00000080,  # CA request
        "cross_ca":     0x00000800,  # cross-cert
        # Reserved (not exposed): 0x00010000, 0x00020000
    },
}


# --- Helpers ----------------------------------------------------------------

def flags_from_bools(bools: Dict[str, bool], catalog: Dict[str, int]) -> int:
    """
    Convert a dict {flag_name: bool} into an integer mask using
    the submap of the catalog (e.g. FLAG_CATALOG["subject_name_flags"]).
    Unknown keys are ignored to remain permissive.
    """
    mask = 0
    if not bools:
        return 0
    for k, v in bools.items():
        if v and k in catalog:
            mask |= catalog[k]
    return mask


def bools_from_mask(mask: int, catalog: Dict[str, int]) -> Dict[str, bool]:
    """
    Inverse of flags_from_bools: return a dict {flag_name: bool}
    from a mask and a catalog submap.
    """
    out: Dict[str, bool] = {}
    for name, bit in catalog.items():
        out[name] = bool(mask & bit)
    return out

