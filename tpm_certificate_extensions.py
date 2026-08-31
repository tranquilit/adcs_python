"""Certificate-extension contract for verified MS-WCCE V2 TPM attestation."""

from __future__ import annotations

import base64

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier


OID_MS_CERTSRV_V2_ATTESTATION_VERIFIED = "1.3.6.1.4.1.311.21.49"
V2_ATTESTATION_VERIFIED_DER = b"\x05\x00"  # ASN.1 NULL


def required_tpm_attestation_extension_specs(tpm_result) -> list[dict]:
    """Return certificate extensions required by a successful TPM flow.

    The result contract is deliberately explicit so custom issuance callbacks
    can consume the same information without depending on internal state.
    """
    if not isinstance(tpm_result, dict) or not tpm_result.get(
        "v2_attestation_verified"
    ):
        return []

    raw_specs = tpm_result.get("required_certificate_extensions")
    if raw_specs is None:
        raw_specs = [
            {
                "oid": OID_MS_CERTSRV_V2_ATTESTATION_VERIFIED,
                "critical": False,
                "value_der_b64": base64.b64encode(
                    V2_ATTESTATION_VERIFIED_DER
                ).decode("ascii"),
            }
        ]
    if not isinstance(raw_specs, list) or not raw_specs:
        raise ValueError(
            "Verified V2 attestation is missing its required certificate extension"
        )

    specs = []
    for item in raw_specs:
        if not isinstance(item, dict):
            raise ValueError(
                "TPM certificate extension specification must be a mapping"
            )
        oid = str(item.get("oid") or "").strip()
        if not oid:
            raise ValueError(
                "TPM certificate extension specification is missing an OID"
            )
        try:
            ObjectIdentifier(oid)
            value_der = base64.b64decode(item["value_der_b64"], validate=True)
        except Exception as exc:
            raise ValueError(
                f"TPM certificate extension {oid or '<missing>'} has invalid data"
            ) from exc
        specs.append(
            {
                "oid": oid,
                "critical": bool(item.get("critical", False)),
                "value_der": value_der,
            }
        )

    v2_specs = [
        item
        for item in specs
        if item["oid"] == OID_MS_CERTSRV_V2_ATTESTATION_VERIFIED
    ]
    if len(v2_specs) != 1:
        raise ValueError(
            "Verified V2 attestation requires exactly one .21.49 extension"
        )
    if (
        v2_specs[0]["critical"]
        or v2_specs[0]["value_der"] != V2_ATTESTATION_VERIFIED_DER
    ):
        raise ValueError(
            "The .21.49 extension must be non-critical ASN.1 NULL"
        )
    return specs


def apply_tpm_attestation_extensions(
    builder: x509.CertificateBuilder,
    tpm_result,
) -> x509.CertificateBuilder:
    """Apply all certificate extensions required by the TPM result."""
    for spec in required_tpm_attestation_extension_specs(tpm_result):
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier(spec["oid"]), spec["value_der"]
            ),
            critical=spec["critical"],
        )
    return builder


def validate_tpm_attestation_certificate_extensions(
    certificate: x509.Certificate,
    tpm_result,
) -> None:
    """Fail closed when an issuance callback omitted a required TPM marker."""
    for spec in required_tpm_attestation_extension_specs(tpm_result):
        oid = ObjectIdentifier(spec["oid"])
        try:
            extension = certificate.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound as exc:
            raise ValueError(
                f"Issued certificate is missing required TPM extension {spec['oid']}"
            ) from exc
        if extension.critical != spec["critical"]:
            raise ValueError(
                f"Issued certificate TPM extension {spec['oid']} has the wrong criticality"
            )
        value = extension.value
        if (
            not isinstance(value, x509.UnrecognizedExtension)
            or value.value != spec["value_der"]
        ):
            raise ValueError(
                f"Issued certificate TPM extension {spec['oid']} has the wrong DER value"
            )
