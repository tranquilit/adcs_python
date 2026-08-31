"""Small, strict X.509 trust helpers for template issuance callbacks.

The TPM core intentionally performs no local EK/AIK chain-trust decision.
Template ``emit_certificate()`` callbacks can use this module to build paths to
explicit trust anchors without consulting the host OS trust store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier


class CertificateTrustError(ValueError):
    """Raised when a certificate path cannot be validated."""


def _certificate_fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


def _split_pem_certificates(data: bytes) -> list[x509.Certificate]:
    marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"
    result: list[x509.Certificate] = []
    cursor = 0
    while True:
        start = data.find(marker, cursor)
        if start < 0:
            break
        end = data.find(end_marker, start)
        if end < 0:
            raise CertificateTrustError("Truncated PEM certificate block")
        end += len(end_marker)
        result.append(x509.load_pem_x509_certificate(data[start:end] + b"\n"))
        cursor = end
    return result


def load_certificates_from_bytes(data: bytes) -> list[x509.Certificate]:
    """Load one DER certificate or one/more PEM certificates."""
    if not data:
        return []
    if b"-----BEGIN CERTIFICATE-----" in data:
        certs = _split_pem_certificates(data)
        if not certs:
            raise CertificateTrustError("No PEM certificate found")
        return certs
    try:
        return [x509.load_der_x509_certificate(data)]
    except Exception as exc:
        raise CertificateTrustError("Input is not a DER or PEM X.509 certificate") from exc


def load_certificates_from_paths(paths: str | Path | Sequence[str | Path] | None) -> list[x509.Certificate]:
    """Load certificates from files and directories.

    Directories are scanned non-recursively in lexical order.  Files that do
    not contain a certificate are ignored only when they are discovered while
    scanning a directory; an explicitly named invalid file is an error.
    """
    if paths is None:
        return []
    if isinstance(paths, (str, Path)):
        items: list[str | Path] = [paths]
    else:
        items = list(paths)

    result: list[x509.Certificate] = []
    seen: set[bytes] = set()

    def _append(certs: Iterable[x509.Certificate]) -> None:
        for cert in certs:
            fp = _certificate_fingerprint(cert)
            if fp not in seen:
                seen.add(fp)
                result.append(cert)

    for item in items:
        path = Path(item)
        if path.is_dir():
            for child in sorted(p for p in path.iterdir() if p.is_file()):
                try:
                    _append(load_certificates_from_bytes(child.read_bytes()))
                except CertificateTrustError:
                    continue
            continue
        if not path.is_file():
            raise CertificateTrustError(f"Certificate path does not exist: {path}")
        _append(load_certificates_from_bytes(path.read_bytes()))
    return result


def _verify_certificate_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    signature = cert.signature
    tbs = cert.tbs_certificate_bytes
    hash_algorithm = cert.signature_hash_algorithm
    parameters = cert.signature_algorithm_parameters

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            rsa_padding = parameters if isinstance(parameters, padding.AsymmetricPadding) else padding.PKCS1v15()
            public_key.verify(signature, tbs, rsa_padding, hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algorithm = parameters if isinstance(parameters, ec.ECDSA) else ec.ECDSA(hash_algorithm)
            public_key.verify(signature, tbs, algorithm)
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, tbs, hash_algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, tbs)
        else:
            raise CertificateTrustError(
                f"Unsupported issuer public key type: {type(public_key).__name__}"
            )
    except InvalidSignature as exc:
        raise CertificateTrustError("Certificate signature validation failed") from exc


def _check_validity(cert: x509.Certificate, at_time: datetime) -> None:
    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    else:  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if at_time < not_before or at_time > not_after:
        raise CertificateTrustError(
            f"Certificate is not valid at {at_time.isoformat()}: subject={cert.subject.rfc4514_string()}"
        )


def _check_ca_constraints(cert: x509.Certificate) -> None:
    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound as exc:
        raise CertificateTrustError(
            f"Issuer certificate lacks BasicConstraints: {cert.subject.rfc4514_string()}"
        ) from exc
    if not basic.ca:
        raise CertificateTrustError(
            f"Issuer certificate is not a CA: {cert.subject.rfc4514_string()}"
        )

    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return
    if not key_usage.key_cert_sign:
        raise CertificateTrustError(
            f"Issuer certificate KeyUsage does not permit certificate signing: {cert.subject.rfc4514_string()}"
        )


def _check_leaf_constraints(cert: x509.Certificate) -> None:
    """Reject a CA certificate when the caller expects an end-entity leaf."""
    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return
    if basic.ca:
        raise CertificateTrustError(
            f"Leaf certificate is marked as a CA: {cert.subject.rfc4514_string()}"
        )


def _check_path_length_constraints(chain: Sequence[x509.Certificate]) -> None:
    """Enforce BasicConstraints.path_length on a completed leaf-first chain.

    ``path_length`` counts non-self-issued CA certificates below a CA in the
    path. The end-entity leaf at index zero is not included in that count.
    """
    for index, cert in enumerate(chain[1:], start=1):
        try:
            basic = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
        except x509.ExtensionNotFound as exc:
            raise CertificateTrustError(
                f"Issuer certificate lacks BasicConstraints: {cert.subject.rfc4514_string()}"
            ) from exc
        if not basic.ca or basic.path_length is None:
            continue
        ca_below = 0
        for subordinate in chain[1:index]:
            try:
                subordinate_basic = subordinate.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                ).value
            except x509.ExtensionNotFound:
                continue
            if subordinate_basic.ca and subordinate.subject != subordinate.issuer:
                ca_below += 1
        if ca_below > basic.path_length:
            raise CertificateTrustError(
                "Certificate path exceeds BasicConstraints path_length for "
                f"{cert.subject.rfc4514_string()}"
            )


def _check_required_eku(cert: x509.Certificate, required_eku_oid: str | ObjectIdentifier | None) -> None:
    if not required_eku_oid:
        return
    oid = required_eku_oid if isinstance(required_eku_oid, ObjectIdentifier) else ObjectIdentifier(required_eku_oid)
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound as exc:
        raise CertificateTrustError(
            f"Leaf certificate lacks required EKU {oid.dotted_string}"
        ) from exc
    if oid not in eku:
        raise CertificateTrustError(
            f"Leaf certificate does not contain required EKU {oid.dotted_string}"
        )


def validate_certificate_chain(
    leaf: x509.Certificate,
    *,
    intermediates: Sequence[x509.Certificate] | None = None,
    trust_anchors: Sequence[x509.Certificate] | None = None,
    required_eku_oid: str | ObjectIdentifier | None = None,
    at_time: datetime | None = None,
    max_depth: int = 12,
) -> list[x509.Certificate]:
    """Build and validate ``leaf -> ... -> trust anchor``.

    The returned list includes both the leaf and the selected trust anchor.
    Trust is explicit: a self-signed certificate is accepted only when its
    SHA-256 fingerprint exactly matches a configured trust anchor.
    """
    anchors = list(trust_anchors or [])
    if not anchors:
        raise CertificateTrustError("No trust anchors are configured")
    candidates = list(intermediates or []) + anchors
    now = at_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    _check_validity(leaf, now)
    _check_leaf_constraints(leaf)
    _check_required_eku(leaf, required_eku_oid)

    anchor_by_fp = {_certificate_fingerprint(cert): cert for cert in anchors}
    by_subject: dict[str, list[x509.Certificate]] = {}
    for cert in candidates:
        by_subject.setdefault(cert.subject.rfc4514_string(), []).append(cert)

    def _walk(current: x509.Certificate, path: list[x509.Certificate], visited: set[bytes]) -> list[x509.Certificate] | None:
        if len(path) > max_depth:
            return None
        current_fp = _certificate_fingerprint(current)
        if current_fp in anchor_by_fp:
            _check_validity(current, now)
            if len(path) > 1:
                _check_ca_constraints(current)
            # Validate self-signature when the trust anchor is self-issued.  A
            # cross-signed anchor is still trusted by exact fingerprint.
            if current.subject == current.issuer:
                _verify_certificate_signature(current, current)
            return path

        issuers = by_subject.get(current.issuer.rfc4514_string(), [])
        for issuer in issuers:
            issuer_fp = _certificate_fingerprint(issuer)
            if issuer_fp in visited:
                continue
            try:
                _check_validity(issuer, now)
                _check_ca_constraints(issuer)
                _verify_certificate_signature(current, issuer)
            except CertificateTrustError:
                continue
            resolved = _walk(issuer, path + [issuer], visited | {issuer_fp})
            if resolved is not None:
                return resolved
        return None

    chain = _walk(leaf, [leaf], {_certificate_fingerprint(leaf)})
    if chain is None:
        raise CertificateTrustError(
            f"Could not build certificate chain to a configured trust anchor for {leaf.subject.rfc4514_string()}"
        )
    _check_path_length_constraints(chain)
    return chain
