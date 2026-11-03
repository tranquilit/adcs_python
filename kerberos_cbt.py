"""RFC 5929 TLS server-end-point channel binding for nginx TLS offload.

Read the *public leaf certificate* nginx serves, not its private key. The
certificate is loaded once on application startup by adcs_config.
"""

import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

_LEAF_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def tls_server_end_point_application_data(certificate_path: str) -> bytes:
    """Return GSS channel bindings application_data for a TLS leaf cert.

    RFC 5929 section 4.1: use the certificate signature hash algorithm;
    MD5 and SHA-1 signatures are upgraded to SHA-256. Unsupported signature
    algorithms must fail startup, not disable CBT.
    """
    pem = Path(certificate_path).read_bytes()
    match = _LEAF_CERT.search(pem)
    if not match:
        raise ValueError("TLS certificate file does not contain a PEM certificate")

    certificate = x509.load_pem_x509_certificate(match.group(0))
    algorithm = certificate.signature_hash_algorithm
    if algorithm is None:
        raise ValueError("RFC 5929 is undefined for this TLS certificate signature")
    if algorithm.name.lower() in ("md5", "sha1"):
        algorithm = hashes.SHA256()

    return b"tls-server-end-point:" + certificate.fingerprint(algorithm)
