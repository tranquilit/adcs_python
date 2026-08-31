"""CMS signing and verification primitives shared by enrollment protocols.

This module intentionally has no dependency on Flask, Samba or pyasn1, so the
TPM protocol codecs can be tested independently of the full CES runtime.
"""

from __future__ import annotations

import hashlib

from asn1crypto import cms as a_cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:  # pragma: no cover
    mldsa = None


def _hash_for_name(name: str):
    algos = {
        "sha1": hashes.SHA1(),
        "sha224": hashes.SHA224(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    algo = algos.get(name)
    if algo is None:
        raise ValueError(f"Unsupported digest algorithm: {name}")
    return algo


def _get_sd_certificates(sd) -> list:
    certs = []
    if sd["certificates"] is None:
        return certs
    for choice in sd["certificates"]:
        if choice.name == "certificate":
            certs.append(choice.chosen)
    return certs


def _get_cert_ski(cert):
    try:
        exts = cert["tbs_certificate"]["extensions"]
    except Exception:
        return None
    for ext in exts:
        try:
            if ext["extn_id"].dotted == "2.5.29.14":
                return ext["extn_value"].parsed.native
        except Exception:
            continue
    return None


def _find_signer_cert(sd, signer_info):
    certs = _get_sd_certificates(sd)
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        wanted = sid.chosen
        for cert in certs:
            if cert.issuer == wanted["issuer"] and cert.serial_number == wanted["serial_number"].native:
                return cert
    elif sid.name == "subject_key_identifier":
        wanted_ski = sid.native
        for cert in certs:
            if _get_cert_ski(cert) == wanted_ski:
                return cert
    return None


def _extract_attr_value(signed_attrs, *, oid: str | None = None, native_name: str | None = None):
    if signed_attrs is None:
        return None
    for attr in signed_attrs:
        try:
            matches = (oid is not None and attr["type"].dotted == oid) or (
                native_name is not None and attr["type"].native == native_name
            )
            if matches and len(attr["values"]):
                return attr["values"][0].native
        except Exception:
            continue
    return None


def _verify_cms_signature_with_cert(cert, signer_info, signed_bytes: bytes):
    public_key = x509.load_der_x509_certificate(cert.dump()).public_key()
    signature = signer_info["signature"].native
    sig_algo = signer_info["signature_algorithm"]["algorithm"].native

    if isinstance(public_key, rsa.RSAPublicKey):
        hash_algo = _hash_for_name(signer_info["digest_algorithm"]["algorithm"].native)
        if sig_algo in (
            "rsassa_pkcs1v15",
            "sha1_rsa",
            "sha224_rsa",
            "sha256_rsa",
            "sha384_rsa",
            "sha512_rsa",
        ):
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_algo)
            return
        if sig_algo == "rsassa_pss":
            public_key.verify(
                signature,
                signed_bytes,
                padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=hash_algo.digest_size),
                hash_algo,
            )
            return
        raise ValueError(f"Unsupported RSA CMS signature algorithm: {sig_algo}")

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        hash_algo = _hash_for_name(signer_info["digest_algorithm"]["algorithm"].native)
        public_key.verify(signature, signed_bytes, ec.ECDSA(hash_algo))
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, signed_bytes)
        return
    if isinstance(public_key, ed448.Ed448PublicKey):
        public_key.verify(signature, signed_bytes)
        return
    raise ValueError(f"Unsupported CMS signer public key: {type(public_key).__name__}")


def _tbs_signed_attrs(attrs: a_cms.CMSAttributes) -> bytes:
    der = attrs.dump()
    return (b"\x31" + der[1:]) if der and der[0] == 0xA0 else der


def _verify_signer_info(sd, signer_info):
    result = {"signature_valid": False, "message_digest_valid": None, "errors": []}
    cert = _find_signer_cert(sd, signer_info)
    if cert is None:
        result["errors"].append("Unable to match signerInfo.sid to a certificate")
        return result
    try:
        content_field = sd["encap_content_info"]["content"]
        content = content_field.native if content_field is not None else b""
        signed_attrs = signer_info["signed_attrs"]
        if signed_attrs is not None:
            content_type = _extract_attr_value(signed_attrs, native_name="content_type")
            expected_type = sd["encap_content_info"]["content_type"].native
            if content_type != expected_type:
                raise ValueError("contentType attribute mismatch")
            message_digest = _extract_attr_value(signed_attrs, native_name="message_digest")
            if message_digest is None:
                raise ValueError("messageDigest attribute is missing")
            digest_name = signer_info["digest_algorithm"]["algorithm"].native
            computed = hashlib.new(digest_name, content).digest()
            result["message_digest_valid"] = computed == message_digest
            if not result["message_digest_valid"]:
                raise ValueError("messageDigest attribute mismatch")
            signed_bytes = _tbs_signed_attrs(signed_attrs)
        else:
            signed_bytes = content
        _verify_cms_signature_with_cert(cert, signer_info, signed_bytes)
        result["signature_valid"] = True
    except Exception as exc:
        result["errors"].append(f"CMS signature verification failed: {exc}")
    return result


def _mldsa_ca_signature_oid(private_key):
    if mldsa is None:
        return None
    if isinstance(private_key, mldsa.MLDSA44PrivateKey):
        return "2.16.840.1.101.3.4.3.17"
    if isinstance(private_key, mldsa.MLDSA65PrivateKey):
        return "2.16.840.1.101.3.4.3.18"
    if isinstance(private_key, mldsa.MLDSA87PrivateKey):
        return "2.16.840.1.101.3.4.3.19"
    return None


def _signature_algo_for_ca_key(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        return a_cms.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return a_cms.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return a_cms.SignedDigestAlgorithm({"algorithm": "ed25519"})
    if isinstance(private_key, ed448.Ed448PrivateKey):
        return a_cms.SignedDigestAlgorithm({"algorithm": "ed448"})
    oid = _mldsa_ca_signature_oid(private_key)
    if oid:
        return a_cms.SignedDigestAlgorithm({"algorithm": oid})
    raise ValueError(f"Unsupported private key type: {type(private_key).__name__}")


def _sign_tbs_with_ca_key(private_key, data: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return private_key.sign(data)
    if _mldsa_ca_signature_oid(private_key):
        return private_key.sign(data)
    raise ValueError(f"Unsupported private key type: {type(private_key).__name__}")
