#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import yaml
import os
from typing import Tuple

from asn1crypto import x509 as a_x509, core as a_core

from callback_loader import load_func
from flags_catalog import FLAG_CATALOG  # canonical table alias -> bitmask


# ---------------- Helpers: encoders for "human" extensions (CEP) ----------------

class MsftCertTemplateInfo(a_core.Sequence):
    _fields = [
        ('templateID', a_core.ObjectIdentifier),
        ('templateMajorVersion', a_core.Integer),
        ('templateMinorVersion', a_core.Integer),
    ]


class PolicyInfo(a_core.Sequence):
    _fields = [('policyIdentifier', a_core.ObjectIdentifier)]


class PolicyInfos(a_core.SequenceOf):
    _child_spec = PolicyInfo


def _encode_eku(oids):
    """EKU (2.5.29.37) -> SEQUENCE OF KeyPurposeId."""
    seq = a_x509.ExtKeyUsageSyntax([str(oid) for oid in oids])
    return seq.dump()


def _encode_app_policies(oids):
    """Application Policies (1.3.6.1.4.1.311.21.10) -> SEQUENCE OF PolicyInfo."""
    infos = PolicyInfos([
        PolicyInfo({'policyIdentifier': a_core.ObjectIdentifier(oid)}) for oid in oids
    ])
    return infos.dump()


def _encode_key_usage(bits_map: dict) -> bytes:
    """
    KeyUsage (2.5.29.15) -> DER BIT STRING (minimal).
    Order (i = bit index): 0..8 in the standard order.
    """
    order = [
        'digital_signature', 'content_commitment', 'key_encipherment',
        'data_encipherment', 'key_agreement', 'key_cert_sign',
        'crl_sign', 'encipher_only', 'decipher_only',
    ]
    max_i = -1
    for i, name in enumerate(order):
        if bits_map.get(name, False):
            max_i = i
    if max_i < 0:
        return b"\x03\x01\x00"

    num_bits = max_i + 1
    num_bytes = (num_bits + 7) // 8
    unused_bits = (num_bytes * 8) - num_bits

    data = bytearray(num_bytes)
    for i, name in enumerate(order):
        if bits_map.get(name, False):
            byte_idx = i // 8
            bit_pos = 7 - (i % 8)
            data[byte_idx] |= (1 << bit_pos)

    content = bytes([unused_bits]) + bytes(data)
    return b"\x03" + bytes([len(content)]) + content


def _encode_template_info(oid: str, major: int, minor: int):
    """Certificate Template Information (1.3.6.1.4.1.311.21.7)."""
    seq = MsftCertTemplateInfo({
        'templateID': a_core.ObjectIdentifier(oid),
        'templateMajorVersion': a_core.Integer(int(major)),
        'templateMinorVersion': a_core.Integer(int(minor)),
    })
    return seq.dump()


def _materialize_required_extensions_static_in_place(tpl: dict):
    """
    For each “human” extension of the template, compute DER + base64 if it is static,
    and mark dynamic ones (ntds_security/dynamic) without materializing them.
    """
    items = tpl.get("required_extensions", []) or []
    for ext in items:
        oid = ext.get("oid")
        if not oid:
            raise ValueError("required_extensions item without 'oid'")

        # Dynamic extensions are not materialized for CEP
        if "ntds_security" in ext or "dynamic" in ext:
            ext["__dynamic"] = True
            ext["__der"] = None
            ext["value_b64"] = None
            continue

        # Encoders for static ones
        if "eku_oids" in ext:
            oids = ext.get("eku_oids") or []
            if not isinstance(oids, list) or not oids:
                raise ValueError(f"EKU requires non-empty list 'eku_oids' for OID {oid}")
            der = _encode_eku(oids)

        elif "key_usage" in ext:
            ku = ext.get("key_usage") or {}
            if not isinstance(ku, dict):
                raise ValueError(f"KeyUsage requires mapping 'key_usage' for OID {oid}")
            der = _encode_key_usage(ku)

        elif "template_info" in ext:
            ti = ext.get("template_info") or {}
            t_oid = ti.get("oid")
            maj = ti.get("major_version")
            minv = ti.get("minor_version")
            if not t_oid or maj is None or minv is None:
                raise ValueError(f"template_info requires 'oid', 'major_version', 'minor_version' for OID {oid}")
            der = _encode_template_info(t_oid, maj, minv)

        elif "app_policies" in ext:
            aps = ext.get("app_policies") or []
            if not isinstance(aps, list) or not aps:
                raise ValueError(f"Application Policies requires non-empty list 'app_policies' for OID {oid}")
            der = _encode_app_policies(aps)

        else:
            raise ValueError(
                f"Extension {oid} has no recognized block. "
                f"Expected: eku_oids, key_usage, template_info, app_policies, or ntds_security/dynamic."
            )

        ext["__der"] = der
        ext["value_b64"] = base64.b64encode(der).decode('ascii')

    # For CEP: keep only static ones in required_extensions
    tpl["__all_required_extensions"] = list(items)
    tpl["required_extensions"] = [e for e in items if e.get("value_b64")]


def _ensure_cep_fields(tpl: dict):
    """
    Normalize fields expected by the CEP Jinja template to avoid UndefinedError.
    """
    tpl.setdefault("policy_schema", 2)
    tpl.setdefault("revision", {"major": 1, "minor": 0})
    tpl.setdefault("validity", {"validity_seconds": 31536000, "renewal_seconds": 0})
    tpl.setdefault("permissions", {"enroll": True, "auto_enroll": False})
    tpl.setdefault("private_key_attributes", {
        "minimal_key_length": 2048,
        "key_spec": 1,
        "algorithm_oid_reference": None,
        "crypto_providers": [
            "Microsoft Enhanced Cryptographic Provider v1.0",
            "Microsoft Base Cryptographic Provider v1.0",
        ],
    })
    tpl.setdefault("flags", {
        "private_key_flags": {},
        "subject_name_flags": {},
        "enrollment_flags": {},
        "general_flags": {},
    })
    tpl.setdefault("required_extensions", [])
    tpl.setdefault("ca_references", [])


# ---------------- Flags: compile booleans -> integer masks -------------------

def _compile_flags_value_bool_first(val, table: dict, *, field_name: str) -> int:
    """
    Compile a flag field into an integer.
    - dict[str,bool] -> OR of enabled aliases (via canonical table)
    - {'__raw__': int|str} -> raw escape hatch (hex/dec)
    - int -> unchanged (compat)
    - None -> 0
    """
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        if "__raw__" in val:  # optional escape hatch
            raw = val["__raw__"]
            return int(raw, 0) if isinstance(raw, str) else int(raw)
        out = 0
        for name, enabled in val.items():
            if not enabled:
                continue
            if name not in table:
                raise ValueError(f"Unknown flag '{name}' in {field_name}")
            bit = table[name]
            out |= int(bit, 0) if isinstance(bit, str) else int(bit)
        return out
    raise TypeError(
        f"{field_name} must be a mapping alias->bool, integer, or {{'__raw__': value}}; got {type(val).__name__}"
    )


SERVER_MASK = 0x000F0000
CLIENT_MASK = 0x0F000000
SERVER_SHIFT = 16
CLIENT_SHIFT = 24

def _set_nibble(mask: int, *, value: int, shift: int, field_mask: int) -> int:
    if value is None:
        return mask
    v = int(value)
    if not (0 <= v <= 15):
        raise ValueError(f"compat nibble must be 0..15, got {value}")
    mask &= ~field_mask
    mask |= (v & 0xF) << shift
    return mask


def _compile_flags_block(flags, aliases_root: dict) -> dict:
    """
    Compile the 4 flag families to integers, using the canonical table.
    Also inject privateKeyFlags compatibility nibbles (server/client) if provided.
    """
    flags = dict(flags or {})

    # Compile bool flags -> int
    for key in ("private_key_flags", "subject_name_flags", "enrollment_flags", "general_flags"):
        table = aliases_root.get(key, {})
        flags[key] = _compile_flags_value_bool_first(flags.get(key), table, field_name=key)

    # Optional: inject compatibility bitfields into private_key_flags
    compat = flags.get("private_key_compat") or {}
    if compat:
        pk = int(flags.get("private_key_flags", 0))
        pk = _set_nibble(pk, value=compat.get("min_ca", 0), shift=SERVER_SHIFT, field_mask=SERVER_MASK)
        pk = _set_nibble(pk, value=compat.get("min_client", 0), shift=CLIENT_SHIFT, field_mask=CLIENT_MASK)
        flags["private_key_flags"] = pk

    return flags

# ---------------- YAML loading & runtime context ----------------

def _pem_to_inner_b64(pem_text: str) -> str:
    parts = pem_text.split('-----')
    if len(parts) < 3:
        raise ValueError("Invalid PEM (missing headers)")
    return "".join(parts[2].strip().splitlines())


# --- CA keys: PEM or HSM (no environment variables) ---------------------------

def _load_ca_key(ca: dict):
    """
    Load the CA private key as either:
      - PEM mode (legacy) if ca['pem'] contains key_path_pem
      - HSM mode if ca['hsm'] is present

    HSM block schema (no environment variables used):
      hsm.pkcs11_lib    : path to PKCS#11 library (.so/.dll)
      hsm.pkcs11_uri    : token pkcs11_uri
      hsm.key_id        : CKA_ID as hex "a1b2c3..."
      hsm.user_pin      : PIN as plain text (dev)
      hsm.user_pin_file : path to a file whose first line contains the PIN (recommended)
    """
    from cryptography.hazmat.primitives import serialization

    pem = ca.get("pem", {}) or {}
    hsm = ca.get("hsm", {}) or {}

    has_pem_key = bool(pem.get("key_path_pem"))
    has_hsm     = bool(hsm)

    if has_pem_key and has_hsm:
        raise ValueError(f"CA '{ca.get('id','?')}': specify either 'pem.key_path_pem' or 'hsm', not both.")

    if not has_pem_key and not has_hsm:
        print('keyless mode')
        return

    # --- PEM mode (as before)
    if has_pem_key:
        key_path = pem.get("key_path_pem")
        key_pass = pem.get("key_passphrase")
        with open(key_path, "rb") as f:
            key_bytes = f.read()
        return serialization.load_pem_private_key(
            key_bytes, password=key_pass.encode() if key_pass else None
        )

    # --- HSM mode (PKCS#11)
    pkcs11_lib    = hsm.get("pkcs11_lib")
    pkcs11_uri   = hsm.get("pkcs11_uri")
    key_id        = hsm.get("key_id")  # bytes or hex str (normalized by myhsm)
    user_pin      = hsm.get("user_pin")  # string or null
    user_pin_file = hsm.get("user_pin_file")  # path to PIN file

    if not pkcs11_lib or not pkcs11_uri:
        raise ValueError(f"CA '{ca.get('id','?')}': hsm.pkcs11_lib and hsm.pkcs11_uri are required.")

    if not key_id :
        raise ValueError(f"CA '{ca.get('id','?')}': specify hsm.key_id (hex) ")

    # Resolve PIN: the file takes precedence if provided
    if user_pin_file:
        try:
            with open(user_pin_file, "r", encoding="utf-8") as f:
                first_line = f.readline()
            user_pin = (first_line or "").strip()
        except Exception as e:
            raise ValueError(f"Could not read hsm.user_pin_file='{user_pin_file}': {e}") from e

    # user_pin may remain empty if the token does not require a PIN (rare)
    if user_pin is None:
        user_pin = ""

    try:
        from myhsm import HSMRSAPrivateKey
    except Exception as e:
        raise RuntimeError("Module 'myhsm' not found. Place 'myhsm.py' next to 'adcs_config.py'.") from e

    return HSMRSAPrivateKey(
        lib_path=pkcs11_lib,
        pkcs11_uri=pkcs11_uri,
        user_pin=user_pin,
        key_id=key_id,
        rw=True,
        login_on_init=True,
    )


def load_yaml_conf(path="adcs.yaml"):
    """
    Load adcs.yaml, read global config and CAs, and record
    ONLY template declarations (callbacks) without building them.
    Templates will be built on demand (CEP/CES) via
    build_templates_for_policy_response(...).
    """
    #from cryptography.hazmat.primitives import serialization

    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    conf = {}
    gbl = cfg.get("global", {})
    
    policy_provider = gbl.get("policy_provider", {})
    storage_paths_global = gbl.get("storage_paths", {}) or {}
    conf["path_list_request_id"] = gbl.get("path_list_request_id", "/var/lib/adcs/list_request_id")
    conf["next_update_hours_crl"] = gbl.get("next_update_hours_crl", 8)

    conf["policyid"] = policy_provider.get("policy_id")
    conf["policyfriendlyname"] = policy_provider.get("policyfriendlyname","CEP policy")
    conf["next_update_hours"] = policy_provider.get("next_update_hours", 8)

    conf["auth_callbacks"] = []

    conf['auth_kerberos'] = True
    for adecl in (cfg.get("auth") or []):

        if adecl.get("kerberos") != None :
            conf['auth_kerberos'] = adecl["kerberos"]

        cb = adecl.get("callback") or {}
        cb_path = cb.get("path")
        if not cb_path :
            continue
        cb_func = cb.get("func",'check_auth')
        conf["auth_callbacks"] = {"path": cb_path, "func": cb_func}

    # Global fallbacks for storage
    conf["path_cert_fallback"] = storage_paths_global.get("cert_dir", "/tmp/certs")
    conf["path_csr_fallback"]  = storage_paths_global.get("csr_dir",  "/tmp/csr")

    # ---- CAs
    conf["cas_list"] = []
    conf["cas_by_refid"] = {}
    conf["cas_by_id"] = {}
    conf["cas_by_display_name"] = {}
    default_ca = None
    next_ca_refid = 0

    for ca in cfg.get("cas", []) or []:
        pem = ca.get("pem", {}) or {}
        if "certificate_inline_pem" in pem:
            raise ValueError("Inline PEM not allowed. Use pem.certificate_path_pem.")

        cert_path = pem.get("certificate_path_pem")
        if not cert_path:
            raise ValueError("Each CA must define pem.certificate_path_pem (public certificate path)")

        # Read the CA public certificate (unchanged)
        with open(cert_path, "r", encoding="utf-8") as f:
            cert_pem = f.read()
        cert_b64 = _pem_to_inner_b64(cert_pem)
        ca["__certificate_pem"] = cert_pem
        ca["__certificate_b64"] = cert_b64
        ca["__certificate_der"] = base64.b64decode(cert_b64)

        # CA private key: PEM (legacy) or HSM (new)
        ca["__key_obj"] = _load_ca_key(ca)

        ces_path = ca.get("urls", {}).get("ces_path")
        if not ces_path:
            ca["__ces_path"] = f"/CES/{ca['id']}"
        else:
            ca["__ces_path"] = ces_path

        sp = ca.get("storage_paths", {}) or {}
        ca["__path_cert"] = sp.get("cert_dir", conf["path_cert_fallback"])
        ca["__path_csr"]  = sp.get("csr_dir",  conf["path_csr_fallback"])

        refid = next_ca_refid
        next_ca_refid += 1
        ca["__refid"] = refid

        conf["cas_list"].append(ca)
        conf["cas_by_refid"][refid] = ca
        if ca.get("id"):
            conf["cas_by_id"][ca["id"]] = ca
        if ca.get("display_name"):
            conf["cas_by_display_name"][ca["display_name"]] = ca
        if ca.get("default"):
            default_ca = ca

        if ca.get('ket_cert_pem'):
            with open(ca.get('ket_cert_pem'), "r", encoding="utf-8") as f:
                ket_cert_pem = f.read()
            cert_b64 = _pem_to_inner_b64(ket_cert_pem)
            ca["__ket_certificate_b64"] = cert_b64
    

    if not conf["cas_list"]:
        raise ValueError("No CA defined in 'cas'")
    conf["default_ca"] = default_ca or conf["cas_list"][0]

    # ---- Only remember template callbacks (no build here)
    conf["__template_decls__"] = []
    for tdecl in cfg.get("templates", []) or []:
        cb = (tdecl.get("callback") or {})
        cb_path   = cb.get("path")
        cb_define = cb.get("define",'define_template')
        cb_issue  = cb.get("issue",'emit_certificate')
        if not (cb_path and cb_define and cb_issue):
            raise ValueError("Each template must define callback.path / callback.define / callback.issue")

        conf["__template_decls__"].append({
            "path": cb_path,
            "define": cb_define,
            "issue": cb_issue
        })
    return conf


# ---------------- Per-request build (CEP/CES): templates + OIDs (stateless) -----

def build_templates_for_policy_response(
    conf: dict,
    *,
    username = None,
    request,
    **kwargs
) -> Tuple[list[dict], list[dict]]:
    """
    Build **per-request** templates and a **per-request** OIDs registry.
    Does **not** mutate the global conf (no writes into conf["templates_*"] nor conf["oids_*"]).
    Returns: (templates_list, oids_list)
    """

    # Local OIDs registry (not global)
    oids_by_value: dict[str, int] = {}
    oids_by_refid: dict[int, dict] = {}
    oids_list: list[dict] = []
    next_oid_refid = 1

    def register_oid(value: str, group: int = 6, default_name = None) -> int:
        nonlocal next_oid_refid
        if not value:
            raise ValueError("register_oid: empty value")
        if value in oids_by_value:
            return oids_by_value[value]
        refid = next_oid_refid
        next_oid_refid += 1
        entry = {
            "value": value,
            "group": group,
            "default_name": default_name or f"OID {value}",
            "__refid": refid,
        }
        oids_list.append(entry)
        oids_by_refid[refid] = entry
        oids_by_value[value] = refid
        return refid

    templates_list: list[dict] = []

    # Build each template via its "define" callback
    for cb in conf.get("__template_decls__") or []:

        if cb["path"].startswith('/'):
            cb_path = cb["path"]
        else:
            cb_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),cb["path"])

        define_template = load_func(cb_path, cb["define"])
        tpl = define_template(
            app_conf=conf,                 # conf remains read-only
            username=username,
            request=request,
            **kwargs
        )
        if not tpl:
            continue
        if not isinstance(tpl, dict):
            raise TypeError(f"{cb['path']}:{cb['define']} must return a dict")

        # Normalize for CEP Jinja
        _ensure_cep_fields(tpl)

        # Compile flag booleans -> integers
        tpl["flags"] = _compile_flags_block(tpl.get("flags"), FLAG_CATALOG)

        # Resolve CAs into __ca_refids (read-only in conf)
        resolved = []
        raw = tpl.get("ca_references") or []
        if isinstance(raw, (str, int)):
            raw = [raw]
        for item in raw:
            cand = None
            if isinstance(item, int):
                cand = conf["cas_by_refid"].get(item)
            elif isinstance(item, str):
                cand = conf["cas_by_id"].get(item) or conf["cas_by_display_name"].get(item)
            if cand is None:
                raise ValueError(f"Template '{tpl.get('common_name','?')}' references unknown CA '{item}'")
            resolved.append(cand["__refid"])
        tpl["__ca_refids"] = resolved

        # Register the template OID in the **local** registry
        t_oid = (tpl.get("template_oid") or {}).get("value")
        if not t_oid:
            raise ValueError("define_template must set template_oid.value")
        policy_refid = register_oid(
            t_oid, group=9, default_name=(tpl.get("template_oid") or {}).get("name")
        )
        tpl["__policy_oid_reference"] = policy_refid

        # Register extension OIDs (local) and materialize statics
        for ext in tpl.get("required_extensions", []) or []:
            dotted = ext.get("oid")
            if not dotted:
                raise ValueError("Each required_extension must have an 'oid'")
            ext_refid = register_oid(dotted, group=6)
            ext["__oid_reference"] = ext_refid

        _materialize_required_extensions_static_in_place(tpl)

        # Remember emission callback (for CES)
        tpl["__callback"] = {"path": cb["path"], "issue": cb["issue"]}

        templates_list.append(tpl)

    return templates_list, oids_list

