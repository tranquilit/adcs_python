# myhsm.py
# -*- coding: utf-8 -*-
"""
PKCS#11 wrapper → object compatible with cryptography.RSAPrivateKey
to use a *non-exportable* key stored in an HSM/TPM.

Design goals
------------
- No environment variables required (everything is passed explicitly).
- Tolerant to python-pkcs11 variants:
  * some ignore Token.open(user_pin=...) → fallback re-open
  * some lack Session.login → we avoid calling it
  * some objects don't support `.get(...)` → use subscript access `[Attribute.*]`
- Robust key lookup (CKA_ID-only):
  * PRIVATE_KEY lookup by CKA_ID (key_id) only
  * Try multiple CKA_ID encodings (binary vs ASCII-hex, upper/lower)
  * Fallback via PUBLIC_KEY to derive the right CKA_ID
  * Final full-scan match by ID variants
- Token selection by pkcs11_uri only (deterministic):
  * Match token info (serial/model/manufacturer/token label) from pkcs11_uri
  * Compatible with python-pkcs11 variants where Token info is exposed as .token_info or .info
- Works with TPM2-PKCS#11 (tpm2-pkcs11) and most HSMs speaking PKCS#11.
- Never exports private key material; exposes only the cryptography API.

Dependencies
------------
    apt-get install -y python3-pkcs11
    pip install python-pkcs11 cryptography   # (pip alternative)

Quick usage
-----------
    from myhsm import HSMRSAPrivateKey
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as P

    key = HSMRSAPrivateKey(
        lib_path="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        pkcs11_uri="pkcs11:model=PKCS%2315%20emulated;manufacturer=www.CardContact.de;serial=DENK0301429;token=SmartCard-HSM",
        user_pin="123456",
        key_id="01ab23cd",                # CKA_ID (hex string) or raw bytes
        # slot_index=0,                   # optional vendor quirk (index into pkcs11.get_slots())
    )

    sig = key.sign(b"hello", P.PKCS1v15(), hashes.SHA256())
"""

from __future__ import annotations

import binascii
import ctypes
from typing import Optional, Union, Dict, Any, Iterable, List
from urllib.parse import unquote

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding


class HSMError(RuntimeError):
    """Generic HSM/PKCS#11 error."""


def _attr(obj, key, default=None):
    """Safe attribute fetch for pkcs11 objects using subscript access; returns default on failure."""
    try:
        return obj[key]
    except Exception:
        return default


def _parse_pkcs11_uri(uri: str) -> Dict[str, str]:
    """
    Minimal pkcs11 URI parser:
      pkcs11:key1=val1;key2=val2  -> {"key1":"val1", ...} (URL-decoded)

    Common keys seen in pkcs11-tool -L:
      - serial
      - token
      - manufacturer
      - model
    """
    if not uri:
        raise ValueError("pkcs11_uri is required")
    uri = uri.strip()
    if not uri.startswith("pkcs11:"):
        raise ValueError(f"Invalid pkcs11_uri (must start with 'pkcs11:'): {uri!r}")

    out: Dict[str, str] = {}
    body = uri[len("pkcs11:"):]
    for part in body.split(";"):
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k] = unquote(v)
    return out


def _get_token_info(tok):
    """
    Compat: python-pkcs11 Token exposes either .token_info or .info depending on build/version.
    Returns an object with label/serial/manufacturer/model attributes (best-effort).
    """
    info = getattr(tok, "token_info", None)
    if info is not None:
        return info
    info = getattr(tok, "info", None)
    if info is not None:
        return info
    return None


def _ti_get(info, *names, default=""):
    """Get attribute from token-info object with multiple possible attribute spellings."""
    for n in names:
        v = getattr(info, n, None)
        if v is None:
            continue
        if isinstance(v, str):
            return (v or "").strip()
        return v
    return default


def _token_matches_uri_from_token(tok, uri_kv: Dict[str, str]) -> bool:
    """
    Match Token info against the pkcs11_uri fields that are present.

    We match strictly only on keys present in URI.
    Your key disambiguator is usually `serial=...`.
    """
    info = _get_token_info(tok)
    if info is None:
        return False

    label = (_ti_get(info, "label", default="") or "").strip()
    serial = (_ti_get(info, "serial_number", "serialNumber", "serial", default="") or "").strip()
    manufacturer = (_ti_get(info, "manufacturer_id", "manufacturerID", "manufacturer", default="") or "").strip()
    model = (_ti_get(info, "model", default="") or "").strip()

    uri_serial = (uri_kv.get("serial") or "").strip()
    uri_token = (uri_kv.get("token") or "").strip()
    uri_manu = (uri_kv.get("manufacturer") or "").strip()
    uri_model = (uri_kv.get("model") or "").strip()

    if uri_serial and serial != uri_serial:
        return False
    if uri_token and label != uri_token:
        return False
    if uri_manu and manufacturer != uri_manu:
        return False
    if uri_model and model != uri_model:
        return False
    return True


class HSMRSAPrivateKey(rsa.RSAPrivateKey):
    """
    Implements the cryptography RSAPrivateKey interface delegating operations to the HSM via PKCS#11.
    Never exposes the private key material (private_numbers/private_bytes -> TypeError).
    """

    # ---------------- Construction ---------------- #

    def __init__(
        self,
        lib_path: str,
        pkcs11_uri: str,
        user_pin: Optional[str] = None,
        *,
        key_id: Union[bytes, str],
        slot_index: Optional[int] = None,
        rw: bool = True,
        login_on_init: bool = True,
    ) -> None:
        """
        Args:
            lib_path: path to the PKCS#11 library (.so/.dylib/.dll) for the HSM/TPM.
            pkcs11_uri: pkcs11 URI used to select the token deterministically.
                       Example from pkcs11-tool -L:
                         pkcs11:model=...;manufacturer=...;serial=DENK...;token=SmartCard-HSM
            user_pin: user PIN (CKU_USER). If provided, a login is attempted.
            key_id: identifier (CKA_ID) of the private key:
                    - bytes (raw)
                    - or hex string "A1B2...", with or without ':' / spaces
            slot_index: optional index to select a slot explicitly (vendor quirk; index into get_slots()).
            rw: open the session read/write (often required).
            login_on_init: perform CKU_USER login during initialization (best-effort).

        Raises:
            HSMError on PKCS#11 failures or key resolution issues.
        """
        # Late import to avoid hard dependency for importers of this module
        try:
            import pkcs11
            from pkcs11 import Attribute, ObjectClass, UserType
            from pkcs11.exceptions import UserAlreadyLoggedIn
        except Exception as e:
            raise HSMError(f"python-pkcs11 not found or invalid: {e}") from e

        self._Attribute = Attribute
        self._ObjectClass = ObjectClass
        self._UserType = UserType
        self._backend = default_backend()

        uri_kv = _parse_pkcs11_uri(pkcs11_uri)

        # Keep original key_id string (if any) for alternative encodings
        original_key_id_str: Optional[str] = None
        key_id_bytes: bytes

        if isinstance(key_id, str):
            original_key_id_str = key_id.strip()
            cleaned = original_key_id_str.replace(":", "").replace(" ", "")
            try:
                key_id_bytes = binascii.unhexlify(cleaned)
            except Exception as e:
                raise ValueError(f"Invalid hex key_id: {original_key_id_str!r}") from e
        else:
            key_id_bytes = bytes(key_id)

        # 1) Load PKCS#11 library (pre-check with ctypes for helpful error messages)
        lib_candidates = [lib_path]
        if lib_path.endswith(".so"):
            # Try typical SONAME suffix as a convenience (e.g., .so.1)
            try:
                ctypes.CDLL(lib_path + ".1")
                lib_candidates.append(lib_path + ".1")
            except Exception:
                pass

        last_err = None
        loaded = False
        for cand in lib_candidates:
            try:
                ctypes.CDLL(cand)  # ensures dependencies are resolvable
                self._pkcs11 = pkcs11.lib(cand)
                lib_path = cand  # remember what we actually loaded
                loaded = True
                break
            except Exception as e:
                last_err = e
        if not loaded:
            raise HSMError(f"Cannot load PKCS#11 library: {lib_path} → {last_err!r}")

        # 2) Locate the token by pkcs11_uri (scan slots, match token info)
        try:
            slots = list(self._pkcs11.get_slots())

            self._token = None

            # If slot_index is provided, try it first (vendor quirk / deterministic)
            if slot_index is not None:
                if not (0 <= slot_index < len(slots)):
                    raise HSMError(f"slot_index out of range (got {slot_index}, have {len(slots)} slots)")
                tok = slots[slot_index].get_token()
                if _token_matches_uri_from_token(tok, uri_kv):
                    self._token = tok

            # Otherwise scan all slots
            if self._token is None:
                for s in slots:
                    try:
                        tok = s.get_token()
                        if _token_matches_uri_from_token(tok, uri_kv):
                            self._token = tok
                            break
                    except Exception:
                        continue

            if self._token is None:
                raise HSMError(f"Token not found for pkcs11_uri={pkcs11_uri!r}")

        except Exception as e:
            raise HSMError(f"Token not found (pkcs11_uri={pkcs11_uri!r}): {e}") from e

        # 3) Open a session (first try: with possible implicit login)
        self._user_pin = (user_pin or "")
        try:
            self._session = self._token.open(
                rw=rw,
                user_pin=(self._user_pin if (login_on_init and self._user_pin) else None)
            )
        except UserAlreadyLoggedIn:
            self._session = self._token.open(rw=rw, user_pin=None)
        except Exception as e:
            raise HSMError(f"Cannot open PKCS#11 session: {e}") from e

        # 4) Optional explicit login (best-effort; many builds lack Session.login)
        if login_on_init and self._user_pin:
            self._login_user()

        # 5) Resolve the key (private → fallbacks)
        self._priv = None

        # Build candidate encodings for CKA_ID, to cover vendor differences
        id_candidates: List[bytes] = []

        raw = key_id_bytes
        # a) raw bytes
        id_candidates.append(raw)
        # b) ASCII hex of those bytes (lower + upper)
        ascii_hex = binascii.hexlify(raw)  # b'3463...'
        id_candidates.append(ascii_hex)
        id_candidates.append(ascii_hex.upper())

        if original_key_id_str:
            cleaned = original_key_id_str.replace(":", "").replace(" ", "")
            id_candidates.append(cleaned.encode("ascii"))
            id_candidates.append(cleaned.upper().encode("ascii"))

        # 5.1 First attempt: by id candidates
        self._priv = self._try_find_private_by_ids(id_candidates)

        # 5.2 If not found and we have a PIN, some modules ignored login on first open():
        if self._priv is None and self._user_pin:
            try:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = self._token.open(rw=rw, user_pin=self._user_pin)
                self._priv = self._try_find_private_by_ids(id_candidates)
            except Exception:
                pass

        # 5.3 Fallback: via PUBLIC_KEY → derive CKA_ID → search PRIVATE_KEY by that id
        if self._priv is None:
            pub = None
            for cid in id_candidates:
                if not cid:
                    continue
                pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, id=cid)
                if pub:
                    break
            kid_from_pub = _attr(pub, self._Attribute.ID, None) if pub is not None else None
            if kid_from_pub is not None:
                self._priv = self._find_one(object_class=self._ObjectClass.PRIVATE_KEY, id=kid_from_pub)

        # 5.4 FINAL TRY: full scan of PRIVATE_KEY objects, match by any candidate ID
        if self._priv is None:
            try:
                it = self._session.get_objects({self._Attribute.CLASS: self._ObjectClass.PRIVATE_KEY})
                all_privs = list(it)
            except Exception:
                all_privs = []

            cand_ids = set()
            for cid in id_candidates:
                if not cid:
                    continue
                cand_ids.add(cid)
                try:
                    cand_ids.add(binascii.unhexlify(cid.decode("ascii")))
                except Exception:
                    pass
                try:
                    cand_ids.add(cid.lower())
                    cand_ids.add(cid.upper())
                except Exception:
                    pass

            for o in all_privs:
                try:
                    oid = _attr(o, self._Attribute.ID, b"")
                    oid_b = oid.encode("ascii", "ignore") if isinstance(oid, str) else bytes(oid or b"")
                    if (oid_b in cand_ids) or (binascii.hexlify(oid_b) in cand_ids) or (oid_b.upper() in cand_ids) or (oid_b.lower() in cand_ids):
                        self._priv = o
                        break
                except Exception:
                    continue

        if self._priv is None:
            self.close()
            target = f"id={binascii.hexlify(key_id_bytes).decode()}"
            if original_key_id_str:
                target = f"id={original_key_id_str}"
            raise HSMError(
                f"Private key not found ({target}). "
                f"Confirm with pkcs11-tool --list-objects / pkcs11-tool -O "
                f"(check CKA_ID and that the session is USER-authenticated)."
            )

        # 6) Retrieve public key: prefer separate PUBLIC_KEY object by CKA_ID; fallback to private attrs
        try:
            kid = _attr(self._priv, self._Attribute.ID, None)
            pub = None
            if kid is not None:
                pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, id=kid)

            if pub is None:
                # last resort: try reading from private key object (may be disallowed)
                n_bytes = _attr(self._priv, self._Attribute.MODULUS, None)
                e_bytes = _attr(self._priv, self._Attribute.PUBLIC_EXPONENT, None)
                if n_bytes and e_bytes:
                    n = int.from_bytes(n_bytes, "big")
                    e = int.from_bytes(e_bytes, "big")
                else:
                    raise HSMError(
                        "Matching public key not found and private key does not expose MODULUS/PUBLIC_EXPONENT. "
                        "Export the public key to the token (PUBLIC_KEY object with same CKA_ID) or "
                        "allow reading modulus/exponent on the private object."
                    )
            else:
                n = int.from_bytes(_attr(pub, self._Attribute.MODULUS), "big")
                e = int.from_bytes(_attr(pub, self._Attribute.PUBLIC_EXPONENT), "big")

            self._pub_numbers = rsa.RSAPublicNumbers(e, n)
        except Exception as e:
            self.close()
            raise HSMError(f"Failed to retrieve public key: {e}") from e

        # 7) Check ALWAYS_AUTHENTICATE (best-effort)
        try:
            self._always_auth = bool(_attr(self._priv, self._Attribute.ALWAYS_AUTHENTICATE, False))
        except Exception:
            self._always_auth = False

    # ---------------- Internal helpers ---------------- #

    def _try_find_private_by_ids(self, id_candidates: Iterable[bytes]):
        oc = self._ObjectClass.PRIVATE_KEY
        for cid in id_candidates:
            if not cid:
                continue
            obj = self._find_one(object_class=oc, id=cid)
            if obj is not None:
                return obj
        return None

    def _login_user(self) -> None:
        """CKU_USER login. Tolerates 'already logged in' and missing Session.login()."""
        if not self._user_pin:
            return
        if not hasattr(self._session, "login"):
            return
        try:
            self._session.login(self._user_pin, user_type=self._UserType.USER)
        except Exception as e:
            msg = str(e).lower()
            if "already" in msg:
                return
            raise HSMError(f"User login (PIN) failed: {e}") from e

    def _context_login_if_needed(self) -> None:
        """Re-login context-specific if the key requires ALWAYS_AUTHENTICATE (best-effort)."""
        if not getattr(self, "_always_auth", False) or not self._user_pin:
            return
        if hasattr(self._session, "login"):
            try:
                user_type = getattr(self._UserType, "CONTEXT_SPECIFIC", self._UserType.USER)
                self._session.login(self._user_pin, user_type=user_type)
            except Exception:
                pass

    def _find_one(self, **attrs: Any):
        """Return the first object matching attrs, mapping to concrete PKCS#11 Attributes."""
        try:
            q = {}
            for k, v in attrs.items():
                if k in ("object_class", "class"):
                    q[self._Attribute.CLASS] = v
                elif k == "id":
                    if isinstance(v, str):
                        v = v.encode("ascii", "strict")
                    q[self._Attribute.ID] = v
                else:
                    q[k] = v

            it = self._session.get_objects(q)

            for obj in it:
                try:
                    list(it)
                except Exception:
                    pass
                return obj
            try:
                list(it)
            except Exception:
                pass
        except Exception:
            pass
        return None

    # ---------------- cryptography.RSAPrivateKey API ---------------- #

    @property
    def key_size(self) -> int:
        return self._pub_numbers.n.bit_length()

    def public_key(self):
        return self._pub_numbers.public_key(self._backend)

    # --- Sign ---
    def sign(self, data: bytes, padding, algorithm):
        """
        Supports:
            - PKCS#1 v1.5 (SHA1/224/256/384/512)
            - RSASSA-PSS (SHA256/384/512) if supported by the HSM / token
        """
        from pkcs11 import Mechanism
        from pkcs11.exceptions import UserNotLoggedIn

        pin = self._user_pin or None  # may be None if no PIN

        if isinstance(padding, asym_padding.PKCS1v15):
            mech = {
                hashes.SHA1:   Mechanism.SHA1_RSA_PKCS,
                hashes.SHA224: Mechanism.SHA224_RSA_PKCS,
                hashes.SHA256: Mechanism.SHA256_RSA_PKCS,
                hashes.SHA384: Mechanism.SHA384_RSA_PKCS,
                hashes.SHA512: Mechanism.SHA512_RSA_PKCS,
            }.get(type(algorithm))
            if mech is None:
                raise ValueError("Hash not supported for PKCS#1 v1.5")

            try:
                return self._priv.sign(data, mechanism=mech, pin=pin)
            except TypeError:
                return self._priv.sign(data, mechanism=mech)
            except UserNotLoggedIn:
                return self._priv.sign(data, mechanism=mech, pin=pin)

        if isinstance(padding, asym_padding.PSS):
            from pkcs11.util.rsa import RsaPssParams

            hash_mech = {
                hashes.SHA256: Mechanism.SHA256,
                hashes.SHA384: Mechanism.SHA384,
                hashes.SHA512: Mechanism.SHA512,
            }.get(type(algorithm))
            if hash_mech is None:
                raise ValueError("Hash not supported for PSS")

            params = RsaPssParams(hash_mech, algorithm.digest_size, hash_mech)

            try:
                return self._priv.sign(
                    data,
                    mechanism=Mechanism.RSA_PKCS_PSS,
                    mechanism_param=params,
                    pin=pin,
                )
            except TypeError:
                return self._priv.sign(
                    data,
                    mechanism=Mechanism.RSA_PKCS_PSS,
                    mechanism_param=params,
                )
            except UserNotLoggedIn:
                return self._priv.sign(
                    data,
                    mechanism=Mechanism.RSA_PKCS_PSS,
                    mechanism_param=params,
                    pin=pin,
                )

        raise ValueError("Unsupported signing padding (expect PKCS1v15 or PSS).")

    # --- Decrypt ---
    def decrypt(self, ciphertext: bytes, padding):
        """
        Supports:
            - RSAES-PKCS1 v1.5
            - RSAES-OAEP (SHA1/224/256/384/512) if supported by the HSM / token
        """
        from pkcs11 import Mechanism
        from pkcs11.util.rsa import RsaOaepParams
        from pkcs11.exceptions import UserNotLoggedIn

        pin = self._user_pin or None

        if isinstance(padding, asym_padding.PKCS1v15):
            try:
                return self._priv.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS, pin=pin)
            except TypeError:
                return self._priv.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS)
            except UserNotLoggedIn:
                return self._priv.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS, pin=pin)

        if isinstance(padding, asym_padding.OAEP):
            hash_algo = getattr(padding._mgf, "_algorithm", None)
            hash_map = {
                hashes.SHA1: Mechanism.SHA_1,
                hashes.SHA224: Mechanism.SHA224,
                hashes.SHA256: Mechanism.SHA256,
                hashes.SHA384: Mechanism.SHA384,
                hashes.SHA512: Mechanism.SHA512,
            }
            mech_hash = hash_map.get(type(hash_algo))
            if mech_hash is None:
                raise ValueError("OAEP hash not supported by the HSM")

            params = RsaOaepParams(mech_hash, mech_hash, None)

            try:
                return self._priv.decrypt(
                    ciphertext,
                    mechanism=Mechanism.RSA_PKCS_OAEP,
                    mechanism_param=params,
                    pin=pin,
                )
            except TypeError:
                return self._priv.decrypt(
                    ciphertext,
                    mechanism=Mechanism.RSA_PKCS_OAEP,
                    mechanism_param=params,
                )
            except UserNotLoggedIn:
                return self._priv.decrypt(
                    ciphertext,
                    mechanism=Mechanism.RSA_PKCS_OAEP,
                    mechanism_param=params,
                    pin=pin,
                )

        raise ValueError("Unsupported decryption padding (expect PKCS1v15 or OAEP).")

    # --- Non exportable ---
    def private_numbers(self):  # type: ignore[override]
        raise TypeError("Non-exportable key (HSM).")

    def private_bytes(self, *args, **kwargs):  # type: ignore[override]
        raise TypeError("Non-exportable key (HSM).")

    # --- Context / teardown ---
    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "HSMRSAPrivateKey":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --- Helpers ---
    def token_info(self) -> Dict[str, Any]:
        """
        Return a few useful, non-sensitive token details (manufacturer, model, serial…).
        Compatible with token.info/token.token_info variants.
        """
        try:
            info = _get_token_info(self._token)
            if info is None:
                return {}
            return {
                "label": _ti_get(info, "label", default=""),
                "manufacturer_id": _ti_get(info, "manufacturer_id", "manufacturerID", default=""),
                "model": _ti_get(info, "model", default=""),
                "serial_number": _ti_get(info, "serial_number", "serialNumber", "serial", default=""),
                "flags": int(getattr(info, "flags", 0) or 0),
            }
        except Exception:
            return {}
