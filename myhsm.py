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
- Robust key lookup:
  * Try PRIVATE_KEY by id/label
  * Try multiple CKA_ID encodings (binary vs ASCII-hex, upper/lower)
  * Fallback via PUBLIC_KEY to derive the right CKA_ID
  * Final full-scan match (IDs/labels)
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
        lib_path="/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so.1",
        token_label="CA-TOKEN",
        user_pin="123456",
        key_label="CA-KEY",               # or key_id="34633630..." (CKA_ID hex string)
        # slot_index=0,                   # optional vendor quirk
    )

    sig = key.sign(b"hello", P.PKCS1v15(), hashes.SHA256())
"""

from __future__ import annotations

import binascii
import ctypes
from typing import Optional, Union, Dict, Any, Iterable, List

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


class HSMRSAPrivateKey(rsa.RSAPrivateKey):
    """
    Implements the cryptography RSAPrivateKey interface delegating operations to the HSM via PKCS#11.
    Never exposes the private key material (private_numbers/private_bytes -> TypeError).
    """

    # ---------------- Construction ---------------- #

    def __init__(
        self,
        lib_path: str,
        token_label: Optional[str] = None,
        user_pin: Optional[str] = None,
        *,
        key_label: Optional[str] = None,
        key_id: Optional[Union[bytes, str]] = None,
        slot_index: Optional[int] = None,
        rw: bool = True,
        login_on_init: bool = True,
    ) -> None:
        """
        Args:
            lib_path: path to the PKCS#11 library (.so/.dylib/.dll) for the HSM/TPM.
            token_label: label of the token to open.
            user_pin: user PIN (CKU_USER). If provided, a login is attempted.
            key_label: label (CKA_LABEL) of the private key to retrieve.
            key_id: identifier (CKA_ID) of the private key:
                    - bytes (raw)
                    - or hex string "A1B2...", with or without ':' / spaces
            slot_index: optional index to select a slot explicitly (vendor quirk).
            rw: open the session read/write (often required).
            login_on_init: perform CKU_USER login during initialization (best-effort).

        Raises:
            HSMError on PKCS#11 failures or key resolution issues.
        """
        # Late import to avoid hard dependency for importers of this module
        try:
            import pkcs11
            from pkcs11 import Attribute, ObjectClass, UserType
        except Exception as e:
            raise HSMError(f"python-pkcs11 not found or invalid: {e}") from e

        self._Attribute = Attribute
        self._ObjectClass = ObjectClass
        self._UserType = UserType
        self._backend = default_backend()

        if not token_label:
            raise ValueError("token_label is required")

        if not (key_label or key_id):
            raise ValueError("Provide key_label or key_id (CKA_ID) to select the key")

        # Keep original key_id string (if any) for alternative encodings
        original_key_id_str: Optional[str] = None
        if isinstance(key_id, str):
            original_key_id_str = key_id.strip()
            # normalize: remove separators then decode hex → raw bytes
            cleaned = original_key_id_str.replace(":", "").replace(" ", "")
            try:
                key_id = binascii.unhexlify(cleaned)
            except Exception as e:
                raise ValueError(f"Invalid hex key_id: {original_key_id_str!r}") from e

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

        # 2) Locate the token
        try:
            if slot_index is not None:
                try:
                    slots = list(self._pkcs11.get_slots())
                    if not (0 <= slot_index < len(slots)):
                        raise HSMError(f"slot_index out of range (got {slot_index}, have {len(slots)} slots)")
                    tok = slots[slot_index].get_token()
                    if (tok.token_info.label or "").strip() != (token_label or "").strip():
                        self._token = self._pkcs11.get_token(token_label=token_label)
                    else:
                        self._token = tok
                except Exception:
                    self._token = self._pkcs11.get_token(token_label=token_label)
            else:
                self._token = self._pkcs11.get_token(token_label=token_label)
        except Exception as e:
            raise HSMError(f"Token not found (label={token_label!r}): {e}") from e

        # 3) Open a session (first try: with possible implicit login)
        self._user_pin = (user_pin or "")
        try:
            self._session = self._token.open(
                rw=rw,
                user_pin=(self._user_pin if (login_on_init and self._user_pin) else None)
            )
        except Exception as e:
            raise HSMError(f"Cannot open PKCS#11 session: {e}") from e

        # 4) Optional explicit login (best-effort; many builds lack Session.login)
        if login_on_init and self._user_pin:
            self._login_user()

        # 5) Resolve the key (private → fallbacks)
        self._priv = None

        # Build candidate encodings for CKA_ID, to cover vendor differences
        id_candidates: List[bytes] = []
        if isinstance(key_id, (bytes, bytearray)):
            raw = bytes(key_id)
            # a) raw bytes
            id_candidates.append(raw)
            # b) ASCII hex of those bytes (lower + upper)
            ascii_hex = binascii.hexlify(raw)            # b'3463...'
            id_candidates.append(ascii_hex)
            id_candidates.append(ascii_hex.upper())
        if original_key_id_str:
            # c) ASCII as provided (no separators) lower/upper
            cleaned = original_key_id_str.replace(":", "").replace(" ", "")
            id_candidates.append(cleaned.encode("ascii"))
            id_candidates.append(cleaned.upper().encode("ascii"))

        # 5.1 First attempt: by id candidates then by label
        self._priv = self._try_find_private_by_ids(id_candidates) or \
                     (self._find_one(object_class=self._ObjectClass.PRIVATE_KEY, label=key_label) if key_label else None)

        # 5.2 If not found and we have a PIN, some modules ignored login on first open():
        if self._priv is None and self._user_pin:
            try:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = self._token.open(rw=rw, user_pin=self._user_pin)
                self._priv = self._try_find_private_by_ids(id_candidates) or \
                             (self._find_one(object_class=self._ObjectClass.PRIVATE_KEY, label=key_label) if key_label else None)
            except Exception:
                pass

        # 5.3 Fallback: via PUBLIC_KEY → derive CKA_ID → search PRIVATE_KEY by that id
        if self._priv is None:
            kid_from_pub = None
            pub = None
            if key_label:
                pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, label=key_label)
            if pub is None and id_candidates:
                for cid in id_candidates:
                    pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, id=cid)
                    if pub:
                        break
            if pub is not None:
                kid_from_pub = _attr(pub, self._Attribute.ID, None)
            if kid_from_pub is not None:
                self._priv = self._find_one(object_class=self._ObjectClass.PRIVATE_KEY, id=kid_from_pub)

        # 5.4 FINAL TRY: full scan of PRIVATE_KEY objects, match by label or by any candidate ID
        if self._priv is None:
            try:
                it = self._session.get_objects({self._Attribute.CLASS: self._ObjectClass.PRIVATE_KEY})
                all_privs = list(it)
            except Exception:
                all_privs = []
            # rebuild candidate set with variants (lower/upper and hex-of-bytes)
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
                    olabel = _attr(o, self._Attribute.LABEL, "")
                    if isinstance(olabel, bytes):
                        olabel = olabel.decode("utf-8", "ignore")
                    if key_label and olabel == key_label:
                        self._priv = o
                        break
                    oid_b = oid.encode("ascii", "ignore") if isinstance(oid, str) else bytes(oid or b"")
                    if (oid_b in cand_ids) or (binascii.hexlify(oid_b) in cand_ids) or (oid_b.upper() in cand_ids) or (oid_b.lower() in cand_ids):
                        self._priv = o
                        break
                except Exception:
                    continue

        if self._priv is None:
            self.close()
            target = None
            if isinstance(key_id, (bytes, bytearray)):
                target = f"id={binascii.hexlify(key_id).decode()}"
            elif original_key_id_str:
                target = f"id={original_key_id_str}"
            elif key_label:
                target = f"label={key_label!r}"
            else:
                target = "<?>"
            raise HSMError(
                f"Private key not found ({target}). "
                f"Confirm with tpm2_ptool listobjects / pkcs11-tool --list-objects "
                f"(check CKA_LABEL/CKA_ID and that the session is USER-authenticated)."
            )

        # 6) Retrieve public key: prefer separate PUBLIC_KEY object by CKA_ID; fallback to private attrs
        try:
            kid = _attr(self._priv, self._Attribute.ID, None)
            pub = None
            if kid is not None:
                pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, id=kid)
            if pub is None and key_label:
                pub = self._find_one(object_class=self._ObjectClass.PUBLIC_KEY, label=key_label)

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
            # Normalize to explicit Attribute.* keys (python-pkcs11 expects this on some builds)
            q = {}
            for k, v in attrs.items():
                if k in ("object_class", "class"):
                    q[self._Attribute.CLASS] = v
                elif k == "id":
                    if isinstance(v, str):
                        v = v.encode("ascii", "strict")
                    q[self._Attribute.ID] = v
                elif k == "label":
                    if isinstance(v, bytes):
                        v = v.decode("utf-8", "ignore")
                    q[self._Attribute.LABEL] = v
                else:
                    q[k] = v

            it = self._session.get_objects(q)

            # Return first match; drain iterator to avoid buggy __del__ warnings
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
            - RSASSA-PSS (SHA256/384/512) if supported by the HSM
        """
        # Local import (keeps top-level deps light and avoids storing Mechanism on self)
        from pkcs11 import Mechanism

        self._context_login_if_needed()

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
            return self._priv.sign(data, mechanism=mech)

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
            return self._priv.sign(data, mechanism=Mechanism.RSA_PKCS_PSS, mechanism_param=params)

        raise ValueError("Unsupported signing padding (expect PKCS1v15 or PSS).")

    # --- Decrypt ---
    def decrypt(self, ciphertext: bytes, padding):
        """
        Supports:
            - RSAES-PKCS1 v1.5
            - RSAES-OAEP (SHA1/224/256/384/512) if supported by the HSM
        """
        from pkcs11 import Mechanism
        from pkcs11.util.rsa import RsaOaepParams

        self._context_login_if_needed()

        if isinstance(padding, asym_padding.PKCS1v15):
            return self._priv.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS)

        if isinstance(padding, asym_padding.OAEP):
            # cryptography stores OAEP hash on padding._mgf._algorithm
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
            params = RsaOaepParams(mech_hash, mech_hash, None)  # label=None, MGF1(hash)
            return self._priv.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=params)

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
        """
        try:
            info = self._token.token_info
            return {
                "label": (info.label or "").strip(),
                "manufacturer_id": (info.manufacturer_id or "").strip(),
                "model": (info.model or "").strip(),
                "serial_number": (info.serial_number or "").strip(),
                "flags": int(info.flags),
            }
        except Exception:
            return {}

