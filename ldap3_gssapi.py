"""SASL/GSSAPI Sign/Seal for ldap3's synchronous Connection (including 2.9.1).

RFC 4752 security layer negotiation + 4-byte length-prefixed GSS-wrapped
LDAP messages. Does not patch ldap3 globally and does not use TLS or subprocess.

Only this application's synchronous connection is supported. Require a signed
layer at minimum; prefer confidentiality whenever AD offers it. No auth-only
fallback, even if the DC offers it.
"""

import logging

import gssapi
from ldap3 import Connection, KERBEROS, SASL
from ldap3.protocol.sasl.sasl import send_sasl_negotiation

log = logging.getLogger(__name__)

SASL_NONE = 0x01
SASL_SIGN = 0x02
SASL_SEAL = 0x04
MAX_SASL_TOKEN = (1 << 24) - 1
# Limit the size of an incoming wrapped token to 64 KiB. Larger LDAP replies
# are transmitted in multiple SASL records; this is NOT a limit on LDAP size.
CLIENT_MAX_TOKEN = 65536
MAX_GSS_ROUNDS = 16


class SASLProtectionError(OSError):
    """GSSAPI negotiation, record framing or message protection failed."""


def _flag_set(ctx, flag):
    return flag in set(ctx.actual_flags)


def _parse_offer(offer, ctx):
    """Return (layer, server_max_token) from signed RFC 4752 offer."""
    if not isinstance(offer, bytes) or len(offer) != 4:
        raise SASLProtectionError("Invalid SASL/GSSAPI security-layer offer")
    supported = offer[0]
    max_token = int.from_bytes(offer[1:4], 'big')
    if supported & ~(SASL_NONE | SASL_SIGN | SASL_SEAL):
        raise SASLProtectionError("Unsupported GSSAPI security-layer bits")
    if supported == SASL_NONE and max_token != 0:
        raise SASLProtectionError("Invalid authentication-only SASL buffer size")
    if supported & (SASL_SIGN | SASL_SEAL) and not max_token:
        raise SASLProtectionError("Server offered SASL protection without a buffer size")
    if supported & SASL_SEAL and _flag_set(ctx, gssapi.RequirementFlag.confidentiality):
        return SASL_SEAL, max_token
    if supported & SASL_SIGN:
        return SASL_SIGN, max_token
    raise SASLProtectionError("Server does not offer usable SASL Sign/Seal")


class GSSAPIProtectedSocket:
    """Socket facade: LDAP BER in/out; GSSAPI SASL records on the wire.

    The synchronous ldap3 strategy uses socket.sendall() and socket.recv().
    Buffering decrypted bytes inside recv() makes this work even when TCP
    fragments/coalesces records or LDAP messages span multiple GSSAPI tokens.
    """

    def __init__(self, sock, context, layer, server_max_token, client_max_token=CLIENT_MAX_TOKEN):
        if layer not in (SASL_SIGN, SASL_SEAL):
            raise SASLProtectionError("Refusing unprotected SASL socket")
        if not 0 < server_max_token <= MAX_SASL_TOKEN:
            raise SASLProtectionError("Invalid server SASL token limit")
        if not 0 < client_max_token <= MAX_SASL_TOKEN:
            raise SASLProtectionError("Invalid client SASL token limit")
        if not context.complete or not _flag_set(context, gssapi.RequirementFlag.integrity):
            raise SASLProtectionError("GSSAPI context does not provide integrity")
        self._sock = sock
        self._context = context
        self._encrypted = layer == SASL_SEAL
        self._server_max = server_max_token
        self._client_max = client_max_token
        self._plain_buffer = bytearray()
        self._failed = False
        self._max_plain = context.get_wrap_size_limit(server_max_token, encrypted=self._encrypted)
        if not isinstance(self._max_plain, int) or self._max_plain <= 0:
            raise SASLProtectionError("GSSAPI cannot wrap messages at server buffer size")
        self._max_plain = min(self._max_plain, CLIENT_MAX_TOKEN)

    _DELEGATED = frozenset((
        "fileno", "getpeername", "getsockname", "settimeout", "gettimeout",
        "setblocking", "getblocking", "shutdown", "close", "family",
        "type", "proto", "getsockopt", "setsockopt",
    ))

    def __getattr__(self, name):
        # Never expose raw send/recv_into/makefile via __getattr__. A future
        # ldap3 strategy must fail rather than accidentally bypass SASL.
        if name not in self._DELEGATED:
            raise AttributeError(name)
        return getattr(self._sock, name)

    def _fail_closed(self):
        self._failed = True
        self._plain_buffer.clear()
        try:
            self._sock.close()
        except OSError:
            pass

    def sendall(self, data, flags=0):
        if self._failed:
            raise SASLProtectionError("SASL-protected socket is unusable")
        try:
            if flags:
                raise SASLProtectionError("Socket flags are unsupported with SASL")
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise TypeError("A bytes-like LDAP message is required")
            data = bytes(data)
            for i in range(0, len(data), self._max_plain):
                chunk = data[i:i + self._max_plain]
                wrapped = self._context.wrap(chunk, encrypt=self._encrypted)
                if bool(wrapped.encrypted) != self._encrypted:
                    raise SASLProtectionError("GSSAPI wrap did not honor negotiated Sign/Seal")
                token = wrapped.message
                if not token or len(token) > self._server_max:
                    raise SASLProtectionError("GSSAPI output exceeds server's SASL token limit")
                self._sock.sendall(len(token).to_bytes(4, 'big') + token)
        except Exception as exc:
            self._fail_closed()
            if isinstance(exc, SASLProtectionError):
                raise
            raise SASLProtectionError("Failed to send protected SASL message") from exc

    def _read_exact(self, needed):
        parts = []
        while needed:
            data = self._sock.recv(needed)
            if not data:
                raise SASLProtectionError("Unexpected EOF in protected SASL record")
            parts.append(data)
            needed -= len(data)
        return b''.join(parts)

    def recv(self, bufsize, flags=0):
        if self._failed:
            raise SASLProtectionError("SASL-protected socket is unusable")
        try:
            if flags:
                raise SASLProtectionError("Socket flags are unsupported with SASL")
            if bufsize <= 0:
                return b''
            if not self._plain_buffer:
                token_size = int.from_bytes(self._read_exact(4), 'big')
                if not 0 < token_size <= self._client_max:
                    raise SASLProtectionError("Invalid or oversized incoming SASL record")
                unwrapped = self._context.unwrap(self._read_exact(token_size))
                # GSSAPI verifies the MIC and replay/sequence protection. The
                # encrypted flag prevents downgrading sealed messages.
                if bool(unwrapped.encrypted) != self._encrypted:
                    raise SASLProtectionError("GSSAPI peer violated negotiated Sign/Seal")
                if not unwrapped.message:
                    raise SASLProtectionError("Empty protected LDAP record")
                self._plain_buffer.extend(unwrapped.message)
            data = bytes(self._plain_buffer[:bufsize])
            del self._plain_buffer[:bufsize]
            return data
        except Exception as exc:
            self._fail_closed()
            if isinstance(exc, SASLProtectionError):
                raise
            raise SASLProtectionError("Failed to receive verified SASL message") from exc


class ProtectedKerberosConnection(Connection):
    """ldap3 Connection with per-instance RFC 4752 Sign/Seal negotiation."""

    def do_sasl_bind(self, controls):
        if self.authentication != SASL or self.sasl_mechanism != KERBEROS:
            raise SASLProtectionError("Only Kerberos SASL is allowed")
        if not self.strategy.sync or self.strategy.pooled or self.strategy.no_real_dsa:
            raise SASLProtectionError("Only ldap3 synchronous socket strategy is supported")
        if self.sasl_in_progress:
            raise SASLProtectionError("SASL bind already in progress")
        params = self.sasl_credentials or ()
        if len(params) != 3 or params[0] != self.server.host or params[2] is None:
            raise SASLProtectionError("Expected explicit credentials and the target DC FQDN")
        if params[1] is not None and not isinstance(params[1], str):
            raise SASLProtectionError("Invalid authorization identity")

        self.sasl_in_progress = True
        try:
            raw_creds = params[2]
            creds = gssapi.Credentials(base=raw_creds, usage='initiate')
            target = gssapi.Name('ldap@' + self.server.host,
                                 name_type=gssapi.NameType.hostbased_service)
            flags = [
                gssapi.RequirementFlag.mutual_authentication,
                gssapi.RequirementFlag.integrity,
                gssapi.RequirementFlag.out_of_sequence_detection,
                gssapi.RequirementFlag.replay_detection,
                gssapi.RequirementFlag.confidentiality,
            ]
            ctx = gssapi.SecurityContext(name=target, mech=gssapi.MechType.kerberos,
                                         creds=creds, flags=flags, usage='initiate')
            token = None
            for _ in range(MAX_GSS_ROUNDS):
                output = ctx.step(token)
                result = send_sasl_negotiation(self, controls, output or b'')
                if result.get('result') not in (0, 14):
                    raise SASLProtectionError('LDAP server rejected GSSAPI context establishment')
                token = result.get('saslCreds')
                if ctx.complete:
                    break
                if not token or result['result'] != 14:
                    raise SASLProtectionError('Incomplete GSSAPI context without server challenge')
            else:
                raise SASLProtectionError('Too many GSSAPI negotiation rounds')

            required = (
                gssapi.RequirementFlag.mutual_authentication,
                gssapi.RequirementFlag.integrity,
                gssapi.RequirementFlag.out_of_sequence_detection,
                gssapi.RequirementFlag.replay_detection,
            )
            if not all(_flag_set(ctx, flag) for flag in required):
                raise SASLProtectionError('GSSAPI context lacks mutual authentication/integrity/sequence')
            if not token:
                raise SASLProtectionError('Missing signed GSSAPI server security-layer offer')
            server_offer = ctx.unwrap(token)
            if server_offer.encrypted:
                raise SASLProtectionError('Expected a signed, not encrypted, SASL offer')
            layer, server_max = _parse_offer(server_offer.message, ctx)
            # The layer-negotiation message itself is always signed, never
            # encrypted, even when the application data will be sealed.
            authz_id = (params[1] or '').encode('utf-8')
            client_offer = bytes((layer,)) + CLIENT_MAX_TOKEN.to_bytes(3, 'big') + authz_id
            response = ctx.wrap(client_offer, encrypt=False)
            if response.encrypted:
                raise SASLProtectionError('Expected signed, not encrypted, SASL selection')
            final_result = send_sasl_negotiation(self, controls, response.message)
            if final_result.get('result') != 0:
                raise SASLProtectionError('LDAP server rejected signed GSSAPI layer selection')

            # The final bindResponse has been consumed in the clear, as the
            # protocol requires. Install the socket facade BEFORE any search.
            self.socket = GSSAPIProtectedSocket(self.socket, ctx, layer, server_max)
            self.gssapi_security_layer = 'seal' if layer == SASL_SEAL else 'sign'
            if layer == SASL_SEAL:
                log.info('LDAP %s:389: SASL/GSSAPI Seal negotiated', self.server.host)
            else:
                log.warning('LDAP %s:389: SASL/GSSAPI Sign only; LDAP data is not encrypted',
                            self.server.host)
            return final_result
        except BaseException:
            # Never leave a successful bind with a raw/unprotected socket.
            # A new bind must use a fresh connection.
            try:
                self.strategy.close()
            except Exception:
                pass
            raise
        finally:
            self.sasl_in_progress = False
