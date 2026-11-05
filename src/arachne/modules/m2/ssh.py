"""SSH credential authentication for the credentialed host checks (WP-20, REQ-CREDS-006).

``m2.smb-auth`` established the split this check follows: the *module* owns the protocol, the
*broker* owns the secret. ``m2.ssh-auth`` is the SSH half — the gap the archive recorded as
"designed, not implemented" — and it obeys the same three rules:

* the credential never enters the check: :class:`SshAuthenticator` is called by the broker with
  a username and one secret, performs one exchange, and returns a verdict;
* every byte goes through the scan's :class:`~arachne.core.net.ScopedNetClient`, so the scope
  gate, the address policy, the airgap, the rate limiter and the ``net.probe`` audit line all
  apply — an out-of-scope host is refused by ``_authorize`` **before** a socket is opened;
* nothing that could carry the secret is logged: the verdict carries a status name, never a
  password, a private key or a signature.

The protocol profile is deliberately narrow and modern, because a narrow profile is one a
reader can check: ``curve25519-sha256`` key exchange (RFC 8731), an ``ssh-ed25519`` host key,
``aes128-ctr`` with ``hmac-sha2-256``, no compression, and the ``publickey`` and ``password``
user-auth methods. The primitives are pure Python — X25519 (RFC 7748) and AES-128 (FIPS-197),
both pinned by published test vectors in ``tests/unit/test_ssh_wire.py`` — and Ed25519 is the
module the trust layer already ships (RFC 8032), not a second implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

from arachne.core.ed25519 import KEY_SIZE as ED25519_KEY_SIZE
from arachne.core.ed25519 import SIGNATURE_SIZE as ED25519_SIGNATURE_SIZE
from arachne.core.ed25519 import derive_public_key
from arachne.core.ed25519 import sign as ed25519_sign
from arachne.core.ed25519 import verify as ed25519_verify
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = [
    "AES_BLOCK_SIZE",
    "CLIENT_VERSION",
    "HOST_KEY_ALGORITHM",
    "SshAuth",
    "SshAuthenticator",
    "aes128_encrypt_block",
    "expand_aes128_key",
    "x25519",
]

#: The algorithms this build offers, in preference order. One of each: a profile that can be
#: read against the RFC in a minute is worth more than a long list nobody audits.
KEX_ALGORITHM = "curve25519-sha256"
HOST_KEY_ALGORITHM = "ssh-ed25519"
CIPHER = "aes128-ctr"
MAC = "hmac-sha2-256"
COMPRESSION = "none"
#: The version string ARACHNE presents. It identifies the tool, not the operator.
CLIENT_VERSION = "SSH-2.0-Arachne_0.1"

AES_BLOCK_SIZE = 16
_SHA256_SIZE = 32
_MAC_SIZE = 32
_MAX_PACKET = 256 * 1024

# --- message numbers (RFC 4253 §12) ---------------------------------------
SSH_MSG_DISCONNECT = 1
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)


# --------------------------------------------------------------------------- X25519


_P25519 = 2**255 - 19
_A24 = 121665


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """``X25519(scalar, u)`` — RFC 7748 §5, Montgomery ladder over 2^255-19.

    The scalar is clamped as §5 requires, so a caller cannot accidentally use an
    unclamped key; the u-coordinate's high bit is masked, which is what makes the function
    accept an encoded point as-is.
    """
    if len(scalar) != 32 or len(u_coordinate) != 32:
        msg = "an X25519 scalar and u-coordinate are each 32 bytes"
        raise ValueError(msg)
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    x1 = int.from_bytes(u_coordinate, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for bit in reversed(range(255)):
        current = (n >> bit) & 1
        swap ^= current
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = current
        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519
        x3 = (da + cb) % _P25519
        x3 = x3 * x3 % _P25519
        z3 = (da - cb) % _P25519
        z3 = z3 * z3 % _P25519
        z3 = z3 * x1 % _P25519
        x2 = aa * bb % _P25519
        z2 = e * (aa + _A24 * e) % _P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P25519 - 2, _P25519) % _P25519).to_bytes(32, "little")


# --------------------------------------------------------------------------- AES-128


def _build_sbox() -> tuple[int, ...]:
    """The AES S-box, generated from its definition rather than transcribed."""
    sbox = [0] * 256
    p = q = 1
    while True:
        # p walks the multiplicative group by multiplying by 3 in GF(2^8)…
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # …and q walks it backwards, so q is the inverse of p.
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        rotated = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6))
        rotated ^= ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (rotated ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return tuple(sbox)


_SBOX = _build_sbox()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x1B) & 0xFF if value & 0x100 else value


def expand_aes128_key(key: bytes) -> tuple[tuple[int, ...], ...]:
    """The eleven 16-byte round keys of an AES-128 key schedule (FIPS-197 §5.2)."""
    if len(key) != 16:
        msg = "an AES-128 key is 16 bytes"
        raise ValueError(msg)
    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = list(words[index - 1])
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[byte] for byte in temp]
            temp[0] ^= _RCON[index // 4 - 1]
        words.append([words[index - 4][position] ^ temp[position] for position in range(4)])
    return tuple(
        tuple(byte for word in words[index : index + 4] for byte in word)
        for index in range(0, 44, 4)
    )


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """One AES-128 block encryption (FIPS-197 §5.1)."""
    return _encrypt_with_schedule(expand_aes128_key(key), block)


def _encrypt_with_schedule(round_keys: tuple[tuple[int, ...], ...], block: bytes) -> bytes:
    """Encrypt one block with an expanded schedule (the counter mode's hot path)."""
    if len(block) != AES_BLOCK_SIZE:
        msg = "an AES block is 16 bytes"
        raise ValueError(msg)
    state = [
        block[row + 4 * column] ^ round_keys[0][row + 4 * column]
        for column in range(4)
        for row in range(4)
    ]
    for round_index in range(1, 11):
        state = [_SBOX[byte] for byte in state]
        state = _shift_rows(state)
        if round_index != 10:
            state = _mix_columns(state)
        state = [
            state[position] ^ round_keys[round_index][position]
            for position in range(AES_BLOCK_SIZE)
        ]
    return bytes(state)


def _shift_rows(state: list[int]) -> list[int]:
    """Column-major state: row ``r`` rotates left by ``r``."""
    out = list(state)
    for row in range(4):
        for column in range(4):
            out[row + 4 * column] = state[row + 4 * ((column + row) % 4)]
    return out


def _mix_columns(state: list[int]) -> list[int]:
    out = list(state)
    for column in range(4):
        a = state[4 * column : 4 * column + 4]
        total = a[0] ^ a[1] ^ a[2] ^ a[3]
        out[4 * column] = a[0] ^ total ^ _xtime(a[0] ^ a[1])
        out[4 * column + 1] = a[1] ^ total ^ _xtime(a[1] ^ a[2])
        out[4 * column + 2] = a[2] ^ total ^ _xtime(a[2] ^ a[3])
        out[4 * column + 3] = a[3] ^ total ^ _xtime(a[3] ^ a[0])
    return out


class _CtrCipher:
    """AES-128 in counter mode, as SSH uses it (RFC 4344 §1): a 16-byte counter, big-endian."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(iv) != AES_BLOCK_SIZE:
            msg = "an AES-CTR IV is 16 bytes"
            raise ValueError(msg)
        self._round_keys = expand_aes128_key(key)
        self._counter = int.from_bytes(iv, "big")
        #: Unused keystream from the last block. AES-CTR is a continuous stream, and the SSH
        #: packet layer genuinely splits it: the four-byte length field is read before the
        #: body is, so the cipher has to carry the remainder of a block across calls. A
        #: counter that advanced per *call* instead of per *block* would decrypt every packet
        #: wrongly from the fifth byte onward.
        self._keystream = b""

    def transform(self, data: bytes) -> bytes:
        out = bytearray()
        index = 0
        while index < len(data):
            if not self._keystream:
                block = self._counter.to_bytes(AES_BLOCK_SIZE, "big")
                self._counter = (self._counter + 1) % (1 << 128)
                self._keystream = _encrypt_with_schedule(self._round_keys, block)
            take = min(len(data) - index, len(self._keystream))
            chunk = data[index : index + take]
            out.extend(left ^ right for left, right in zip(chunk, self._keystream, strict=False))
            self._keystream = self._keystream[take:]
            index += take
        return bytes(out)


# --------------------------------------------------------------------------- wire helpers


def _uint32(value: int) -> bytes:
    return struct.pack(">I", value)


def _string(value: bytes) -> bytes:
    return _uint32(len(value)) + value


def _text(value: str) -> bytes:
    return _string(value.encode("utf-8"))


def _read_uint32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack(">I", data[offset : offset + 4])[0], offset + 4


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _read_uint32(data, offset)
    return data[offset : offset + length], offset + length


def _mpint(value: int) -> bytes:
    """A non-negative integer in RFC 4251 ``mpint`` form."""
    if value == 0:
        return _uint32(0)
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _string(encoded)


def _name_list(names: tuple[str, ...]) -> bytes:
    return _text(",".join(names))


class SshProtocolError(Exception):
    """The peer did not speak the profile this build offers, or spoke it illegibly."""


@dataclass(slots=True)
class KexInit:
    """The negotiated half of a peer's KEXINIT that this build reads."""

    kex: tuple[str, ...]
    host_keys: tuple[str, ...]
    ciphers_client_to_server: tuple[str, ...]
    ciphers_server_to_client: tuple[str, ...]
    macs_client_to_server: tuple[str, ...]
    macs_server_to_client: tuple[str, ...]
    compressions_client_to_server: tuple[str, ...]
    compressions_server_to_client: tuple[str, ...]
    first_kex_packet_follows: bool


def parse_kexinit(payload: bytes) -> KexInit:
    """Parse an ``SSH_MSG_KEXINIT`` payload (RFC 4253 §7.1)."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        msg = "not a KEXINIT"
        raise SshProtocolError(msg)
    offset = 1 + 16  # message number + cookie
    lists: list[tuple[str, ...]] = []
    for _ in range(10):
        raw, offset = _read_string(payload, offset)
        lists.append(tuple(name for name in raw.decode("ascii", "replace").split(",") if name))
    follows = payload[offset] != 0
    return KexInit(
        kex=lists[0],
        host_keys=lists[1],
        ciphers_client_to_server=lists[2],
        ciphers_server_to_client=lists[3],
        macs_client_to_server=lists[4],
        macs_server_to_client=lists[5],
        compressions_client_to_server=lists[6],
        compressions_server_to_client=lists[7],
        first_kex_packet_follows=follows,
    )


def build_kexinit(cookie: bytes) -> bytes:
    """The client's KEXINIT, offering exactly one algorithm of each kind."""
    return b"".join(
        (
            bytes([SSH_MSG_KEXINIT]),
            cookie,
            _name_list((KEX_ALGORITHM,)),
            _name_list((HOST_KEY_ALGORITHM,)),
            _name_list((CIPHER,)),
            _name_list((CIPHER,)),
            _name_list((MAC,)),
            _name_list((MAC,)),
            _name_list((COMPRESSION,)),
            _name_list((COMPRESSION,)),
            _name_list(()),
            _name_list(()),
            b"\x00",
            _uint32(0),
        )
    )


def ed25519_host_key(public_key: bytes) -> bytes:
    """The ``ssh-ed25519`` public-key blob: algorithm name then the 32-byte key."""
    return _text(HOST_KEY_ALGORITHM) + _string(public_key)


def ed25519_signature_blob(signature: bytes) -> bytes:
    """The outer ``string`` an SSH signature field carries: algorithm then the raw signature."""
    return _string(_text(HOST_KEY_ALGORITHM) + _string(signature))


# --------------------------------------------------------------------------- the client


class SshSession:
    """One SSH transport: version exchange, key exchange, NEWKEYS, then user auth.

    It owns the packet layer (framing, padding, sequence numbers, the two cipher states) and
    exposes :meth:`authenticate_publickey` / :meth:`authenticate_password`. Everything it
    reads goes through the :class:`~arachne.core.net.NetStream` the scoped client handed it,
    so this class never opens a socket and cannot bypass the scope gate.
    """

    def __init__(self, stream: Any, *, client_version: str = CLIENT_VERSION) -> None:
        self._stream = stream
        self._client_version = client_version
        self._server_version = ""
        self._buffer = b""
        self._send_sequence = 0
        self._recv_sequence = 0
        self._out_cipher: _CtrCipher | None = None
        self._in_cipher: _CtrCipher | None = None
        self._out_mac: bytes | None = None
        self._in_mac: bytes | None = None
        self.session_id: bytes = b""
        self.host_key: bytes = b""
        self.host_key_verified = False
        self.exchanges = 0
        self._pending_shared = 0
        self._pending_hash = b""
        #: Redacted step records for the finding's evidence — versions, algorithm names and
        #: verdicts only. Nothing here can carry a secret: the password and the signature go
        #: into packets, never into a step record.
        self.steps: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ plumbing
    async def _fill(self) -> None:
        chunk = await self._stream.receive()
        if not chunk:
            msg = "the peer closed the connection"
            raise SshProtocolError(msg)
        self._buffer += chunk

    async def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            await self._fill()
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    async def _read_line(self) -> str:
        while b"\r\n" not in self._buffer:
            if len(self._buffer) > 4096:
                msg = "the peer's version line is longer than 4096 bytes"
                raise SshProtocolError(msg)
            await self._fill()
        line, _, rest = self._buffer.partition(b"\r\n")
        self._buffer = rest
        return line.decode("utf-8", "replace")

    # ------------------------------------------------------------------ packet layer
    def _block_size(self, *, incoming: bool) -> int:
        cipher = self._in_cipher if incoming else self._out_cipher
        return AES_BLOCK_SIZE if cipher is not None else 8

    def _seal(self, payload: bytes) -> bytes:
        block = self._block_size(incoming=False)
        padding = block - ((len(payload) + 1 + 4) % block)
        if padding < 4:
            padding += block
        packet = (
            _uint32(len(payload) + 1 + padding) + bytes([padding]) + payload + os.urandom(padding)
        )
        mac = b""
        if self._out_mac is not None:
            mac = hmac.new(
                self._out_mac, _uint32(self._send_sequence) + packet, hashlib.sha256
            ).digest()
        self._send_sequence += 1
        wire = self._out_cipher.transform(packet) if self._out_cipher is not None else packet
        return wire + mac

    async def _receive_packet(self) -> bytes:
        first = await self._read_exact(4)
        if self._in_cipher is not None:
            first = self._in_cipher.transform(first)
        length = struct.unpack(">I", first)[0]
        if length <= 0 or length > _MAX_PACKET:
            msg = f"the peer sent an implausible packet length ({length})"
            raise SshProtocolError(msg)
        remainder = await self._read_exact(length)
        if self._in_cipher is not None:
            remainder = self._in_cipher.transform(remainder)
        padding = remainder[0]
        mac = b""
        if self._in_mac is not None:
            mac = await self._read_exact(_MAC_SIZE)
            expected = hmac.new(
                self._in_mac, _uint32(self._recv_sequence) + first + remainder, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(mac, expected):
                msg = "the peer's packet MAC did not verify"
                raise SshProtocolError(msg)
        self._recv_sequence += 1
        return remainder[1 : len(remainder) - padding] if padding else remainder[1:]

    async def _send_packet(self, payload: bytes) -> None:
        await self._stream.send(self._seal(payload))

    # ------------------------------------------------------------------ handshake
    async def open(self) -> None:
        """Version exchange, ``curve25519-sha256`` key exchange and NEWKEYS."""
        await self._stream.send(f"{self._client_version}\r\n".encode())
        # RFC 4253 §4.2: the server MAY send other lines before its version line.
        while True:
            line = await self._read_line()
            if line.startswith("SSH-"):
                self._server_version = line
                break
        if not self._server_version.startswith("SSH-2.0-"):
            msg = f"the peer speaks {self._server_version.split('-')[1:2]}, not SSH-2.0"
            raise SshProtocolError(msg)
        self.steps.append(
            {"step": "version", "client": self._client_version, "server": self._server_version}
        )

        client_cookie = os.urandom(16)
        client_kexinit = build_kexinit(client_cookie)
        await self._send_packet(client_kexinit)
        server_kexinit = await self._receive_packet()
        peer = parse_kexinit(server_kexinit)
        for offered, ours, label in (
            (peer.kex, KEX_ALGORITHM, "key exchange"),
            (peer.host_keys, HOST_KEY_ALGORITHM, "host key"),
            (peer.ciphers_client_to_server, CIPHER, "cipher"),
            (peer.ciphers_server_to_client, CIPHER, "cipher"),
            (peer.macs_client_to_server, MAC, "MAC"),
            (peer.macs_server_to_client, MAC, "MAC"),
            (peer.compressions_client_to_server, COMPRESSION, "compression"),
            (peer.compressions_server_to_client, COMPRESSION, "compression"),
        ):
            if ours not in offered:
                msg = (
                    f"the peer offers no {label} this build speaks ({', '.join(offered) or 'none'})"
                )
                raise SshProtocolError(msg)

        private = os.urandom(32)
        public = x25519(private, (9).to_bytes(32, "little"))
        await self._send_packet(bytes([SSH_MSG_KEX_ECDH_INIT]) + _string(public))
        reply = await self._receive_packet()
        if not reply or reply[0] != SSH_MSG_KEX_ECDH_REPLY:
            msg = "the peer did not answer the key-exchange init"
            raise SshProtocolError(msg)
        offset = 1
        host_key, offset = _read_string(reply, offset)
        server_public, offset = _read_string(reply, offset)
        signature, offset = _read_string(reply, offset)
        shared = int.from_bytes(x25519(private, server_public), "little")

        transcript = (
            _text(self._client_version)
            + _text(self._server_version)
            + _string(client_kexinit)
            + _string(server_kexinit)
            + _string(host_key)
            + _string(public)
            + _string(server_public)
            + _mpint(shared)
        )
        exchange_hash = hashlib.sha256(transcript).digest()
        if not self.session_id:
            self.session_id = exchange_hash

        self.host_key = host_key
        self.host_key_verified = self._verify_host_key(host_key, signature, exchange_hash)
        if not self.host_key_verified:
            msg = "the peer's host-key signature did not verify"
            raise SshProtocolError(msg)
        self.steps.append(
            {
                "step": "host_key",
                "algorithm": HOST_KEY_ALGORITHM,
                "fingerprint": hashlib.sha256(host_key).hexdigest()[:32],
                "verified": True,
            }
        )

        self._install_keys(shared, exchange_hash)
        await self._send_packet(bytes([SSH_MSG_NEWKEYS]))
        newkeys = await self._receive_packet()
        if not newkeys or newkeys[0] != SSH_MSG_NEWKEYS:
            msg = "the peer did not acknowledge NEWKEYS"
            raise SshProtocolError(msg)
        self._enable_crypto()

    def _verify_host_key(self, host_key: bytes, signature: bytes, data: bytes) -> bool:
        """Verify the server's signature over the exchange hash, or refuse the host."""
        offset = 0
        algorithm, offset = _read_string(host_key, offset)
        if algorithm.decode("ascii", "replace") != HOST_KEY_ALGORITHM:
            return False
        key, offset = _read_string(host_key, offset)
        if len(key) != ED25519_KEY_SIZE:
            return False
        offset = 0
        signature_algorithm, offset = _read_string(signature, offset)
        if signature_algorithm.decode("ascii", "replace") != HOST_KEY_ALGORITHM:
            return False
        raw, offset = _read_string(signature, offset)
        if len(raw) != ED25519_SIGNATURE_SIZE:
            return False
        return ed25519_verify(key, data, raw)

    def _derive(self, shared: int, exchange_hash: bytes, letter: bytes, length: int) -> bytes:
        material = _mpint(shared) + exchange_hash + letter + self.session_id
        return hashlib.sha256(material).digest()[:length]

    def _install_keys(self, shared: int, exchange_hash: bytes) -> None:
        """Remember the key material until NEWKEYS has been exchanged both ways."""
        self._pending_shared = shared
        self._pending_hash = exchange_hash

    def _enable_crypto(self) -> None:
        """Turn on both directions once NEWKEYS has been read (RFC 4253 §7.3).

        Nothing is sent between the client's NEWKEYS and the server's, so enabling both
        directions here is equivalent to the per-direction rule the RFC states — and it keeps
        the two cipher states from being installed at different points in the exchange.
        """
        shared_value = self._pending_shared
        digest = self._pending_hash
        self._out_cipher = _CtrCipher(
            self._derive(shared_value, digest, b"C", 16),
            self._derive(shared_value, digest, b"A", 16),
        )
        self._in_cipher = _CtrCipher(
            self._derive(shared_value, digest, b"D", 16),
            self._derive(shared_value, digest, b"B", 16),
        )
        self._out_mac = self._derive(shared_value, digest, b"E", _SHA256_SIZE)
        self._in_mac = self._derive(shared_value, digest, b"F", _SHA256_SIZE)

    # ------------------------------------------------------------------ user auth
    async def _service(self, name: str) -> None:
        await self._send_packet(bytes([SSH_MSG_SERVICE_REQUEST]) + _text(name))
        reply = await self._receive_packet()
        self.exchanges += 1
        if not reply or reply[0] != SSH_MSG_SERVICE_ACCEPT:
            msg = f"the peer refused the {name} service"
            raise SshProtocolError(msg)

    async def _read_auth_reply(self) -> tuple[str, str]:
        """Read until SUCCESS or FAILURE, returning ``(status, detail)``."""
        while True:
            reply = await self._receive_packet()
            self.exchanges += 1
            if not reply:
                self.steps.append({"step": "userauth", "status": "NO_REPLY"})
                return ("NO_REPLY", "the peer sent an empty packet")
            kind = reply[0]
            if kind == SSH_MSG_USERAUTH_SUCCESS:
                self.steps.append({"step": "userauth", "status": "SUCCESS"})
                return ("SUCCESS", "the peer accepted the credential")
            if kind == SSH_MSG_USERAUTH_FAILURE:
                offset = 1
                methods, offset = _read_string(reply, offset)
                partial = reply[offset] if offset < len(reply) else 0
                offered = methods.decode("ascii", "replace") or "none"
                detail = f"the peer refused the credential (it still offers: {offered})"
                if partial:
                    detail += "; partial success reported"
                self.steps.append(
                    {"step": "userauth", "status": "FAILURE", "methods_offered": offered}
                )
                return ("FAILURE", detail)
            if kind == SSH_MSG_USERAUTH_BANNER:
                continue
            if kind == SSH_MSG_DISCONNECT:
                self.steps.append({"step": "userauth", "status": "DISCONNECTED"})
                return ("DISCONNECTED", "the peer disconnected during authentication")
            self.steps.append({"step": "userauth", "status": f"UNEXPECTED_{kind}"})
            return (f"UNEXPECTED_{kind}", "the peer sent an unexpected message")

    async def authenticate_password(self, username: str, password: str) -> tuple[str, str]:
        await self._service("ssh-userauth")
        payload = (
            bytes([SSH_MSG_USERAUTH_REQUEST])
            + _text(username)
            + _text("ssh-connection")
            + _text("password")
            + b"\x00"
            + _text(password)
        )
        await self._send_packet(payload)
        return await self._read_auth_reply()

    async def authenticate_publickey(
        self, username: str, private_key: bytes, *, passphrase: str | None = None
    ) -> tuple[str, str]:
        """``ssh-ed25519`` public-key auth: one signed USERAUTH_REQUEST (RFC 4252 §7)."""
        del passphrase  # an OpenSSH key's passphrase is unwrapped by the caller
        await self._service("ssh-userauth")
        if len(private_key) != 32:
            msg = "ssh-ed25519 user auth needs a 32-byte Ed25519 seed"
            raise SshProtocolError(msg)
        public = derive_public_key(private_key)
        key_blob = ed25519_host_key(public)
        base = (
            bytes([SSH_MSG_USERAUTH_REQUEST])
            + _text(username)
            + _text("ssh-connection")
            + _text("publickey")
            + b"\x01"
            + _text(HOST_KEY_ALGORITHM)
            + _string(key_blob)
        )
        signature = ed25519_sign(private_key, _string(self.session_id) + base)
        await self._send_packet(base + ed25519_signature_blob(signature))
        return await self._read_auth_reply()

    async def close(self) -> None:
        try:
            await self._stream.send(
                self._seal(
                    bytes([SSH_MSG_DISCONNECT])
                    + _uint32(11)  # SSH_DISCONNECT_BY_APPLICATION
                    + _text("session complete")
                    + _text("")
                )
            )
        except (OSError, SshProtocolError):
            return


# --------------------------------------------------------------------------- the check


@dataclass(slots=True)
class _Outcome:
    """What one authentication attempt established, in words the report can carry."""

    status: str
    detail: str
    exchanges: int
    host_key_verified: bool


class SshAuthenticator:
    """The SSH exchange, driven by the broker with the material it holds.

    Implements :class:`arachne.creds.broker.Authenticator`: one call in, one verdict out.
    The broker has already checked that the credential's scope covers this host — and the
    scoped client refuses an out-of-scope host before a socket exists — so this class can
    concentrate on the protocol.
    """

    protocol = "ssh"

    def __init__(self, client: Any, service: ServiceRecord) -> None:
        self.client = client
        self.service = service
        self.endpoint = service.key or f"{service.host}:{service.port}"

    async def attempt(
        self, username: str, password: str, extra: Mapping[str, str] | None = None
    ) -> Any:
        from arachne.creds.broker import ProtocolAuthResult

        options = dict(extra or {})
        method = (options.get("auth_method") or "password").lower()
        steps: list[dict[str, Any]] = []
        try:
            async with self.client.open_stream(
                self.service.host, self.service.port, protocol="ssh"
            ) as stream:
                session = SshSession(stream)
                await session.open()
                if method == "publickey":
                    seed, status, detail = _seed_from_material(password, options)
                    if seed is None:
                        return ProtocolAuthResult(
                            protocol=self.protocol,
                            endpoint=self.endpoint,
                            attempted=False,
                            accepted=False,
                            status_name=status,
                            detail=detail,
                            exchanges=tuple(session.steps),
                        )
                    result_status, result_detail = await session.authenticate_publickey(
                        username, seed
                    )
                else:
                    result_status, result_detail = await session.authenticate_password(
                        username, password
                    )
                steps = list(session.steps)
                verified = session.host_key_verified
                await session.close()
        except Exception as exc:  # a protocol failure is a verdict, not a scan crash
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name=type(exc).__name__,
                detail=str(exc),
                exchanges=tuple(steps),
            )
        accepted = result_status == "SUCCESS"
        return ProtocolAuthResult(
            protocol=self.protocol,
            endpoint=self.endpoint,
            attempted=True,
            accepted=accepted,
            status_name=result_status,
            detail=result_detail if verified else f"{result_detail}; host key NOT verified",
            exchanges=tuple(steps),
        )


def _seed_from_material(secret: str, options: Mapping[str, str]) -> tuple[bytes | None, str, str]:
    """Turn the vault's secret into an Ed25519 seed, or say why it cannot be used.

    The vault stores a secret as text. An SSH private key arrives either as the raw hex seed
    (what ``arachne vault put --ssh-key`` writes) or as an OpenSSH private-key file. This
    build accepts the raw seed and refuses anything else *without sending it*, because a
    half-parsed key would be a credential sent to a peer under a bogus claim.
    """
    key_type = (options.get("key_type") or "ed25519").lower()
    if key_type != "ed25519":
        return (
            None,
            "UNSUPPORTED_KEY_TYPE",
            f"this build authenticates with ssh-ed25519 keys, not {key_type}",
        )
    cleaned = "".join(secret.split())
    if cleaned.startswith("-----BEGIN"):
        return (
            None,
            "ENCRYPTED_OR_FOREIGN_KEY",
            "the stored key is an OpenSSH/PEM file; store the 32-byte Ed25519 seed instead "
            "(no credential was sent)",
        )
    try:
        seed = bytes.fromhex(cleaned)
    except ValueError:
        return (None, "MALFORMED_KEY", "the stored key is not a hex-encoded Ed25519 seed")
    if len(seed) != 32:
        return (
            None,
            "MALFORMED_KEY",
            f"an Ed25519 seed is 32 bytes, and the stored key is {len(seed)}",
        )
    return (seed, "OK", "")


class SshAuth(NetworkCheck, Module):
    """``m2.ssh-auth`` — verify a vault SSH credential against a host (REQ-CREDS-006)."""

    metadata = CheckMetadata(
        id="m2.ssh-auth",
        module="M2",
        name="ssh-auth",
        version="1.0",
        title="SSH credential verification",
        description=(
            "Authenticates to an SSH service with the credential this scan selected from the "
            "vault, over a curve25519-sha256 / ssh-ed25519 / aes128-ctr profile, and reports "
            "whether the peer accepted it. The credential never enters the check: the broker "
            "supplies it for one exchange and drops it. The host key is verified before any "
            "credential is offered, and an out-of-scope host is refused before a socket is "
            "opened. Opt-in, active, and refused when the credential is not scoped to the "
            "target."
        ),
        research_ref="ch02#24",
        framework=("WSTG-CONF-01", "CWE-1392"),
        compliance=("CIS-4.7", "CIS-5.2", "ISO-A.8.5", "CSF-PR.AA-03", "PCI-8"),
        cwe="CWE-1392",
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=6,
        requires_active_checks=True,
        requires_credentials=("ssh",),
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        broker = ctx.credentials
        if broker is None:
            yield ctx.skipped(
                "no credential capability in this step: credentialed host checks need a "
                "credential selected for the scan"
            )
            return
        client, skipped = net_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert client is not None
        inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None

        services = _ssh_services(ctx)
        if not services:
            yield ctx.skipped(
                f"no SSH service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            result = await broker.authenticate(
                SshAuthenticator(client, service), host=service.host, port=service.port
            )
            evidence = [self._evidence(service, result)]
            if not result.attempted:
                yield ctx.skipped(f"no SSH credential for {service.key}: {result.detail}".strip())
                continue
            service.notes["ssh_auth"] = result.to_dict()
            if result.accepted:
                yield ctx.info(
                    f"SSH accepted the configured credential on {service.key}",
                    detail=(
                        f"credential {result.label!r} authenticated over SSH "
                        f"({result.status_name}); the account has shell access to this host"
                    ),
                    evidence=evidence,
                    confidence=0.9,
                )
                continue
            yield ctx.info(
                f"SSH refused the configured credential on {service.key}",
                detail=(
                    f"credential {result.label!r} did not authenticate "
                    f"({result.status_name}): the stored secret is wrong, expired, or the "
                    "account is locked or disabled"
                    + (f" — {result.detail}" if result.detail else "")
                ),
                evidence=evidence,
                confidence=0.8,
            )

    @staticmethod
    def _evidence(service: ServiceRecord, result: Any) -> Evidence:
        payload: dict[str, Any] = {
            "service": service.key,
            "port": service.port,
            "protocol": result.protocol,
            "endpoint": result.endpoint,
            "credential": result.label,
            "attempted": result.attempted,
            "accepted": result.accepted,
            "status": result.status_name,
            "exchanges": len(result.exchanges) if result.exchanges else 0,
        }
        return Evidence.of("banner", payload, source=f"ssh://{result.endpoint}")


def _ssh_services(ctx: CheckContext) -> tuple[ServiceRecord, ...]:
    catalog = port_catalog_for(ctx)
    wanted = {22}
    wanted.update(catalog.ports_for_probe("ssh"))
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() == "ssh":
            matches.append(service)
            continue
        if service.port in wanted:
            matches.append(service)
    return tuple(matches)
