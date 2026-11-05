"""A loopback SSH server that accepts exactly one credential (REQ-CREDS-006's lab target).

``m2.ssh-auth`` authenticates with a real SSH exchange: version strings, a curve25519 key
exchange, NEWKEYS and an encrypted user-auth request. A canned banner cannot prove any of
that, so this fixture is a *server*: the same profile the check offers, in reverse, over a
real TCP socket on ``127.0.0.1``.

It is a test fixture and nothing else — it lives under ``tests/``, it listens on loopback, and
it exists so "an authenticated scan produces a result an anonymous one cannot" is a measured
statement rather than an assertion about a mock.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import threading
from typing import Any

from arachne.core.ed25519 import derive_public_key
from arachne.core.ed25519 import sign as ed25519_sign
from arachne.core.ed25519 import verify as ed25519_verify
from arachne.modules.m2.ssh import (
    AES_BLOCK_SIZE,
    CIPHER,
    COMPRESSION,
    HOST_KEY_ALGORITHM,
    KEX_ALGORITHM,
    MAC,
    SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEX_ECDH_REPLY,
    SSH_MSG_NEWKEYS,
    SSH_MSG_SERVICE_ACCEPT,
    SSH_MSG_SERVICE_REQUEST,
    SSH_MSG_USERAUTH_FAILURE,
    SSH_MSG_USERAUTH_REQUEST,
    SSH_MSG_USERAUTH_SUCCESS,
    _CtrCipher,
    _mpint,
    _read_string,
    _string,
    _text,
    _uint32,
    build_kexinit,
    ed25519_host_key,
    ed25519_signature_blob,
    parse_kexinit,
    x25519,
)

__all__ = ["SshLabServer"]

#: The host key the fixture presents. Fixed so a test can assert the client verified *this*
#: key, and so a run is reproducible.
HOST_KEY_SEED = bytes(range(32))
SERVER_VERSION = "SSH-2.0-OpenSSH_9.6lab"
#: What the server says it supports. One algorithm of each, so the negotiation is a decision.
_SERVER_ALGORITHMS = (
    KEX_ALGORITHM,
    HOST_KEY_ALGORITHM,
    CIPHER,
    CIPHER,
    MAC,
    MAC,
    COMPRESSION,
    COMPRESSION,
)


class _ServerChannel:
    """The server's half of the packet layer: framing, padding, sequence numbers, ciphers."""

    def __init__(self, connection: socket.socket) -> None:
        self._socket = connection
        self._buffer = b""
        self._send_sequence = 0
        self._recv_sequence = 0
        self._out_cipher: _CtrCipher | None = None
        self._in_cipher: _CtrCipher | None = None
        self._out_mac: bytes | None = None
        self._in_mac: bytes | None = None
        self.version_sent = SERVER_VERSION
        self.client_version = ""
        self.session_id = b""

    # ------------------------------------------------------------------ raw io
    def send_raw(self, data: bytes) -> None:
        self._socket.sendall(data)

    def read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise ConnectionError("client closed")
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def read_line(self) -> str:
        while b"\r\n" not in self._buffer:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise ConnectionError("client closed")
            self._buffer += chunk
        line, _, rest = self._buffer.partition(b"\r\n")
        self._buffer = rest
        return line.decode("utf-8", "replace")

    # ------------------------------------------------------------------ packets
    def _block(self, *, incoming: bool) -> int:
        cipher = self._in_cipher if incoming else self._out_cipher
        return AES_BLOCK_SIZE if cipher is not None else 8

    def send_packet(self, payload: bytes) -> None:
        block = self._block(incoming=False)
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
        self.send_raw(wire + mac)

    def receive_packet(self) -> bytes:
        first = self.read_exact(4)
        if self._in_cipher is not None:
            first = self._in_cipher.transform(first)
        length = struct.unpack(">I", first)[0]
        remainder = self.read_exact(length)
        if self._in_cipher is not None:
            remainder = self._in_cipher.transform(remainder)
        padding = remainder[0]
        if self._in_mac is not None:
            mac = self.read_exact(32)
            expected = hmac.new(
                self._in_mac, _uint32(self._recv_sequence) + first + remainder, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(mac, expected):
                raise ConnectionError("the client's packet MAC did not verify")
        self._recv_sequence += 1
        return remainder[1 : len(remainder) - padding] if padding else remainder[1:]

    # ------------------------------------------------------------------ keys
    def enable_crypto(self, shared: int, exchange_hash: bytes) -> None:
        """Server side: outbound uses D/F/B, inbound uses C/E/A (RFC 4253 §7.2)."""

        def derive(letter: bytes, length: int) -> bytes:
            material = _mpint(shared) + exchange_hash + letter + self.session_id
            return hashlib.sha256(material).digest()[:length]

        self._out_cipher = _CtrCipher(derive(b"D", 16), derive(b"B", 16))
        self._in_cipher = _CtrCipher(derive(b"C", 16), derive(b"A", 16))
        self._out_mac = derive(b"F", 32)
        self._in_mac = derive(b"E", 32)


class SshLabServer:
    """A loopback SSH server that accepts exactly one credential.

    ``password`` and ``public_key`` are the accepted credentials; either may be ``None`` to
    disable that method. Every attempt (accepted or refused) is recorded in :attr:`attempts`
    so a test can assert the client actually reached the auth step.
    """

    def __init__(
        self,
        *,
        username: str = "labuser",
        password: str | None = None,
        public_key: bytes | None = None,
        host_key_seed: bytes | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.public_key = public_key
        self.host_key_seed = host_key_seed or HOST_KEY_SEED
        self.attempts: list[dict[str, Any]] = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(4)
        self._socket.settimeout(0.4)
        self.port = int(self._socket.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> SshLabServer:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def stop(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = self._socket.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                connection.settimeout(5.0)
                try:
                    self._handle(connection)
                except (ConnectionError, OSError, ValueError, IndexError):
                    continue

    # ------------------------------------------------------------------ the exchange
    def _handle(self, connection: socket.socket) -> None:
        channel = _ServerChannel(connection)
        channel.send_raw(f"{SERVER_VERSION}\r\n".encode())
        while True:
            line = channel.read_line()
            if line.startswith("SSH-"):
                channel.client_version = line
                break

        server_kexinit = _server_kexinit()
        channel.send_packet(server_kexinit)
        client_kexinit = channel.receive_packet()
        peer = parse_kexinit(client_kexinit)
        for offered, ours in zip(
            (
                peer.kex,
                peer.host_keys,
                peer.ciphers_client_to_server,
                peer.ciphers_server_to_client,
                peer.macs_client_to_server,
                peer.macs_server_to_client,
                peer.compressions_client_to_server,
                peer.compressions_server_to_client,
            ),
            _SERVER_ALGORITHMS,
            strict=False,
        ):
            if ours not in offered:
                raise ConnectionError(f"the client does not offer {ours}")

        init = channel.receive_packet()
        if not init or init[0] != SSH_MSG_KEX_ECDH_INIT:
            raise ConnectionError("expected KEX_ECDH_INIT")
        client_public, _ = _read_string(init, 1)

        private = os.urandom(32)
        server_public = x25519(private, (9).to_bytes(32, "little"))
        shared = int.from_bytes(x25519(private, client_public), "little")
        host_public = derive_public_key(self.host_key_seed)
        host_key = ed25519_host_key(host_public)

        transcript = (
            _text(channel.client_version)
            + _text(SERVER_VERSION)
            + _string(client_kexinit)
            + _string(server_kexinit)
            + _string(host_key)
            + _string(client_public)
            + _string(server_public)
            + _mpint(shared)
        )
        exchange_hash = hashlib.sha256(transcript).digest()
        channel.session_id = exchange_hash
        signature = ed25519_sign(self.host_key_seed, exchange_hash)
        channel.send_packet(
            bytes([SSH_MSG_KEX_ECDH_REPLY])
            + _string(host_key)
            + _string(server_public)
            + ed25519_signature_blob(signature)
        )
        channel.send_packet(bytes([SSH_MSG_NEWKEYS]))
        if not channel.receive_packet()[0] == SSH_MSG_NEWKEYS:
            raise ConnectionError("expected NEWKEYS")
        channel.enable_crypto(shared, exchange_hash)

        request = channel.receive_packet()
        if not request or request[0] != SSH_MSG_SERVICE_REQUEST:
            raise ConnectionError("expected SERVICE_REQUEST")
        service, _ = _read_string(request, 1)
        channel.send_packet(bytes([SSH_MSG_SERVICE_ACCEPT]) + _string(service))

        auth = channel.receive_packet()
        accepted, method, detail = self._check_auth(auth, channel.session_id)
        self.attempts.append({"method": method, "accepted": accepted, "detail": detail})
        if accepted:
            channel.send_packet(bytes([SSH_MSG_USERAUTH_SUCCESS]))
        else:
            channel.send_packet(
                bytes([SSH_MSG_USERAUTH_FAILURE]) + _text("password,publickey") + b"\x00"
            )

    def _check_auth(self, payload: bytes, session_id: bytes) -> tuple[bool, str, str]:
        if not payload or payload[0] != SSH_MSG_USERAUTH_REQUEST:
            return (False, "unknown", "expected USERAUTH_REQUEST")
        offset = 1
        raw_user, offset = _read_string(payload, offset)
        _service, offset = _read_string(payload, offset)
        raw_method, offset = _read_string(payload, offset)
        user = raw_user.decode("utf-8", "replace")
        method = raw_method.decode("ascii", "replace")
        if user != self.username:
            return (False, method, f"unknown user {user!r}")
        if method == "password":
            if self.password is None:
                return (False, method, "password auth disabled")
            _change, offset = payload[offset], offset + 1
            candidate, offset = _read_string(payload, offset)
            ok = hmac.compare_digest(candidate.decode("utf-8", "replace"), self.password)
            return (ok, method, "password accepted" if ok else "password refused")
        if method == "publickey":
            if self.public_key is None:
                return (False, method, "public-key auth disabled")
            has_signature = payload[offset]
            offset += 1
            algorithm, offset = _read_string(payload, offset)
            key_blob, offset = _read_string(payload, offset)
            if not has_signature:
                return (False, method, "probe without a signature")
            signature_blob, offset = _read_string(payload, offset)
            _inner_algorithm, key_offset = _read_string(key_blob, 0)
            presented, _ = _read_string(key_blob, key_offset)
            if algorithm.decode("ascii", "replace") != HOST_KEY_ALGORITHM:
                return (False, method, "unsupported key algorithm")
            if not hmac.compare_digest(presented, self.public_key):
                return (False, method, "the presented key is not the authorized key")
            signed = _string(session_id) + payload[: offset - len(_string(signature_blob))]
            _sig_algorithm, sig_offset = _read_string(signature_blob, 0)
            raw_signature, _ = _read_string(signature_blob, sig_offset)
            ok = ed25519_verify(self.public_key, signed, raw_signature)
            return (ok, method, "public key accepted" if ok else "signature refused")
        return (False, method, f"unsupported method {method!r}")


def _server_kexinit() -> bytes:
    """The server's KEXINIT: the same single-algorithm profile the client offers."""
    return build_kexinit(os.urandom(16))
