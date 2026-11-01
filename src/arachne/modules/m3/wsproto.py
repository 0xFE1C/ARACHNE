"""Minimal RFC 6455 framing for the WebSocket depth checks (research ch03#33).

The M3 WebSocket probes need two things the shared HTTP client cannot give them: a handshake
they can *finish* (the ``101`` reply, then the same connection carried into a frame
conversation) and frames. Rather than adding a WebSocket client library — which would open a
second egress path around :class:`~arachne.core.net.ScopedNetClient` and its scope, address
and audit gates — this module carries just enough framing to (a) build the upgrade request,
(b) verify the server's ``Sec-WebSocket-Accept``, and (c) encode one masked client frame and
decode the server's reply.

Everything here is pure: no socket, no I/O, no waiting. The bytes go out through the scoped
network client, so the one-egress-path invariant holds (``tests/unit/test_http_hygiene.py``).

The decoder is deliberately *bounded and defensive*: a frame header is validated against the
buffer, a declared length above ``max_payload`` is refused rather than allocated, and a
truncated frame yields what was complete. A hostile peer cannot make the scanner allocate
memory in proportion to a number it chose.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Final

__all__ = [
    "CLOSE",
    "CONTROL_OPCODES",
    "GUID",
    "PING",
    "PONG",
    "TEXT",
    "Frame",
    "accept_key",
    "build_upgrade_request",
    "decode_frames",
    "encode_frame",
    "frame_payloads",
]

#: The RFC 6455 handshake GUID. Concatenated with the client's key and hashed with SHA-1.
GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

TEXT: Final = 0x1
BINARY: Final = 0x2
CLOSE: Final = 0x8
PING: Final = 0x9
PONG: Final = 0xA

#: Opcodes whose payload is a control payload (never fragmented, at most 125 bytes).
CONTROL_OPCODES: Final[frozenset[int]] = frozenset({CLOSE, PING, PONG})

#: A frame larger than this is refused rather than buffered: a server's declared length is
#: its own claim, and the probe has no reason to honour a large one.
_MAX_PAYLOAD: Final = 65536


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded frame (server→client, so an unmasked payload)."""

    fin: bool
    opcode: int
    payload: bytes
    #: The whole frame's length in bytes, so a caller can walk a buffer of several frames.
    size: int

    @property
    def is_control(self) -> bool:
        return self.opcode in CONTROL_OPCODES

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", errors="replace")


def accept_key(client_key: str) -> str:
    """The ``Sec-WebSocket-Accept`` a correct server returns for ``client_key``."""
    digest = hashlib.sha1((client_key + GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
    return base64.b64encode(digest).decode("ascii")


def build_upgrade_request(
    path: str,
    *,
    host: str,
    key: str,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
) -> bytes:
    """The bytes of an RFC 6455 upgrade request.

    ``path`` is the request target (``/ws``), ``host`` the ``Host`` header value. Any
    ``headers`` are appended last, so a caller can add (or deliberately omit) an
    authorization header: an upgrade sent with none is how the auth-on-upgrade check asks
    "does this endpoint require a credential at all?".
    """
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {key}",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    for name, value in (headers or {}).items():
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            continue  # header injection is unrepresentable, not merely refused
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="replace")


def encode_frame(payload: bytes, *, opcode: int = TEXT, mask: bool = True) -> bytes:
    """One client→server frame. A client frame **must** be masked (RFC 6455 §5.3)."""
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))  # FIN set: no fragmentation is ever emitted
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(length.to_bytes(2, "big"))
    else:
        header.append(mask_bit | 127)
        header.extend(length.to_bytes(8, "big"))
    if not mask:
        return bytes(header) + payload
    key = secrets.token_bytes(4)
    header.extend(key)
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return bytes(header) + masked


def decode_frames(data: bytes, *, max_payload: int = _MAX_PAYLOAD) -> tuple[Frame, ...]:
    """Every complete frame in ``data`` (a truncated tail is simply not returned).

    Server→client frames are unmasked, so a set mask bit means the peer is not an RFC 6455
    server; the frame is skipped rather than decoded on a guess.
    """
    frames: list[Frame] = []
    index = 0
    total = len(data)
    while index + 2 <= total:
        first = data[index]
        second = data[index + 1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        cursor = index + 2
        if length == 126:
            if cursor + 2 > total:
                break
            length = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += 2
        elif length == 127:
            if cursor + 8 > total:
                break
            length = int.from_bytes(data[cursor : cursor + 8], "big")
            cursor += 8
        if masked or length > max_payload:
            break
        if cursor + length > total:
            break
        payload = data[cursor : cursor + length]
        frames.append(Frame(fin=fin, opcode=opcode, payload=payload, size=cursor + length - index))
        index = cursor + length
    return tuple(frames)


def frame_payloads(frames: tuple[Frame, ...], *, opcodes: frozenset[int] | None = None) -> str:
    """Concatenated text of the data frames (control frames excluded unless asked for)."""
    wanted = opcodes if opcodes is not None else frozenset({TEXT, BINARY})
    return "".join(frame.text for frame in frames if frame.opcode in wanted)
