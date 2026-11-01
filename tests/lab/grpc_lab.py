"""The lab's HTTP/2 and gRPC fixtures (S29, REQ-DEPTH-003).

Two gRPC services on ephemeral ports, and the difference between them is the whole point of
the requirement: one is deployed the way gRPC usually is in a hurry (cleartext, reflection on,
metadata echoed), the other is deployed the way it should be (the plaintext preface is refused,
reflection answers UNIMPLEMENTED, metadata stays where it was sent).

The fixture is a real HTTP/2 peer, not a response-template: it reads the connection preface,
exchanges SETTINGS, decodes the request's HPACK header block (literal and indexed forms, no
Huffman — see :mod:`arachne.modules.m2.grpc` for the client half and why), reads the gRPC
length-prefixed message, and then answers with the frames a real server would send:
``HEADERS`` with ``:status``/``content-type``/``grpc-status``. A check that pattern-matched on
a canned byte string could not pass one service and fail the other here.
"""

from __future__ import annotations

import socket
import struct

# --------------------------------------------------------------------------- HTTP/2 framing
_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_DATA, _HEADERS, _RST_STREAM, _SETTINGS, _PING, _GOAWAY, _WINDOW_UPDATE = (
    0x0,
    0x1,
    0x3,
    0x4,
    0x6,
    0x7,
    0x8,
)
_END_STREAM, _END_HEADERS, _ACK = 0x1, 0x4, 0x1

REFLECTION_PATH = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
HEALTH_PATH = "/grpc.health.v1.Health/Check"
STATUS_UNIMPLEMENTED = "12"

#: The service list a reflection-enabled server publishes.
SERVICES = ("grpc.reflection.v1alpha.ServerReflection", "arachne.lab.Echo", "arachne.lab.Admin")


def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def _encode_int(value: int, prefix_bits: int, prefix: int) -> bytes:
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([prefix | value])
    out = bytearray([prefix | limit])
    value -= limit
    while value >= 128:
        out.append((value % 128) + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def _encode_str(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _encode_int(len(raw), 7, 0x00) + raw


def _literal_header(name: str, value: str, *, indexed: bool = False) -> bytes:
    """A literal header field (with or without incremental indexing)."""
    prefix = 0x40 if indexed else 0x00
    return _encode_int(0, 6 if indexed else 4, prefix) + _encode_str(name) + _encode_str(value)


_STATIC_NAMES: dict[int, str] = {
    1: ":authority",
    2: ":method",
    3: ":method",
    4: ":path",
    5: ":path",
    6: ":scheme",
    7: ":scheme",
    8: ":status",
    31: "content-type",
    58: "user-agent",
    23: "authorization",
    55: "set-cookie",
}


def _decode_int(data: bytes, index: int, prefix_bits: int) -> tuple[int, int]:
    limit = (1 << prefix_bits) - 1
    value = data[index] & limit
    index += 1
    if value < limit:
        return value, index
    shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, index


def _decode_str(data: bytes, index: int) -> tuple[str, int]:
    """One HPACK string. The H bit is read but the fixture never decodes a Huffman string."""
    huffman = bool(data[index] & 0x80)
    length, index = _decode_int(data, index, 7)
    raw = data[index : index + length]
    if huffman:
        # The lab's own client never Huffman-codes; a peer that does gets an empty value here
        # rather than a fabricated one (mirrors the check-side limitation).
        return "", index + length
    return raw.decode("utf-8", "replace"), index + length


def decode_request_headers(block: bytes) -> dict[str, str]:
    """The headers of a request block (literal forms + static-table indexed names)."""
    headers: dict[str, str] = {}
    index = 0
    while index < len(block):
        byte = block[index]
        if byte & 0x80:
            field_index, index = _decode_int(block, index, 7)
            name = _STATIC_NAMES.get(field_index, "")
            if name:
                headers.setdefault(name, "")
            continue
        if byte & 0x40:
            field_index, index = _decode_int(block, index, 6)
        elif byte & 0x20:
            _, index = _decode_int(block, index, 5)
            continue
        elif byte & 0x10:
            field_index, index = _decode_int(block, index, 4)
        else:
            field_index, index = _decode_int(block, index, 4)
        if field_index:
            name = _STATIC_NAMES.get(field_index)
            if name is None:
                name, index = _decode_str(block, index)
        else:
            name, index = _decode_str(block, index)
        value, index = _decode_str(block, index)
        headers[name] = value
    return headers


# --------------------------------------------------------------------------- the fixture
class GrpcLab:
    """One gRPC service's behaviour, which is to say its deployment mistakes."""

    def __init__(self, *, plaintext: bool, reflection: bool, echo_metadata: bool) -> None:
        self.plaintext = plaintext
        self.reflection = reflection
        self.echo_metadata = echo_metadata
        #: Requests the fixture answered, for a test to assert what was sent.
        self.requests: list[dict[str, str]] = []


def _response_frames(stream_id: int, lab: GrpcLab, headers: dict[str, str]) -> bytes:
    """HEADERS + (DATA) + trailers for one request, honouring the fixture's configuration."""
    path = headers.get(":path", "")
    body = b""
    status = "0"
    if path.endswith("ServerReflectionInfo"):
        if not lab.reflection:
            status = STATUS_UNIMPLEMENTED
        else:
            # A descriptor-shaped payload: the service names, length-prefixed, which is what a
            # real reflection response carries (and what the check looks for).
            body = b"".join(
                struct.pack(">B", 0x0A) + bytes([len(name)]) + name.encode() for name in SERVICES
            )
    elif lab.echo_metadata:
        # The leak: whatever the caller put in its metadata comes back in the body.
        echoed = " ".join(
            f"{name}={value}"
            for name, value in headers.items()
            if name in {"authorization", "x-arachne-nonce"}
        )
        body = echoed.encode("utf-8")
    response_headers = [
        (":status", "200"),
        ("content-type", "application/grpc"),
        ("grpc-status", status),
    ]
    out = bytearray()
    if body:
        payload = b"\x00" + struct.pack(">I", len(body)) + body
        out.extend(
            _frame(
                _HEADERS,
                _END_HEADERS,
                stream_id,
                b"".join(_literal_header(n, v, indexed=True) for n, v in response_headers[:2]),
            )
        )
        out.extend(_frame(_DATA, 0, stream_id, payload))
        out.extend(
            _frame(
                _HEADERS,
                _END_HEADERS | _END_STREAM,
                stream_id,
                _literal_header("grpc-status", status),
            )
        )
    else:
        out.extend(
            _frame(
                _HEADERS,
                _END_HEADERS | _END_STREAM,
                stream_id,
                b"".join(_literal_header(n, v, indexed=True) for n, v in response_headers),
            )
        )
    return bytes(out)


def handle_connection(connection: socket.socket, lab: GrpcLab) -> None:
    """Serve one connection: preface, SETTINGS, then request frames until the peer stops."""
    connection.settimeout(3.0)
    preface = _read_exactly(connection, len(_PREFACE))
    if preface != _PREFACE:
        # Not an HTTP/2 peer. A hardened fixture simply closes: that is what refusing h2c
        # prior knowledge looks like on the wire.
        return
    if not lab.plaintext:
        return
    connection.sendall(_frame(_SETTINGS, 0, 0))
    buffer = b""
    stream_id = 1
    while True:
        try:
            chunk = connection.recv(16384)
        except (TimeoutError, OSError):
            return
        if not chunk:
            return
        buffer += chunk
        while True:
            parsed = _take_frame(buffer)
            if parsed is None:
                break
            frame_type, flags, frame_stream, payload, consumed = parsed
            buffer = buffer[consumed:]
            if frame_type == _SETTINGS and not flags & _ACK:
                connection.sendall(_frame(_SETTINGS, _ACK, 0))
            elif frame_type == _HEADERS:
                stream_id = frame_stream
                headers = decode_request_headers(payload)
                lab.requests.append(headers)
                # Wait for the DATA frame that carries the gRPC message before answering.
                continue
            elif frame_type == _DATA:
                headers = lab.requests[-1] if lab.requests else {}
                connection.sendall(_response_frames(stream_id or frame_stream, lab, headers))
                return
            elif frame_type == _PING and not flags & _ACK:
                connection.sendall(_frame(_PING, _ACK, 0))


def _read_exactly(connection: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        try:
            chunk = connection.recv(count - len(data))
        except (TimeoutError, OSError):
            return data
        if not chunk:
            return data
        data += chunk
    return data


def _take_frame(buffer: bytes) -> tuple[int, int, int, bytes, int] | None:
    if len(buffer) < 9:
        return None
    length = int.from_bytes(buffer[:3], "big")
    if len(buffer) < 9 + length:
        return None
    frame_type = buffer[3]
    flags = buffer[4]
    stream_id = int.from_bytes(buffer[5:9], "big") & 0x7FFFFFFF
    return frame_type, flags, stream_id, buffer[9 : 9 + length], 9 + length


#: The planted-vulnerable service: cleartext, reflection on, metadata echoed.
VULNERABLE = GrpcLab(plaintext=True, reflection=True, echo_metadata=True)

#: A service that keeps HTTP/2 cleartext but hardens the application: reflection answers
#: UNIMPLEMENTED and metadata is not echoed. This is the control for the reflection and
#: metadata facets.
HARDENED = GrpcLab(plaintext=True, reflection=False, echo_metadata=False)

#: A service that refuses the plaintext preface outright — what a TLS-only deployment looks
#: like to this probe, and the control for the plaintext facet.
TLS_ONLY = GrpcLab(plaintext=False, reflection=False, echo_metadata=False)
