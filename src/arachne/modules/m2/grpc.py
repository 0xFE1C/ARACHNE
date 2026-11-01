"""gRPC / HTTP-2 posture checks for M2 (research ch02#12, REQ-DEPTH-003).

gRPC is HTTP/2 with a binary payload convention, and its two most common deployment failures
are what this module probes — read-only, over the scoped network client:

``m2.grpc-plaintext``
    Sends the HTTP/2 connection preface (the "prior knowledge" form of ``h2c``) and reports a
    server that answers with a ``SETTINGS`` frame. That answer means the endpoint speaks
    cleartext HTTP/2, so every gRPC call and its metadata travel unencrypted (CWE-319).
``m2.grpc-reflection``
    Calls the standard reflection method and reports a server that answers it. Reflection is a
    debugging feature that publishes the whole service definition — message shapes, field
    names, method signatures — to any client that asks (CWE-200).
``m2.grpc-metadata-leak``
    Attaches a unique inert nonce as ``authorization``/``x-arachne-nonce`` metadata and reports
    a response that carries the nonce back. A server that echoes request metadata into its
    response leaks credentials to whoever can read the response — logs, proxies, a shared
    cache, another caller (CWE-522). The nonce is inert: it is not a credential and authorizes
    nothing.

All three are **L1** (active read-only) and declare it: they open one connection per candidate
port, send frames, read frames, and change nothing. There is no mutation, no state, no
callback. Every frame carries ARACHNE's own stream id and no flow-control window update beyond
the connection preface, so the probe cannot be mistaken for a flood.

The framing here is deliberately minimal, and the one place it is knowingly partial is HPACK
****Huffman decoding****: a header field whose string is Huffman-coded is reported as
``undecoded`` rather than guessed at (see :func:`decode_headers`). Nothing in these checks
depends on it — the plaintext signal is a frame *type*, and the reflection and leak signals are
byte patterns inside the response body — so a target that Huffman-codes its headers is still
measured correctly, and the limitation is stated rather than hidden.
"""

from __future__ import annotations

import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from arachne.core.results import CheckResult
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.netinfra import _candidate_ports, _hosts_for
from arachne.modules.m2.support import (
    NetworkCheck,
    catalog_ports_for_probe,
    inventory_or_skip,
    net_or_skip,
    skip_result,
    target_kinds_for_network_probes,
)

__all__ = [
    "GrpcMetadataLeak",
    "GrpcPlaintext",
    "GrpcReflection",
    "decode_headers",
    "encode_headers",
    "frame",
    "grpc_frame",
    "parse_frames",
]

# --------------------------------------------------------------------------- HTTP/2 framing
DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = (
    0x0,
    0x1,
    0x3,
    0x4,
    0x6,
    0x7,
    0x8,
    0x9,
)
END_STREAM, END_HEADERS, ACK = 0x1, 0x4, 0x1

#: The client connection preface (RFC 9113 §3.4) followed by an empty SETTINGS frame. Sending
#: the preface is exactly what "prior knowledge" h2c is: no upgrade dance, no ALPN.
CLIENT_PREFACE: bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

REFLECTION_PATH = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
HEALTH_PATH = "/grpc.health.v1.Health/Check"

#: A bounded frame payload: the probe reads a handful of frames from its own stream, and a
#: peer's declared length is its own claim (never allocated on trust).
MAX_FRAME_PAYLOAD = 65536


@dataclass(frozen=True, slots=True)
class Frame:
    """One HTTP/2 frame."""

    type: int
    flags: int
    stream_id: int
    payload: bytes


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """One HTTP/2 frame (9-byte header + payload)."""
    header = len(payload).to_bytes(3, "big") + bytes([frame_type, flags])
    return header + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload


def parse_frames(data: bytes, *, max_payload: int = MAX_FRAME_PAYLOAD) -> tuple[Frame, ...]:
    """Every complete frame in ``data`` (a truncated tail is simply not returned)."""
    out: list[Frame] = []
    index = 0
    total = len(data)
    while index + 9 <= total:
        length = int.from_bytes(data[index : index + 3], "big")
        frame_type = data[index + 3]
        flags = data[index + 4]
        stream_id = int.from_bytes(data[index + 5 : index + 9], "big") & 0x7FFFFFFF
        start = index + 9
        if length > max_payload or start + length > total:
            break
        out.append(Frame(frame_type, flags, stream_id, data[start : start + length]))
        index = start + length
    return tuple(out)


def grpc_frame(message: bytes) -> bytes:
    """One gRPC length-prefixed message (compression flag 0 + big-endian length)."""
    return b"\x00" + struct.pack(">I", len(message)) + message


def grpc_messages(payload: bytes) -> tuple[bytes, ...]:
    """The gRPC messages in a DATA frame's payload (bounded, never on trust)."""
    out: list[bytes] = []
    index = 0
    while index + 5 <= len(payload):
        flag = payload[index]
        length = int.from_bytes(payload[index + 1 : index + 5], "big")
        start = index + 5
        if flag != 0 or start + length > len(payload):
            break
        out.append(payload[start : start + length])
        index = start + length
    return tuple(out)


# --------------------------------------------------------------------------- HPACK
#: The HPACK static table (RFC 7541 Appendix A) — name/value pairs, 1-indexed by position.
STATIC_TABLE: tuple[tuple[str, str], ...] = (
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
)


def _encode_integer(value: int, prefix_bits: int, prefix: int) -> bytes:
    """HPACK prefix integer (RFC 7541 §5.1)."""
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


def _encode_string(value: str) -> bytes:
    """An HPACK string literal, **never Huffman-coded** (the H bit stays 0)."""
    raw = value.encode("utf-8")
    return _encode_integer(len(raw), 7, 0x00) + raw


def encode_headers(headers: list[tuple[str, str]]) -> bytes:
    """A header block using literal-without-indexing for every field.

    No dynamic-table insertions and no Huffman coding: the probe is a handful of headers, so
    the most obvious encoding is also the one that is trivial to audit, and any conformant
    server accepts it.
    """
    out = bytearray()
    for name, value in headers:
        out.extend(_encode_integer(0, 4, 0x00))  # literal without indexing, new name
        out.extend(_encode_string(name))
        out.extend(_encode_string(value))
    return bytes(out)


@dataclass
class _DynamicTable:
    """The peer's HPACK dynamic table, enough to follow a response's field indices."""

    entries: list[tuple[str, str]] = field(default_factory=list)

    def add(self, name: str, value: str) -> None:
        # A bounded table is all this probe needs: it never decodes more than one response.
        self.entries.insert(0, (name, value))
        del self.entries[200:]

    def get(self, index: int) -> tuple[str, str] | None:
        if 1 <= index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        dynamic = index - len(STATIC_TABLE) - 1
        if 0 <= dynamic < len(self.entries):
            return self.entries[dynamic]
        return None


@dataclass(frozen=True, slots=True)
class HeaderBlock:
    """A decoded header block plus what the decoder refused to guess at."""

    headers: tuple[tuple[str, str], ...]
    #: True when a field carried a Huffman-coded string, which this probe does not decode.
    huffman_seen: bool = False

    def first(self, name: str) -> str | None:
        for field_name, value in self.headers:
            if field_name == name:
                return value
        return None


def _decode_integer(data: bytes, index: int, prefix_bits: int) -> tuple[int, int]:
    limit = (1 << prefix_bits) - 1
    if index >= len(data):
        raise ValueError("truncated integer")
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
            return value, index
        if shift > 28:
            raise ValueError("integer overflow")
    raise ValueError("truncated integer")


def decode_headers(block: bytes, *, dynamic: _DynamicTable | None = None) -> HeaderBlock:
    """Decode an HPACK header block, stopping (and flagging) at a Huffman-coded string.

    Indexed fields, literal-with-incremental-indexing, literal-without-indexing and
    literal-never-indexed are all decoded. Huffman-coded strings are **not** decoded: the
    probe reports ``huffman_seen`` instead of inventing a value. Nothing in these checks
    depends on those fields (the signals are frame types and response-body bytes), which is
    why the limitation is acceptable and stated.
    """
    table = dynamic if dynamic is not None else _DynamicTable()
    out: list[tuple[str, str]] = []
    index = 0
    huffman_seen = False
    while index < len(block):
        byte = block[index]
        try:
            if byte & 0x80:  # indexed header field
                field_index, index = _decode_integer(block, index, 7)
                entry = table.get(field_index)
                if entry is None:
                    break
                out.append(entry)
                continue
            if byte & 0x40:  # literal with incremental indexing
                field_index, index = _decode_integer(block, index, 6)
                name = _name_at(table, field_index)
            elif byte & 0x20:  # dynamic table size update
                _, index = _decode_integer(block, index, 5)
                continue
            elif byte & 0x10:  # literal never indexed
                field_index, index = _decode_integer(block, index, 4)
                name = _name_at(table, field_index)
            else:  # literal without indexing
                field_index, index = _decode_integer(block, index, 4)
                name = _name_at(table, field_index)
            if name is None:
                huffman, index = _decode_string(block, index)
                if huffman is None:
                    huffman_seen = True
                    break
                name = huffman
            value, index = _decode_string(block, index)
            if value is None:
                huffman_seen = True
                break
            out.append((name, value))
            if byte & 0x40:
                table.add(name, value)
        except ValueError:
            break
    return HeaderBlock(headers=tuple(out), huffman_seen=huffman_seen)


def _name_at(table: _DynamicTable, index: int) -> str | None:
    """The field *name* at a table index (``None`` for "new name follows as a literal")."""
    if not index:
        return None
    entry = table.get(index)
    return None if entry is None else entry[0]


def _decode_string(data: bytes, index: int) -> tuple[str | None, int]:
    """``(value, next_index)``; ``value`` is ``None`` when the string is Huffman-coded."""
    huffman = bool(data[index] & 0x80)
    length, index = _decode_integer(data, index, 7)
    raw = data[index : index + length]
    if len(raw) < length:
        raise ValueError("truncated string")
    if huffman:
        return None, index + length
    return raw.decode("utf-8", "replace"), index + length


# --------------------------------------------------------------------------- probe plumbing
def _grpc_request_headers(path: str, *, authority: str, metadata: list[tuple[str, str]]) -> bytes:
    """A gRPC request header block: pseudo-headers first, then the caller's metadata."""
    headers = [
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", authority),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", "arachne-grpc-probe/1.0"),
        *metadata,
    ]
    return encode_headers(headers)


def _probe_payload(header_block: bytes, message: bytes | None, *, stream_id: int = 1) -> bytes:
    """Preface + SETTINGS + HEADERS (+ DATA ending the stream) in one write."""
    out = bytearray(CLIENT_PREFACE)
    out.extend(frame(SETTINGS, 0, 0))
    out.extend(frame(HEADERS, END_HEADERS, stream_id, header_block))
    if message is not None:
        out.extend(frame(DATA, END_STREAM, stream_id, grpc_frame(message)))
    return bytes(out)


def _response_view(frames: tuple[Frame, ...], stream_id: int = 1) -> tuple[str, bytes, bool]:
    """``(grpc-status, response body bytes, stream_reset)`` from a response's frames."""
    body = bytearray()
    status: str | None = None
    reset = False
    dynamic = _DynamicTable()
    for item in frames:
        if item.type == RST_STREAM and (item.stream_id in {0, stream_id}):
            reset = True
        elif item.type == DATA and item.stream_id == stream_id:
            body.extend(item.payload)
        elif item.type in {HEADERS, CONTINUATION} and item.stream_id == stream_id:
            decoded = decode_headers(item.payload, dynamic=dynamic)
            for name, value in decoded.headers:
                if name == "grpc-status":
                    status = value
    return (status or "", bytes(body), reset)


async def _candidate_grpc_ports(ctx: CheckContext, host: str) -> tuple[int, ...]:
    """Ports worth probing for gRPC: the catalogue's ``grpc`` entries plus open-port hints."""
    declared = catalog_ports_for_probe(ctx, "grpc") or (50051,)
    return _candidate_ports(ctx, host, declared)


@dataclass(frozen=True, slots=True)
class _GrpcTarget:
    host: str
    port: int


async def _targets(ctx: CheckContext) -> tuple[_GrpcTarget, ...]:
    """Up to four (host, port) pairs, bounded by the configured host cap."""
    hosts = _hosts_for(ctx)
    out: list[_GrpcTarget] = []
    for host in hosts:
        for port in await _candidate_grpc_ports(ctx, host):
            out.append(_GrpcTarget(host, port))
            if len(out) >= 4:
                return tuple(out)
    return tuple(out)


class _GrpcProbe:
    """Shared run loop: one HTTP/2 preface per candidate port, then a facet-specific reading.

    A plain mixin, not a ``Module``: every concrete check declares its own metadata, and this
    class only carries the plumbing they share (mix it in *after* ``NetworkCheck`` and before
    ``Module``, the way the other M2 checks order their bases).
    """

    async def _probe(
        self, ctx: CheckContext, target: _GrpcTarget, payload: bytes, *, reads: int = 3
    ) -> tuple[Frame, ...]:
        client = ctx.net
        assert client is not None
        exchange = await client.tcp(target.host, target.port, payload=payload, reads=reads)
        if not exchange.is_open:
            return ()
        return parse_frames(exchange.banner)

    async def _preflight(
        self, ctx: CheckContext
    ) -> tuple[tuple[_GrpcTarget, ...] | None, CheckResult | None]:
        """``(targets, None)`` or ``(None, skipped)`` for the common preconditions."""
        _client, skipped = net_or_skip(ctx)
        if skipped is not None:
            return None, skipped
        _inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            return None, skipped
        targets = await _targets(ctx)
        if not targets:
            return None, skip_result(ctx, f"no probed host for asset {ctx.asset.key}")
        return targets, None


# --------------------------------------------------------------------------- plaintext
class GrpcPlaintext(NetworkCheck, _GrpcProbe, Module):
    """``m2.grpc-plaintext`` — cleartext HTTP/2 accepted (research ch02#12)."""

    metadata = CheckMetadata(
        id="m2.grpc-plaintext",
        module="M2",
        name="grpc-plaintext",
        version="1.0",
        title="gRPC cleartext HTTP/2 acceptance",
        description=(
            "Sends the HTTP/2 connection preface (h2c prior knowledge) and reports a server "
            "that answers with a SETTINGS frame, which means it speaks cleartext HTTP/2 and "
            "every gRPC call and its metadata travel unencrypted."
        ),
        research_ref="ch02#12",
        cwe="CWE-319",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        targets, skipped = await self._preflight(ctx)
        if skipped is not None:
            yield skipped
            return
        assert targets is not None
        findings = 0
        probed = 0
        for target in targets:
            frames = await self._probe(ctx, target, CLIENT_PREFACE + frame(SETTINGS, 0, 0), reads=1)
            probed += 1
            if not any(item.type == SETTINGS for item in frames):
                continue
            findings += 1
            yield ctx.candidate(
                f"cleartext HTTP/2 (h2c) accepted on {target.host}:{target.port}",
                detail=(
                    "the server answered the HTTP/2 connection preface with a SETTINGS frame, "
                    "so it accepts cleartext HTTP/2 with prior knowledge. A gRPC service on "
                    "this port carries its method, its message bodies and its metadata — "
                    "including any authorization header — in the clear (research ch02#12)."
                ),
                cwe="CWE-319",
                confidence=0.8,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "host": target.host,
                            "port": target.port,
                            "protocol": "h2c",
                            "settings_frames": sum(1 for item in frames if item.type == SETTINGS),
                            "frames_seen": [item.type for item in frames],
                        },
                        source=f"{target.host}:{target.port}/tcp",
                    )
                ],
            )
        if not findings:
            yield ctx.clean(
                "no cleartext HTTP/2 acceptance observed",
                detail=(
                    f"sent the HTTP/2 preface to {probed} candidate port(s); none answered "
                    "with a SETTINGS frame"
                ),
                confidence=0.6,
            )


# --------------------------------------------------------------------------- reflection
class GrpcReflection(NetworkCheck, _GrpcProbe, Module):
    """``m2.grpc-reflection`` — server reflection enabled (research ch02#9)."""

    metadata = CheckMetadata(
        id="m2.grpc-reflection",
        module="M2",
        name="grpc-reflection",
        version="1.0",
        title="gRPC server reflection exposure",
        description=(
            "Calls the standard gRPC reflection method over cleartext HTTP/2 and reports a "
            "server that answers it, publishing its whole service definition — message shapes, "
            "field names and method signatures — to any client that asks."
        ),
        research_ref="ch02#9-10",
        cwe="CWE-200",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        targets, skipped = await self._preflight(ctx)
        if skipped is not None:
            yield skipped
            return
        assert targets is not None
        findings = 0
        probed = 0
        for target in targets:
            authority = f"{target.host}:{target.port}"
            block = _grpc_request_headers(REFLECTION_PATH, authority=authority, metadata=[])
            # The reflection request with an empty ``list_services`` field: field 7, wire type
            # 2, zero length. It asks the server to enumerate its own services.
            request = b"\x3a\x00"
            frames = await self._probe(ctx, target, _probe_payload(block, request), reads=3)
            probed += 1
            if not frames:
                continue
            status, body, reset = _response_view(frames)
            if reset and status != "0":
                continue
            messages = grpc_messages(body)
            if not messages:
                continue
            descriptor = b"".join(messages)
            answered = (
                b"reflection" in descriptor.lower()
                or b"ServerReflection" in descriptor
                or status == "0"
            )
            if not answered:
                continue
            findings += 1
            yield ctx.candidate(
                f"gRPC server reflection answered on {target.host}:{target.port}",
                detail=(
                    "the standard reflection method returned a response "
                    f"({'grpc-status 0' if status == '0' else 'a descriptor payload'}), so any "
                    "client that can reach this port can enumerate every service, message and "
                    "field the server implements. Reflection is a development feature: disable "
                    "it in production, or restrict it to an authenticated management plane "
                    "(research ch02#9)."
                ),
                cwe="CWE-200",
                confidence=0.8,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "host": target.host,
                            "port": target.port,
                            "protocol": "grpc",
                            "method": REFLECTION_PATH,
                            "grpc_status": status or "unknown",
                            "response_bytes": len(body),
                            "descriptor_like": b"reflection" in descriptor.lower(),
                        },
                        source=f"{target.host}:{target.port}/tcp",
                    )
                ],
            )
        if not findings:
            yield ctx.clean(
                "no gRPC reflection response observed",
                detail=(
                    f"called the reflection method on {probed} candidate port(s); none "
                    "returned a descriptor response"
                ),
                confidence=0.6,
            )


# --------------------------------------------------------------------------- metadata leak
class GrpcMetadataLeak(NetworkCheck, _GrpcProbe, Module):
    """``m2.grpc-metadata-leak`` — request metadata echoed back (research ch02#12)."""

    metadata = CheckMetadata(
        id="m2.grpc-metadata-leak",
        module="M2",
        name="grpc-metadata-leak",
        version="1.0",
        title="gRPC request metadata leakage",
        description=(
            "Attaches a unique inert nonce as authorization and x-arachne-nonce metadata and "
            "reports a response that carries the nonce back: a server that echoes request "
            "metadata leaks credentials into its responses."
        ),
        research_ref="ch02#12",
        cwe="CWE-522",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        targets, skipped = await self._preflight(ctx)
        if skipped is not None:
            yield skipped
            return
        assert targets is not None
        findings = 0
        probed = 0
        for target in targets:
            nonce = f"ar9x{target.port:05d}{target.host.replace('.', '')[:6]}"
            authority = f"{target.host}:{target.port}"
            # The nonce is inert: it is not a credential, it authorizes nothing, and it is
            # unique per probe so a cached or pre-existing value cannot be mistaken for a
            # reflection.
            block = _grpc_request_headers(
                HEALTH_PATH,
                authority=authority,
                metadata=[
                    ("authorization", f"Bearer {nonce}"),
                    ("x-arachne-nonce", nonce),
                ],
            )
            frames = await self._probe(ctx, target, _probe_payload(block, b"\x0a\x00"), reads=3)
            probed += 1
            if not frames:
                continue
            status, body, _reset = _response_view(frames)
            if nonce.encode("ascii") not in body:
                continue
            findings += 1
            yield ctx.candidate(
                f"gRPC metadata echoed back on {target.host}:{target.port}",
                detail=(
                    "the response body carries the inert marker this check sent as request "
                    "metadata, so the server copies caller metadata into what it returns. In a "
                    "real deployment that means an authorization header can land in logs, a "
                    "shared cache, a proxy's response or another caller's view (research "
                    "ch02#12). The marker is not a credential and proved no access: it only "
                    "shows the echo."
                ),
                cwe="CWE-522",
                confidence=0.7,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "host": target.host,
                            "port": target.port,
                            "protocol": "grpc",
                            "method": HEALTH_PATH,
                            "marker_echoed": True,
                            "grpc_status": status or "unknown",
                            "response_bytes": len(body),
                        },
                        source=f"{target.host}:{target.port}/tcp",
                    )
                ],
            )
        if not findings:
            yield ctx.clean(
                "no gRPC request metadata echoed back",
                detail=(
                    f"attached an inert marker to {probed} candidate port(s); no response "
                    "carried it back"
                ),
                confidence=0.5,
            )
