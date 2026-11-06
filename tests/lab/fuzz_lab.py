"""The fuzzing lab: ARC/1, a small binary record protocol with a **planted parsing bug** (S30).

Every other lab in this directory is a *detection* fixture: it is deliberately vulnerable so a
check can be scored against declared ground truth. This one is a *parser* fixture, because that
is what a fuzzer needs: a real service, speaking a real length-prefixed protocol, whose parser
has one specific defect that well-formed traffic never reaches and a grammar-aware mutation does.

**The protocol (ARC/1 — ARACHNE Record Channel).** A request is an 8-byte header plus a body::

    request                           response
    0   u8  magic 0xA1                0   u8  magic 0xA2
    1   u8  version 1                 1   u8  version 1
    2   u16 request-id (big-endian)   2   u16 request-id (echoed)
    4   u8  opcode                    4   u8  status
    5   u8  flags                     5   u8  reserved
    6   u16 body-length               6   u16 body-length
    8   body                          8   body

Opcodes are ``1`` STATS (no body), ``2`` LOOKUP (``u16 key-length`` + key) and ``3`` LIST
(``u8 count``). Statuses are ``0`` OK, ``1`` BAD_OPCODE, ``2`` BAD_LENGTH, ``3`` INTERNAL_FAULT,
``4`` UNSUPPORTED_VERSION. Every one of them is a legitimate answer: the service reports its own
faults and stays up, exactly as a real daemon does.

**The planted bug** is in :meth:`ArcServer._lookup` and it is the single most common parser defect
there is: the ``key-length`` field is trusted for *the index arithmetic* as well as for the key
slice, so a declared length the body does not deliver indexes off the end of the record table and
raises. ``tests/helpers/fuzz.py`` reaches it with a grammar-declared mutation — ``key-length``
with the ``length-max`` operator, an all-ones ``u16`` — which is a well-framed ARC/1 message whose
length field is internally inconsistent. The service answers status ``3`` and keeps serving.

**Induced degradation** is the fixture's second job (REQ-FUZZ-005's acceptance). ``inject_*``
turns on a fault mode for the *next* requests, so a test can prove the abort guard fires: ``drop``
closes connections without answering (transport failures), ``slow`` delays every answer (the
latency ratio), ``fault`` answers status 3 to everything including the health probe (the error
rate). ``clear_degradation()`` restores normal service — which is what lets a test show the
service was healthy again afterwards.

The fixture is loopback-only and opens no outbound socket: it is a server, and the only thing that
connects to it is the run under test.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final, Literal

__all__ = [
    "ARC_MAGIC_REQUEST",
    "ARC_MAGIC_RESPONSE",
    "ARC_RECORDS",
    "LAB_VERSION",
    "STATUS_BAD_LENGTH",
    "STATUS_BAD_OPCODE",
    "STATUS_INTERNAL_FAULT",
    "STATUS_OK",
    "STATUS_UNSUPPORTED_VERSION",
    "ArcLabFixture",
    "ArcServer",
    "DegradationMode",
    "arc_stats_request",
    "start_arc_lab",
]

LAB_VERSION: Final = "1.0"

ARC_MAGIC_REQUEST: Final = 0xA1
ARC_MAGIC_RESPONSE: Final = 0xA2
ARC_VERSION: Final = 1

STATUS_OK: Final = 0
STATUS_BAD_OPCODE: Final = 1
STATUS_BAD_LENGTH: Final = 2
STATUS_INTERNAL_FAULT: Final = 3
STATUS_UNSUPPORTED_VERSION: Final = 4

OPCODE_STATS: Final = 1
OPCODE_LOOKUP: Final = 2
OPCODE_LIST: Final = 3

#: The record table a LOOKUP indexes into. Four entries, which is what makes ``key-length``
#: values at or above 8 walk off the end.
ARC_RECORDS: Final[tuple[str, ...]] = ("alpha", "bravo", "charlie", "delta")

#: The largest request this service will read. A fuzzer that sends more than this is not
#: exercising the parser, and the fixture refuses rather than allocating.
MAX_REQUEST_BYTES: Final = 8192

DegradationMode = Literal["drop", "slow", "fault"]


def arc_request(
    opcode: int,
    body: bytes = b"",
    *,
    request_id: int = 1,
    version: int = ARC_VERSION,
) -> bytes:
    """A well-formed ARC/1 request, for a test that wants one by hand."""
    return (
        struct.pack(">BBHBBH", ARC_MAGIC_REQUEST, version, request_id, opcode, 0, len(body)) + body
    )


def arc_stats_request(*, request_id: int = 1) -> bytes:
    """The health probe's request: STATS, which any healthy ARC/1 service answers."""
    return arc_request(OPCODE_STATS, request_id=request_id)


def arc_lookup_request(key: bytes, *, request_id: int = 1) -> bytes:
    """A well-formed LOOKUP for ``key``."""
    return arc_request(OPCODE_LOOKUP, struct.pack(">H", len(key)) + key, request_id=request_id)


@dataclass
class ArcServer:
    """The ARC/1 service. One request per connection, as the client's probe shape implies."""

    records: tuple[str, ...] = ARC_RECORDS
    #: Validate the declared key length against the body before using it (the *correct* parser).
    #: Off by default, because the defect is exactly this check being absent — so flipping it on
    #: is what proves a candidate came from the missing validation rather than from the protocol.
    strict: bool = False
    #: Induced degradation, if a test turned it on.
    degrade_mode: DegradationMode | None = None
    #: How many *more* requests the degradation applies to (``None``: until cleared).
    degrade_remaining: int | None = None
    degrade_delay_s: float = 0.0
    #: When set, the degradation is armed but inert until the service has answered this many
    #: requests. That is what makes induced degradation reachable *mid-run*: the baseline and
    #: the first cases see a healthy service, and the guard's job is to notice what follows.
    degrade_after: int | None = None
    started_at: float = field(default_factory=time.monotonic)
    #: Counters a test asserts on.
    requests: int = 0
    stats: int = 0
    lookups: int = 0
    lists: int = 0
    faults: int = 0
    bad_lengths: int = 0
    bad_opcodes: int = 0
    dropped: int = 0
    slow: int = 0

    # ------------------------------------------------------------------ degradation
    def inject_degradation(
        self,
        mode: DegradationMode,
        *,
        requests: int | None = None,
        delay_s: float = 0.0,
    ) -> None:
        """Make the next ``requests`` answers misbehave (``None``: until cleared)."""
        self.degrade_mode = mode
        self.degrade_remaining = requests
        self.degrade_delay_s = delay_s

    def arm_degradation(
        self,
        mode: DegradationMode,
        *,
        after_requests: int,
        delay_s: float = 0.0,
    ) -> None:
        """Serve ``after_requests`` more requests normally, then misbehave.

        This is what a test uses to induce degradation *mid-run*: the target is genuinely healthy
        for the baseline and the first cases, and then stops coping — which is the situation the
        abort guard exists for. Arming it before the run instead would only prove the
        refuse-to-start path (a target already failing is not fuzzed at all).
        """
        self.degrade_mode = mode
        self.degrade_remaining = None
        self.degrade_delay_s = delay_s
        self.degrade_after = self.requests + after_requests

    def clear_degradation(self) -> None:
        self.degrade_mode = None
        self.degrade_remaining = None
        self.degrade_delay_s = 0.0
        self.degrade_after = None

    def _degrading(self) -> DegradationMode | None:
        if self.degrade_mode is None:
            return None
        if self.degrade_after is not None and self.requests < self.degrade_after:
            return None
        if self.degrade_remaining is not None:
            if self.degrade_remaining <= 0:
                return None
            self.degrade_remaining -= 1
        return self.degrade_mode

    @property
    def uptime_s(self) -> int:
        return int(time.monotonic() - self.started_at)

    # ------------------------------------------------------------------ protocol
    def handle(self, data: bytes) -> bytes | None:
        """Answer one request, or ``None`` to close without answering.

        ``None`` is what the ``drop`` degradation returns: a connection that was accepted and
        then abandoned is the transport-level signal the abort guard watches for.
        """
        mode = self._degrading()
        if mode == "drop":
            self.dropped += 1
            return None
        if mode == "slow":
            self.slow += 1
            time.sleep(self.degrade_delay_s)
        self.requests += 1
        if len(data) < 8:
            return self._respond(0, STATUS_BAD_LENGTH, b"short header", request_id=0)
        magic, version, request_id, opcode, _flags, body_length = struct.unpack(">BBHBBH", data[:8])
        if mode == "fault":
            self.faults += 1
            return self._respond(
                request_id, STATUS_INTERNAL_FAULT, b"induced", request_id=request_id
            )
        if magic != ARC_MAGIC_REQUEST:
            return self._respond(request_id, STATUS_BAD_LENGTH, b"bad magic", request_id=request_id)
        if version != ARC_VERSION:
            return self._respond(request_id, STATUS_UNSUPPORTED_VERSION, b"", request_id=request_id)
        body = data[8 : 8 + body_length]
        if len(body) != body_length:
            self.bad_lengths += 1
            return self._respond(
                request_id, STATUS_BAD_LENGTH, b"body shorter than declared", request_id=request_id
            )
        try:
            if opcode == OPCODE_STATS:
                return self._stats(request_id)
            if opcode == OPCODE_LOOKUP:
                return self._lookup(request_id, body)
            if opcode == OPCODE_LIST:
                return self._list(request_id, body)
        except Exception as exc:  # a parser fault is data, not a fixture failure
            self.faults += 1
            return self._respond(
                request_id,
                STATUS_INTERNAL_FAULT,
                type(exc).__name__.encode(),
                request_id=request_id,
            )
        self.bad_opcodes += 1
        return self._respond(request_id, STATUS_BAD_OPCODE, b"", request_id=request_id)

    def _respond(self, _seen_id: int, status: int, body: bytes, *, request_id: int = 0) -> bytes:
        return (
            struct.pack(
                ">BBHBBH",
                ARC_MAGIC_RESPONSE,
                ARC_VERSION,
                request_id & 0xFFFF,
                status,
                0,
                len(body),
            )
            + body
        )

    def _stats(self, request_id: int) -> bytes:
        self.stats += 1
        body = f"records={len(self.records)};uptime_s={self.uptime_s}".encode()
        return self._respond(0, STATUS_OK, body, request_id=request_id)

    def _lookup(self, request_id: int, body: bytes) -> bytes:
        """LOOKUP — and the planted parsing bug.

        ``key_length`` is read from the body and used for two different things: to slice the key
        (where a short body is silently tolerated) and to derive the record index (where it is
        not). The field is never validated against the table's size, so a declared length the
        body does not deliver — an all-ones ``u16``, say — indexes past the end and raises. A
        real implementation validates the field against the table; this one trusts it, which is
        exactly the defect a fuzzer is for.
        """
        self.lookups += 1
        if len(body) < 2:
            return self._respond(request_id, STATUS_BAD_LENGTH, b"", request_id=request_id)
        key_length = struct.unpack(">H", body[:2])[0]
        # The key slice tolerates a short body (Python slicing does), which is what hides the
        # defect from well-formed traffic: only the index arithmetic below notices.
        key = body[2 : 2 + key_length]
        if self.strict and len(key) != key_length:
            # The check a correct parser makes, and the exact one this fixture omits.
            self.bad_lengths += 1
            return self._respond(
                request_id, STATUS_BAD_LENGTH, b"key shorter than declared", request_id=request_id
            )
        # PLANTED PARSING BUG: the promised length is used as an index, unchecked.
        index = key_length - len(self.records)
        record = self.records[index]
        assert key is not None  # the slice is read above; kept so the intended read is explicit
        return self._respond(
            request_id, STATUS_OK, f"{record}:{key_length}".encode(), request_id=request_id
        )

    def _list(self, request_id: int, body: bytes) -> bytes:
        self.lists += 1
        count = body[0] if body else 0
        if count > len(self.records):
            # A well-formed refusal: the service says no rather than guessing. This is the
            # behaviour the *fuzzer* must not mistake for a fault, and it is deliberate.
            return self._respond(
                request_id, STATUS_BAD_LENGTH, b"count exceeds table", request_id=request_id
            )
        body_out = b"".join(struct.pack(">H", index) for index in range(count))
        return self._respond(request_id, STATUS_OK, body_out, request_id=request_id)

    def reset_counters(self) -> None:
        for name in (
            "requests",
            "stats",
            "lookups",
            "lists",
            "faults",
            "bad_lengths",
            "bad_opcodes",
            "dropped",
            "slow",
        ):
            setattr(self, name, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": LAB_VERSION,
            "records": len(self.records),
            "requests": self.requests,
            "stats": self.stats,
            "lookups": self.lookups,
            "lists": self.lists,
            "faults": self.faults,
            "bad_lengths": self.bad_lengths,
            "bad_opcodes": self.bad_opcodes,
            "dropped": self.dropped,
            "slow": self.slow,
        }


class _ArcHandler(socketserver.BaseRequestHandler):
    """Reads one ARC/1 request and answers it. Never raises out of the handler."""

    server: _ArcTCPServer  # type: ignore[assignment]

    def handle(self) -> None:
        connection: socket.socket = self.request
        connection.settimeout(2.0)
        data = b""
        try:
            chunk = connection.recv(MAX_REQUEST_BYTES)
            if chunk:
                data += chunk
            if len(data) >= 8:
                declared = struct.unpack(">H", data[6:8])[0]
                if len(data) < 8 + declared:
                    # A service has a read deadline: it answers the bytes it has rather than
                    # waiting forever for a body a client declared and never delivered. That
                    # deadline is what makes an over-declared ``body-length`` a BAD_LENGTH
                    # answer — a parser-level fact — instead of a stalled connection, which
                    # would be a socket-level artifact and would tell a fuzzer nothing about the
                    # parser it is trying to exercise.
                    connection.settimeout(0.25)
                    try:
                        while len(data) < 8 + declared:
                            more = connection.recv(8 + declared - len(data))
                            if not more:
                                break
                            data += more
                    except (TimeoutError, OSError):
                        pass
        except (TimeoutError, OSError):
            return
        if not data:
            return
        response = self.server.arc.handle(data)
        if response is None:
            return
        try:
            connection.sendall(response)
        except OSError:
            return


class _ArcTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], arc: ArcServer) -> None:
        self.arc = arc
        super().__init__(address, _ArcHandler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        """Accept a connection with TCP_NODELAY: same loopback Nagle stall as the HTTP lab."""
        connection, address = super().get_request()
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return connection, address


@dataclass
class ArcLabFixture:
    """A running ARC/1 lab, and the counters a test asserts on."""

    host: str
    port: int
    arc: ArcServer
    server: _ArcTCPServer
    _thread: threading.Thread

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    # ------------------------------------------------------------------ degradation helpers
    def inject_drop(self, *, requests: int | None = None) -> None:
        self.arc.inject_degradation("drop", requests=requests)

    def inject_slow(self, *, delay_s: float = 1.0, requests: int | None = None) -> None:
        self.arc.inject_degradation("slow", delay_s=delay_s, requests=requests)

    def inject_fault(self, *, requests: int | None = None) -> None:
        self.arc.inject_degradation("fault", requests=requests)

    def arm_drop_after(self, requests: int) -> None:
        """Drop every connection once the service has answered ``requests`` more requests."""
        self.arc.arm_degradation("drop", after_requests=requests)

    def arm_slow_after(self, requests: int, *, delay_s: float = 1.0) -> None:
        """Delay every answer once the service has answered ``requests`` more requests."""
        self.arc.arm_degradation("slow", after_requests=requests, delay_s=delay_s)

    def clear_degradation(self) -> None:
        self.arc.clear_degradation()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@contextmanager
def start_arc_lab() -> Iterator[ArcLabFixture]:
    """Start the ARC/1 lab on an ephemeral loopback port and yield it, stopping it on exit."""
    arc = ArcServer()
    server = _ArcTCPServer(("127.0.0.1", 0), arc)
    thread = threading.Thread(
        target=server.serve_forever, args=(0.05,), name="arc-lab", daemon=True
    )
    thread.start()
    host, port = server.server_address[:2]
    fixture = ArcLabFixture(host=host, port=port, arc=arc, server=server, _thread=thread)
    try:
        yield fixture
    finally:
        fixture.stop()
