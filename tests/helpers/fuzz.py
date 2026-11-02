"""The fuzzing wiring the S30 tests share (area FUZZ).

One place that builds what a fuzzing test needs — the ARC/1 lab grammar, an attested target
definition, a fuzzing attestation, a settings bundle that permits loopback, and a runner over a
real :class:`~arachne.core.net.ScopedNetClient` — so each test states a property of fuzzing
rather than re-deriving the wiring.

The ARC/1 grammar here is the point of the exercise: it is built with the *public*
:class:`~arachne.fuzz.grammar.MessageGrammar` API, in test code, for a test fixture's protocol.
A lab that could only be fuzzed by a grammar shipped in the product would prove nothing about the
interface an operator gets.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import (
    HttpSettings,
    NetSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.events import EventBus
from arachne.core.net import ScopedNetClient
from arachne.core.safety import Scope
from arachne.core.target import (
    AuthorizationAttestation,
    TargetDefinition,
    TargetKind,
    TargetSelector,
)
from arachne.fuzz.attestation import FuzzingAttestation
from arachne.fuzz.bounds import FuzzBudget
from arachne.fuzz.grammar import (
    FieldKind,
    FieldSpec,
    FramingSpec,
    MessageGrammar,
    ResponseReading,
)
from arachne.fuzz.runner import FuzzPlan, FuzzRunner, WireTargetSpec
from tests.lab.fuzz_lab import (
    ARC_MAGIC_RESPONSE,
    ARC_RECORDS,
    STATUS_INTERNAL_FAULT,
    STATUS_OK,
    ArcLabFixture,
    start_arc_lab,
)

__all__ = [
    "ARC_KEY",
    "ARC_REQUEST_ID",
    "arc1_grammar",
    "arc_budget",
    "arc_grammars_registered",
    "arc_plan",
    "arc_reading",
    "arc_target",
    "build_runner",
    "fuzz_attestation",
    "fuzz_definition",
    "fuzz_settings",
    "lab_arc",
]

#: The key the ARC/1 grammar's seed looks up, and the request id it uses. Fixed, so the seed is
#: byte-identical on every run and a reported case is reproducible.
ARC_KEY = b"alph"
ARC_REQUEST_ID = 0x1234

ARC_OP_STATS = 1
ARC_OP_LOOKUP = 2
ARC_OP_LIST = 3


def arc_reading(data: bytes) -> ResponseReading:
    """Read an ARC/1 response: status 3 is the planted parser fault, other statuses are refusals."""
    if len(data) < 8:
        return ResponseReading("unknown", "shorter than an ARC/1 header")
    magic, _version, _request_id, status, _reserved, body_length = struct.unpack(
        ">BBHBBH", data[:8]
    )
    if magic != ARC_MAGIC_RESPONSE:
        return ResponseReading("unknown", "not an ARC/1 response")
    body = data[8 : 8 + body_length]
    text = body.decode("latin-1", "replace")
    if status == STATUS_INTERNAL_FAULT:
        return ResponseReading("fault", f"ARC/1 internal fault: {text}")
    if status == STATUS_OK:
        return ResponseReading("ok", f"status 0, {text}")
    return ResponseReading("refused", f"ARC/1 status {status}: {text}")


def arc1_grammar() -> MessageGrammar:
    """The ARC/1 LOOKUP grammar, built with the public API.

    ``key-length`` is a declared length field inside the framed region, so the grammar recomputes
    the frame on every other mutation and leaves the length inconsistent only when the mutation
    *is* the length field — which is exactly the case that reaches the fixture's planted bug.
    """
    seed = _arc_seed()
    key_offset = 10
    key_length = len(seed) - key_offset
    return MessageGrammar(
        name="arc1.lookup",
        protocol="arc1",
        description=(
            "An ARC/1 record lookup: an 8-byte header (magic, version, request id, opcode, flags, "
            "body length) and a key-length-prefixed body."
        ),
        builder=_arc_seed,
        fields=(
            FieldSpec("magic", 0, 1, FieldKind.ENUM, values=(0xA1,)),
            FieldSpec("version", 1, 1, FieldKind.ENUM, values=(1, 2)),
            FieldSpec("request-id", 2, 2, FieldKind.ID),
            FieldSpec(
                "opcode",
                4,
                1,
                FieldKind.OPCODE,
                values=(ARC_OP_STATS, ARC_OP_LOOKUP, ARC_OP_LIST),
                description="the three read-only ARC/1 operations",
            ),
            FieldSpec("flags", 5, 1, FieldKind.U8),
            FieldSpec("body-length", 6, 2, FieldKind.LENGTH, description="the framed body"),
            FieldSpec(
                "key-length",
                8,
                2,
                FieldKind.LENGTH,
                description="the key's declared length — the field the parser trusts",
            ),
            FieldSpec("key", key_offset, key_length, FieldKind.OPAQUE),
        ),
        framings=(FramingSpec("body-length", start=8),),
        classify=arc_reading,
        verifier=None,
        response="binary",
    )


def _arc_seed() -> bytes:
    """The grammar's baseline: a well-formed LOOKUP for :data:`ARC_KEY`."""
    body = struct.pack(">H", len(ARC_KEY)) + ARC_KEY
    return struct.pack(">BBHBBH", 0xA1, 1, ARC_REQUEST_ID, ARC_OP_LOOKUP, 0, len(body)) + body


def fuzz_settings(*, extended: bool = True) -> Settings:
    """Settings a loopback lab scan needs: the permissive-local policy and high rate limits."""
    return Settings(
        safety=SafetySettings.permissive_local(),
        net=NetSettings(allow_udp=True),
        http=HttpSettings(),
        rate_limit=RateLimitSettings(
            per_host_rate=500.0, per_host_burst=500, global_rate=500.0, global_burst=500
        ),
        actor="pytest",
    )


def fuzz_definition(
    *, name: str = "fuzz-lab", targets: tuple[str, ...] = ("127.0.0.1",)
) -> TargetDefinition:
    """An attested target definition for a loopback lab (the *inherited* gate)."""
    return TargetDefinition(
        name=name,
        targets=tuple(TargetSelector(kind=TargetKind.IP, value=value) for value in targets),
        attestation=AuthorizationAttestation(
            attested_by="pytest <pytest@example.test>",
            attested_at=datetime(2026, 10, 1, tzinfo=UTC),
            scope_statement="Unit-test authorization for the loopback fuzzing lab",
            authorization_ref="LAB-FUZZ-1",
            allowed_targets=list(targets),
            active_checks_authorized=True,
        ),
    )


def fuzz_attestation(
    *,
    targets: tuple[str, ...] = ("127.0.0.1",),
    environment: str = "lab",
    allow_production: bool = False,
    **overrides: Any,
) -> FuzzingAttestation:
    """The area's own grant: non-production by default, covering ``targets``."""
    payload: dict[str, Any] = {
        "attested_by": "pytest <pytest@example.test>",
        "attested_at": datetime(2026, 10, 1, tzinfo=UTC),
        "scope_statement": "Unit-test authorization to fuzz the loopback lab",
        "allowed_targets": list(targets),
        "environment": environment,
        "allow_production": allow_production,
        "authorization_ref": "LAB-FUZZ-1",
    }
    payload.update(overrides)
    return FuzzingAttestation(**payload)


def arc_target(fixture: ArcLabFixture, **overrides: Any) -> WireTargetSpec:
    payload: dict[str, Any] = {
        "label": "arc1-lab",
        "grammar": "arc1.lookup",
        "host": fixture.host,
        "port": fixture.port,
    }
    payload.update(overrides)
    return WireTargetSpec(**payload)


def arc_budget(**overrides: Any) -> FuzzBudget:
    payload: dict[str, Any] = {
        "max_cases": 40,
        "max_requests": 80,
        "max_seconds": 30.0,
        "batch_size": 10,
    }
    payload.update(overrides)
    return FuzzBudget(**payload)


def arc_plan(
    fixture: ArcLabFixture,
    *,
    definition: TargetDefinition | None = None,
    attestation: FuzzingAttestation | None = None,
    budget: FuzzBudget | None = None,
    engine: str | None = None,
    **target_overrides: Any,
) -> FuzzPlan:
    return FuzzPlan(
        definition=definition or fuzz_definition(),
        attestation=attestation if attestation is not None else fuzz_attestation(),
        wire_targets=(arc_target(fixture, **target_overrides),),
        budget=budget or arc_budget(),
        engine=engine,
    )


@dataclass
class FuzzHarness:
    """A runner, its audit sink and the grammars it can reach."""

    settings: Settings
    scope: Scope
    sink: MemoryAuditSink
    auditor: Auditor
    bus: EventBus
    runner: FuzzRunner
    net: ScopedNetClient
    grammars: dict[str, MessageGrammar] = field(default_factory=dict)

    def actions(self) -> list[str]:
        return [event.action.value for event in self.sink.events]

    def audit_meta(self, action: str) -> list[dict[str, Any]]:
        """The ``meta`` of every audit event with ``action``, in order."""
        return [
            dict(event.meta or {}) for event in self.sink.events if event.action.value == action
        ]


def build_runner(
    *,
    settings: Settings | None = None,
    definition: TargetDefinition | None = None,
    grammars: dict[str, MessageGrammar] | None = None,
    **runner_kwargs: Any,
) -> FuzzHarness:
    """A runner over a real scoped client, ready for a run.

    The ARC/1 grammar is *not* registered here: the runner resolves grammars at run time, so a
    test wraps both this call and ``runner.run(...)`` in :func:`arc_grammars_registered`.
    """
    resolved_settings = settings or fuzz_settings()
    resolved_definition = definition or fuzz_definition()
    scope = resolved_definition.compile_scope()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    bus = EventBus()
    net = ScopedNetClient(settings=resolved_settings, scope=scope, auditor=auditor)
    runner = FuzzRunner(
        settings=resolved_settings,
        scope=scope,
        auditor=auditor,
        bus=bus,
        net_factory=lambda _scope: net,
        **runner_kwargs,
    )
    return FuzzHarness(
        settings=resolved_settings,
        scope=scope,
        sink=sink,
        auditor=auditor,
        bus=bus,
        runner=runner,
        net=net,
        grammars=grammars or {"arc1.lookup": arc1_grammar()},
    )


@contextmanager
def arc_grammars_registered(
    grammars: dict[str, MessageGrammar] | None = None,
) -> Iterator[dict[str, MessageGrammar]]:
    """Register the lab grammars for the duration of a run, then take them back out.

    The product's grammar table is restored exactly, so a test that adds a lab protocol cannot
    leak it into another test — and the shipped set stays what a deployment ships.
    """
    from arachne.fuzz import wire as fuzz_wire

    resolved = dict(grammars or {"arc1.lookup": arc1_grammar()})
    added = [name for name in resolved if name not in fuzz_wire.GRAMMARS]
    original = {name: fuzz_wire.GRAMMARS[name] for name in added if name in fuzz_wire.GRAMMARS}
    for name, grammar in resolved.items():
        fuzz_wire.GRAMMARS[name] = grammar
    try:
        yield resolved
    finally:
        for name in resolved:
            if name in original:
                fuzz_wire.GRAMMARS[name] = original[name]
            elif name in added:
                fuzz_wire.GRAMMARS.pop(name, None)


@contextmanager
def lab_arc() -> Iterator[ArcLabFixture]:
    with start_arc_lab() as fixture:
        yield fixture


#: The record table the lab serves, re-exported so a test can be explicit about what it indexes.
RECORDS = ARC_RECORDS
