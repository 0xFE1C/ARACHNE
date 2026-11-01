"""Message grammars and grammar-aware mutation (S30, area FUZZ, REQ-FUZZ-001/002).

A grammar is a *declaration of a message's structure*: which byte ranges are the operation
code, the length, an identifier, free text, opaque payload. The engine mutates the declared
ranges and nothing else, which is what "mutate M2 wire messages within their grammars"
(REQ-FUZZ-002) means in practice — the fuzzer produces messages that are still *messages*,
with well-formed framing and a legal operation code, and puts the pressure on the field values
a parser is least likely to have handled: a length one greater than the body, an all-ones
count, a truncated field, a quote where a hostname was expected.

Three properties are enforced here rather than left to the engine:

**The operation field never leaves its allowlist.** A field of kind :attr:`FieldKind.OPCODE`
carries declared ``values``, and the constructor refuses any value that is not a read-only
operation of its protocol (:func:`~arachne.fuzz.prohibitions.grammar_operation_problems`). The
mutation operators for such a field draw from those declarations only, so no mutation —
present or future — can make a grammar issue a state-changing operation.

**Every generated payload passes the prohibition table.** Cases are built by
:meth:`MessageGrammar.build_case`, which calls
:func:`~arachne.fuzz.prohibitions.require_non_destructive` on the exact bytes it is about to
return. A payload the table refuses raises before it is ever handed to a transport, so there
is no code path from "the engine generated something prohibited" to "a socket saw it".

**Framing is recomputed, not corrupted.** When a field *inside* a message's length-covered
region is mutated, the declared length field is recomputed from the mutated payload, so the
result is still a well-framed message. When the length field itself is the target, the length
is deliberately left inconsistent with the body — that inconsistency *is* the test case, and
it is the single most productive class of parser bug there is.

The seed message of every grammar comes from the real builders in
:mod:`arachne.modules.m2.wire`, the same bytes the shipped M2 checks send: a fuzzer that
generated its own idea of what an SNMP GetRequest looks like would be testing that idea rather
than the target.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Literal

from arachne.core.errors import ConfigurationError, FuzzPayloadRefused
from arachne.fuzz.prohibitions import (
    grammar_operation_problems,
    operation_is_destructive,
    require_non_destructive,
)

__all__ = [
    "MAX_PAYLOAD_BYTES",
    "OPERATORS_BY_KIND",
    "RESPONSE_OUTCOMES",
    "ChecksumSpec",
    "FieldKind",
    "FieldSpec",
    "FramingSpec",
    "FuzzCase",
    "MessageGrammar",
    "MutationOperator",
    "ResponseReading",
]

#: The largest payload a mutation may produce. A grammar-aware mutation cannot grow a message
#: much, but an operator that repeats or extends a region can, and a fuzzer that hands a target
#: a megabyte because an operator looped is a fuzzer that disrupts by accident.
MAX_PAYLOAD_BYTES: Final = 4096


class FieldKind(StrEnum):
    """What a declared byte range is, which decides how it may be mutated.

    The kind is the grammar's statement about the *meaning* of a range, and the mutation
    operators are chosen from it: a length behaves like a length, an operation code stays
    inside its allowlist, an identifier is barely touched.
    """

    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    #: A framing length field. Mutating one *desynchronizes* the frame on purpose.
    LENGTH = "length"
    #: An operation code. Mutations stay inside the declared read-only allowlist.
    OPCODE = "opcode"
    #: A small closed set of meaningful values (a PDU tag, a dialect, a version).
    ENUM = "enum"
    #: A correlation identifier: a request id, a transaction id, a message id.
    ID = "id"
    #: Free text (a hostname, a community string, a path).
    TEXT = "text"
    #: Bytes with no meaning the grammar can name: padding, a nonce, a session id.
    OPAQUE = "opaque"


NUMERIC_KINDS: Final[frozenset[FieldKind]] = frozenset(
    {FieldKind.U8, FieldKind.U16, FieldKind.U32}
)
_WIDTH_BY_KIND: Final[Mapping[FieldKind, int]] = {
    FieldKind.U8: 1,
    FieldKind.U16: 2,
    FieldKind.U32: 4,
}


class MutationOperator(StrEnum):
    """One named way to change one declared field.

    Named, closed and enumerable rather than random: a report says *what* was tried ("the
    length field one greater than the body"), a run is reproducible from its case list, and a
    test can assert that a specific operator still produces the specific bytes it produced
    yesterday. Each operator is a hypothesis about what a parser forgot to check.
    """

    # Numeric boundary values.
    ZERO = "zero"
    ONE = "one"
    MAX = "max"
    MAX_MINUS_ONE = "max-minus-one"
    PLUS_ONE = "plus-one"
    MINUS_ONE = "minus-one"
    # Framing length fields: the inconsistency *is* the case.
    LENGTH_ZERO = "length-zero"
    LENGTH_OVER = "length-over"
    LENGTH_UNDER = "length-under"
    LENGTH_MAX = "length-max"
    # Operation codes and closed sets: a different *legal* value.
    ALTERNATE_VALUE = "alternate-value"
    VALUE_FIRST = "value-first"
    VALUE_LAST = "value-last"
    # Text boundaries.
    TEXT_EMPTY = "text-empty"
    TEXT_LONG = "text-long"
    TEXT_QUOTE = "text-quote"
    TEXT_ANGLE = "text-angle"
    TEXT_PERCENT = "text-percent"
    TEXT_CRLF = "text-crlf"
    # Region shape.
    DROP_FIELD = "drop-field"
    REPEAT_FIELD = "repeat-field"
    EXTEND_FIELD = "extend-field"
    #: Length-preserving region fills, for an opaque field inside a frame that must keep its
    #: size (a session id, a nonce, an extension block): "what does this parser do with a
    #: region that is entirely zeros / entirely ones" without moving any later offset.
    FILL_ZERO = "fill-zero"
    FILL_MAX = "fill-max"
    # A checksum field: break the transport integrity check on purpose.
    CORRUPT_CHECKSUM = "corrupt-checksum"


#: Which operators apply to which kind. The single source of truth for "may this mutation be
#: asked for at all"; :meth:`MessageGrammar.operators` filters this further by framing.
OPERATORS_BY_KIND: Final[Mapping[FieldKind, tuple[MutationOperator, ...]]] = {
    FieldKind.U8: (
        MutationOperator.ZERO,
        MutationOperator.ONE,
        MutationOperator.MAX,
        MutationOperator.MAX_MINUS_ONE,
        MutationOperator.PLUS_ONE,
        MutationOperator.MINUS_ONE,
    ),
    FieldKind.U16: (
        MutationOperator.ZERO,
        MutationOperator.ONE,
        MutationOperator.MAX,
        MutationOperator.MAX_MINUS_ONE,
        MutationOperator.PLUS_ONE,
        MutationOperator.MINUS_ONE,
    ),
    FieldKind.U32: (
        MutationOperator.ZERO,
        MutationOperator.ONE,
        MutationOperator.MAX,
        MutationOperator.MAX_MINUS_ONE,
        MutationOperator.PLUS_ONE,
        MutationOperator.MINUS_ONE,
    ),
    FieldKind.LENGTH: (
        MutationOperator.LENGTH_ZERO,
        MutationOperator.LENGTH_OVER,
        MutationOperator.LENGTH_UNDER,
        MutationOperator.LENGTH_MAX,
        MutationOperator.MAX_MINUS_ONE,
    ),
    FieldKind.OPCODE: (
        MutationOperator.ALTERNATE_VALUE,
        MutationOperator.VALUE_FIRST,
        MutationOperator.VALUE_LAST,
    ),
    FieldKind.ENUM: (
        MutationOperator.ALTERNATE_VALUE,
        MutationOperator.VALUE_FIRST,
        MutationOperator.VALUE_LAST,
    ),
    FieldKind.ID: (MutationOperator.ZERO, MutationOperator.MAX),
    FieldKind.TEXT: (
        MutationOperator.TEXT_EMPTY,
        MutationOperator.TEXT_LONG,
        MutationOperator.TEXT_QUOTE,
        MutationOperator.TEXT_ANGLE,
        MutationOperator.TEXT_PERCENT,
        MutationOperator.TEXT_CRLF,
    ),
    FieldKind.OPAQUE: (
        MutationOperator.FILL_ZERO,
        MutationOperator.FILL_MAX,
        MutationOperator.DROP_FIELD,
        MutationOperator.REPEAT_FIELD,
        MutationOperator.EXTEND_FIELD,
    ),
}

#: The fixed replacement value of each text operator.
_TEXT_BOUNDARIES: Final[Mapping[MutationOperator, bytes]] = {
    MutationOperator.TEXT_EMPTY: b"",
    MutationOperator.TEXT_LONG: b"a" * 255,
    MutationOperator.TEXT_QUOTE: b"'\"",
    MutationOperator.TEXT_ANGLE: b"<>",
    MutationOperator.TEXT_PERCENT: b"%00",
    MutationOperator.TEXT_CRLF: b"\r\n\r\n",
}

#: Operators that change the payload's length (and therefore need the framing rules below).
_LENGTH_CHANGING: Final[frozenset[MutationOperator]] = frozenset(
    {
        MutationOperator.TEXT_EMPTY,
        MutationOperator.TEXT_LONG,
        MutationOperator.TEXT_QUOTE,
        MutationOperator.TEXT_ANGLE,
        MutationOperator.TEXT_PERCENT,
        MutationOperator.TEXT_CRLF,
        MutationOperator.DROP_FIELD,
        MutationOperator.REPEAT_FIELD,
        MutationOperator.EXTEND_FIELD,
    }
)


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One declared byte range of a message."""

    name: str
    offset: int
    width: int
    kind: FieldKind = FieldKind.OPAQUE
    #: Legal values, required for :attr:`FieldKind.OPCODE` and :attr:`FieldKind.ENUM`.
    values: tuple[int, ...] = ()
    description: str = ""
    #: Byte order of a numeric field. Network protocols are mostly big-endian, but DNP3, RDP's
    #: negotiation block and NTLM's security buffers are little-endian, and a grammar that read
    #: those big-endian would compute nonsense for the ``plus-one``/``minus-one`` operators.
    endian: Literal["big", "little"] = "big"

    def __post_init__(self) -> None:
        if not self.name:
            msg = "a field needs a name"
            raise ConfigurationError(msg)
        if self.offset < 0:
            msg = f"field {self.name}: offset must be >= 0"
            raise ConfigurationError(msg)
        if self.width < 1:
            msg = f"field {self.name}: width must be >= 1"
            raise ConfigurationError(msg)
        if self.endian not in ("big", "little"):
            msg = f"field {self.name}: endian must be 'big' or 'little'"
            raise ConfigurationError(msg)
        expected = _WIDTH_BY_KIND.get(self.kind)
        if expected is not None and self.width != expected:
            msg = (
                f"field {self.name}: kind {self.kind.value} needs width {expected}, "
                f"got {self.width}"
            )
            raise ConfigurationError(msg)
        if self.kind in (FieldKind.OPCODE, FieldKind.ENUM) and not self.values:
            msg = f"field {self.name}: kind {self.kind.value} needs a non-empty values list"
            raise ConfigurationError(msg)
        if self.kind not in (FieldKind.OPCODE, FieldKind.ENUM) and self.values:
            msg = (
                f"field {self.name}: only an opcode or enum field may declare values "
                f"(got {self.kind.value})"
            )
            raise ConfigurationError(msg)
        if self.values:
            limit = 1 << (8 * self.width)
            for value in self.values:
                if not 0 <= value < limit:
                    msg = f"field {self.name}: value {value} does not fit in {self.width} byte(s)"
                    raise ConfigurationError(msg)
            if len(set(self.values)) != len(self.values):
                msg = f"field {self.name}: duplicate declared values"
                raise ConfigurationError(msg)

    @property
    def end(self) -> int:
        return self.offset + self.width

    def read(self, payload: bytes) -> int:
        """The field's current value in ``payload``, in the field's own byte order."""
        region = payload[self.offset : self.end]
        if len(region) != self.width:
            msg = f"field {self.name}: payload is shorter than the field ({len(payload)} bytes)"
            raise ConfigurationError(msg)
        return int.from_bytes(region, self.endian)

    def encode(self, value: int) -> bytes:
        return value.to_bytes(self.width, self.endian)

    def covers(self, offset: int) -> bool:
        return self.offset <= offset < self.end

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "offset": self.offset,
            "width": self.width,
            "kind": self.kind.value,
        }
        if self.values:
            payload["values"] = list(self.values)
        if self.endian != "big":
            payload["endian"] = self.endian
        if self.description:
            payload["description"] = self.description
        return payload


@dataclass(frozen=True, slots=True)
class FramingSpec:
    """A length field and the region it counts.

    ``adjustment`` is what is added to the region's byte length to get the value the field
    should hold: ``0`` for the common "length prefix covers everything after it" shape, and the
    size of an excluded header otherwise. ``end`` is the region's last byte, or ``None`` when
    the region runs to the end of the message — which is also what decides whether
    length-changing mutations are offered (see :meth:`MessageGrammar.operators`).

    A grammar keeps this honest by validating the seed against it (see
    :meth:`MessageGrammar.__post_init__`), so a wrong adjustment is a configuration error at
    import rather than a fuzzer that never produces a well-framed message.
    """

    field: str
    start: int
    adjustment: int = 0
    end: int | None = None

    def __post_init__(self) -> None:
        if not self.field:
            msg = "framing needs the name of its length field"
            raise ConfigurationError(msg)
        if self.start < 0:
            msg = "framing region must start at offset >= 0"
            raise ConfigurationError(msg)
        if self.adjustment < 0:
            msg = "framing adjustment must be >= 0"
            raise ConfigurationError(msg)
        if self.end is not None and self.end < self.start:
            msg = "framing region must end at or after its start"
            raise ConfigurationError(msg)

    def region_length(self, payload: bytes) -> int:
        """The length the frame should declare for ``payload``.

        With an explicit ``end`` the arithmetic is against the region the grammar described;
        with ``end is None`` it tracks the payload's real length, which is what makes the
        recompute correct after a length-changing mutation.
        """
        stop = len(payload) if self.end is None else self.end
        return max(0, stop - self.start + self.adjustment)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "start": self.start,
            "adjustment": self.adjustment,
            "end": self.end,
        }


@dataclass(frozen=True, slots=True)
class ChecksumSpec:
    """A checksum field and the region it covers.

    A real protocol fuzzer has to recompute the checksum, or every mutation past the first
    byte is thrown away by a target that validates it before it parses anything — which is
    most of them (DNP3's CRC is checked at the link layer, so without this the only DNP3 case
    that reaches the parser is the one that leaves the CRC alone). Recomputing it is not a
    weakening: the checksum is a *transport* integrity check, and a fuzzer's job is to deliver
    a well-transported but malformed message to the code that reads it. Where a grammar
    declares a checksum, one operator is added — :attr:`MutationOperator.CORRUPT_CHECKSUM` —
    which breaks it on purpose, because "does the target verify its checksum at all" is itself
    a finding worth having.
    """

    field: str
    start: int
    end: int
    compute: Callable[[bytes], int]
    endian: Literal["big", "little"] = "little"

    def __post_init__(self) -> None:
        if not self.field:
            msg = "a checksum needs the name of its field"
            raise ConfigurationError(msg)
        if self.start < 0 or self.end <= self.start:
            msg = "a checksum region must be a non-empty forward range"
            raise ConfigurationError(msg)
        if self.endian not in ("big", "little"):
            msg = "a checksum endian must be 'big' or 'little'"
            raise ConfigurationError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "start": self.start, "end": self.end, "endian": self.endian}


@dataclass(frozen=True, slots=True)
class ResponseReading:
    """How a grammar reads a target's answer to one of its messages.

    ``outcome`` is one of the four readings a fuzzing run acts on, and they are deliberately
    finer than "ok/not ok":

    ``ok``
        a well-formed answer of the kind the seed produces — the target is healthy *and* the
        input landed.
    ``refused``
        a well-formed rejection: a DNS RCODE, a Modbus exception, a RESP error. The target
        parsed the message, understood it and declined it. **This is not a fault** — it is the
        parser doing its job, and treating it as one would make a fuzzer report every
        well-behaved server.
    ``fault``
        the target's own internal-error marker: an HTTP 500, a protocol status that means "I
        failed", a reply that is truncated or garbled where the protocol says it must parse.
        The strongest raw signal, and still only a candidate.
    ``unknown``
        bytes this grammar cannot read at all (an empty reply, a protocol the target does not
        speak). Recorded, never escalated.
    """

    outcome: str
    detail: str = ""

    @property
    def is_fault(self) -> bool:
        return self.outcome == "fault"

    @property
    def is_healthy(self) -> bool:
        """True for the two readings that mean the target is coping: ``ok`` and ``refused``."""
        return self.outcome in ("ok", "refused")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"outcome": self.outcome}
        if self.detail:
            payload["detail"] = self.detail
        return payload


#: The readings a grammar may return, as a closed set.
RESPONSE_OUTCOMES: Final[frozenset[str]] = frozenset({"ok", "refused", "fault", "unknown"})


def _any_bytes_are_ok(data: bytes) -> ResponseReading:
    """The default classifier: bytes came back, so the target is answering.

    A grammar with a real parser passes its own classifier (see :mod:`arachne.fuzz.wire`); the
    default is for a grammar of a protocol this build cannot parse, where "it answered" is the
    most that can honestly be said.
    """
    if not data:
        return ResponseReading("unknown", "no response bytes")
    return ResponseReading("ok")


@dataclass(frozen=True, slots=True)
class FuzzCase:
    """One generated message: what was changed, how, and the exact bytes to send.

    A case carries both the mutated payload and the baseline it came from, so a report can show
    the differential ("the frame said 0x0011 where the body held 0x0010") without holding on to
    a grammar object. Deliberately **not** a finding, and with no field that could be mistaken
    for one: a case is an input, not an observation.
    """

    index: int
    grammar: str
    protocol: str
    field: str
    operator: MutationOperator
    payload: bytes
    baseline: bytes

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    @property
    def delta(self) -> int:
        """How the payload's length differs from its baseline (0 for an in-place change)."""
        return len(self.payload) - len(self.baseline)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "grammar": self.grammar,
            "protocol": self.protocol,
            "field": self.field,
            "operator": self.operator.value,
            "payload_hex": self.payload.hex(),
            "payload_sha256": self.payload_sha256,
            "baseline_sha256": hashlib.sha256(self.baseline).hexdigest(),
            "payload_bytes": len(self.payload),
            "delta": self.delta,
        }


@dataclass(frozen=True, slots=True)
class MessageGrammar:
    """A message's structure, its seed bytes and the mutations it permits.

    ``builder`` is called once, at construction, and its result is kept as the baseline every
    case is derived from — so every case in a run starts from exactly the same bytes, and a
    report's differentials are meaningful. (A builder that randomizes its output would make each
    case a different message; the shipped grammars therefore pass explicit identifiers and
    fixed nonces to the wire builders they wrap.)
    """

    name: str
    protocol: str
    description: str
    builder: Callable[[], bytes]
    fields: tuple[FieldSpec, ...]
    #: Every length field this build can recompute. A protocol with nested length prefixes
    #: (TLS has three: record, handshake, extensions) needs more than one, and recomputing all
    #: of them is what keeps a mutation of an inner field a *well-framed* message.
    framings: tuple[FramingSpec, ...] = ()
    #: Checksum fields, recomputed on every mutation except one that targets the checksum.
    checksums: tuple[ChecksumSpec, ...] = ()
    #: The registered check id that can verify a signal from this grammar (REQ-FUZZ-004).
    #: ``None`` means no shipped check can prove a candidate from this grammar, and the
    #: candidate is recorded for manual triage instead of being proposed as a hypothesis —
    #: naming an unrelated check would be worse than admitting there is no verifier.
    verifier: str | None = None
    #: The grammar used as this target's health probe (unmutated). ``None`` uses this
    #: grammar's own seed, which is the right default when the seed is a valid request.
    health: str | None = None
    #: How to read a target's answer. A grammar that knows its protocol passes the parser the
    #: shipped checks use, so "the target faulted" is the protocol's own error signal rather
    #: than a guess about shape.
    classify: Callable[[bytes], ResponseReading] = _any_bytes_are_ok
    #: Free-form protocol note for the report.
    response: str = "binary"
    #: The seed, computed once (see the class docstring).
    _seed: bytes = field(default=b"", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            msg = "a grammar needs a name"
            raise ConfigurationError(msg)
        if not self.protocol:
            msg = f"grammar {self.name}: needs a protocol"
            raise ConfigurationError(msg)
        if not self.fields:
            msg = f"grammar {self.name}: declares no fields"
            raise ConfigurationError(msg)
        seed = self.builder()
        if not seed:
            msg = f"grammar {self.name}: the seed builder returned no bytes"
            raise ConfigurationError(msg)
        names = [spec.name for spec in self.fields]
        if len(set(names)) != len(names):
            msg = f"grammar {self.name}: duplicate field names"
            raise ConfigurationError(msg)
        ordered = sorted(self.fields, key=lambda spec: spec.offset)
        previous_end = 0
        for spec in ordered:
            if spec.end > len(seed):
                msg = (
                    f"grammar {self.name}: field {spec.name} extends past the "
                    f"{len(seed)}-byte seed"
                )
                raise ConfigurationError(msg)
            if spec.offset < previous_end:
                msg = f"grammar {self.name}: field {spec.name} overlaps the previous field"
                raise ConfigurationError(msg)
            previous_end = spec.end
        # The operation table is consulted at definition time, so a grammar that *declares* a
        # read-only-violating operation cannot be constructed at all (REQ-FUZZ-001).
        for spec in self.fields:
            if spec.kind is not FieldKind.OPCODE:
                continue
            problems = grammar_operation_problems(
                self.protocol, spec.values, field_name=f"{spec.name} value"
            )
            if problems:
                msg = (
                    f"grammar {self.name} declares a state-changing operation: "
                    f"{'; '.join(problems)}"
                )
                raise FuzzPayloadRefused(msg, reason="; ".join(problems))
            declared = spec.read(seed)
            if operation_is_destructive(self.protocol, declared):
                msg = (
                    f"grammar {self.name}: field {spec.name} holds {declared:#x}, which is "
                    f"not a declared read-only {self.protocol} operation"
                )
                raise FuzzPayloadRefused(msg, reason=msg)
        self._validate_framings(seed)
        self._validate_checksums(seed)
        object.__setattr__(self, "_seed", seed)

    def _validate_framings(self, seed: bytes) -> None:
        """Every declared frame must describe the seed exactly, by interval arithmetic."""
        for framing in self.framings:
            spec = self.field(framing.field)
            if spec.kind is not FieldKind.LENGTH:
                msg = f"grammar {self.name}: framing field {framing.field} is not a length field"
                raise ConfigurationError(msg)
            if spec.offset < framing.start < spec.end:
                msg = (
                    f"grammar {self.name}: framing {framing.field} straddles the start of the "
                    f"region it covers"
                )
                raise ConfigurationError(msg)
            if framing.end is not None and spec.offset >= framing.end:
                msg = (
                    f"grammar {self.name}: framing {framing.field} lies outside the region it "
                    f"covers"
                )
                raise ConfigurationError(msg)
            actual = spec.read(seed)
            expected = framing.region_length(seed)
            if actual != expected:
                msg = (
                    f"grammar {self.name}: framing {framing.field} does not describe the seed "
                    f"(field holds {actual}, seed region implies {expected})"
                )
                raise ConfigurationError(msg)

    def _validate_checksums(self, seed: bytes) -> None:
        """Every declared checksum must be correct for the seed, or the grammar is wrong."""
        for checksum in self.checksums:
            spec = self.field(checksum.field)
            limit = 1 << (8 * spec.width)
            if checksum.end > len(seed):
                msg = f"grammar {self.name}: checksum {checksum.field} region exceeds the seed"
                raise ConfigurationError(msg)
            actual = spec.read(seed)
            computed = checksum.compute(seed[checksum.start : checksum.end]) % limit
            if actual != computed:
                msg = (
                    f"grammar {self.name}: checksum {checksum.field} does not verify against "
                    f"the seed (field holds {actual:#x}, region computes {computed:#x})"
                )
                raise ConfigurationError(msg)

    # ------------------------------------------------------------------ readings
    def seed(self) -> bytes:
        """The baseline message, identical for every case of this grammar."""
        return self._seed

    def field(self, name: str) -> FieldSpec:
        for spec in self.fields:
            if spec.name == name:
                return spec
        msg = f"grammar {self.name}: no field named {name!r}"
        raise ConfigurationError(msg)

    def _framing_for(self, name: str) -> FramingSpec | None:
        for framing in self.framings:
            if framing.field == name:
                return framing
        return None

    def _checksum_for(self, name: str) -> ChecksumSpec | None:
        for checksum in self.checksums:
            if checksum.field == name:
                return checksum
        return None

    def operators(self, spec: FieldSpec) -> tuple[MutationOperator, ...]:
        """The operators this field may be mutated with, given the framing rules.

        Three rules, each of which removes a mutation that would produce something other than
        a *well-framed message with a bad field*:

        * A checksum field's only operator is :attr:`MutationOperator.CORRUPT_CHECKSUM` — the
          numeric operators are meaningless on a value that is recomputed on every other case.
        * A length-changing operator is offered only when the field sits after the start of
          *every* framed region and no region has a fixed end, so that a length change cannot
          invalidate a region's arithmetic or move a later field's offset.
        * Everything else is offered as declared by the kind.

        Filtering here rather than raising in :meth:`mutate` means an engine cannot even ask for
        a mutation that would produce a malformed frame by accident — the only malformed framing
        a grammar produces is the one that targets the length field itself.
        """
        if self._checksum_for(spec.name) is not None:
            return (MutationOperator.CORRUPT_CHECKSUM,)
        candidates = OPERATORS_BY_KIND[spec.kind]
        if not self.framings:
            return candidates
        if any(framing.end is not None for framing in self.framings):
            return tuple(op for op in candidates if op not in _LENGTH_CHANGING)
        if all(spec.offset >= framing.start for framing in self.framings):
            return candidates
        return tuple(op for op in candidates if op not in _LENGTH_CHANGING)

    # ------------------------------------------------------------------ mutation
    def mutate(self, field_name: str, operator: MutationOperator) -> bytes:
        """``field_name`` under ``operator``, as a complete message."""
        spec = self.field(field_name)
        if operator not in self.operators(spec):
            msg = (
                f"grammar {self.name}: operator {operator.value} does not apply to field "
                f"{field_name} ({spec.kind.value})"
            )
            raise ConfigurationError(msg)
        seed = self._seed
        replacement = self._replacement(spec, operator, seed)
        mutated = seed[: spec.offset] + replacement + seed[spec.end :]
        if len(mutated) > MAX_PAYLOAD_BYTES:
            msg = (
                f"grammar {self.name}: mutation {field_name}/{operator.value} would produce "
                f"{len(mutated)} bytes (limit {MAX_PAYLOAD_BYTES})"
            )
            raise ConfigurationError(msg)
        mutated = self._reframe(mutated, spec)
        return self._rechecksum(mutated, spec)

    def _reframe(self, payload: bytes, mutated_field: FieldSpec) -> bytes:
        """Recompute every declared framing except the one the mutation targeted."""
        for framing in self.framings:
            if framing.field == mutated_field.name:
                # The targeted length keeps its inconsistent value: that inconsistency is the
                # test case, and papering over it would delete the operator's whole point.
                continue
            spec = self.field(framing.field)
            value = framing.region_length(payload)
            limit = 1 << (8 * spec.width)
            if value >= limit:
                msg = (
                    f"grammar {self.name}: recomputed framing {framing.field} = {value} does "
                    f"not fit in {spec.width} byte(s)"
                )
                raise ConfigurationError(msg)
            encoded = spec.encode(value)
            payload = payload[: spec.offset] + encoded + payload[spec.end :]
        return payload

    def _rechecksum(self, payload: bytes, mutated_field: FieldSpec) -> bytes:
        """Recompute every declared checksum except one the mutation deliberately broke."""
        for checksum in self.checksums:
            if checksum.field == mutated_field.name:
                continue
            spec = self.field(checksum.field)
            limit = 1 << (8 * spec.width)
            if checksum.end > len(payload):
                # A length-changing mutation before the checksum region can pull it out of the
                # message entirely. Recomputing is then impossible, and the honest answer is to
                # leave the truncated frame alone rather than invent bytes: the case is a
                # malformed frame, which is what the operator asked for.
                continue
            value = checksum.compute(payload[checksum.start : checksum.end]) % limit
            encoded = value.to_bytes(spec.width, checksum.endian)
            payload = payload[: spec.offset] + encoded + payload[spec.end :]
        return payload

    def _replacement(self, spec: FieldSpec, operator: MutationOperator, seed: bytes) -> bytes:
        """The bytes that go in ``spec``'s range under ``operator``."""
        if operator is MutationOperator.CORRUPT_CHECKSUM:
            checksum = self._checksum_for(spec.name)
            assert checksum is not None  # only offered for a checksum field
            limit = 1 << (8 * spec.width)
            correct = checksum.compute(seed[checksum.start : checksum.end]) % limit
            return ((correct + 1) % limit).to_bytes(spec.width, checksum.endian)
        if spec.kind in (FieldKind.OPCODE, FieldKind.ENUM):
            return spec.encode(self._value_replacement(spec, operator))
        if spec.kind is FieldKind.TEXT:
            return _TEXT_BOUNDARIES[operator]
        if spec.kind is FieldKind.OPAQUE:
            region = seed[spec.offset : spec.end]
            if operator is MutationOperator.FILL_ZERO:
                return bytes(len(region))
            if operator is MutationOperator.FILL_MAX:
                return bytes([0xFF]) * len(region)
            if operator is MutationOperator.DROP_FIELD:
                return b""
            if operator is MutationOperator.REPEAT_FIELD:
                return region * 2
            return region + bytes([region[-1] if region else 0])  # EXTEND_FIELD
        current = spec.read(seed)
        limit = 1 << (8 * spec.width)
        if operator is MutationOperator.LENGTH_ZERO:
            return spec.encode(0)
        if operator is MutationOperator.LENGTH_OVER:
            # One more than the region actually holds: the classic unvalidated length.
            return spec.encode(self._framed_length(spec, seed) + 1)
        if operator is MutationOperator.LENGTH_UNDER:
            return spec.encode(max(0, self._framed_length(spec, seed) - 1))
        if operator in (MutationOperator.LENGTH_MAX, MutationOperator.MAX):
            return spec.encode(limit - 1)
        if operator is MutationOperator.MAX_MINUS_ONE:
            return spec.encode(limit - 2)
        if operator is MutationOperator.ZERO:
            return spec.encode(0)
        if operator is MutationOperator.ONE:
            return spec.encode(1)
        if operator is MutationOperator.PLUS_ONE:
            return spec.encode((current + 1) % limit)
        if operator is MutationOperator.MINUS_ONE:
            return spec.encode((current - 1) % limit)
        msg = f"grammar {self.name}: operator {operator.value} has no replacement rule"
        raise ConfigurationError(msg)

    def _framed_length(self, spec: FieldSpec, seed: bytes) -> int:
        """The length ``spec`` should hold for ``seed``: the frame's own arithmetic if the
        framing describes it, otherwise the value it already carries.

        The distinction matters for the over/under operators: on a framed length field the
        off-by-one is against *the region's real length* — which is what a parser compares the
        field to — while on a length field whose region this grammar cannot recompute, it is
        against the value the seed carries. Both state the same hypothesis ("the parser trusted
        the field") against the only ground truth available.
        """
        framing = self._framing_for(spec.name)
        if framing is not None:
            return framing.region_length(seed)
        return spec.read(seed)


    def _value_replacement(self, spec: FieldSpec, operator: MutationOperator) -> int:
        """A declared operation/value for ``spec``, refused if it is not read-only.

        This is where the operation guarantee is actually enforced, and it is exact: the value
        is chosen from ``spec.values`` and then checked against the protocol's read-only table
        *before it is written*, so there is no path by which a fuzzed message carries a
        state-changing operation. A post-hoc scan of the assembled bytes could not do this — a
        length-changing mutation can shift any byte into the operation field's offset, which
        would produce refusals on legitimate cases and prove nothing about what was written.
        """
        current = spec.read(self._seed)
        index = spec.values.index(current) if current in spec.values else 0
        if operator is MutationOperator.VALUE_FIRST:
            value = spec.values[0]
        elif operator is MutationOperator.VALUE_LAST:
            value = spec.values[-1]
        else:
            value = spec.values[(index + 1) % len(spec.values)]
        if spec.kind is FieldKind.OPCODE and operation_is_destructive(self.protocol, value):
            msg = (
                f"grammar {self.name}: refusing to write {value:#x} into {spec.name}: it is not "
                f"a declared read-only {self.protocol} operation"
            )
            raise FuzzPayloadRefused(msg, reason=msg)
        return value

    # ------------------------------------------------------------------ cases
    def build_case(
        self, field_name: str, operator: MutationOperator, *, index: int
    ) -> FuzzCase:
        """One case, refused by the prohibition table if its payload would be prohibited.

        The validation is here, at the single point where a payload becomes a case, so no
        engine — the shipped one or a third-party one behind the pluggable interface — can
        produce a case that skips it.
        """
        payload = self.mutate(field_name, operator)
        require_non_destructive(payload, protocol=self.protocol, source=f"grammar {self.name}")
        return FuzzCase(
            index=index,
            grammar=self.name,
            protocol=self.protocol,
            field=field_name,
            operator=operator,
            payload=payload,
            baseline=self._seed,
        )

    def case_plan(self) -> tuple[tuple[str, MutationOperator], ...]:
        """Every (field, operator) this grammar offers, in a stable order.

        Field order is the declaration order (the message's own order, so a report reads like
        the protocol) and operator order is :data:`OPERATORS_BY_KIND` — deliberately not
        randomized, because a fuzzing run that cannot be replayed exactly is a fuzzing run
        whose result cannot be reproduced.
        """
        plan: list[tuple[str, MutationOperator]] = []
        for spec in self.fields:
            for operator in self.operators(spec):
                plan.append((spec.name, operator))
        return tuple(plan)

    def health_payload(self) -> bytes:
        """The bytes used to probe this target's health: the seed, which is a valid request."""
        return self._seed

    def read_response(self, data: bytes) -> ResponseReading:
        """Read a target's answer to one of this grammar's messages.

        See :class:`ResponseReading` for the four readings and what they mean.
        """
        reading = self.classify(data)
        if reading.outcome not in RESPONSE_OUTCOMES:
            msg = (
                f"grammar {self.name}: classifier returned an unknown outcome "
                f"{reading.outcome!r} (expected one of {', '.join(sorted(RESPONSE_OUTCOMES))})"
            )
            raise ConfigurationError(msg)
        return reading

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "protocol": self.protocol,
            "description": self.description,
            "verifier": self.verifier,
            "health": self.health or self.name,
            "response": self.response,
            "seed_bytes": len(self._seed),
            "seed_sha256": hashlib.sha256(self._seed).hexdigest(),
            "fields": [spec.to_dict() for spec in self.fields],
            "framings": [framing.to_dict() for framing in self.framings],
            "checksums": [checksum.to_dict() for checksum in self.checksums],
            "cases": len(self.case_plan()),
        }
