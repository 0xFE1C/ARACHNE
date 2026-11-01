"""Message grammars and grammar-aware mutation (S30, REQ-FUZZ-001/002).

Three properties carry the area, and each is asserted here:

* a grammar **describes its own seed** — the framing arithmetic is verified at construction, so a
  wrong offset is an import error rather than a fuzzer that mutates the wrong byte;
* the **operation field never leaves its allowlist** — declaring a write operation, or holding one
  in the seed, is refused at construction, and no operator can produce one;
* a mutation produces a **well-framed message with a bad field** — the frame is recomputed for
  every mutation except one that targets the length itself, which is the case that finds the
  unvalidated-length class of parser bug.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError, FuzzPayloadRefused
from arachne.fuzz.grammar import (
    FieldKind,
    FieldSpec,
    FramingSpec,
    MessageGrammar,
    MutationOperator,
    ResponseReading,
)
from arachne.fuzz.prohibitions import (
    READ_ONLY_OPERATIONS,
    fuzz_payload_problems,
    operation_is_destructive,
)
from arachne.fuzz.wire import GRAMMAR_NAMES, GRAMMARS, get_grammar, grammar_catalogue

# --------------------------------------------------------------------------- the shipped set


def test_every_shipped_grammar_builds_and_offers_cases() -> None:
    assert len(GRAMMAR_NAMES) == 10
    for name in GRAMMAR_NAMES:
        grammar = GRAMMARS[name]
        assert grammar.seed(), f"{name} has no seed"
        assert grammar.fields
        assert grammar.case_plan(), f"{name} offers no cases"
        for field in grammar.fields:
            assert grammar.operators(field), f"{name}: field {field.name} is unmutatable"


def test_every_shipped_grammar_is_deterministic() -> None:
    for name in GRAMMAR_NAMES:
        first = get_grammar(name)
        second = get_grammar(name)
        assert first.seed() == second.seed(), f"{name} seeds differ between instances"
        assert first.case_plan() == second.case_plan()
        for field_name, operator in first.case_plan():
            assert first.mutate(field_name, operator) == second.mutate(field_name, operator)


def test_no_shipped_grammar_can_produce_a_prohibited_payload() -> None:
    """The exhaustive version of the rule: every case of every grammar, against the table."""
    checked = 0
    for name in GRAMMAR_NAMES:
        grammar = GRAMMARS[name]
        for field_name, operator in grammar.case_plan():
            case = grammar.build_case(field_name, operator, index=checked)
            checked += 1
            verdict = fuzz_payload_problems(case.payload)
            assert verdict.ok, f"{name}/{field_name}/{operator.value}: {verdict.problems}"
    assert checked > 300, "the shipped grammars should offer a few hundred cases"


def test_no_shipped_grammar_can_issue_a_state_changing_operation() -> None:
    """Read every operation field in every generated case, using the declared offset."""
    seen: dict[str, set[int]] = {}
    for name in GRAMMAR_NAMES:
        grammar = GRAMMARS[name]
        for field in grammar.fields:
            if field.kind is not FieldKind.OPCODE:
                continue
            for field_name, operator in grammar.case_plan():
                if field_name != field.name:
                    continue
                case = grammar.build_case(field_name, operator, index=0)
                value = field.read(case.payload)
                assert not operation_is_destructive(grammar.protocol, value), (
                    f"{name}: {field.name} carried {value:#x}, which is not read-only"
                )
                seen.setdefault(grammar.protocol, set()).add(value)
    assert seen, "at least one shipped grammar should declare an operation field"
    for protocol, values in seen.items():
        assert values <= READ_ONLY_OPERATIONS[protocol]


def test_a_grammar_declares_a_read_only_allowlist_or_it_does_not_build() -> None:
    with pytest.raises(FuzzPayloadRefused):
        _grammar_with_opcode_values("modbus", (0x03, 0x10))  # 0x10 writes multiple registers
    with pytest.raises(FuzzPayloadRefused):
        _grammar_with_opcode_values("s7comm", (0x04, 0x05))  # 0x05 is Write Var
    with pytest.raises(FuzzPayloadRefused):
        _grammar_with_opcode_values("snmp", (0xA0, 0xA3))  # 0xA3 is SetRequest


def test_a_grammar_whose_seed_already_holds_a_write_operation_does_not_build() -> None:
    """A defect far easier to introduce than to notice: the *seed* is the write."""
    with pytest.raises(FuzzPayloadRefused) as caught:
        MessageGrammar(
            name="bad.seed",
            protocol="modbus",
            description="a seed that is itself a write",
            builder=lambda: bytes(
                [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x0A]
            ),
            fields=(FieldSpec("function-code", 7, 1, FieldKind.OPCODE, values=(0x03, 0x06)),),
        )
    assert "not a declared read-only modbus operation" in str(caught.value)


def _grammar_with_opcode_values(protocol: str, values: tuple[int, ...]) -> MessageGrammar:
    """A one-field grammar whose opcode field declares ``values`` for ``protocol``."""
    seed = bytes([0x00] * 7 + [values[0]])
    return MessageGrammar(
        name=f"probe.{protocol}",
        protocol=protocol,
        description="a grammar that exists to be refused",
        builder=lambda: seed,
        fields=(FieldSpec("operation", 7, 1, FieldKind.OPCODE, values=values),),
    )


# --------------------------------------------------------------------------- framing


def test_framing_is_recomputed_when_a_field_inside_the_frame_changes() -> None:
    grammar = get_grammar("modbus.read-device-id")
    mutated = grammar.mutate("unit-id", MutationOperator.MAX)
    stated = grammar.field("length").read(mutated)
    assert stated == len(mutated) - 6, "the MBAP length must describe the mutated frame"


def test_a_deliberate_length_inconsistency_survives() -> None:
    """The single most productive case: a frame whose length field lies about the body."""
    grammar = get_grammar("modbus.read-device-id")
    mutated = grammar.mutate("length", MutationOperator.LENGTH_OVER)
    stated = grammar.field("length").read(mutated)
    assert stated == len(mutated) - 6 + 1
    assert stated != len(mutated) - 6


def test_a_nested_frame_recomputes_all_its_lengths() -> None:
    grammar = get_grammar("tls.client-hello")
    mutated = grammar.mutate("extensions", MutationOperator.FILL_MAX)
    assert grammar.field("record-length").read(mutated) == len(mutated) - 5
    assert grammar.field("handshake-length").read(mutated) == len(mutated) - 9
    assert grammar.field("extensions-length").read(mutated) == len(mutated) - 62
    assert mutated[62:] == b"\xff" * (len(mutated) - 62)


def test_a_grammar_whose_framing_does_not_describe_its_seed_does_not_build() -> None:
    seed = b"\x01\x02\x03\x04\x05\x06"
    with pytest.raises(ConfigurationError) as caught:
        MessageGrammar(
            name="bad.framing",
            protocol="probe",
            description="a frame that lies about its own seed",
            builder=lambda: seed,
            fields=(
                FieldSpec("length", 0, 2, FieldKind.LENGTH),
                FieldSpec("body", 2, 4, FieldKind.OPAQUE),
            ),
            framings=(FramingSpec("length", start=2),),
        )
    assert "does not describe the seed" in str(caught.value)


def test_a_field_that_extends_past_the_seed_does_not_build() -> None:
    with pytest.raises(ConfigurationError) as caught:
        MessageGrammar(
            name="bad.field",
            protocol="probe",
            description="a field that runs off the end",
            builder=lambda: b"\x01\x02",
            fields=(FieldSpec("body", 0, 8, FieldKind.OPAQUE),),
        )
    assert "extends past" in str(caught.value)


def test_overlapping_fields_do_not_build() -> None:
    with pytest.raises(ConfigurationError) as caught:
        MessageGrammar(
            name="bad.overlap",
            protocol="probe",
            description="two fields over the same byte",
            builder=lambda: b"\x01\x02\x03\x04",
            fields=(
                FieldSpec("a", 0, 3, FieldKind.OPAQUE),
                FieldSpec("b", 2, 2, FieldKind.OPAQUE),
            ),
        )
    assert "overlaps" in str(caught.value)


def test_a_length_changing_operator_is_withheld_when_it_would_invalidate_the_frame() -> None:
    """TLS has fixed-end frames, so no field may change the message's length by accident."""
    grammar = get_grammar("tls.client-hello")
    operators = grammar.operators(grammar.field("cipher-suites"))
    assert MutationOperator.DROP_FIELD not in operators
    assert MutationOperator.FILL_ZERO in operators, "a length-preserving fill is still offered"
    with pytest.raises(ConfigurationError):
        grammar.mutate("cipher-suites", MutationOperator.DROP_FIELD)


def test_a_mutation_may_not_grow_a_payload_past_the_cap() -> None:
    grammar = get_grammar("tls.client-hello")
    long_extensions = MessageGrammar(
        name="big.extensions",
        protocol="tls",
        description="a grammar whose extension block is already near the cap",
        builder=lambda: (
            grammar.seed()[:-2] + b"\x30\x00" + b"\xaa" * 4000
        ),
        fields=(FieldSpec("extensions", 62, 4000, FieldKind.OPAQUE),),
    )
    with pytest.raises(ConfigurationError):
        long_extensions.mutate("extensions", MutationOperator.REPEAT_FIELD)


# --------------------------------------------------------------------------- checksums


def test_a_checksum_is_recomputed_when_the_message_changes() -> None:
    grammar = get_grammar("dnp3.link-status")
    mutated = grammar.mutate("control", MutationOperator.MAX)
    from arachne.modules.m2 import wire

    assert grammar.field("crc").read(mutated) == wire.dnp3_crc(mutated[:8])


def test_the_checksum_operator_breaks_the_checksum_by_one_on_purpose() -> None:
    grammar = get_grammar("dnp3.link-status")
    mutated = grammar.mutate("crc", MutationOperator.CORRUPT_CHECKSUM)
    from arachne.modules.m2 import wire

    assert grammar.field("crc").read(mutated) == wire.dnp3_crc(mutated[:8]) + 1


def test_a_grammar_whose_checksum_does_not_verify_does_not_build() -> None:
    seed = get_grammar("dnp3.link-status").seed()
    broken = seed[:8] + b"\x00\x00"
    with pytest.raises(ConfigurationError) as caught:
        MessageGrammar(
            name="bad.crc",
            protocol="dnp3",
            description="a checksum that does not verify against its own seed",
            builder=lambda: broken,
            fields=(
                FieldSpec("control", 3, 1, FieldKind.U8),
                FieldSpec("crc", 8, 2, FieldKind.U16, endian="little"),
            ),
            checksums=_dnp3_crc_spec(),
        )
    assert "does not verify" in str(caught.value)


def _dnp3_crc_spec() -> tuple[object, ...]:
    from arachne.fuzz.grammar import ChecksumSpec
    from arachne.modules.m2.wire import dnp3_crc

    return (ChecksumSpec("crc", start=0, end=8, compute=dnp3_crc, endian="little"),)


# --------------------------------------------------------------------------- readings


def test_a_response_reading_is_a_closed_set() -> None:
    grammar = get_grammar("redis.ping")
    assert grammar.read_response(b"+PONG\r\n").outcome == "ok"
    assert grammar.read_response(b"-ERR unknown command\r\n").outcome == "refused"
    assert grammar.read_response(b"").outcome == "unknown"
    assert grammar.read_response(b"+PONG\r\n").is_healthy
    assert grammar.read_response(b"-ERR nope\r\n").is_healthy, (
        "a well-formed refusal is a target doing its job, not a fault"
    )


def test_a_classifier_that_invents_an_outcome_is_refused() -> None:
    grammar = MessageGrammar(
        name="bad.classify",
        protocol="probe",
        description="a classifier returning an outcome the contract does not define",
        builder=lambda: b"\x01\x02",
        fields=(FieldSpec("body", 0, 2, FieldKind.OPAQUE),),
        classify=lambda _data: ResponseReading("probably-fine"),
    )
    with pytest.raises(ConfigurationError) as caught:
        grammar.read_response(b"\x01\x02")
    assert "unknown outcome" in str(caught.value)


def test_the_catalogue_renders_every_grammar() -> None:
    catalogue = grammar_catalogue()
    assert len(catalogue) == len(GRAMMAR_NAMES)
    for row in catalogue:
        assert row["name"]
        assert row["protocol"]
        assert row["cases"] >= 1
        assert row["seed_sha256"]
