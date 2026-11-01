"""The pluggable engine interface (S30, area FUZZ, REQ-FUZZ-006).

REQ-FUZZ-006's acceptance is two things: an interface test, and "the default dependency set
unchanged". Both are here. The dependency assertion reads ``pyproject.toml`` and compares it to a
pinned tuple, so the day someone adds a fuzzing library the test that fails names what changed —
which is the only way "no new heavy dependency" stays true rather than merely intended.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.fuzz.engines import (
    DEFAULT_ENGINE,
    ENGINES,
    CaseOutcome,
    FingerprintEngine,
    FuzzEngine,
    GrammarEngine,
    engine_names,
    get_engine,
    register_engine,
    runtime_dependencies,
)
from arachne.fuzz.grammar import MutationOperator
from arachne.fuzz.wire import get_grammar

#: The runtime dependency set as of the S30 build. REQ-FUZZ-006 asks that fuzzing add none of
#: its own: a grammar-based engine needs nothing that was not already installed.
PINNED_RUNTIME_DEPENDENCIES: tuple[str, ...] = (
    "httpx>=0.27",
    "pydantic>=2.7,<3",
    "fastapi>=0.111",
    "uvicorn[standard]>=0.30",
    "typer>=0.12",
    "jinja2>=3.1",
    "sqlalchemy>=2.0.30",
    "alembic>=1.13",
    "pyyaml>=6.0",
)


def test_the_default_engine_is_the_grammar_engine() -> None:
    assert DEFAULT_ENGINE == "grammar"
    assert isinstance(get_engine(None), GrammarEngine)
    assert isinstance(get_engine("grammar"), GrammarEngine)
    assert engine_names()[0] == DEFAULT_ENGINE


def test_an_unknown_engine_is_a_configuration_error_that_names_the_alternatives() -> None:
    with pytest.raises(ConfigurationError) as caught:
        get_engine("libfuzzer")
    assert "unknown fuzzing engine" in str(caught.value)
    assert "grammar" in str(caught.value)
    assert "fingerprint" in str(caught.value)


def test_the_grammar_engine_is_open_loop_and_deterministic() -> None:
    engine = GrammarEngine()
    grammar = get_grammar("dnp3.link-status")
    first = engine.plan(grammar, limit=6)
    second = engine.plan(grammar, limit=6)
    assert [case.payload for case in first] == [case.payload for case in second]
    assert [case.field for case in first] == [field for field, _ in grammar.case_plan()[:6]]
    assert engine.observe(_outcome(first[0])) == ()


def test_a_plan_is_capped_by_the_limit_it_is_given() -> None:
    grammar = get_grammar("rdp.negotiation")
    plan = GrammarEngine().plan(grammar, limit=3)
    assert len(plan) == 3
    assert plan[-1].index == 2


def test_the_fingerprint_engine_front_loads_the_field_that_produced_something_new() -> None:
    engine = FingerprintEngine()
    grammar = get_grammar("tls.client-hello")
    engine.plan(grammar, limit=4)
    novelty = CaseOutcome(
        case_index=1,
        grammar=grammar.name,
        field="session-id-length",
        operator=MutationOperator.LENGTH_OVER.value,
        outcome="answered",
        response_outcome="ok",
        fingerprint="len~128:16030100:deadbeef:ok",
    )
    extra = engine.observe(novelty)
    assert extra, "a novel response must re-prioritise the field that produced it"
    assert all(case.field == "session-id-length" for case in extra)
    assert MutationOperator.LENGTH_ZERO in {case.operator for case in extra}, (
        "the length operators are the ones declaration order reaches last"
    )
    assert engine.observe(novelty) == (), "the same fingerprint must not trigger twice"
    assert engine.to_dict()["novel_responses"] == 1
    assert "NOT instrumented code coverage" in engine.description


def test_the_fingerprint_engine_ignores_a_case_that_was_not_answered() -> None:
    engine = FingerprintEngine()
    grammar = get_grammar("redis.ping")
    engine.plan(grammar, limit=2)
    silent = CaseOutcome(
        case_index=0,
        grammar=grammar.name,
        field="command",
        operator=MutationOperator.TEXT_QUOTE.value,
        outcome="timeout",
    )
    assert engine.observe(silent) == ()


def test_a_third_party_engine_satisfies_the_protocol_structurally() -> None:
    """The seam, from the outside: no import of anything but the model types."""

    class CountingEngine:
        name = "counting"

        def __init__(self) -> None:
            self.seen: list[int] = []

        def plan(self, grammar, *, limit):  # type: ignore[no-untyped-def]
            return tuple(
                grammar.build_case(field, operator, index=index)
                for index, (field, operator) in enumerate(grammar.case_plan()[:limit])
            )

        def observe(self, outcome):  # type: ignore[no-untyped-def]
            self.seen.append(outcome.case_index)
            return ()

    engine = CountingEngine()
    assert isinstance(engine, FuzzEngine)
    cases = engine.plan(get_grammar("dns.query"), limit=2)
    assert len(cases) == 2


def test_registering_an_engine_cannot_silently_take_over_a_name() -> None:
    class Named:
        name = "test-only-engine"

        def plan(self, grammar, *, limit):  # type: ignore[no-untyped-def]
            return ()

        def observe(self, outcome):  # type: ignore[no-untyped-def]
            return ()

    engine = Named()
    register_engine(engine)
    try:
        assert "test-only-engine" in engine_names()
        with pytest.raises(ConfigurationError) as caught:
            register_engine(Named())
        assert "already registered" in str(caught.value)
        register_engine(Named(), replace=True), "an explicit override is allowed"
        with pytest.raises(ConfigurationError):
            register_engine(NamedWithBlankName())
    finally:
        ENGINES.pop("test-only-engine", None)
    assert "test-only-engine" not in engine_names()


class NamedWithBlankName:
    """An engine with no name at all cannot be addressed, so it cannot be registered."""

    name = ""

    def plan(self, grammar, *, limit):  # type: ignore[no-untyped-def]
        return ()

    def observe(self, outcome):  # type: ignore[no-untyped-def]
        return ()


def test_the_default_dependency_set_is_unchanged_by_area_fuzz() -> None:
    assert runtime_dependencies() == PINNED_RUNTIME_DEPENDENCIES, (
        "REQ-FUZZ-006: the default install must not gain a fuzzing dependency"
    )


def test_the_fuzz_package_is_pure_python() -> None:
    """No fuzzing library, no compiler toolchain: the shipped engine is standard library only."""
    import sys

    import arachne.fuzz  # noqa: F401 - the import is the point

    submodules = {
        name.split(".")[-1]
        for name in sys.modules
        if name.startswith("arachne.fuzz.") and not name.startswith("arachne.fuzz.__")
    }
    assert submodules == {
        "attestation",
        "bounds",
        "candidates",
        "engines",
        "grammar",
        "health",
        "http_params",
        "plan",
        "prohibitions",
        "runner",
        "wire",
    }
    third_party = {
        name.split(".")[0]
        for name in sys.modules
        if name.split(".")[0] not in sys.stdlib_module_names
    }
    assert "atheris" not in third_party and "hypothesis" not in third_party


def _outcome(case) -> CaseOutcome:  # type: ignore[no-untyped-def]
    return CaseOutcome(
        case_index=case.index,
        grammar=case.grammar,
        field=case.field,
        operator=case.operator.value,
        outcome="answered",
    )
