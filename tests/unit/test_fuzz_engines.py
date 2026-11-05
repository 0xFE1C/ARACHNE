"""The pluggable engine interface (S30, area FUZZ, REQ-FUZZ-006).

REQ-FUZZ-006's acceptance is two things: an interface test, and "the default dependency set
unchanged". Both are here. The dependency assertion reads ``pyproject.toml`` and compares it to a
pinned tuple, so the day someone adds a fuzzing library the test that fails names what changed —
which is the only way "no new heavy dependency" stays true rather than merely intended.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.fuzz.coverage import (
    COVERAGE_ENGINE,
    COVERAGE_EXTRA,
    COVERAGE_TARGET_ENV,
    CoverageGuidedEngine,
)
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
    select_engine,
)
from arachne.fuzz.grammar import MutationOperator
from arachne.fuzz.wire import get_grammar

REPO_ROOT = Path(__file__).resolve().parents[2]

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
    """No fuzzing library, no compiler toolchain: the shipped engine is standard library only.

    The package's *import surface* is read from its own ``__init__`` rather than from
    ``sys.modules``: the mutation tooling also lives in this package (it is fault injection,
    not fuzzing), so a session that had imported it would make this assertion depend on test
    order instead of on what importing the package actually does.
    """
    import ast
    import sys
    from pathlib import Path

    package = Path(__file__).resolve().parents[2] / "src" / "arachne" / "fuzz"
    tree = ast.parse((package / "__init__.py").read_text(encoding="utf-8"))
    imported = {
        node.module.rsplit(".", 1)[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("arachne.fuzz.")
    }
    assert imported == {
        "attestation",
        "bounds",
        "candidates",
        "coverage",
        "engines",
        "grammar",
        "health",
        "http_params",
        "plan",
        "prohibitions",
        "runner",
        "wire",
    }
    # And nothing in the package imports a fuzzing library or a coverage-guided engine: the
    # engine ships as standard library plus the project's own runtime dependencies.
    banned = {"atheris", "hypothesis", "boofuzz", "afl", "pyfuzzer", "libfuzzer"}
    for path in sorted(package.glob("*.py")):
        module_tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(module_tree):
            roots: set[str] = set()
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                roots = {node.module.split(".")[0]}
            offenders = roots & banned
            assert not offenders, f"{path.name} imports {', '.join(sorted(offenders))}"
    assert "atheris" not in sys.modules and "hypothesis" not in sys.modules


def _outcome(case) -> CaseOutcome:  # type: ignore[no-untyped-def]
    return CaseOutcome(
        case_index=case.index,
        grammar=case.grammar,
        field=case.field,
        operator=case.operator.value,
        outcome="answered",
    )


# ------------------------------------------------- the coverage-guided seam (REQ-FUZZ-007)


class _ScriptedCoverage:
    """A coverage source a test controls: it maps a payload to the coverage it "reached".

    The engine's contract is one method taking the case's bytes, so this is a complete
    implementation of it — which is the point of the seam: the engine's logic is asserted here
    without the optional dependency, and the dependency is asserted separately.
    """

    def __init__(self, mapping: dict[bytes, frozenset[str]]) -> None:
        self.mapping = mapping
        self.reads: list[bytes] = []

    def read(self, payload: bytes) -> frozenset[str]:
        self.reads.append(payload)
        return self.mapping.get(payload, frozenset())


def test_the_coverage_dependency_is_an_extra_and_never_a_runtime_dependency() -> None:
    """REQ-FUZZ-007: installable as an optional extra, absent from the default install."""
    import tomllib

    document = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = document["project"]["optional-dependencies"]
    assert "fuzz-coverage" in extras
    assert any(dependency.startswith("coverage") for dependency in extras["fuzz-coverage"])
    assert all("coverage" not in dependency for dependency in document["project"]["dependencies"])
    assert runtime_dependencies() == PINNED_RUNTIME_DEPENDENCIES
    assert "fuzz-coverage" not in document["project"]["dependencies"]


def test_the_coverage_engine_cannot_be_built_without_its_source(monkeypatch) -> None:
    from arachne.fuzz import coverage as coverage_module

    monkeypatch.setattr(coverage_module, "coverage_available", lambda: False)
    with pytest.raises(ConfigurationError) as caught:
        CoverageGuidedEngine()
    assert "fuzz-coverage" in str(caught.value)
    assert "CoverageSource" in str(caught.value)


def test_a_coverage_target_that_cannot_be_resolved_is_reported_not_ignored(monkeypatch) -> None:
    from arachne.fuzz.coverage import COVERAGE_TARGET_ENV, coverage_target

    monkeypatch.delenv(COVERAGE_TARGET_ENV, raising=False)
    target, problem = coverage_target()
    assert target is None and problem and COVERAGE_TARGET_ENV in problem
    monkeypatch.setenv(COVERAGE_TARGET_ENV, "no_such_module_at_all:parse")
    target, problem = coverage_target()
    assert target is None and problem and "no_such_module_at_all" in problem
    monkeypatch.setenv(COVERAGE_TARGET_ENV, "arachne:__version__")
    target, problem = coverage_target()
    assert target is None and problem and "callable" in problem


def test_the_coverage_engine_registers_only_when_both_halves_are_present(
    monkeypatch, tmp_path
) -> None:
    """The dependency *and* a target: either one missing is a stated reason, not a silent run."""
    from arachne.fuzz import engines as engines_module

    monkeypatch.delenv(COVERAGE_TARGET_ENV, raising=False)
    engines_module.ENGINES.pop(COVERAGE_ENGINE, None)
    try:
        # Half one missing: the optional dependency.
        monkeypatch.setattr(engines_module, "coverage_available", lambda: False)
        reason = engines_module.register_coverage_engine()
        assert reason is not None and COVERAGE_EXTRA in reason
        assert COVERAGE_ENGINE not in engines_module.ENGINES
        # Half two missing: nothing to instrument. Coverage of nothing is not a signal.
        monkeypatch.setattr(engines_module, "coverage_available", lambda: True)
        reason = engines_module.register_coverage_engine()
        assert reason is not None and COVERAGE_TARGET_ENV in reason
        assert COVERAGE_ENGINE not in engines_module.ENGINES
        # Both present: registered, measuring, and honest in its description about *what* it
        # measures — an in-process target, never a remote one.
        module = tmp_path / "scripted_target.py"
        module.write_text(
            "def parse(payload: bytes) -> None:\n"
            "    if payload.startswith(b'x'):\n"
            "        return\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.setenv(COVERAGE_TARGET_ENV, "scripted_target:parse")
        assert engines_module.register_coverage_engine() is None
        registered = engines_module.ENGINES[COVERAGE_ENGINE]
        assert isinstance(registered, CoverageGuidedEngine)
        assert registered.measuring is True
        assert "NOT a remote target's coverage" in registered.description
        # A name that was never registered is still a hard error: a typo is not a request for
        # the default engine, which is exactly the difference `select_engine` draws.
        with pytest.raises(ConfigurationError):
            select_engine("libfuzzer")
    finally:
        engines_module.ENGINES.pop(COVERAGE_ENGINE, None)


def test_asking_for_coverage_without_it_degrades_and_says_so(monkeypatch) -> None:
    """REQ-FUZZ-007: absence degrades to the existing engines — and the report is told."""
    from arachne.fuzz import engines as engines_module

    monkeypatch.delitem(engines_module.ENGINES, COVERAGE_ENGINE, raising=False)
    monkeypatch.setattr(
        engines_module,
        "COVERAGE_UNAVAILABLE",
        f"the coverage-guided engine needs the optional extra `arachne[{COVERAGE_EXTRA}]`",
    )
    engine, reason = select_engine(COVERAGE_ENGINE)
    assert isinstance(engine, GrammarEngine), "absence must degrade to the default engine"
    assert reason is not None
    assert COVERAGE_EXTRA in reason and DEFAULT_ENGINE in reason


def test_select_engine_leaves_a_registered_engine_alone() -> None:
    engine, reason = select_engine(None)
    assert isinstance(engine, GrammarEngine) and reason is None
    fingerprint_engine, reason = select_engine("fingerprint")
    assert isinstance(fingerprint_engine, FingerprintEngine) and reason is None


def test_the_coverage_engine_front_loads_the_field_that_reached_new_code() -> None:
    grammar = get_grammar("tls.client-hello")
    novelty_case = grammar.build_case("session-id-length", MutationOperator.LENGTH_OVER, index=1)
    source = _ScriptedCoverage({novelty_case.payload: frozenset({"tls.py:410", "tls.py:411"})})
    engine = CoverageGuidedEngine(source=source)
    engine.plan(grammar, limit=4)
    novelty = CaseOutcome(
        case_index=1,
        grammar=grammar.name,
        field="session-id-length",
        operator=MutationOperator.LENGTH_OVER.value,
        outcome="answered",
    )
    extra = engine.observe(novelty)
    assert extra, "a case that reached new code must re-prioritise its own field"
    assert all(case.field == "session-id-length" for case in extra)
    assert MutationOperator.LENGTH_ZERO in {case.operator for case in extra}
    assert source.reads == [novelty_case.payload], "the source is asked about the case's bytes"
    assert engine.observe(novelty) == (), "already-reached code must not trigger twice"
    payload = engine.to_dict()
    assert payload["coverage_points"] == 2
    assert payload["measuring"] is True
    assert "last_error" not in payload


def test_the_coverage_engine_behaves_like_the_default_one_without_a_source() -> None:
    """No target to instrument is not a licence to reorder: the plan is the grammar's own."""
    grammar = get_grammar("dns.query")
    engine = CoverageGuidedEngine(source=_ScriptedCoverage({}))
    first = engine.plan(grammar, limit=5)
    second = engine.plan(grammar, limit=5)
    assert [case.payload for case in first] == [case.payload for case in second]
    assert [case.field for case in first] == [field for field, _ in grammar.case_plan()[:5]]
    assert engine.observe(_outcome(first[0])) == ()


def test_a_coverage_source_that_fails_is_reported_never_swallowed() -> None:
    grammar = get_grammar("redis.ping")
    engine = CoverageGuidedEngine(source=_FailingCoverage())
    engine.plan(grammar, limit=2)
    case = grammar.build_case("command", MutationOperator.TEXT_QUOTE, index=0)
    assert engine.observe(_outcome(case)) == ()
    assert "coverage source failed" in engine.to_dict()["last_error"]


def test_an_operator_the_grammar_does_not_carry_is_refused_rather_than_guessed() -> None:
    """An HTTP case's operator is ``family:encoding``, which no wire grammar case carries."""
    grammar = get_grammar("redis.ping")
    engine = CoverageGuidedEngine(source=_ScriptedCoverage({}))
    engine.plan(grammar, limit=2)
    http_outcome = CaseOutcome(
        case_index=0,
        grammar=grammar.name,
        field="command",
        operator="sqli:url",
        outcome="answered",
    )
    assert engine.observe(http_outcome) == ()
    assert "sqli:url" in engine.to_dict()["last_error"]


class _FailingCoverage:
    def read(self, payload: bytes) -> frozenset[str]:
        msg = "the instrumentation went away"
        raise RuntimeError(msg)
