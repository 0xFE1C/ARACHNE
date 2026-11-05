"""The pluggable fuzzing engine interface (S30, area FUZZ, REQ-FUZZ-006).

REQ-FUZZ-006 permits a coverage-guided engine *behind a pluggable interface*, with the
grammar-based engine as the default and the default dependency set unchanged. That is what this
module is: the seam, the default implementation, and a second implementation that shows the seam
carries real feedback rather than only decorating the first.

The seam is small on purpose. An engine answers two questions — *what should I send next* and
*what did I learn from what came back* — and nothing else:

:meth:`FuzzEngine.plan`
    The cases to run for a grammar, in the order the engine wants them, bounded by a limit.
:meth:`FuzzEngine.observe`
    The feedback hook. It is handed what the target did with a case and may return more cases to
    run. The default engine returns nothing, which is what makes it deterministic and dependent
    on nothing.

An engine never touches the network, never decides a budget and never writes a candidate: the
runner owns all three. So a third-party engine can change *which mutations get tried* without
being able to change what a run is allowed to do — a boundary that matters because a fuzzing
engine is exactly the kind of plug-in an operator might one day install from elsewhere.

Two engines ship:

``grammar`` (the default)
    :class:`GrammarEngine` — the declared case plan, in declaration order, with no feedback. Its
    value is reproducibility: the same grammar produces the same cases in the same order on
    every run, so a bounded run's output can be compared to yesterday's.

``fingerprint``
    :class:`ResponseFingerprintEngine` — a feedback engine that notices when a case produced a
    response *shape* no earlier case produced and spends the rest of its attention on the field
    that did. Its docstring is explicit about what it is not: this is novelty in the *response*,
    not instrumented code coverage. A genuinely coverage-guided engine needs target
    instrumentation (a compiled-in sanitizer, a VM with edge counters) which is out of scope for
    a default install — REQ-FUZZ-006 says "MAY", and the honest deliverable is the interface plus
    the dependency-free engine that uses the only feedback available without one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from arachne.core.errors import ConfigurationError
from arachne.fuzz.coverage import (
    COVERAGE_ENGINE,
    COVERAGE_EXTRA,
    CoverageGuidedEngine,
    InProcessCoverage,
    coverage_available,
    coverage_target,
)
from arachne.fuzz.grammar import FuzzCase, MessageGrammar, MutationOperator

__all__ = [
    "DEFAULT_ENGINE",
    "ENGINES",
    "CaseOutcome",
    "FingerprintEngine",
    "FuzzEngine",
    "GrammarEngine",
    "engine_names",
    "get_engine",
    "register_coverage_engine",
    "register_engine",
    "runtime_dependencies",
    "select_engine",
]

#: The engine a run uses when its plan names none (REQ-FUZZ-006's default).
DEFAULT_ENGINE: Final = "grammar"

#: The outcome readings a case can have, as the engine's feedback vocabulary.
OUTCOME_ANSWERED: Final = "answered"
OUTCOME_TIMEOUT: Final = "timeout"
OUTCOME_ERROR: Final = "error"
OUTCOME_REFUSED: Final = "refused"

#: Operators that grow or shrink a message. A feedback engine prioritises them on a field that
#: produced novel behaviour, because framing arithmetic is where parser bugs live.
_LENGTH_OPERATORS: Final[frozenset[MutationOperator]] = frozenset(
    {
        MutationOperator.LENGTH_ZERO,
        MutationOperator.LENGTH_OVER,
        MutationOperator.LENGTH_UNDER,
        MutationOperator.LENGTH_MAX,
        MutationOperator.DROP_FIELD,
        MutationOperator.REPEAT_FIELD,
        MutationOperator.EXTEND_FIELD,
    }
)


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """What a target did with one case — the feedback an engine consumes.

    Only the *observation* half of a candidate is here; a candidate is the runner's to write.
    ``fingerprint`` is a digest of the response's shape (its length class and its first bytes),
    which is the dependency-free stand-in for coverage this build can offer.
    """

    case_index: int
    grammar: str
    field: str
    #: The varied thing, as a string: a mutation operator for a wire case, ``family:encoding``
    #: for an HTTP one. A string rather than the enum because the two transports vary different
    #: things and a single closed enum could only describe one of them honestly.
    operator: str
    outcome: str = OUTCOME_ANSWERED
    response_outcome: str = ""
    response_bytes: int = 0
    fingerprint: str = ""
    latency_s: float = 0.0
    detail: str = ""

    @property
    def answered(self) -> bool:
        return self.outcome == OUTCOME_ANSWERED

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "case_index": self.case_index,
            "grammar": self.grammar,
            "field": self.field,
            "operator": self.operator,
            "outcome": self.outcome,
            "response_bytes": self.response_bytes,
            "latency_ms": round(self.latency_s * 1000, 1),
        }
        if self.response_outcome:
            payload["response_outcome"] = self.response_outcome
        if self.fingerprint:
            payload["fingerprint"] = self.fingerprint
        if self.detail:
            payload["detail"] = self.detail
        return payload


def fingerprint(data: bytes, *, detail: str = "") -> str:
    """A response's shape, cheaply: nothing, else length class + leading bytes + a digest.

    Two answers that the target produced by different code paths usually differ in one of these,
    and an answer produced by the same path usually does not. It is a heuristic and is described
    as one; its only job is to give a dependency-free engine a signal to order its work by.
    """
    if not data:
        return "empty"
    bucket = 16 if len(data) < 16 else 1 << (len(data).bit_length() - 1)
    digest = hashlib.sha256(data[:64]).hexdigest()[:8]
    prefix = data[:4].hex()
    shape = f"len~{bucket}:{prefix}:{digest}"
    return f"{shape}:{detail}" if detail else shape


@runtime_checkable
class FuzzEngine(Protocol):
    """What the runner requires of a fuzzing engine (REQ-FUZZ-006).

    A ``Protocol`` rather than a base class, so a third-party engine can satisfy it structurally
    without importing anything from this package beyond the model types.
    """

    name: str

    def plan(self, grammar: MessageGrammar, *, limit: int) -> tuple[FuzzCase, ...]:
        """The cases to run for ``grammar``, in order, at most ``limit`` of them."""
        ...

    def observe(self, outcome: CaseOutcome) -> tuple[FuzzCase, ...]:
        """What ``outcome`` suggests trying next; ``()`` when it suggests nothing."""
        ...


@dataclass
class GrammarEngine:
    """The default engine: the grammar's declared case plan, in order, no feedback.

    Deterministic by construction — :meth:`MessageGrammar.case_plan` is a stable order and this
    engine neither reorders nor samples it — which is the property that makes a bounded fuzzing
    run comparable across days and a regression in its output attributable.
    """

    name: str = DEFAULT_ENGINE
    description: str = "Grammar-aware boundary mutation in declaration order; no feedback (default)"
    _index: int = field(default=0, init=False, repr=False, compare=False)

    def plan(self, grammar: MessageGrammar, *, limit: int) -> tuple[FuzzCase, ...]:
        cases: list[FuzzCase] = []
        for field_name, operator in grammar.case_plan():
            if len(cases) >= limit:
                break
            cases.append(grammar.build_case(field_name, operator, index=len(cases)))
        return tuple(cases)

    def observe(self, outcome: CaseOutcome) -> tuple[FuzzCase, ...]:
        """Nothing: the default engine is open loop, and that is a feature."""
        return ()


@dataclass
class FingerprintEngine:
    """A response-novelty-guided engine, built on the same interface (REQ-FUZZ-006).

    What it does: it runs the grammar's cases in declaration order, fingerprints every response,
    and when a case produces a fingerprint it has not seen before it **front-loads the rest of
    that field's operators** — including, where the grammar permits them, the length-changing
    ones, which the declaration order generally reaches last. When the case budget is smaller
    than the case plan (the normal case for a bounded run), that is the difference between
    spending it in declaration order and spending it where the target has just shown it does
    something new.

    What it is not: **coverage-guided**. Its signal is novelty in the *response*, which is a
    proxy. Real coverage needs target instrumentation — edge counters, a sanitizer build — and
    installing one is a decision about the *target*, not about this scanner, so this build does
    not. The engine says so in its own ``description``, which the report renders, so an operator
    reading "fingerprint" never mistakes it for a coverage-guided engine.
    """

    name: str = "fingerprint"
    description: str = (
        "Response-novelty-guided ordering (NOT instrumented code coverage): "
        "re-prioritises the field that produced a new response shape"
    )
    _grammar: MessageGrammar | None = field(default=None, init=False, repr=False, compare=False)
    _seen: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _queue: list[tuple[str, MutationOperator]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _issued: int = field(default=0, init=False, repr=False, compare=False)

    def plan(self, grammar: MessageGrammar, *, limit: int) -> tuple[FuzzCase, ...]:
        self._grammar = grammar
        self._seen.clear()
        self._queue.clear()
        self._issued = 0
        cases: list[FuzzCase] = []
        for field_name, operator in grammar.case_plan():
            if len(cases) >= limit:
                break
            cases.append(grammar.build_case(field_name, operator, index=len(cases)))
        return tuple(cases)

    def observe(self, outcome: CaseOutcome) -> tuple[FuzzCase, ...]:
        """Front-load the rest of a field's operators when its response was novel."""
        grammar = self._grammar
        if grammar is None or not outcome.answered or not outcome.fingerprint:
            return ()
        if outcome.fingerprint in self._seen:
            return ()
        self._seen.add(outcome.fingerprint)
        extra: list[FuzzCase] = []
        spec = grammar.field(outcome.field)
        for operator in grammar.operators(spec):
            if operator in _LENGTH_OPERATORS:
                self._queue.append((outcome.field, operator))
        while self._queue:
            field_name, operator = self._queue.pop(0)
            extra.append(grammar.build_case(field_name, operator, index=outcome.case_index))
        return tuple(extra)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "novel_responses": len(self._seen),
        }


#: The engines this build ships, by name. ``coverage`` is registered only when **both** halves of
#: REQ-FUZZ-007's optionality are present: the optional dependency (``arachne[fuzz-coverage]``)
#: and the in-process target it instruments (``ARACHNE_FUZZ_COVERAGE_TARGET``). With either
#: absent the name is not registered at all, so nothing can claim a coverage-guided run happened
#: when it did not — and ``select_engine`` says so in the report rather than failing the run.
ENGINES: dict[str, FuzzEngine] = {
    DEFAULT_ENGINE: GrammarEngine(),
    "fingerprint": FingerprintEngine(),
}


def register_coverage_engine() -> str | None:
    """Register the coverage-guided engine when both of its halves are available.

    Returns ``None`` on success or the reason it could not be registered, which is exactly what
    the report's degradation note carries.
    """
    if not coverage_available():
        return (
            f"the {COVERAGE_ENGINE}-guided engine needs the optional extra "
            f"`arachne[{COVERAGE_EXTRA}]`, which is not installed"
        )
    target, problem = coverage_target()
    if target is None:
        return f"the {COVERAGE_ENGINE}-guided engine has no target to instrument ({problem})"
    ENGINES[COVERAGE_ENGINE] = CoverageGuidedEngine(source=InProcessCoverage(target=target))
    return None


COVERAGE_UNAVAILABLE: str | None = register_coverage_engine()


def register_engine(engine: FuzzEngine, *, replace: bool = False) -> None:
    """Add an engine to the registry (REQ-FUZZ-006's pluggability).

    A name collision is refused unless ``replace`` is set, so a plug-in cannot silently take
    over the default engine's name — which would let "install a plug-in" mean "change what the
    default fuzzing run does" without anyone deciding that.
    """
    if not getattr(engine, "name", ""):
        msg = "a fuzzing engine needs a non-empty name"
        raise ConfigurationError(msg)
    if engine.name in ENGINES and not replace:
        msg = (
            f"a fuzzing engine named {engine.name!r} is already registered "
            f"(pass replace=True to override it deliberately)"
        )
        raise ConfigurationError(msg)
    ENGINES[engine.name] = engine


def engine_names() -> tuple[str, ...]:
    """Every registered engine name, the default first."""
    others = sorted(name for name in ENGINES if name != DEFAULT_ENGINE)
    names = [DEFAULT_ENGINE] if DEFAULT_ENGINE in ENGINES else []
    return tuple(names + others)


def get_engine(name: str | None) -> FuzzEngine:
    """The engine called ``name``, or the default for ``None``.

    An unknown name is a configuration error naming the alternatives, never a silent fallback:
    an operator who asked for the feedback engine and silently got the deterministic one would
    be reading a report about a run that did not happen.
    """
    resolved = name or DEFAULT_ENGINE
    try:
        return ENGINES[resolved]
    except KeyError as exc:
        known = ", ".join(engine_names())
        msg = f"unknown fuzzing engine {resolved!r} (this build registers: {known})"
        raise ConfigurationError(msg) from exc


def select_engine(name: str | None) -> tuple[FuzzEngine, str | None]:
    """The engine a run should use, plus the reason it differs from the one that was asked for.

    This is what the *runner* uses, and it is deliberately more forgiving than :func:`get_engine`
    in exactly one place. REQ-FUZZ-007 requires the coverage-guided engine's absence to *degrade*
    to the existing engines, so a plan that asks for ``coverage`` on a build without it runs the
    default engine — and returns a note the report carries, because a run that silently used a
    different engine than the plan named is a report about a run that did not happen. Every other
    unknown name is still a configuration error: a typo must not be quietly re-interpreted.
    """
    requested = name or DEFAULT_ENGINE
    if requested in ENGINES:
        return ENGINES[requested], None
    if requested == COVERAGE_ENGINE:
        reason = COVERAGE_UNAVAILABLE or (
            f"the {COVERAGE_ENGINE}-guided engine is not registered in this process"
        )
        return get_engine(DEFAULT_ENGINE), (
            f"{reason}; the run used the {DEFAULT_ENGINE} engine instead"
        )
    return get_engine(requested), None


def runtime_dependencies() -> tuple[str, ...]:
    """The project's runtime dependency list, read from ``pyproject.toml``.

    Exposed so a test can pin it: REQ-FUZZ-006's acceptance is "the default dependency set is
    unchanged", and the only way to state that as a test is to read the declaration and compare
    it to a recorded tuple. This function is the reading; the assertion lives in the test suite.
    """
    import tomllib
    from pathlib import Path

    candidates = [
        Path(__file__).resolve().parents[3] / "pyproject.toml",
        Path(__file__).resolve().parents[2] / "pyproject.toml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open("rb") as handle:
                document = tomllib.load(handle)
            declared = document.get("project", {}).get("dependencies", [])
            return tuple(str(item) for item in declared)
    msg = "pyproject.toml not found: cannot read the runtime dependency set"
    raise ConfigurationError(msg)
