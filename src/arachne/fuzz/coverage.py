"""The coverage-guided engine seam (REQ-FUZZ-007).

The pluggable interface in :mod:`arachne.fuzz.engines` deliberately admits an engine that
changes *which mutations get tried* without changing what a run is allowed to do. This module is
the coverage-guided engine that fits behind it, and it is deliberately the last engine the
default install registers: **it needs an optional dependency**, so the default and air-gapped
installs contain neither the dependency nor the engine.

What "coverage" means here, stated honestly
-------------------------------------------

The signal is instrumented code coverage of an **in-process target** — the bytes of a case are
fed to a callable the operator registers (a parser, a decoder, a library entry point), and the
lines that callable executed are the coverage of that case. That is genuine coverage-guided
fuzzing: a case that reaches a line no earlier case reached is spent differently from one that
repeats the same path, which is the whole idea.

It is **not** the coverage of a remote service. Measuring a remote target's coverage needs
instrumentation *inside that target* — a sanitizer build, edge counters, a reporting channel —
and installing one is a decision about somebody else's system, not about this scanner. An
operator who has such a target supplies its coverage through the same :class:`CoverageSource`
contract (:meth:`CoverageSource.read` takes the case's bytes and returns the coverage reached);
nothing else about the engine changes. The distinction is stated in the engine's
``description``, which the report renders, so an operator never mistakes a coverage-guided run
for one that was not.

The safety boundary is unchanged
--------------------------------

The engine implements the same two methods as every other engine and touches nothing else: it
does not plan a budget, does not see the network, does not write a candidate and does not decide
a proof level. So the case budget, the request ledger, the health probe, the abort guard and the
prohibition table apply to it *identically* — none of them ever consulted the engine's name, and
``tests/test_fuzz_safety.py`` asserts that for this engine the same way it does for the others.

Degrading without the extra
---------------------------

``coverage`` (coverage.py) is the optional dependency, declared as the ``fuzz-coverage`` extra.
When it is absent the engine is not registered, and a plan that asks for it is served by the
default engine **with the substitution recorded in the report** (see
``arachne.fuzz.engines.select_engine``) — never silently, because a report that says "coverage"
about a run that used the grammar engine is a lie.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from arachne.core.errors import ConfigurationError
from arachne.fuzz.grammar import FuzzCase, MessageGrammar, MutationOperator

if TYPE_CHECKING:  # pragma: no cover - a type-only import; `engines` imports this module
    from arachne.fuzz.engines import CaseOutcome

__all__ = [
    "COVERAGE_DEPENDENCY",
    "COVERAGE_ENGINE",
    "COVERAGE_EXTRA",
    "COVERAGE_TARGET_ENV",
    "CoverageGuidedEngine",
    "CoverageSource",
    "InProcessCoverage",
    "coverage_available",
    "coverage_target",
]

#: The engine's name, the optional dependency it needs, and the extra that installs it.
COVERAGE_ENGINE: Final = "coverage"
COVERAGE_DEPENDENCY: Final = "coverage"
COVERAGE_EXTRA: Final = "fuzz-coverage"

#: The setting that names the in-process target the built-in source instruments, as
#: ``package.module:callable``. The dependency makes the engine installable; this names *what*
#: it is pointed at, because coverage of nothing is not a signal.
COVERAGE_TARGET_ENV: Final = "ARACHNE_FUZZ_COVERAGE_TARGET"

#: Operators that grow or shrink a message, front-loaded for a field that reached new code —
#: the same set the response-novelty engine prioritises, and for the same reason: framing
#: arithmetic is where parser bugs live.
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


def coverage_available() -> bool:
    """True when the optional dependency behind this engine can be imported."""
    return importlib.util.find_spec(COVERAGE_DEPENDENCY) is not None


def coverage_target() -> tuple[Callable[[bytes], object] | None, str | None]:
    """The in-process target to instrument, from the environment.

    Exactly one of the two values is ``None``: either the callable, or the reason there is none.
    A setting that cannot be resolved is *reported*, never ignored — an operator who configured a
    target and silently got the default engine would be reading a report about a run that did not
    happen.
    """
    spec = os.environ.get(COVERAGE_TARGET_ENV, "").strip()
    if not spec:
        return None, f"no in-process target is configured ({COVERAGE_TARGET_ENV}=module:attribute)"
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        return None, f"{COVERAGE_TARGET_ENV} must be 'module:attribute', not {spec!r}"
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        return None, f"cannot import {module_name!r}: {exc}"
    target = getattr(module, attribute, None)
    if not callable(target):
        return None, f"{spec!r} does not name a callable"
    return target, None


@runtime_checkable
class CoverageSource(Protocol):
    """Where the engine reads coverage from.

    One method, because that is the whole contract: hand it the bytes of a case and it returns
    the coverage those bytes reached, as a set of stable identifiers. In-process instrumentation
    is one implementation (see :class:`InProcessCoverage`); a target that reports its own
    coverage through a channel is another, and neither the engine nor the runner has to know
    which one it is talking to.
    """

    def read(self, payload: bytes) -> frozenset[str]:
        """The coverage reached by executing ``payload``."""
        ...


@dataclass
class InProcessCoverage:
    """Coverage of a callable in this process, measured with the optional ``coverage`` extra.

    The callable receives the case's bytes. It is expected to *raise* on input it rejects — that
    is what a parser does with hostile input — and the coverage it reached before raising is
    still the coverage of that case, which is why this class lets the exception through and the
    engine records it rather than swallowing it.

    ``coverage`` is imported inside :meth:`read` rather than at module import: the engine and
    this class are importable without the extra (so the seam is testable and the report can
    explain the absence), and only an actual measurement needs the dependency.
    """

    target: Callable[[bytes], object]

    def read(self, payload: bytes) -> frozenset[str]:
        if not coverage_available():  # pragma: no cover - the engine refuses first
            msg = (
                f"{COVERAGE_ENGINE} measurement needs the optional extra "
                f"`arachne[{COVERAGE_EXTRA}]` (the {COVERAGE_DEPENDENCY} package)"
            )
            raise ConfigurationError(msg)
        import coverage

        tracer = coverage.Coverage(branch=True, data_file=None)
        tracer.start()
        # A target that rejects hostile input by raising is the normal case, and the coverage it
        # reached *before* raising is still the coverage of this case: suppress the exception and
        # keep the measurement.
        with contextlib.suppress(Exception):
            self.target(payload)
        tracer.stop()
        data = tracer.get_data()
        reached: set[str] = set()
        for measured in data.measured_files():
            for line in data.lines(measured) or ():
                reached.add(f"{measured}:{line}")
        return frozenset(reached)


@dataclass
class CoverageGuidedEngine:
    """Order cases by the instrumentation they reach, in declaration order otherwise.

    Its plan is the grammar's own case plan — the same deterministic starting point every engine
    shares — and its feedback changes only the *order* of what is left: when a case reaches code
    no earlier case reached, the rest of that field's length-changing operators are front-loaded,
    because the target has just shown that this field is where its parser does something new.

    With a source that never reports anything new (or none at all) the engine behaves exactly
    like the default one. That is the honest failure mode: coverage-guided ordering can only
    reorder the same bounded set of cases, so a run is never *worse* than the default, only
    differently ordered.
    """

    name: str = COVERAGE_ENGINE
    description: str = (
        "Coverage-guided ordering: re-prioritises the field whose case reached code no earlier "
        "case reached (in-process target instrumentation via the optional extra "
        f"`arachne[{COVERAGE_EXTRA}]`; NOT a remote target's coverage)"
    )
    #: Where coverage is read from. ``None`` means "no target to instrument": the engine then
    #: behaves exactly like the default one, which is why constructing it that way is refused
    #: when the optional dependency is missing — and why the registry only registers it with a
    #: target in hand (see ``arachne.fuzz.engines``).
    source: CoverageSource | None = None
    _grammar: MessageGrammar | None = field(default=None, init=False, repr=False, compare=False)
    _reached: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _queue: list[tuple[str, MutationOperator]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    #: The last error a source raised while measuring, if any: reported, never swallowed.
    last_error: str = field(default="", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.source is None and not coverage_available():
            msg = (
                f"the {COVERAGE_ENGINE}-guided engine needs a coverage source, and its built-in "
                f"one needs the optional extra `arachne[{COVERAGE_EXTRA}]` (the "
                f"{COVERAGE_DEPENDENCY} package). Install the extra, or inject a "
                f"`CoverageSource` of your own."
            )
            raise ConfigurationError(msg)

    @property
    def measuring(self) -> bool:
        """True when this engine will actually read coverage (a source is attached)."""
        return self.source is not None

    def plan(self, grammar: MessageGrammar, *, limit: int) -> tuple[FuzzCase, ...]:
        self._grammar = grammar
        self._reached.clear()
        self._queue.clear()
        self.last_error = ""
        cases: list[FuzzCase] = []
        for field_name, operator in grammar.case_plan():
            if len(cases) >= limit:
                break
            cases.append(grammar.build_case(field_name, operator, index=len(cases)))
        return tuple(cases)

    def observe(self, outcome: CaseOutcome) -> tuple[FuzzCase, ...]:
        """Front-load a field's remaining operators when its case reached new code."""
        grammar = self._grammar
        source = self.source
        if grammar is None or source is None or not outcome.answered:
            return ()
        try:
            case = grammar.build_case(
                outcome.field, _operator_of(outcome), index=outcome.case_index
            )
            reached = source.read(case.payload)
        except Exception as exc:
            self.last_error = f"coverage source failed on {outcome.field}: {exc}"
            return ()
        novel = reached - self._reached
        if not novel:
            return ()
        self._reached |= reached
        for operator in grammar.operators(grammar.field(outcome.field)):
            if operator in _LENGTH_OPERATORS:
                self._queue.append((outcome.field, operator))
        extra: list[FuzzCase] = []
        while self._queue:
            field_name, operator = self._queue.pop(0)
            extra.append(grammar.build_case(field_name, operator, index=outcome.case_index))
        return tuple(extra)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "coverage_points": len(self._reached),
            "measuring": self.measuring,
        }
        if self.last_error:
            payload["last_error"] = self.last_error
        return payload


def _operator_of(outcome: CaseOutcome) -> MutationOperator:
    """The operator an outcome names, as the enum.

    A wire case's operator is a ``MutationOperator`` value; an HTTP case's is ``family:encoding``
    (the two transports vary different things). An HTTP outcome therefore has no case to rebuild
    here, and the refusal is reported through ``last_error`` rather than guessed at.
    """
    for operator in MutationOperator:
        if operator.value == outcome.operator:
            return operator
    msg = f"the outcome names an operator no grammar case carries: {outcome.operator!r}"
    raise ValueError(msg)
