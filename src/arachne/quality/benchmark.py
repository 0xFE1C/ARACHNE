"""The benchmark harness: scored, version-committed detection results (REQ-QUAL-005).

"This claim is provable" is the requirement's whole content, and it has four parts, each of
which is a function here and a file on disk:

**Ground truth as data.** A :class:`BenchmarkSuite` is a versioned list of cases — a check id, a
marker that must (or must not) appear in the candidate's evidence — loaded from
``templates/benchmark/suites/<name>.yaml``. The markers are what makes a score meaningful: a
suite whose cases were inferred from what the scanner happened to report measures nothing.

**The existing scoring pattern.** :func:`measure` is the same arithmetic the lab acceptance tests
use (detection = matched planted cases / planted cases; FP rate = candidates that match no case /
all scored candidates), lifted out of the test file so the tests, the harness and CI compute the
same numbers the same way.

**Version-committed results.** A :class:`BenchmarkResult` is written to
``benchmarks/<suite>/baseline.json`` and committed. It records the suite version, the Arachne
version, the target it was measured against and the timestamp, so "we scored 62% on 2026-10-30
with suite 1.0" is a fact in the repository rather than a sentence in a slide.

**Regressions block.** :func:`compare` is the gate: a detection drop beyond the tolerance (or an
FP-rate rise) turns the job red. Tolerances are explicit parameters because a benchmark that
fails at ±0.1% noise is a benchmark people switch off.

Two kinds of suite ship, and the difference is recorded rather than hidden:
``source: lab`` runs against a ground-truth target in this repository (which CI *can* run, and
does); ``source: recorded`` holds results captured against an externally hosted target (OWASP
Benchmark, Juice Shop, DVWA) with the exact command to reproduce them. A recorded baseline still
gates: its scores are compared, and its internal consistency is checked.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError

__all__ = [
    "BENCHMARK_SUITE_RESOURCE",
    "BenchmarkCase",
    "BenchmarkResult",
    "BenchmarkScore",
    "BenchmarkSuite",
    "Regression",
    "compare",
    "load_baseline",
    "load_suite",
    "load_suites",
    "measure",
    "result_from_score",
    "write_result",
]

#: Where the shipped suites live inside the package.
BENCHMARK_SUITE_RESOURCE: Final = ("benchmark", "suites")

_MODEL = ConfigDict(frozen=True, extra="forbid")

#: ``tp`` = the marker must appear; ``fp`` = a candidate matching it is a false positive.
Expectation = Literal["tp", "fp"]


class BenchmarkCase(BaseModel):
    """One expected detection, or one documented hardened counterpart."""

    model_config = _MODEL

    check_id: str = Field(min_length=3, max_length=128)
    marker: str = Field(min_length=1, max_length=512)
    expect: Expectation = "tp"
    note: str = Field(default="", max_length=512)


class BenchmarkSuite(BaseModel):
    """A versioned benchmark: what a target should and should not produce."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    target: str = Field(min_length=1, max_length=512)
    #: ``lab`` (runnable in this repository) or ``recorded`` (captured from a hosted target).
    source: Literal["lab", "recorded"] = "lab"
    #: ``False`` for a suite whose target is hosted elsewhere: its baseline is optional until an
    #: operator records one, and the gate reports the absence as a note rather than a failure.
    required: bool = True
    #: How an operator reproduces a recorded suite against the real target.
    reproduce: str = Field(default="", max_length=1000)
    notes: str = Field(default="", max_length=2000)
    cases: tuple[BenchmarkCase, ...] = Field(min_length=1)

    @property
    def planted(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if case.expect == "tp")

    @property
    def traps(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if case.expect == "fp")


@dataclass(frozen=True, slots=True)
class BenchmarkScore:
    """One measurement: the numbers the gate compares."""

    detection: float
    true_positives: int
    planted: int
    false_positives: int
    #: Scored candidates: true positives plus false positives (the benchmark convention).
    candidates: int
    fp_rate: float
    #: Candidates from the suite's checks that matched no case at all. Reported, never
    #: penalised: a benchmark scores its *cases*, and a finding on a path the suite does not
    #: describe is outside its ground truth (it is the suite's blind spot, not a false alarm).
    unscored: int = 0
    missed: tuple[str, ...] = ()
    fp_examples: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection": round(self.detection, 4),
            "true_positives": self.true_positives,
            "planted": self.planted,
            "false_positives": self.false_positives,
            "candidates": self.candidates,
            "fp_rate": round(self.fp_rate, 4),
            "unscored": self.unscored,
            "missed": list(self.missed),
            "fp_examples": list(self.fp_examples),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> BenchmarkScore:
        return cls(
            detection=float(payload.get("detection") or 0.0),
            true_positives=int(payload.get("true_positives") or 0),
            planted=int(payload.get("planted") or 0),
            false_positives=int(payload.get("false_positives") or 0),
            candidates=int(payload.get("candidates") or 0),
            fp_rate=float(payload.get("fp_rate") or 0.0),
            unscored=int(payload.get("unscored") or 0),
            missed=tuple(str(item) for item in payload.get("missed") or ()),
            fp_examples=tuple(str(item) for item in payload.get("fp_examples") or ()),
        )

    def record(self) -> str:
        return (
            f"detection {self.true_positives}/{self.planted} ({self.detection:.0%}); "
            f"FP {self.false_positives}/{self.candidates} ({self.fp_rate:.0%})"
            + (f"; unscored {self.unscored}" if self.unscored else "")
            + (f"; missed: {list(self.missed)}" if self.missed else "")
        )


class BenchmarkResult(BaseModel):
    """A committed score: the suite, the target, and the numbers that were measured."""

    model_config = _MODEL

    suite: str
    suite_version: str
    arachne_version: str = ""
    target: str = ""
    source: str = "lab"
    measured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    score: dict[str, Any] = Field(default_factory=dict)

    @property
    def numbers(self) -> BenchmarkScore:
        return BenchmarkScore.from_dict(self.score)

    def to_document(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "suite_version": self.suite_version,
            "arachne_version": self.arachne_version,
            "target": self.target,
            "source": self.source,
            "measured_at": self.measured_at.isoformat(),
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class Regression:
    """One way a run got worse than its committed baseline."""

    kind: str
    detail: str
    baseline: float
    current: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "baseline": self.baseline,
            "current": self.current,
        }


# --------------------------------------------------------------------------- loading


def load_suite(name: str, *, path: str | Path | None = None) -> BenchmarkSuite:
    """Load one shipped suite (or a file when ``path`` is given)."""
    if path is not None:
        document = _read_yaml(Path(path))
    else:
        resource = files("arachne.templates")
        for part in (*BENCHMARK_SUITE_RESOURCE, f"{name}.yaml"):
            resource = resource.joinpath(part)
        try:
            document = yaml.safe_load(resource.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError) as exc:
            raise ConfigurationError(f"unknown benchmark suite {name!r}: {exc}") from exc
    try:
        return BenchmarkSuite.model_validate(document)
    except ValidationError as exc:  # pragma: no cover - a broken suite is an operator error
        raise ConfigurationError(f"{name}: invalid benchmark suite: {exc}") from exc


def load_suites() -> dict[str, BenchmarkSuite]:
    """Every shipped suite, keyed by name (deterministic order)."""
    resource = files("arachne.templates")
    for part in BENCHMARK_SUITE_RESOURCE:
        resource = resource.joinpath(part)
    out: dict[str, BenchmarkSuite] = {}
    for entry in sorted(resource.iterdir(), key=lambda item: item.name):
        if not entry.name.endswith(".yaml"):
            continue
        suite = load_suite(entry.name[: -len(".yaml")])
        out[suite.name] = suite
    return out


def _read_yaml(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{path}: not valid YAML: {exc}") from exc


# --------------------------------------------------------------------------- scoring


def measure(records: Iterable[Any], suite: BenchmarkSuite) -> BenchmarkScore:
    """Score stored candidates against the suite's cases (the lab tests' arithmetic).

    A candidate *matches* a case when its check id is the case's and the marker appears in its
    evidence payloads. That is the whole scoring rule, and it is the benchmark convention the
    named targets use: their ground truth marks specific cases as vulnerable or not, so a
    finding that hits a ``tp`` case is a true positive, one that hits an ``fp`` trap is a false
    positive, and one that hits neither is **unscored** — outside the suite's ground truth.

    Counting "anything the suite did not list" as a false positive would punish a check for
    finding something real on a path the suite's authors never described, and would make the
    FP rate a measure of the suite's exhaustiveness rather than of the scanner's precision.
    The unscored count is reported so that blind spot stays visible.

    Only the checks the suite names are scored (the same scoping the S6 acceptance test applies
    to its core set), so a family the suite does not measure cannot move its numbers.
    """
    scored_checks = {case.check_id for case in suite.cases}
    matched: set[tuple[str, str]] = set()
    false_positives: list[str] = []
    unscored = 0
    for record in records:
        check_id = _check_id_of(record)
        if check_id not in scored_checks:
            continue
        blob = _blob(record)
        hits = [
            (case.check_id, case.marker)
            for case in suite.planted
            if case.check_id == check_id and case.marker in blob
        ]
        if hits:
            matched.update(hits)
            continue
        trap = [
            case.marker for case in suite.traps if case.check_id == check_id and case.marker in blob
        ]
        if trap:
            false_positives.append(f"{check_id}:trap={trap}")
        else:
            unscored += 1
    scored = len(matched) + len(false_positives)
    return BenchmarkScore(
        detection=round(len(matched) / len(suite.planted), 4) if suite.planted else 0.0,
        true_positives=len(matched),
        planted=len(suite.planted),
        false_positives=len(false_positives),
        candidates=scored,
        fp_rate=round(len(false_positives) / scored, 4) if scored else 0.0,
        unscored=unscored,
        missed=tuple(
            f"{case.check_id}:{case.marker}"
            for case in suite.planted
            if (case.check_id, case.marker) not in matched
        ),
        fp_examples=tuple(sorted(false_positives)[:6]),
    )


def _check_id_of(record: Any) -> str:
    """``M3/sqli-oracle@1.0`` or ``m3.sqli-oracle`` → ``m3.sqli-oracle``."""
    value = str(getattr(record, "check_key", None) or getattr(record, "check_id", "") or "")
    head, _, _version = value.partition("@")
    module, _, name = head.partition("/")
    return f"{module.lower()}.{name}" if module and name else head.lower()


def _blob(record: Any) -> str:
    parts: list[str] = []
    for item in getattr(record, "evidence", ()) or ():
        payload = getattr(item, "payload", None)
        if isinstance(payload, dict):
            parts.extend(f"{key}={value}" for key, value in payload.items())
    title = getattr(record, "title", "")
    if title:
        parts.append(str(title))
    return " ".join(parts)


def result_from_score(
    suite: BenchmarkSuite,
    score: BenchmarkScore,
    *,
    arachne_version: str = "",
    target: str = "",
    measured_at: datetime | None = None,
) -> BenchmarkResult:
    return BenchmarkResult(
        suite=suite.name,
        suite_version=suite.version,
        arachne_version=arachne_version,
        target=target or suite.target,
        source=suite.source,
        measured_at=measured_at or datetime.now(UTC),
        score=score.to_dict(),
    )


# --------------------------------------------------------------------------- the gate


def compare(
    current: BenchmarkResult,
    baseline: BenchmarkResult,
    *,
    max_detection_drop: float = 0.02,
    max_fp_rise: float = 0.02,
) -> tuple[Regression, ...]:
    """Compare a run against its baseline; an empty tuple means "no regression".

    Three checks, in the order a reviewer cares:

    1. the **suite version** must match — comparing scores measured against different ground
       truth is meaningless, and silently accepting it would let a suite edit look like a
       detection change;
    2. **detection** may not drop by more than ``max_detection_drop``;
    3. the **false-positive rate** may not rise by more than ``max_fp_rise``.
    """
    out: list[Regression] = []
    if current.suite_version != baseline.suite_version:
        out.append(
            Regression(
                kind="suite-version",
                detail=(
                    f"suite {current.suite} is now version {current.suite_version}, but the "
                    f"baseline was measured with {baseline.suite_version}"
                ),
                baseline=0.0,
                current=0.0,
            )
        )
    now, before = current.numbers, baseline.numbers
    if now.detection < before.detection - max_detection_drop:
        out.append(
            Regression(
                kind="detection",
                detail=(
                    f"detection fell from {before.detection:.0%} to {now.detection:.0%} "
                    f"(tolerance {max_detection_drop:.0%}); missed: {list(now.missed)}"
                ),
                baseline=before.detection,
                current=now.detection,
            )
        )
    if now.fp_rate > before.fp_rate + max_fp_rise:
        out.append(
            Regression(
                kind="false-positive-rate",
                detail=(
                    f"false-positive rate rose from {before.fp_rate:.0%} to {now.fp_rate:.0%} "
                    f"(tolerance {max_fp_rise:.0%}); examples: {list(now.fp_examples)}"
                ),
                baseline=before.fp_rate,
                current=now.fp_rate,
            )
        )
    return tuple(out)


# --------------------------------------------------------------------------- on-disk


def write_result(path: str | Path, result: BenchmarkResult) -> Path:
    """Write a result document (the committed baseline)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(result.to_document(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return target


def load_baseline(directory: str | Path, suite: str) -> BenchmarkResult | None:
    """The committed baseline for ``suite`` under ``directory``, or ``None``."""
    path = Path(directory) / suite / "baseline.json"
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"{path}: not a readable benchmark baseline: {exc}") from exc
    return BenchmarkResult.model_validate(document)


def baseline_dir(root: str | Path) -> Path:
    """``<root>/benchmarks`` — where the committed results live."""
    return Path(root) / "benchmarks"


def consistency_problems(result: BenchmarkResult) -> tuple[str, ...]:
    """Internal consistency of a committed result (what a recorded baseline can still prove).

    A recorded score cannot be re-measured in CI without the hosted target, but it can be
    checked for the arithmetic that makes it a score: the detection rate must equal its own
    true-positive count over the planted count, and the FP rate must equal its own counts. A
    hand-edited baseline that flatters the scanner fails here.
    """
    problems: list[str] = []
    numbers = result.numbers
    expected_detection = (
        round(numbers.true_positives / numbers.planted, 4) if numbers.planted else 0.0
    )
    if abs(numbers.detection - expected_detection) > 0.0005:
        problems.append(
            f"detection {numbers.detection} != {expected_detection} "
            f"({numbers.true_positives}/{numbers.planted})"
        )
    expected_fp = (
        round(numbers.false_positives / numbers.candidates, 4) if numbers.candidates else 0.0
    )
    if abs(numbers.fp_rate - expected_fp) > 0.0005:
        problems.append(
            f"fp_rate {numbers.fp_rate} != {expected_fp} "
            f"({numbers.false_positives}/{numbers.candidates})"
        )
    if numbers.true_positives > numbers.planted:
        problems.append("more true positives than planted cases")
    return tuple(problems)


@dataclass(frozen=True, slots=True)
class GateReport:
    """The gate's verdict for one suite."""

    suite: str
    measured: bool
    regressions: tuple[Regression, ...] = ()
    problems: tuple[str, ...] = ()
    score: BenchmarkScore | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.regressions and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "ok": self.ok,
            "measured": self.measured,
            "score": self.score.to_dict() if self.score is not None else None,
            "regressions": [item.to_dict() for item in self.regressions],
            "problems": list(self.problems),
            "notes": list(self.notes),
        }


def gate(
    current: BenchmarkResult,
    *,
    directory: str | Path,
    max_detection_drop: float = 0.02,
    max_fp_rise: float = 0.02,
) -> GateReport:
    """Compare one measured result against its committed baseline (the CI gate)."""
    baseline = load_baseline(directory, current.suite)
    if baseline is None:
        return GateReport(
            suite=current.suite,
            measured=True,
            problems=(f"no committed baseline at {Path(directory) / current.suite}",),
            score=current.numbers,
        )
    regressions = compare(
        current, baseline, max_detection_drop=max_detection_drop, max_fp_rise=max_fp_rise
    )
    return GateReport(
        suite=current.suite,
        measured=True,
        regressions=regressions,
        score=current.numbers,
    )


def verify_recorded(suite: BenchmarkSuite, *, directory: str | Path) -> GateReport:
    """What the gate can still check for a suite whose target is hosted elsewhere."""
    baseline = load_baseline(directory, suite.name)
    if baseline is None:
        missing = f"no committed baseline at {Path(directory) / suite.name}"
        if suite.required:
            return GateReport(suite=suite.name, measured=False, problems=(missing,))
        return GateReport(
            suite=suite.name,
            measured=False,
            notes=(
                f"{missing}; run the suite against {suite.target} and commit the result "
                "(the suite is optional until then)",
            ),
        )
    problems = consistency_problems(baseline)
    notes = (
        (
            f"recorded against {baseline.target} with suite v{baseline.suite_version}; "
            f"reproduce with: {suite.reproduce or 'see the suite file'}",
        )
        if suite.source == "recorded"
        else ()
    )
    return GateReport(
        suite=suite.name,
        measured=False,
        problems=problems,
        score=baseline.numbers,
        notes=notes,
    )


def case_names(suite: BenchmarkSuite) -> tuple[str, ...]:
    """``check|marker|expect`` for every case (used by the suite drift test)."""
    return tuple(f"{case.check_id}|{case.marker}|{case.expect}" for case in suite.cases)


def matches_pattern(marker: str, pattern: str) -> bool:
    """Small helper for suite authors writing marker globs."""
    return fnmatchcase(marker, pattern)


def suite_digest(suite: BenchmarkSuite) -> str:
    """A stable digest of a suite's content (documented in the committed result)."""
    import hashlib

    payload = "\n".join([suite.name, suite.version, *case_names(suite)])
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def known_suite_names() -> Sequence[str]:
    """The suites this build ships (for a CLI's ``--help``)."""
    return tuple(load_suites())
