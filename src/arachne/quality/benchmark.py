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

**Reproducibility (REQ-TRUST-010).** A score nobody can re-derive is a claim, not a
measurement, so the committed result carries everything a third party needs: the corpus version
(:func:`suite_digest` names the exact case list), the command that produced it, the environment
the interpreter reported, and the **raw per-case rows** — one row per suite case, saying whether
it matched and which candidate matched it — not only the aggregates. :func:`environment_snapshot`
records the python/platform/build fingerprint and deliberately never the hostname or user, and
:func:`deterministic_projection` strips the wall-clock and environment noise so a reproduction
that differs only in timing compares equal.

**Rotation.** A benchmark whose fixtures never change measures memorisation, so each suite
records when it was last rotated and when it is next due (:func:`rotation_problems` fails a run
past ``review_by``). :func:`stamp_rotation` is the mechanism that writes those fields.

**Time-to-finding.** Precision and recall sit beside the existing detection/FP numbers, and the
measured scan's wall-clock seconds are recorded. Where a per-case time-to-finding is available
(the store timestamps each candidate) it is recorded; where it is not, the artefact says so
rather than inventing one. :func:`measure_with_cases` never fabricates a number.
"""

from __future__ import annotations

import json
import os
import platform
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError

__all__ = [
    "BENCHMARK_SUITE_RESOURCE",
    "ROTATION_INTERVAL_DAYS",
    "BenchmarkCase",
    "BenchmarkResult",
    "BenchmarkScore",
    "BenchmarkSuite",
    "CaseResult",
    "Regression",
    "compare",
    "deterministic_projection",
    "environment_snapshot",
    "load_baseline",
    "load_suite",
    "load_suites",
    "measure",
    "measure_with_cases",
    "result_from_score",
    "rotation_problems",
    "stamp_rotation",
    "suite_file_path",
    "timing_document",
    "write_result",
]

#: Where the shipped suites live inside the package.
BENCHMARK_SUITE_RESOURCE: Final = ("benchmark", "suites")

#: Every suite must be reviewed at least annually (REQ-TRUST-010): a fixture set that never
#: changes stops measuring detection and starts measuring memorisation. The window is 365
#: days, so a rotation recorded on a leap day cannot quietly buy an extra year.
ROTATION_INTERVAL_DAYS: Final = 365

#: The managed rotation block :func:`stamp_rotation` writes at the end of a suite file. Markers
#: rather than a full YAML rewrite, so the hand-written WHY comments above the cases survive a
#: rotation.
ROTATION_MARKER_START: Final = (
    "# --- rotation (managed by `python -m arachne.tools.benchmark --rotate`) ---"
)
ROTATION_MARKER_END: Final = "# --- end rotation ---"

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
    #: When the fixture set was last rotated and when the next review is due (REQ-TRUST-010).
    #: ``None`` is a suite that has never been stamped; :func:`rotation_problems` reports that
    #: as a problem rather than treating it as "not due yet".
    rotated_at: date | None = None
    review_by: date | None = None
    #: ``<iso-date>: <what changed>``, oldest first. Kept in the suite file so the rotation is
    #: a repository fact, not a sentence in a changelog.
    rotation_history: tuple[str, ...] = ()
    cases: tuple[BenchmarkCase, ...] = Field(min_length=1)

    @property
    def planted(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if case.expect == "tp")

    @property
    def traps(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if case.expect == "fp")


class CaseResult(BaseModel):
    """One suite case's raw outcome in a measured run (REQ-TRUST-010's "raw per-case").

    One row per case — planted or trap — so a reader can recompute the aggregates without
    trusting them, and can see *which* candidate matched. ``matched_by`` carries the stored
    candidate ids (not just a count), and ``elapsed_seconds`` is the wall-clock time from scan
    start to the first matching candidate when the store timestamps candidates;
    ``timing_source`` says where that number came from, or why there is none.
    """

    model_config = _MODEL

    check_id: str = Field(min_length=3, max_length=128)
    marker: str = Field(min_length=1, max_length=512)
    expect: Expectation = "tp"
    matched: bool = False
    matched_by: tuple[str, ...] = ()
    elapsed_seconds: float | None = None
    timing_source: str = ""

    @property
    def case(self) -> str:
        """``check|marker`` — the stable key a third party can join on."""
        return f"{self.check_id}|{self.marker}"


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
    #: ``precision = tp / (tp + fp)`` — of the scored candidates, the fraction that hit a
    #: planted case. Degenerate (0.0) when there were no scored candidates: no positive
    #: prediction means precision is undefined, not perfect.
    precision: float = 0.0
    #: ``recall = tp / planted`` — the fraction of the planted cases that were found. This is
    #: the same quantity as ``detection``; both names are kept because "detection rate" is what
    #: the gate already compares and "recall" is what the benchmark claim publishes. Degenerate
    #: (0.0) when the suite plants no cases.
    recall: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection": round(self.detection, 4),
            "true_positives": self.true_positives,
            "planted": self.planted,
            "false_positives": self.false_positives,
            "candidates": self.candidates,
            "fp_rate": round(self.fp_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "unscored": self.unscored,
            "missed": list(self.missed),
            "fp_examples": list(self.fp_examples),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> BenchmarkScore:
        true_positives = int(payload.get("true_positives") or 0)
        planted = int(payload.get("planted") or 0)
        false_positives = int(payload.get("false_positives") or 0)
        candidates = int(payload.get("candidates") or 0)
        # A baseline written before precision/recall existed still loads: derive them from the
        # counts it already carries rather than defaulting them to zero and flagging it.
        scored = true_positives + false_positives
        stored_precision = payload.get("precision")
        stored_recall = payload.get("recall")
        precision = (
            float(stored_precision)
            if stored_precision is not None
            else (round(true_positives / scored, 4) if scored else 0.0)
        )
        recall = (
            float(stored_recall)
            if stored_recall is not None
            else (round(true_positives / planted, 4) if planted else 0.0)
        )
        return cls(
            detection=float(payload.get("detection") or 0.0),
            true_positives=true_positives,
            planted=planted,
            false_positives=false_positives,
            candidates=candidates,
            fp_rate=float(payload.get("fp_rate") or 0.0),
            unscored=int(payload.get("unscored") or 0),
            missed=tuple(str(item) for item in payload.get("missed") or ()),
            fp_examples=tuple(str(item) for item in payload.get("fp_examples") or ()),
            precision=precision,
            recall=recall,
        )

    def record(self) -> str:
        return (
            f"detection {self.true_positives}/{self.planted} ({self.detection:.0%}); "
            f"precision {self.precision:.0%}; recall {self.recall:.0%}; "
            f"FP {self.false_positives}/{self.candidates} ({self.fp_rate:.0%})"
            + (f"; unscored {self.unscored}" if self.unscored else "")
            + (f"; missed: {list(self.missed)}" if self.missed else "")
        )


class BenchmarkResult(BaseModel):
    """A committed score: the corpus, the target, the environment and the raw rows.

    Every field added for REQ-TRUST-010 has a default, so a baseline committed before the
    reproducibility work still validates and still gates; it simply reports empty ``command``,
    ``environment``, ``timing`` and ``cases``.
    """

    model_config = _MODEL

    suite: str
    suite_version: str
    arachne_version: str = ""
    target: str = ""
    source: str = "lab"
    measured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    score: dict[str, Any] = Field(default_factory=dict)
    #: ``<suite>@<version>+<digest>`` — the version of the *corpus* (the case list), which is
    #: what makes "the same benchmark" meaningful. Prominent because the requirement names it
    #: first; ``suite``/``suite_version`` stay for compatibility with older readers.
    corpus_version: str = ""
    #: The exact command that reproduces this result (the suite's documented ``reproduce``).
    command: str = ""
    #: python/platform/interpreter/build fingerprint. Never the hostname or the user.
    environment: dict[str, Any] = Field(default_factory=dict)
    #: The measured scan's wall-clock seconds and the per-case timing source.
    timing: dict[str, Any] = Field(default_factory=dict)
    #: One row per suite case (REQ-TRUST-010's raw per-case results).
    cases: tuple[CaseResult, ...] = ()

    @property
    def numbers(self) -> BenchmarkScore:
        return BenchmarkScore.from_dict(self.score)

    def to_document(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "suite_version": self.suite_version,
            "corpus_version": self.corpus_version,
            "arachne_version": self.arachne_version,
            "target": self.target,
            "source": self.source,
            "command": self.command,
            "measured_at": self.measured_at.isoformat(),
            "environment": self.environment,
            "timing": self.timing,
            "score": self.score,
            "cases": [case.model_dump(mode="json") for case in self.cases],
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


# --------------------------------------------------------------------------- rotation


def suite_file_path(name: str) -> Path:
    """The editable path of a shipped suite (a checkout's ``templates/`` directory)."""
    return (
        Path(__file__).resolve().parents[1] / "templates" / "benchmark" / "suites" / f"{name}.yaml"
    )


def rotation_problems(suite: BenchmarkSuite, *, today: date) -> tuple[str, ...]:
    """Why ``suite`` is not compliant with the annual-rotation policy (REQ-TRUST-010).

    An empty tuple means the suite states a ``rotated_at``, a ``review_by`` no more than
    :data:`ROTATION_INTERVAL_DAYS` later, and today is not past that review date. A suite with
    no rotation record is a problem rather than "not due yet": silence is how a fixture set
    stops rotating without anyone deciding to stop.
    """
    problems: list[str] = []
    if suite.rotated_at is None:
        problems.append(f"suite {suite.name} records no rotated_at")
    if suite.review_by is None:
        problems.append(f"suite {suite.name} records no review_by")
        return tuple(problems)
    if suite.rotated_at is not None:
        if suite.review_by < suite.rotated_at:
            problems.append(
                f"suite {suite.name} has review_by {suite.review_by} before its rotation "
                f"date {suite.rotated_at}"
            )
        interval = (suite.review_by - suite.rotated_at).days
        if interval > ROTATION_INTERVAL_DAYS:
            problems.append(
                f"suite {suite.name} review window is {interval} days, more than the "
                f"{ROTATION_INTERVAL_DAYS}-day annual maximum"
            )
    if today > suite.review_by:
        problems.append(
            f"suite {suite.name} is overdue for rotation: review_by {suite.review_by} is "
            f"before today {today}"
        )
    return tuple(problems)


def stamp_rotation(path: str | Path, *, rotated_at: date, note: str = "") -> date:
    """Record a rotation in a suite file and return the new ``review_by`` date.

    The managed block is appended at the end of the file, delimited by markers, so the
    hand-written explanation at the top of a suite survives a rotation. The previous block is
    replaced, and the prior history is carried forward (oldest first).
    """
    target = Path(path)
    suite = load_suite(target.stem, path=target)
    review_by = rotated_at + timedelta(days=ROTATION_INTERVAL_DAYS)
    entry = f"{rotated_at.isoformat()}: {note}" if note else rotated_at.isoformat()
    history = (*suite.rotation_history, entry)
    kept = _strip_rotation_block(target.read_text(encoding="utf-8").splitlines())
    while kept and not kept[-1].strip():
        kept.pop()
    block = _rotation_block(rotated_at=rotated_at, review_by=review_by, history=history)
    target.write_text("\n".join([*kept, "", *block]) + "\n", encoding="utf-8")
    return review_by


def _rotation_block(*, rotated_at: date, review_by: date, history: Sequence[str]) -> list[str]:
    lines = [
        ROTATION_MARKER_START,
        f"rotated_at: {_yaml_scalar(rotated_at.isoformat())}",
        f"review_by: {_yaml_scalar(review_by.isoformat())}",
    ]
    if history:
        lines.append("rotation_history:")
        lines.extend(f"  - {_yaml_scalar(entry)}" for entry in history)
    else:
        lines.append("rotation_history: []")
    lines.append(ROTATION_MARKER_END)
    return lines


def _strip_rotation_block(lines: list[str]) -> list[str]:
    try:
        start = lines.index(ROTATION_MARKER_START)
        end = lines.index(ROTATION_MARKER_END, start)
    except ValueError:
        return lines
    return [*lines[:start], *lines[end + 1 :]]


def _yaml_scalar(value: str) -> str:
    """Single-quote a scalar, doubling any quote in it (YAML 1.1's rule)."""
    return "'" + value.replace("'", "''") + "'"


# --------------------------------------------------------------------------- scoring


def measure(records: Iterable[Any], suite: BenchmarkSuite) -> BenchmarkScore:
    """Score stored candidates against the suite's cases (the lab tests' arithmetic).

    See :func:`measure_with_cases` for the rule this delegates to; this entry point keeps the
    original signature for the tests and CI that only want the aggregates.
    """
    return measure_with_cases(records, suite)[0]


def measure_with_cases(
    records: Iterable[Any],
    suite: BenchmarkSuite,
    *,
    scan_started_at: datetime | None = None,
) -> tuple[BenchmarkScore, tuple[CaseResult, ...]]:
    """Score stored candidates against the suite's cases, keeping the raw per-case rows.

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

    **Definitions (REQ-TRUST-010).** ``precision = tp / (tp + fp)`` and ``recall = tp /
    planted``. ``precision`` is 0.0 when nothing was scored (no positive prediction — undefined,
    not perfect); ``recall`` is 0.0 when the suite plants no cases. ``detection`` is the same
    quantity as ``recall``.

    **Time-to-finding.** When ``scan_started_at`` is given and a matching candidate carries a
    ``created_at``, the case row records the seconds from scan start to that candidate. When the
    store exposes no timestamp, the row records ``None`` and a ``timing_source`` saying why —
    the harness never invents a per-case number.
    """
    scored_checks = {case.check_id for case in suite.cases}
    #: key -> the (id, created_at) of every candidate that matched it, in scan order.
    matched_planted: dict[tuple[str, str], list[tuple[str, datetime | None]]] = {}
    matched_traps: dict[tuple[str, str], list[tuple[str, datetime | None]]] = {}
    false_positive_blobs: list[str] = []
    unscored = 0
    for record in records:
        check_id = _check_id_of(record)
        if check_id not in scored_checks:
            continue
        blob = _blob(record)
        planted_hits = [
            case for case in suite.planted if case.check_id == check_id and case.marker in blob
        ]
        if planted_hits:
            for case in planted_hits:
                matched_planted.setdefault((case.check_id, case.marker), []).append(
                    (_candidate_id(record), getattr(record, "created_at", None))
                )
            continue
        trap_hits = [
            case for case in suite.traps if case.check_id == check_id and case.marker in blob
        ]
        if trap_hits:
            for case in trap_hits:
                matched_traps.setdefault((case.check_id, case.marker), []).append(
                    (_candidate_id(record), getattr(record, "created_at", None))
                )
            false_positive_blobs.append(f"{check_id}:trap={[case.marker for case in trap_hits]}")
        else:
            unscored += 1

    true_positives = len(matched_planted)
    false_positives = len(matched_traps)
    scored = true_positives + false_positives
    planted = len(suite.planted)
    score = BenchmarkScore(
        detection=round(true_positives / planted, 4) if planted else 0.0,
        true_positives=true_positives,
        planted=planted,
        false_positives=false_positives,
        candidates=scored,
        fp_rate=round(false_positives / scored, 4) if scored else 0.0,
        unscored=unscored,
        missed=tuple(
            f"{case.check_id}:{case.marker}"
            for case in suite.planted
            if (case.check_id, case.marker) not in matched_planted
        ),
        fp_examples=tuple(sorted(false_positive_blobs)[:6]),
        precision=round(true_positives / scored, 4) if scored else 0.0,
        recall=round(true_positives / planted, 4) if planted else 0.0,
    )
    cases = tuple(
        _case_result(
            case,
            matches=(matched_planted if case.expect == "tp" else matched_traps).get(
                (case.check_id, case.marker), []
            ),
            scan_started_at=scan_started_at,
        )
        for case in suite.cases
    )
    return score, cases


def _case_result(
    case: BenchmarkCase,
    *,
    matches: Sequence[tuple[str, datetime | None]],
    scan_started_at: datetime | None,
) -> CaseResult:
    """One suite case's raw row, including the honest reason for a missing per-case time."""
    elapsed: float | None = None
    if not matches:
        source = "not matched: there is no finding to time"
    elif scan_started_at is None:
        source = "unavailable: the scan's start time was not recorded"
    elif all(created is None for _identifier, created in matches):
        source = "unavailable: the store exposed no candidate created_at"
    else:
        for _identifier, created in matches:
            if created is None:
                continue
            elapsed = round((_as_utc(created) - _as_utc(scan_started_at)).total_seconds(), 3)
            break
        source = "candidate.created_at minus scan.started_at"
    return CaseResult(
        check_id=case.check_id,
        marker=case.marker,
        expect=case.expect,
        matched=bool(matches),
        matched_by=tuple(identifier for identifier, _created in matches),
        elapsed_seconds=elapsed,
        timing_source=source,
    )


def _as_utc(moment: datetime) -> datetime:
    """A naive timestamp from a store is UTC (every writer here stores UTC)."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _candidate_id(record: Any) -> str:
    """The stored candidate's id as text, or ``"?"`` when the store minted none."""
    identifier = getattr(record, "id", None)
    return str(identifier) if identifier is not None else "?"


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
    command: str = "",
    environment: dict[str, Any] | None = None,
    timing: dict[str, Any] | None = None,
    cases: Sequence[CaseResult] = (),
) -> BenchmarkResult:
    """Assemble the committed result document (REQ-TRUST-010's four named things)."""
    return BenchmarkResult(
        suite=suite.name,
        suite_version=suite.version,
        corpus_version=f"{suite.name}@{suite.version}+{suite_digest(suite)}",
        arachne_version=arachne_version,
        target=target or suite.target,
        source=suite.source,
        measured_at=measured_at or datetime.now(UTC),
        command=command or suite.reproduce,
        environment=environment or {},
        timing=timing or {},
        score=score.to_dict(),
        cases=tuple(cases),
    )


# --------------------------------------------------------------------------- publication


def environment_snapshot(arachne_version: str) -> dict[str, Any]:
    """The interpreter/build fingerprint a reproduction needs (REQ-TRUST-010).

    Deliberately narrow: python version, implementation, a platform string built from
    ``system/release/machine``, the ARACHNE version and ``SOURCE_DATE_EPOCH`` when set.
    Hostname, user, working directory and environment variables generally are **not**
    recorded — a benchmark artefact is published, and those identify a person or a machine.
    """
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": f"{platform.system()}-{platform.release()}-{platform.machine()}",
        "arachne_version": arachne_version,
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH") or None,
    }


def timing_document(
    *,
    scan_seconds: float,
    scan_started_at: datetime | None,
    cases: Sequence[CaseResult],
) -> dict[str, Any]:
    """The measured scan's timing, and an honest statement of what the store exposed.

    ``scan_seconds`` is always measured (wall clock around the scan call). Per-case
    time-to-finding exists only when a matched case has a candidate ``created_at`` *and* the
    scan's start was recorded; when it does not, the document says so instead of filling in a
    plausible-looking number.
    """
    matched = [case for case in cases if case.matched]
    timed = [case for case in matched if case.elapsed_seconds is not None]
    document: dict[str, Any] = {
        "scan_seconds": round(scan_seconds, 3),
        "scan_started_at": scan_started_at.isoformat() if scan_started_at else None,
        "cases_total": len(cases),
        "cases_matched": len(matched),
        "cases_with_time": len(timed),
        "per_case_source": "candidate.created_at minus scan.started_at",
        "per_case_available": bool(matched) and len(timed) == len(matched),
    }
    if matched and len(timed) < len(matched):
        document["note"] = (
            f"{len(matched) - len(timed)} of {len(matched)} matched cases have no per-case "
            "timestamp; see each case row's timing_source"
        )
    elif not matched:
        document["note"] = "no matched case, so there is no time-to-finding to record"
    return document


def deterministic_projection(result: BenchmarkResult) -> dict[str, Any]:
    """The parts of a result that a reproduction can compare byte-for-byte.

    Everything a benchmark measures *about detection* is deterministic given the same corpus
    and code: the corpus version, the aggregate numbers, and each case's ``(check, marker,
    expectation, matched)``. The timestamp, environment, wall-clock timing and the store's
    candidate ids are deliberately excluded — they are provenance, not measurement, and a
    reproduction on another machine is allowed to differ in them.
    """
    numbers = result.numbers.to_dict()
    return {
        "suite": result.suite,
        "suite_version": result.suite_version,
        "corpus_version": result.corpus_version,
        "score": {key: numbers[key] for key in _DETERMINISTIC_SCORE_KEYS},
        "cases": [
            {
                "check_id": case.check_id,
                "marker": case.marker,
                "expect": case.expect,
                "matched": case.matched,
            }
            for case in result.cases
        ],
    }


#: The score fields a reproduction must reproduce; counts and rates, never provenance.
_DETERMINISTIC_SCORE_KEYS: Final = (
    "detection",
    "true_positives",
    "planted",
    "false_positives",
    "candidates",
    "fp_rate",
    "precision",
    "recall",
    "unscored",
    "missed",
    "fp_examples",
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
    true-positive count over the planted count, the FP rate must equal its own counts, and
    precision/recall must agree with the counts they are derived from. A hand-edited baseline
    that flatters the scanner fails here.
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
    expected_precision = (
        round(numbers.true_positives / numbers.candidates, 4) if numbers.candidates else 0.0
    )
    if abs(numbers.precision - expected_precision) > 0.0005:
        problems.append(
            f"precision {numbers.precision} != {expected_precision} "
            f"({numbers.true_positives}/{numbers.candidates})"
        )
    expected_recall = round(numbers.true_positives / numbers.planted, 4) if numbers.planted else 0.0
    if abs(numbers.recall - expected_recall) > 0.0005:
        problems.append(
            f"recall {numbers.recall} != {expected_recall} "
            f"({numbers.true_positives}/{numbers.planted})"
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
    max_fp_rate: float | None = 0.02,
) -> GateReport:
    """Compare one measured result against its committed baseline (the CI gate).

    ``max_fp_rate`` is an **absolute** ceiling, not a relative one: REQ-QUAL-009 makes the
    published false-positive rate a release criterion at or below 2 per cent, so a run that
    stays at its own (bad) baseline still fails. Pass ``None`` to check only for a
    regression against the baseline.
    """
    ceiling = (
        (
            f"false-positive rate {current.numbers.fp_rate:.1%} is over the {max_fp_rate:.0%} "
            "release ceiling (REQ-QUAL-009)",
        )
        if max_fp_rate is not None and current.numbers.fp_rate > max_fp_rate
        else ()
    )
    baseline = load_baseline(directory, current.suite)
    if baseline is None:
        return GateReport(
            suite=current.suite,
            measured=True,
            problems=(f"no committed baseline at {Path(directory) / current.suite}", *ceiling),
            score=current.numbers,
        )
    regressions = compare(
        current, baseline, max_detection_drop=max_detection_drop, max_fp_rise=max_fp_rise
    )
    return GateReport(
        suite=current.suite,
        measured=True,
        regressions=regressions,
        problems=ceiling,
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
