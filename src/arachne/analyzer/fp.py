"""False-positive reduction (F-05-07).

Three mechanisms, in the order an operator would want them:

**Verification** — a candidate whose check declared itself ``verifiable`` is re-requested
once, and the second observation is compared with the first. A contradiction (the endpoint
answers 404 now, or the body no longer carries the signal) is not silently discarded: the
finding is *dropped* with its reason recorded, because "we saw it, then we did not" is
information an operator needs and a report must be able to explain.

**Context filters** — placeholder pages (the web server's default page, a "coming soon"
screen), WAF challenge pages (Cloudflare/Akamai/Imperva interstitials) and login walls
suppress the noise they cause. They *penalise* rather than delete, except when the artifact
they explain is the entire substance of the finding (a 200 with nothing but a placeholder
body), which is dropped.

**The FP tuner** — operators mark findings ``fp``, and the tuner turns those marks into a
per-(check, asset kind, signature) false-positive rate that raises the confidence a finding
needs before it is reported. The rate is read once per analysis run, so the result stays
deterministic for a given feedback state, and the store is a protocol so
the SQLite implementation (``fp_feedback``) can be swapped for an API-backed one in S12.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Any, Final, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.model import (
    Candidate,
    FpStats,
    VerificationOutcome,
)
from arachne.core.errors import ConfigurationError
from arachne.core.results import sha256_of

__all__ = [
    "BUCKET_DAY",
    "DEFAULT_FP_FILTER_RESOURCE",
    "DEFAULT_FP_THRESHOLD_RESOURCE",
    "FeedbackEvent",
    "FeedbackRecord",
    "FeedbackStore",
    "FpAlert",
    "FpFilter",
    "FpFilterSet",
    "FpFlags",
    "FpThresholds",
    "FpTrend",
    "FpTrendPoint",
    "FpTuner",
    "HttpVerifier",
    "MemoryFeedbackStore",
    "NullVerifier",
    "TunerRow",
    "Verifier",
    "classify",
    "compute_trends",
    "feedback_key",
    "feedback_key_for",
    "load_fp_filters",
    "load_fp_thresholds",
    "parse_fp_filters",
    "parse_fp_thresholds",
    "rising_alerts",
    "split_feedback_key",
]

#: Where the shipped filter corpus lives inside the package.
DEFAULT_FP_FILTER_RESOURCE: Final = ("fp", "filters.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: A false-positive rate above this makes a finding "needs more confidence than it has".
MAX_PENALTY = 0.25


class FpFilter(BaseModel):
    """One filter: a class of page that must not be mistaken for a finding."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=2, max_length=128)
    kind: str
    patterns: tuple[str, ...] = Field(min_length=1)
    #: ``True`` when the filter alone is enough to drop the finding (a body that is *only* a
    #: placeholder says nothing), ``False`` when it only lowers confidence.
    decisive: bool = False
    detail: str = ""

    @model_validator(mode="after")
    def _validate(self) -> FpFilter:
        if self.kind not in {"placeholder", "waf", "login_wall"}:
            msg = f"filter {self.id}: kind {self.kind!r} is not placeholder/waf/login_wall"
            raise ValueError(msg)
        return self

    def matches(self, text: str) -> int:
        """How many of this filter's patterns fire on ``text`` (case-insensitive)."""
        lowered = text.lower()
        return sum(1 for pattern in self.patterns if pattern.lower() in lowered)


class FpFilterSet(BaseModel):
    """The whole filter corpus."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    filters: tuple[FpFilter, ...] = Field(min_length=1)

    def of_kind(self, kind: str) -> tuple[FpFilter, ...]:
        return tuple(item for item in self.filters if item.kind == kind)


@dataclass(frozen=True, slots=True)
class FpFlags:
    """What the context filters concluded about one candidate."""

    placeholder: bool = False
    waf: bool = False
    login_wall: bool = False
    decisive: bool = False
    matched: tuple[str, ...] = ()
    detail: str = ""

    @property
    def any(self) -> bool:
        return self.placeholder or self.waf or self.login_wall

    def to_dict(self) -> dict[str, Any]:
        return {
            "placeholder": self.placeholder,
            "waf": self.waf,
            "login_wall": self.login_wall,
            "decisive": self.decisive,
            "matched": list(self.matched),
            "detail": self.detail,
        }


#: Evidence kinds whose ``body``/text participates in context filtering.
_TEXT_KEYS: Final[tuple[str, ...]] = ("body", "text", "content", "banner", "response")


def _candidate_text(candidate: Candidate) -> str:
    """The text the filters look at: HTTP bodies and banner/response fields."""
    chunks: list[str] = []
    for item in candidate.evidence:
        payload = item.payload
        for key in _TEXT_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value:
                chunks.append(value)
    return "\n".join(chunks)


def classify(candidate: Candidate, filters: FpFilterSet) -> FpFlags:
    """Apply every context filter to a candidate's captured text (F-05-07)."""
    text = _candidate_text(candidate)
    if not text:
        return FpFlags()
    matched: list[str] = []
    placeholder = waf = login_wall = False
    decisive = False
    details: list[str] = []
    for item in filters.filters:
        hits = item.matches(text)
        if not hits:
            continue
        matched.append(item.id)
        if item.kind == "placeholder":
            placeholder = True
        elif item.kind == "waf":
            waf = True
        else:
            login_wall = True
        if item.decisive:
            decisive = True
        if item.detail:
            details.append(item.detail)
    return FpFlags(
        placeholder=placeholder,
        waf=waf,
        login_wall=login_wall,
        decisive=decisive and not _has_substantive_signal(candidate),
        matched=tuple(matched),
        detail="; ".join(dict.fromkeys(details)),
    )


def _has_substantive_signal(candidate: Candidate) -> bool:
    """True when the candidate carries a signal beyond "a web page answered".

    A candidate holding a parsed protocol response, a certificate, a socket banner or a
    signature artifact is not "just a placeholder page", so a decisive filter must not drop
    it. Only a bare HTTP body with nothing else behind it is droppable.
    """
    for item in candidate.evidence:
        if item.kind in {"http_response", "http_request"}:
            continue
        return True
    return False


# --------------------------------------------------------------------------- verification


@dataclass(frozen=True, slots=True)
class VerificationTarget:
    """The request to re-issue: what the original capture says was asked."""

    url: str
    method: str = "GET"
    status_code: int | None = None
    body_sha256: str | None = None

    @classmethod
    def from_candidate(cls, candidate: Candidate) -> VerificationTarget | None:
        request = next((item for item in candidate.evidence if item.kind == "http_request"), None)
        response = next((item for item in candidate.evidence if item.kind == "http_response"), None)
        url = None
        method = "GET"
        if request is not None:
            url = request.source or _string(request.payload.get("url"))
            method = _string(request.payload.get("method")) or "GET"
        if not url and response is not None:
            url = response.source
        if not url:
            return None
        status = response.payload.get("status_code") if response is not None else None
        body = response.payload.get("body") if response is not None else None
        return cls(
            url=url,
            method=method.upper(),
            status_code=status if isinstance(status, int) else None,
            body_sha256=sha256_of(body) if isinstance(body, str) and body else None,
        )


def _string(value: Any) -> str | None:
    """A non-empty string value, or ``None`` (evidence payloads are loosely typed)."""
    return value if isinstance(value, str) and value else None


class Verifier(Protocol):
    """Re-issues one request to confirm a candidate reproduces (F-05-07)."""

    async def verify(self, candidate: Candidate) -> VerificationOutcome: ...


class NullVerifier:
    """The dry-run/no-client verifier: nothing is re-requested, nothing is claimed."""

    async def verify(self, candidate: Candidate) -> VerificationOutcome:
        return VerificationOutcome(count=1, attempted=False, reproducible=False)


class HttpVerifier:
    """Re-request a candidate's URL through the scan's scoped client.

    The client is the same one the check used, so a verification request is validated,
    scope-checked, rate-limited, audited and redacted exactly like the original — there is
    no second, privileged egress path (ADR-05).
    """

    def __init__(self, http: Any, *, max_verifications: int = 25, require_body_match: bool = True):
        self._http = http
        self.max_verifications = max_verifications
        self.require_body_match = require_body_match
        self.attempted = 0

    @property
    def available(self) -> bool:
        return self._http is not None

    async def verify(self, candidate: Candidate) -> VerificationOutcome:
        if self._http is None:
            return VerificationOutcome(count=1, attempted=False)
        target = VerificationTarget.from_candidate(candidate)
        if target is None:
            return VerificationOutcome(count=1, attempted=False, detail="no captured request URL")
        if self.attempted >= self.max_verifications:
            return VerificationOutcome(
                count=1,
                attempted=False,
                detail=f"verification budget of {self.max_verifications} reached",
            )
        self.attempted += 1
        try:
            exchange = await self._http.request(
                target.method, target.url, follow_redirects=self.require_body_match
            )
        except Exception as exc:  # a failed re-request is data, not a crash
            return VerificationOutcome(
                count=1,
                attempted=True,
                reproducible=False,
                detail=f"verification request failed: {type(exc).__name__}",
            )
        if target.status_code is not None and exchange.status_code != target.status_code:
            return VerificationOutcome(
                count=1,
                attempted=True,
                contradicted=True,
                detail=(
                    f"re-request returned HTTP {exchange.status_code}, the original capture "
                    f"recorded HTTP {target.status_code}"
                ),
            )
        if (
            self.require_body_match
            and target.body_sha256 is not None
            and sha256_of(exchange.body) != target.body_sha256
        ):
            return VerificationOutcome(
                count=1,
                attempted=True,
                contradicted=True,
                detail="re-request returned a different body than the original capture",
            )
        return VerificationOutcome(
            count=2,
            attempted=True,
            reproducible=True,
            detail="the finding reproduced on a second, independent request",
        )


# --------------------------------------------------------------------------- FP tuner


def feedback_key(candidate: Candidate, *, signature: str | None = None) -> str:
    """The identity the tuner learns on: ``check|asset-kind|signature`` ."""
    return "|".join(
        [
            candidate.check_id or "unknown",
            candidate.asset_kind or "unknown",
            signature or "none",
        ]
    )


def feedback_key_for(
    check_key: str | None, asset_kind: str | None, *, signature: str | None = None
) -> str:
    """The same key for a *stored* finding row (``M4/env-file-probe@1.0``).

    The evidence store keys a check as ``M4/env-file-probe@1.0``; the analyzer's candidates
    use the dot form ``m4.env-file-probe``. One translation, in one place, so a decision
    taken through the CLI or the API adjusts exactly the threshold a scan-time decision
    would (F-05-07).
    """
    module, _, rest = (check_key or "").partition("/")
    name, _, _version = rest.partition("@")
    check_id = f"{module.lower()}.{name}" if module and name else (check_key or "unknown")
    return "|".join([check_id.rsplit("@", 1)[0], asset_kind or "unknown", signature or "none"])


@dataclass(frozen=True, slots=True)
class FeedbackRecord:
    """One operator decision about one finding."""

    key: str
    is_fp: bool
    finding_id: int | None = None
    note: str | None = None


class FeedbackStore(Protocol):
    """Where FP feedback lives; SQL in ``data.analysis_store``, memory in tests."""

    def record(self, record: FeedbackRecord) -> None: ...

    def stats(self, keys: Iterable[str] | None = None) -> Mapping[str, FpStats]: ...


class MemoryFeedbackStore:
    """In-memory feedback (unit tests, and a scan with no database)."""

    def __init__(self) -> None:
        self._records: list[FeedbackRecord] = []

    def record(self, record: FeedbackRecord) -> None:
        self._records.append(record)

    def stats(self, keys: Iterable[str] | None = None) -> Mapping[str, FpStats]:
        wanted = set(keys) if keys is not None else None
        totals: dict[str, int] = {}
        fps: dict[str, int] = {}
        for record in self._records:
            if wanted is not None and record.key not in wanted:
                continue
            totals[record.key] = totals.get(record.key, 0) + 1
            if record.is_fp:
                fps[record.key] = fps.get(record.key, 0) + 1
        return {
            key: FpStats(total=total, false_positives=fps.get(key, 0))
            for key, total in totals.items()
        }


@dataclass(frozen=True, slots=True)
class TunerRow:
    """One learner row: the feedback for one key and the threshold it implies (F-05-07)."""

    key: str
    check_id: str
    asset_kind: str
    signature: str
    total: int
    false_positives: int
    threshold: int
    suggested: int

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "check": self.check_id,
            "asset_kind": self.asset_kind,
            "signature": self.signature,
            "total": self.total,
            "false_positives": self.false_positives,
            "fp_rate": round(self.fp_rate, 4),
            "threshold": self.threshold,
            "suggested_threshold": self.suggested,
        }


def split_feedback_key(key: str) -> tuple[str, str, str]:
    """``check|asset-kind|signature`` → its three fields (tolerating short keys)."""
    check_id, _, rest = key.partition("|")
    asset_kind, _, signature = rest.partition("|")
    return check_id, asset_kind, signature


class FpTuner:
    """Turns operator FP marks into a confidence requirement (F-05-07).

    The rule is deliberately simple and explainable: the more often a (check, asset kind,
    signature) combination has been marked false-positive, the more confidence a *new*
    finding from it needs. The adjustment is capped (:data:`MAX_PENALTY`) so a tuner can
    never make a whole check unreportable, and it is derived from a *frozen* snapshot of the
    feedback, so the same scan yields the same result.

    Two thresholds compose the requirement. ``thresholds`` is the operator's *per-check*
    override table (:class:`FpThresholds`, managed data): a deployment that knows one noisy
    check needs 80 confidence while another is fine at 60 writes that down instead of
    waiting for the learning to catch up. The feedback penalty is then applied on top, and
    :meth:`required_confidence` is the effective bar for one key.
    """

    def __init__(
        self,
        stats: Mapping[str, FpStats] | None = None,
        *,
        threshold: int = 55,
        thresholds: FpThresholds | None = None,
    ) -> None:
        self._stats = dict(stats or {})
        self.thresholds = thresholds
        self.threshold = threshold if thresholds is None else thresholds.default

    @classmethod
    def from_store(
        cls,
        store: FeedbackStore | None,
        keys: Iterable[str],
        *,
        threshold: int = 55,
        thresholds: FpThresholds | None = None,
    ) -> FpTuner:
        if store is None:
            return cls({}, threshold=threshold, thresholds=thresholds)
        wanted = list(dict.fromkeys(keys))
        return cls(store.stats(wanted), threshold=threshold, thresholds=thresholds)

    def stats_for(self, key: str) -> FpStats:
        return self._stats.get(key, FpStats())

    def with_stats(self, stats: Mapping[str, FpStats]) -> FpTuner:
        """A copy of this tuner carrying the run's frozen feedback snapshot.

        The engine is built once per deployment (its thresholds are managed data), while the
        feedback is read once per *scan*; this is the join between the two, and it keeps the
        result deterministic for a given feedback state .
        """
        return FpTuner(stats, threshold=self.threshold, thresholds=self.thresholds)

    def threshold_for(self, key: str) -> int:
        """The per-check threshold for ``key``: the exact key, its check id, or the default."""
        if self.thresholds is None:
            return self.threshold
        check_id, _, _ = split_feedback_key(key)
        if key in self.thresholds.checks:
            return self.thresholds.checks[key]
        if check_id in self.thresholds.checks:
            return self.thresholds.checks[check_id]
        return self.thresholds.default

    def penalty(self, key: str) -> int:
        """The confidence adjustment (0 or negative) this key has earned."""
        stats = self.stats_for(key)
        if not stats.total:
            return 0
        return -round(min(MAX_PENALTY, stats.fp_rate * MAX_PENALTY) * 100)

    def learned(self, key: str) -> int:
        """The threshold the feedback alone implies, ignoring the operator override."""
        return self.threshold - self.penalty(key)

    def required_confidence(self, key: str) -> int:
        """The confidence a finding from ``key`` must reach to be reported as confirmed."""
        return max(self.threshold_for(key), self.learned(key))

    def describe(self, key: str) -> str:
        stats = self.stats_for(key)
        if not stats.total:
            return "no operator feedback for this check"
        return (
            f"{stats.false_positives}/{stats.total} operator-marked findings from this check "
            f"were false positives ({stats.fp_rate:.0%})"
        )

    def rows(self) -> tuple[TunerRow, ...]:
        """One row per key with feedback, sorted by key — the ``arachne fp stats`` table."""
        rows: list[TunerRow] = []
        for key, stats in sorted(self._stats.items()):
            check_id, asset_kind, signature = split_feedback_key(key)
            rows.append(
                TunerRow(
                    key=key,
                    check_id=check_id,
                    asset_kind=asset_kind,
                    signature=signature,
                    total=stats.total,
                    false_positives=stats.false_positives,
                    threshold=self.threshold_for(key),
                    suggested=self.learned(key),
                )
            )
        return tuple(rows)


# --------------------------------------------------------------------------- thresholds


class FpThresholds(BaseModel):
    """Per-check confidence thresholds (F-05-07 "adjusts rule confidence thresholds")."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    default: int = Field(default=55, ge=0, le=100)
    #: ``{"m4.env-file-probe": 70}`` or a whole feedback key; keys are what
    #: :func:`feedback_key` produces or the check id it starts with.
    checks: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate(self) -> FpThresholds:
        for key, value in self.checks.items():
            if not key.strip():
                raise ValueError("a threshold key must not be empty")
            if not 0 <= value <= 100:
                raise ValueError(f"threshold for {key!r} must be within [0, 100], got {value}")
        return self

    @classmethod
    def empty(cls, *, default: int = 55) -> FpThresholds:
        return cls(version="inline", default=default)


#: Where the shipped threshold table lives inside the package.
DEFAULT_FP_THRESHOLD_RESOURCE: Final = ("fp", "thresholds.yaml")


def parse_fp_thresholds(data: Any, *, source: str = "<memory>") -> FpThresholds:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return FpThresholds.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(f"{source}: invalid FP thresholds: {exc}") from exc


def load_fp_thresholds(path: str | None = None) -> FpThresholds:
    """Load the per-check threshold table from ``path``, or the shipped default."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"FP threshold file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_fp_thresholds(_safe_yaml(text, source=str(resolved)), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_FP_THRESHOLD_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled FP threshold table is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_FP_THRESHOLD_RESOURCE)
    return parse_fp_thresholds(_safe_yaml(text, source=source), source=source)


# --------------------------------------------------------------------------- loading


def parse_fp_filters(data: Any, *, source: str = "<memory>") -> FpFilterSet:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return FpFilterSet.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(f"{source}: invalid FP filters: {exc}") from exc


def load_fp_filters(path: str | None = None) -> FpFilterSet:
    """Load the context filters from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"FP filter file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_fp_filters(_safe_yaml(text, source=str(resolved)), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_FP_FILTER_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled FP filter corpus is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_FP_FILTER_RESOURCE)
    return parse_fp_filters(_safe_yaml(text, source=source), source=source)


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


# --------------------------------------------------------------------------- trends (S21)

#: ``FeedbackEvent``/trend types are S21 (REQ-QUAL-004): the marks an operator makes are already
#: the tuner's dataset; the trend view answers the *process* question the requirement adds —
#: "is this check's false-positive rate getting worse?" — which per-key totals cannot.

#: Bucket granularity for a trend. Days are the unit an operator reviews ("this week").
BUCKET_DAY: Final = "day"


@dataclass(frozen=True, slots=True)
class FeedbackEvent:
    """One operator decision, with the time it was taken (the ``fp_feedback`` row)."""

    key: str
    is_fp: bool
    at: datetime


@dataclass(frozen=True, slots=True)
class FpTrendPoint:
    """One bucket of a trend: how many marks, how many of them false positives."""

    bucket: str
    total: int
    false_positives: int

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total if self.total else 0.0


@dataclass(frozen=True, slots=True)
class FpAlert:
    """A rising false-positive rate for one key (REQ-QUAL-004)."""

    key: str
    recent_rate: float
    baseline_rate: float
    delta: float
    recent_marks: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "recent_rate": round(self.recent_rate, 4),
            "baseline_rate": round(self.baseline_rate, 4),
            "delta": round(self.delta, 4),
            "recent_marks": self.recent_marks,
        }


@dataclass(frozen=True, slots=True)
class FpTrend:
    """A key's false-positive rate over time, with the alert it earns."""

    key: str
    points: tuple[FpTrendPoint, ...]

    @property
    def marks(self) -> int:
        return sum(point.total for point in self.points)

    @property
    def false_positives(self) -> int:
        return sum(point.false_positives for point in self.points)

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.marks if self.marks else 0.0

    def recent_rate(self, *, window: int) -> float:
        """The rate over the last ``window`` buckets that have marks."""
        scored = [point for point in self.points if point.total]
        tail = scored[-window:] if window > 0 else []
        total = sum(point.total for point in tail)
        return sum(point.false_positives for point in tail) / total if total else 0.0

    def baseline_rate(self, *, window: int) -> float:
        """The rate over everything *before* those buckets (the trend's context)."""
        scored = [point for point in self.points if point.total]
        head = scored[:-window] if window > 0 else scored
        total = sum(point.total for point in head)
        return sum(point.false_positives for point in head) / total if total else 0.0

    def alert(
        self, *, threshold: float = 0.1, window: int = 2, min_marks: int = 3
    ) -> FpAlert | None:
        """The alert this trend earns, or ``None`` when it is flat.

        Two conditions, both needed: the recent window must carry enough marks to mean
        something (``min_marks`` — a 1/1 rate is noise), and the rate must have risen by at
        least ``threshold`` over the baseline.
        """
        scored = [point for point in self.points if point.total]
        if len(scored) <= window:
            return None
        recent_marks = sum(point.total for point in scored[-window:])
        if recent_marks < min_marks:
            return None
        recent = self.recent_rate(window=window)
        baseline = self.baseline_rate(window=window)
        delta = recent - baseline
        if delta < threshold:
            return None
        return FpAlert(
            key=self.key,
            recent_rate=recent,
            baseline_rate=baseline,
            delta=delta,
            recent_marks=recent_marks,
        )

    def to_dict(self, *, window: int = 2) -> dict[str, Any]:
        return {
            "key": self.key,
            "marks": self.marks,
            "false_positives": self.false_positives,
            "fp_rate": round(self.fp_rate, 4),
            "recent_rate": round(self.recent_rate(window=window), 4),
            "points": [
                {
                    "bucket": point.bucket,
                    "total": point.total,
                    "false_positives": point.false_positives,
                    "fp_rate": round(point.fp_rate, 4),
                }
                for point in self.points
            ],
        }


def compute_trends(
    events: Iterable[FeedbackEvent],
    *,
    days: int = 30,
    now: datetime | None = None,
) -> tuple[FpTrend, ...]:
    """Per-key daily FP-rate trends over the last ``days`` (REQ-QUAL-004).

    Deterministic: same events, same buckets, same order (one trend per key, keys sorted; empty
    days included so a rate is read against its calendar, not against a compressed index).
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    start = (moment - timedelta(days=max(0, days))).date()
    buckets: dict[str, Counter[str]] = {}
    totals: dict[str, Counter[str]] = {}
    for event in events:
        day = event.at.astimezone(UTC).date()
        if day < start:
            continue
        bucket = day.isoformat()
        key = event.key
        buckets.setdefault(key, Counter())
        totals.setdefault(key, Counter())
        totals[key][bucket] += 1
        if event.is_fp:
            buckets[key][bucket] += 1
    out: list[FpTrend] = []
    calendar = [
        (start + timedelta(days=offset)).isoformat() for offset in range(max(0, days) + 1)
    ]
    for key in sorted(totals):
        points = tuple(
            FpTrendPoint(
                bucket=bucket,
                total=totals[key].get(bucket, 0),
                false_positives=buckets[key].get(bucket, 0),
            )
            for bucket in calendar
            if totals[key].get(bucket, 0) or buckets[key].get(bucket, 0)
        )
        out.append(FpTrend(key=key, points=points))
    return tuple(out)


def rising_alerts(
    trends: Iterable[FpTrend],
    *,
    threshold: float = 0.1,
    window: int = 2,
    min_marks: int = 3,
) -> tuple[FpAlert, ...]:
    """Every trend whose recent FP rate rose by at least ``threshold`` (REQ-QUAL-004)."""
    alerts = [
        alert
        for trend in trends
        if (alert := trend.alert(threshold=threshold, window=window, min_marks=min_marks))
        is not None
    ]
    return tuple(sorted(alerts, key=lambda item: (-item.delta, item.key)))
