"""The analysis data model: what an engine consumes and what it produces.

Both engines — :class:`~arachne.analyzer.engine.HeuristicEngine` today,
``AiEngine`` in S9 — consume the same ``Candidate`` plus a ``ScanContext`` and produce the
same :class:`Analysis` (docs/spec/04- §5, docs/spec/02- §2.3). The report engine must not be
able to tell which engine ran except through :class:`Provenance`, so everything an engine
decides lives here as data: severity, confidence, the score breakdown, the narrative, the
remediation reference, the rule trace and the merged-evidence list.

Three deliberate choices:

* **``Candidate`` is not the store's row.** The analyzer may not import the module layer or
  the ORM (docs/spec/07- §4 keeps the engine testable and offline), so the caller builds a
  plain value object from whatever the checks step persisted. One adapter
  (``analyzer.handlers``) does that translation, which is also where check metadata
  (``severity_hint``, ``research_ref``, ``verifiable``) is joined in.
* **Severity is an ordered vocabulary, not a number.** ``critical > high > medium > low >
  info``; the score is a *separate* field so a rule author can say "high" and the report can
  still print "CVSS 7.5". Promotion in the correlation engine is ``raise_severity``.
* **Confidence is an integer 0-100** (docs/spec/06- §2) even though the rules write it as a
  fraction: the two spellings meet exactly once, in :func:`normalize_confidence`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, get_args
from urllib.parse import urlsplit

from arachne.core.results import confidence_percent

__all__ = [
    "CONFIDENCE_THRESHOLD",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Analysis",
    "Candidate",
    "ConfidenceBreakdown",
    "EvidenceFact",
    "Provenance",
    "Remediation",
    "RuleTraceEntry",
    "ScanContext",
    "ScoreBreakdown",
    "Severity",
    "Verdict",
    "clamp_confidence",
    "normalize_confidence",
    "raise_severity",
    "severity_from_rank",
    "severity_rank",
    "worst_severity",
]

#: The severity vocabulary of docs/spec/06- §1/§2, in ascending order.
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITIES: frozenset[str] = frozenset(get_args(Severity))

#: ``analyzed`` is a finding the engine stands behind; ``dropped`` is one an FP filter
#: rejected (verification contradiction, placeholder page) — the row survives so an operator
#: can see *why* it was not reported (docs/spec/04- §2.6); ``merged`` is one the dedupe pass
#: folded into another finding with the same root cause (docs/spec/05- dedupe rules).
Verdict = Literal["analyzed", "dropped", "merged"]

#: Findings below this confidence are "low-confidence observations" (docs/spec/06- §2).
CONFIDENCE_THRESHOLD = 55


def severity_rank(severity: str) -> int:
    """Position of ``severity`` in :data:`SEVERITY_ORDER` (unknown values sort as ``info``)."""
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return 0


def severity_from_rank(rank: int) -> str:
    """Clamp ``rank`` into the vocabulary and return the severity name."""
    bounded = max(0, min(len(SEVERITY_ORDER) - 1, rank))
    return SEVERITY_ORDER[bounded]


def raise_severity(severity: str, levels: int = 1) -> str:
    """Promote ``severity`` by ``levels`` steps, capped at ``critical``."""
    return severity_from_rank(severity_rank(severity) + max(0, levels))


def worst_severity(*severities: str) -> str:
    """The highest severity of ``severities`` (``info`` when none is supplied)."""
    return severity_from_rank(max((severity_rank(item) for item in severities), default=0))


def clamp_confidence(value: float) -> int:
    """Clamp a 0-100 confidence to its integer range."""
    return max(0, min(100, round(value)))


def normalize_confidence(value: float) -> int:
    """Accept a rule's ``0..1`` fraction or its ``0..100`` percentage as 0-100.

    Rules in docs/spec/04- §2.1 write ``0.92``; docs/spec/06- §2 reports ``92``. A value
    above ``1.0`` can only be a percentage, so the two spellings cannot be confused, and the
    conversion itself is :func:`arachne.core.results.confidence_percent` — one implementation
    shared with the candidate-persisting layer.
    """
    return confidence_percent(value)


@dataclass(frozen=True, slots=True)
class EvidenceFact:
    """One captured artifact, as the analyzer sees it (redacted already, F-08-04).

    ``id`` is the ``evidences`` row id when the caller has one, which is what lets a
    correlated finding list the evidence it merged (docs/spec/04- §2.3 ``merge_evidence``).
    """

    kind: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    sha256: str | None = None
    source: str | None = None
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "sha256": self.sha256, "source": self.source, "id": self.id}


@dataclass(frozen=True, slots=True)
class Candidate:
    """A candidate finding plus the check metadata needed to judge it.

    ``finding_id`` links back to the ``findings`` row the analyzer updates; it is ``None``
    for a candidate that has not been persisted (the CLI's re-analysis, unit tests).
    """

    scan_id: int
    title: str
    finding_id: int | None = None
    status: str = "open"
    check_id: str | None = None
    check_module: str | None = None
    check_name: str | None = None
    check_version: str | None = None
    research_ref: str | None = None
    cwe: str | None = None
    cve: str | None = None
    severity_hint: str | None = None
    verifiable: bool = False
    #: The candidate's own confidence (0-100, i.e. the value stored in ``findings.confidence``
    #: once the check's 0-1 fraction has been converted), used as a scoring input.
    check_confidence: float | None = None
    asset_id: int | None = None
    asset_kind: str | None = None
    asset_value: str | None = None
    evidence: tuple[EvidenceFact, ...] = ()

    @property
    def key(self) -> str:
        """``check|asset`` — how the correlation engine names an analyzed finding."""
        return f"{self.check_id or 'unknown'}|{self.asset_value or 'unknown'}"

    @property
    def asset_label(self) -> str:
        """``kind:value`` when both are known, else whichever is (F-06-01 ``asset``)."""
        if self.asset_kind and self.asset_value:
            return f"{self.asset_kind}:{self.asset_value}"
        return self.asset_value or "unknown"

    @property
    def asset_host(self) -> str | None:
        """The host an asset belongs to — what the correlation engine groups "by host" on.

        A URL and a bare host name that refer to the same machine must land in the same
        correlation group, otherwise "exposed credential on the web app" and "unauthenticated
        database on the host" would never meet.
        """
        value = self.asset_value
        if not value:
            return None
        if self.asset_kind == "url" or "://" in value:
            host = urlsplit(value).hostname
            return host or value
        return value


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """Result of the F-05-07 re-request for one candidate.

    ``count`` is the number of successful confirmations *including* the original capture, so
    ``count >= 2`` means "reproducible" exactly as docs/spec/04- §2.1's
    ``verified_reproducible`` condition reads it.
    """

    count: int = 1
    attempted: bool = False
    reproducible: bool = False
    contradicted: bool = False
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "attempted": self.attempted,
            "reproducible": self.reproducible,
            "contradicted": self.contradicted,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class FpStats:
    """Operator feedback for one (check, asset kind, signature) key (F-05-07)."""

    total: int = 0
    false_positives: int = 0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total if self.total else 0.0


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything the analyzer needs beyond the candidates (docs/spec/02- §2.3).

    ``asset_criticality`` feeds the OWASP impact term (docs/spec/04- §2.4), ``epss`` is the
    optional exploit-likelihood feed of F-09-03 keyed by CVE, and ``verification``/``fp``
    carry the F-05-07 inputs the check layer produced.
    """

    scan_id: int
    engine: str = "heuristic"
    asset_criticality: Mapping[str, str] = field(default_factory=dict)
    verification: Mapping[str, VerificationOutcome] = field(default_factory=dict)
    fp: Mapping[str, FpStats] = field(default_factory=dict)
    epss: Mapping[str, float] = field(default_factory=dict)
    #: True when a live HTTP client exists, i.e. verification may re-request (F-05-07).
    can_verify: bool = False

    def verification_for(self, candidate: Candidate) -> VerificationOutcome:
        return self.verification.get(candidate.key, VerificationOutcome())

    def fp_for(self, candidate: Candidate) -> FpStats:
        return self.fp.get(candidate.key, FpStats())

    def criticality_of(self, candidate: Candidate) -> str:
        for key in (candidate.asset_value, candidate.asset_label):
            if key and key in self.asset_criticality:
                return self.asset_criticality[key].lower()
        return "normal"


@dataclass(frozen=True, slots=True)
class RuleTraceEntry:
    """One rule clause that fired, kept as the finding's justification (F-03-05)."""

    rule_id: str
    clause: str
    expression: str
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "clause": self.clause,
            "expression": self.expression,
            "value": self.value,
        }

    def describe(self) -> str:
        rendered = "true" if self.value is None else str(self.value)
        return f"{self.clause}({self.expression}) → {rendered}"


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """The F-05-04 scoring model's output for one finding."""

    cvss_vector: str | None = None
    cvss_base: float = 0.0
    owasp_likelihood: float = 0.0
    owasp_impact: float = 0.0
    owasp_risk: str = "low"
    epss: float | None = None
    derived_severity: str = "info"
    confidence: int = 0
    confidence_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "cvss_vector": self.cvss_vector,
            "cvss_base": self.cvss_base,
            "owasp_likelihood": self.owasp_likelihood,
            "owasp_impact": self.owasp_impact,
            "owasp_risk": self.owasp_risk,
            "epss": self.epss,
            "derived_severity": self.derived_severity,
            "confidence": self.confidence,
            "confidence_reasons": list(self.confidence_reasons),
        }


@dataclass(frozen=True, slots=True)
class Remediation:
    """A remediation plan (docs/spec/06- §6): the catalog entry, resolved.

    ``verification`` is the "verification of fix" half of a catalog entry — the steps an
    operator takes to prove the exposure is gone (re-run the check, look for the alert, read
    the deny rule back). It is separate from ``steps`` because "how to fix it" and "how to
    know you fixed it" are different instructions, and docs/spec/06- §6 requires both.
    """

    id: str
    summary: str
    steps: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    source: str = "catalog"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "steps": list(self.steps),
            "verification": list(self.verification),
            "references": list(self.references),
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class Provenance:
    """Which engine produced an analysis, and on what evidence of its own (F-03-05).

    ``provider`` and ``fallback`` are the AI layer's two extra facts (S9, docs/spec/03- §7):

    * ``provider`` names the adapter that answered (``ollama``, ``openai_compatible``, ...);
    * ``fallback`` records the degradation chain. ``None`` means "everything configured ran".
      ``heuristic_fallback:<reason>`` means the analysis is the deterministic one because the
      AI half failed; ``partial:<stage>:<reason>`` means some stages succeeded and others did
      not. A report must never present a degraded analysis as an AI one, which is why this is
      a field rather than a log line.
    """

    engine: str = "heuristic"
    rule_ids: tuple[str, ...] = ()
    template_version: str | None = None
    model: str | None = None
    prompt_template: str | None = None
    prompt_hash: str | None = None
    provider: str | None = None
    fallback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "rule_ids": list(self.rule_ids),
            "template_version": self.template_version,
            "model": self.model,
            "prompt_template": self.prompt_template,
            "prompt_hash": self.prompt_hash,
            "provider": self.provider,
            "fallback": self.fallback,
        }


@dataclass(frozen=True, slots=True)
class Analysis:
    """The result of analysing one candidate (docs/spec/04- §5 ``Analysis``)."""

    title: str
    severity: str
    confidence: int
    narrative: str
    remediation: Remediation
    finding_id: int | None = None
    check_id: str | None = None
    asset: str | None = None
    cwe: str | None = None
    cve: str | None = None
    risk_notes: str = ""
    verdict: Verdict = "analyzed"
    drop_reason: str | None = None
    #: True when a ``verifiable`` candidate was re-requested and reproduced — which is what
    #: moves a finding to ``verified`` status (F-05-07, docs/spec/06- §2).
    verified: bool = False
    #: Set on a ``merged`` analysis: the finding id that now represents this root cause.
    merged_into: int | None = None
    score: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    provenance: Provenance = field(default_factory=Provenance)
    rule_trace: tuple[RuleTraceEntry, ...] = ()
    #: Finding ids this analysis subsumes (correlation/dedupe, docs/spec/04- §2.3).
    contributors: tuple[int, ...] = ()
    #: Evidence ids merged from contributors, so the report can render one evidence list.
    merged_evidence_refs: tuple[int, ...] = ()
    #: Signature ids that matched this candidate, for provenance and the report appendix.
    signatures: tuple[str, ...] = ()
    #: Set on a compound finding produced by the correlation engine.
    correlated: bool = False
    #: The AI stages' structured outputs, keyed by stage (``triage``, ``explain``,
    #: ``remediate``, ``narrative``), plus ``policy``/``fallback``/``deviation``. Empty for the
    #: heuristic engine, which is what keeps the two engines' payloads distinguishable only
    #: through provenance and this field (docs/spec/04- §5).
    ai: Mapping[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        """``owasp_risk`` — the OWASP-style rating the report prints next to the score."""
        return self.score.owasp_risk

    @property
    def status(self) -> str:
        """The ``findings.status`` this analysis implies (F-05-07, docs/spec/06- §1)."""
        if self.verdict == "dropped":
            return "fp"
        if self.verdict == "merged":
            return "merged"
        return "verified" if self.verified else "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "asset": self.asset,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "cve": self.cve,
            "risk_notes": self.risk_notes,
            "verdict": self.verdict,
            "drop_reason": self.drop_reason,
            "merged_into": self.merged_into,
            "verified": self.verified,
            "status": self.status,
            "score": self.score.to_dict(),
            "remediation": self.remediation.to_dict(),
            "narrative": self.narrative,
            "provenance": self.provenance.to_dict(),
            "rule_trace": [entry.to_dict() for entry in self.rule_trace],
            "contributors": list(self.contributors),
            "merged_evidence_refs": list(self.merged_evidence_refs),
            "signatures": list(self.signatures),
            "correlated": self.correlated,
            "ai": dict(self.ai),
        }


def confidence_reasons(
    *, base: int, adjustments: Sequence[tuple[str, int]], floor: int = 0, ceiling: int = 100
) -> ConfidenceBreakdown:
    """Build a confidence value with its auditable reason list."""
    return ConfidenceBreakdown(
        base=base, adjustments=tuple(adjustments), floor=floor, ceiling=ceiling
    )


@dataclass(frozen=True, slots=True)
class ConfidenceBreakdown:
    """A confidence value and every term that produced it (docs/spec/04- §2.4/§2.6)."""

    base: int
    adjustments: tuple[tuple[str, int], ...] = ()
    floor: int = 0
    ceiling: int = 100

    @property
    def value(self) -> int:
        total = self.base + sum(delta for _, delta in self.adjustments)
        return clamp_confidence(max(self.floor, min(self.ceiling, total)))

    def reasons(self) -> tuple[str, ...]:
        parts = [f"base {self.base}"]
        parts.extend(f"{reason} {delta:+d}" for reason, delta in self.adjustments)
        return tuple(parts)

    def describe(self) -> str:
        return "; ".join(self.reasons())
