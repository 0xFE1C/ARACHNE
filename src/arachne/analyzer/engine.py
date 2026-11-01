"""The heuristic engine: an ``Analyzer`` that needs no model (docs/spec/04-, F-03-01/F-05-*).

``HeuristicEngine.analyze(candidates, context)`` is the whole analysis stage in one pure,
synchronous call: for each candidate it matches the byte-level signals (``SignatureLibrary``),
evaluates the rules, scores, computes confidence, drops what the FP filters reject, and
synthesises the narrative. No network, no clock, no database — which is what makes it the
deterministic default engine (docs/spec/04- §4) and the fallback every AI mode falls back to
(F-03-04).

The interface is docs/spec/02- §2.3, verbatim::

    Analyzer.analyze(candidates, context) -> list[Analysis]

Two deliberate divisions of labour:

* **Verification is not here.** F-05-07's re-request is I/O, so the *caller* (the analysis
  step handler) runs the :class:`~arachne.analyzer.fp.Verifier` and hands the outcome in
  through :class:`~arachne.analyzer.model.ScanContext`. That keeps this call pure and keeps
  docs/spec/04- §2.1's "no network in the rule engine" true of the engine as a whole.
* **Selection is a data question.** Which engine runs is ``ScanOptions.engine``; this module
  answers "is the requested engine available in this build?", so an ``ai`` scan fails with an
  actionable message instead of silently degrading (F-03-03 — AI is opt-in and explicit).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from arachne.analyzer.conditions import FactSpace, build_facts
from arachne.analyzer.fp import (
    FpFilterSet,
    FpFlags,
    FpTuner,
    classify,
    feedback_key,
    load_fp_filters,
)
from arachne.analyzer.model import (
    Analysis,
    Candidate,
    EvidenceFact,
    Provenance,
    ScanContext,
    Verdict,
    clamp_confidence,
    normalize_confidence,
    severity_rank,
    worst_severity,
)
from arachne.analyzer.narrative import NarrativeSynthesizer
from arachne.analyzer.remediation import RemediationCatalog, load_remediation_catalog
from arachne.analyzer.rules import RuleEngine, RuleMatch
from arachne.analyzer.scoring import (
    ScoringModel,
    confidence_breakdown,
    describe_severity_gap,
    severity_from_hint,
)
from arachne.analyzer.signatures import SignatureLibrary, SignatureMatch
from arachne.core.errors import ConfigurationError

__all__ = [
    "AnalysisPolicies",
    "AnalysisSummary",
    "Analyzer",
    "HeuristicEngine",
    "engine_is_available",
    "merged_evidence",
    "rule_ids",
    "select_engine",
    "severity_histogram",
    "signature_ids",
    "summarize",
]

#: Confidence removed from a high/critical finding whose re-request did not reproduce it
#: (F-05-07). Small enough that a reproducible finding is unaffected, large enough that an
#: unverified critical cannot sit at the top of a report unchallenged.
_UNVERIFIED_HIGH_PENALTY: int = 15


@runtime_checkable
class Analyzer(Protocol):
    """The engine interface both engines implement (docs/spec/02- §2.3, F-03-01)."""

    name: str

    def analyze(
        self, candidates: Sequence[Candidate], context: ScanContext
    ) -> tuple[Analysis, ...]: ...


@dataclass(frozen=True, slots=True)
class AnalysisPolicies:
    """The knobs a deployment can turn on the heuristic engine (docs/spec/04- §2.6)."""

    #: Drop a candidate whose verification contradicted it (F-05-07).
    drop_on_contradiction: bool = True
    #: Drop a candidate whose only substance is a placeholder/WAF page.
    drop_on_placeholder: bool = True
    #: Apply the operator FP tuner to confidence (F-05-07).
    tuner_enabled: bool = True
    #: Below this confidence a finding is a "low-confidence observation" (docs/spec/06- §2).
    minimum_confidence: int = 55
    #: A high/critical finding must have reproduced on a re-request to be accepted as
    #: confirmed; one that could not be re-verified keeps its severity but is flagged and
    #: penalised, so an operator sees that the strongest claims are the least attested
    #: (F-05-07 "verification re-request before accepting high-severity findings").
    require_verification_for_high: bool = True
    #: The severities the verification-before-acceptance policy applies to.
    high_severities: tuple[str, ...] = ("critical", "high")
    #: Emit a finding whose derived score is ``info`` at all (M1's reconnaissance candidates
    #: are legitimate info findings, so this is on by default).
    report_info_findings: bool = True


@dataclass(frozen=True, slots=True)
class _EngineInputs:
    """Everything one candidate's analysis needs, computed once per candidate."""

    facts: FactSpace
    criticality: str
    signatures: tuple[SignatureMatch, ...] = ()
    fp_note: str = ""
    fp_penalty: bool = False
    fp_decisive: bool = False


class HeuristicEngine:
    """Rules + signatures + scoring + narrative, with no model involved (F-05-01..07)."""

    name = "heuristic"

    def __init__(
        self,
        *,
        rules: RuleEngine | None = None,
        scoring: ScoringModel | None = None,
        narratives: NarrativeSynthesizer | None = None,
        remediation: RemediationCatalog | None = None,
        signatures: SignatureLibrary | None = None,
        fp_filters: FpFilterSet | None = None,
        tuner: FpTuner | None = None,
        policies: AnalysisPolicies | None = None,
    ) -> None:
        self.rules = rules or RuleEngine()
        self.scoring = scoring or ScoringModel()
        self.narratives = narratives or NarrativeSynthesizer()
        self.remediation = remediation or load_remediation_catalog()
        self.signatures = signatures if signatures is not None else SignatureLibrary()
        self.fp_filters = fp_filters or load_fp_filters()
        self.tuner = tuner or FpTuner()
        self.policies = policies or AnalysisPolicies()

    @property
    def template_version(self) -> str:
        """The versions of the data files this engine ran with (F-03-05, "version everything")."""
        return f"rules-{self.rules.version}+narrative-{self.narratives.version}"

    # ------------------------------------------------------------------ interface
    def analyze(
        self, candidates: Sequence[Candidate], context: ScanContext
    ) -> tuple[Analysis, ...]:
        """Analyse every candidate, in input order (deterministic, docs/spec/04- §4)."""
        return tuple(self.analyze_one(candidate, context) for candidate in candidates)

    def analyze_one(self, candidate: Candidate, context: ScanContext) -> Analysis:
        """Analyse a single candidate (the unit the tests and the CLI drive)."""
        inputs = self._inputs(candidate, context)
        verification = context.verification_for(candidate)
        signature_severity = _signature_severity(inputs.signatures)
        rule_match = self.rules.evaluate(candidate, inputs.facts)

        cwe = rule_match.cwe if rule_match is not None and rule_match.cwe else candidate.cwe
        if rule_match is not None:
            severity = rule_match.severity
        else:
            hint = severity_from_hint(candidate.severity_hint, "info")
            severity = hint
        base_confidence = _base_confidence(candidate, rule_match)

        adjustment_pairs: tuple[tuple[str, int], ...] = ()
        fp_stats = context.fp_for(candidate)
        fp_rate = fp_stats.fp_rate if self.policies.tuner_enabled else 0.0
        kinds = {item.kind for item in candidate.evidence}
        base_confidence, adjustment_pairs = confidence_breakdown(
            base=base_confidence,
            pair_captured={"http_request", "http_response"} <= kinds,
            reproducible=verification.reproducible,
            multiple_confirmations=len(candidate.evidence) >= 2,
            contradicted=verification.contradicted,
            placeholder=inputs.fp_decisive
            or (inputs.fp_note != "" and "placeholder" in inputs.fp_note),
            waf="waf" in inputs.fp_note,
            login_wall="login" in inputs.fp_note,
            fp_rate=fp_rate,
        )

        score = self.scoring.score(
            candidate,
            criticality=inputs.criticality,
            cwe=cwe,
            verification_reproducible=verification.reproducible,
            contradicted=verification.contradicted,
            fp_penalty=inputs.fp_penalty,
            epss=_epss_for(candidate, context),
            base_confidence=base_confidence,
            confidence_adjustments=adjustment_pairs,
        )
        if rule_match is None:
            # No rule spoke, so the score decides — but never below what the check itself
            # declared as its floor (docs/spec/05- "severity_hint").
            severity = worst_severity(severity, score.derived_severity)
        if signature_severity is not None and rule_match is None:
            severity = worst_severity(severity, signature_severity)

        verdict: Verdict = "analyzed"
        drop_reason: str | None = None
        if verification.contradicted and self.policies.drop_on_contradiction:
            verdict, drop_reason = (
                "dropped",
                (verification.detail or "the finding did not reproduce on a second request"),
            )
        elif inputs.fp_decisive and self.policies.drop_on_placeholder:
            verdict, drop_reason = (
                "dropped",
                (inputs.fp_note or "the response body is a placeholder page, not evidence"),
            )

        confidence = score.confidence
        required = self.policies.minimum_confidence
        tuner_note: str | None = None
        key = feedback_key(candidate)
        if self.policies.tuner_enabled:
            run_tuner = self.tuner.with_stats(context.fp)
            tuner_required = run_tuner.required_confidence(key)
            if tuner_required > required:
                required = tuner_required
                tuner_note = (
                    f"the FP tuner raised this check's confidence requirement to {tuner_required} "
                    f"({run_tuner.describe(key)})"
                )
        unverified_high = (
            verdict == "analyzed"
            and severity in self.policies.high_severities
            and self.policies.require_verification_for_high
            and not verification.reproducible
        )
        if unverified_high:
            confidence = clamp_confidence(confidence - _UNVERIFIED_HIGH_PENALTY)
        if verdict == "analyzed" and confidence < required:
            risk_note = (
                f"low-confidence observation ({confidence} < {required}): "
                "reported separately from confirmed findings (docs/spec/06- §2)"
            )
        else:
            risk_note = ""
        unverified_note: str | None = None
        if unverified_high:
            if verification.attempted:
                unverified_note = (
                    "high-severity finding accepted without a reproducing re-request "
                    f"({verification.detail or 'verification did not confirm it'}); "
                    f"confidence reduced by {_UNVERIFIED_HIGH_PENALTY} (F-05-07)"
                )
            else:
                unverified_note = (
                    "high-severity finding was not re-requested before acceptance "
                    "(no verification was possible for this check); "
                    f"confidence reduced by {_UNVERIFIED_HIGH_PENALTY} (F-05-07)"
                )

        remediation = self.remediation.resolve(
            candidate,
            reference=rule_match.remediation_ref if rule_match is not None else None,
            cwe=cwe,
        )
        narrative = self.narratives.render(
            candidate,
            severity=severity,
            confidence=confidence,
            score=score,
            remediation=remediation,
            facts=inputs.facts,
            rule_ids=(rule_match.rule_id,) if rule_match is not None else (),
            trace=rule_match.trace if rule_match is not None else (),
            signatures=tuple(item.signature_id for item in inputs.signatures),
            conditions=dict(rule_match.conditions) if rule_match is not None else {},
            template_id=rule_match.narrative_id if rule_match is not None else None,
        )

        notes = _compose_notes(
            risk_note,
            describe_severity_gap(severity, score.derived_severity),
            verification.detail if verification.attempted else None,
            inputs.fp_note or None,
            unverified_note,
            tuner_note,
            self.tuner.describe(key) if self.policies.tuner_enabled and fp_stats.total else None,
            drop_reason,
        )
        return Analysis(
            title=candidate.title,
            severity=severity,
            confidence=confidence,
            narrative=narrative.text,
            remediation=remediation,
            finding_id=candidate.finding_id,
            check_id=candidate.check_id,
            asset=candidate.asset_label,
            cwe=cwe,
            cve=candidate.cve,
            risk_notes=notes,
            verdict=verdict,
            drop_reason=drop_reason,
            verified=bool(
                candidate.verifiable and verification.reproducible and verdict == "analyzed"
            ),
            score=score,
            provenance=Provenance(
                engine=self.name,
                rule_ids=(rule_match.rule_id,) if rule_match is not None else (),
                template_version=self.template_version,
                prompt_template=narrative.template_id,
            ),
            rule_trace=rule_match.trace if rule_match is not None else (),
            signatures=tuple(item.signature_id for item in inputs.signatures),
        )

    # ------------------------------------------------------------------ internals
    def _inputs(self, candidate: Candidate, context: ScanContext) -> _EngineInputs:
        criticality = context.criticality_of(candidate)
        verification = context.verification_for(candidate)
        matches = self.signatures.match(candidate) if self.signatures else ()
        facts = build_facts(
            candidate,
            criticality=criticality,
            verification=verification,
            signatures=tuple(item.signature_id for item in matches),
        )
        flags = classify(candidate, self.fp_filters)
        return _EngineInputs(
            facts=facts,
            criticality=criticality,
            signatures=matches,
            fp_note=_fp_note(flags),
            fp_penalty=flags.any,
            fp_decisive=flags.decisive,
        )


def _fp_note(flags: FpFlags) -> str:
    parts: list[str] = []
    if flags.placeholder:
        parts.append("placeholder page detected")
    if flags.waf:
        parts.append("waf challenge page detected")
    if flags.login_wall:
        parts.append("login wall detected")
    if not parts:
        return ""
    return "; ".join(parts) + (f" ({', '.join(flags.matched)})" if flags.matched else "")


def _base_confidence(candidate: Candidate, rule_match: RuleMatch | None) -> int:
    """The confidence the rule (or the check) starts from, on the 0-100 scale."""
    if rule_match is not None and rule_match.confidence is not None:
        return normalize_confidence(rule_match.confidence)
    if candidate.check_confidence is not None:
        return normalize_confidence(candidate.check_confidence)
    return 50


def _signature_severity(matches: Sequence[SignatureMatch]) -> str | None:
    severities = [item.severity for item in matches if item.severity != "unknown"]
    if not severities:
        return None
    return worst_severity(*severities)


def _epss_for(candidate: Candidate, context: ScanContext) -> float | None:
    """EPSS for a CVE-correlated finding (F-09-03): the feed first, then the evidence."""
    if candidate.cve and candidate.cve in context.epss:
        return context.epss[candidate.cve]
    values: list[float] = []
    for item in candidate.evidence:
        values.extend(_epss_values(item.payload))
    return max(values) if values else None


def _epss_values(payload: Mapping[str, Any]) -> list[float]:
    found: list[float] = []
    for key, value in payload.items():
        if key == "epss" and isinstance(value, (int, float)) and not isinstance(value, bool):
            found.append(float(value))
        elif isinstance(value, Mapping):
            found.extend(_epss_values(value))
        elif isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, Mapping):
                    found.extend(_epss_values(entry))
    return found


def _compose_notes(*notes: str | None) -> str:
    return "; ".join(item for item in notes if item)


# --------------------------------------------------------------------------- selection


def engine_is_available(name: str, *, ai_available: bool = False) -> bool:
    """True when this build can run engine ``name`` (F-03-03: AI is explicit and optional).

    ``hybrid`` is always available because its heuristic half always is; whether the AI half
    engages depends on a provider being configured, which the caller expresses with
    ``ai_available``. ``ai`` alone is available exactly when a provider is.
    """
    requested = (name or "heuristic").lower()
    if requested in {"heuristic", "hybrid"}:
        return True
    if requested == "ai":
        return ai_available
    return False


def select_engine(
    name: str,
    *,
    heuristic: Analyzer | None = None,
    ai: Analyzer | None = None,
) -> Analyzer:
    """Resolve ``ScanOptions.engine`` to an engine instance (F-03-01/F-03-04).

    ``hybrid`` is the docs/spec/04- §4 default recommendation: heuristics run everything, and
    the AI engine engages *on top of* the heuristic result when a provider is configured. With
    no provider, "hybrid" is exactly "heuristic" — a deployment that has not configured AI gets
    the deterministic engine, not an error.

    ``ai`` without a provider is refused loudly, because silently analysing in heuristic mode a
    scan that asked for AI would misrepresent the report's provenance (F-03-03).
    """
    requested = (name or "heuristic").lower()
    if requested == "heuristic":
        return heuristic or HeuristicEngine()
    if requested == "hybrid":
        return ai if ai is not None else (heuristic or HeuristicEngine())
    if requested == "ai":
        if ai is None:
            msg = (
                "the 'ai' engine is not configured: set ARACHNE_AI_CONFIG (or at least "
                "ARACHNE_AI_PROVIDER/ARACHNE_AI_BASE_URL/ARACHNE_AI_MODEL), or use engine "
                "'heuristic' or 'hybrid'"
            )
            raise ConfigurationError(msg)
        return ai
    raise ConfigurationError(f"unknown engine {name!r}; expected heuristic, ai or hybrid")


def merged_evidence(candidates: Iterable[Candidate]) -> tuple[EvidenceFact, ...]:
    """Every distinct evidence item of ``candidates``, in insertion order."""
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[EvidenceFact] = []
    for candidate in candidates:
        for item in candidate.evidence:
            key = (item.kind, item.sha256, item.source)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return tuple(out)


def severity_histogram(analyses: Iterable[Analysis]) -> dict[str, int]:
    """``{severity: count}`` over analysed findings, descending by severity."""
    histogram: dict[str, int] = {}
    for analysis in analyses:
        if analysis.verdict != "analyzed":
            continue
        histogram[analysis.severity] = histogram.get(analysis.severity, 0) + 1
    return dict(sorted(histogram.items(), key=lambda item: -severity_rank(item[0])))


def rule_ids(analyses: Iterable[Analysis]) -> tuple[str, ...]:
    """Every rule that fired across ``analyses``, sorted and deduplicated."""
    return tuple(sorted({rid for analysis in analyses for rid in analysis.provenance.rule_ids}))


def signature_ids(analyses: Iterable[Analysis]) -> tuple[str, ...]:
    """Every signature that matched across ``analyses``, sorted and deduplicated."""
    return tuple(sorted({sid for analysis in analyses for sid in analysis.signatures}))


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    """The step-statistics shape the analysis handler reports."""

    candidates: int = 0
    analyzed: int = 0
    dropped: int = 0
    low_confidence: int = 0
    verified: int = 0
    reproducible: int = 0
    severities: Mapping[str, int] = field(default_factory=dict)
    rules: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()

    def to_stats(self) -> dict[str, Any]:
        return {
            "candidates_analyzed": self.candidates,
            "findings": self.analyzed,
            "dropped": self.dropped,
            "low_confidence": self.low_confidence,
            "verified": self.verified,
            "reproducible": self.reproducible,
            "severities": dict(self.severities),
            "rules_fired": list(self.rules),
            "signatures_matched": list(self.signatures),
        }


def summarize(
    analyses: Sequence[Analysis],
    candidates: Sequence[Candidate],
    context: ScanContext,
    *,
    minimum_confidence: int = 55,
) -> AnalysisSummary:
    """Collapse an analysis run into the step statistics (used by the handler and the CLI)."""
    verified = reproducible = 0
    for candidate in candidates:
        outcome = context.verification_for(candidate)
        if outcome.attempted:
            verified += 1
        if outcome.reproducible:
            reproducible += 1
    return AnalysisSummary(
        candidates=len(candidates),
        analyzed=sum(1 for item in analyses if item.verdict == "analyzed"),
        dropped=sum(1 for item in analyses if item.verdict == "dropped"),
        low_confidence=sum(
            1
            for item in analyses
            if item.verdict == "analyzed" and item.confidence < minimum_confidence
        ),
        verified=verified,
        reproducible=reproducible,
        severities=severity_histogram(analyses),
        rules=rule_ids(analyses),
        signatures=signature_ids(analyses),
    )
