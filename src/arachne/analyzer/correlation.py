"""The correlation engine: weak signals into compound findings (docs/spec/04- §2.3, F-05-03).

Two passes, in this order, because each makes the next one more meaningful:

**Dedupe** merges findings that describe one root cause — docs/spec/05-'s rule is "by CWE +
asset", keeping the most specific module as owner and attaching the others as contributors.
Without it, the same exposed database reported by M2 and M4 would count twice in a report
and inflate every severity histogram.

**Correlation** then applies the rules: group the surviving findings (by asset, by host, by
kind), test each rule's signal matchers against the group, and when at least
``min_weak_signals`` distinct signals are present, emit one *compound* finding that names
the pattern — "exposed admin panel + wildcard CORS + no HSTS" is one story, not four
sentences. The compound carries the merged evidence, the contributors' ids, a shared
remediation and a severity promoted by ``upgrade_if``.

Both passes are pure functions of the analyses they are given, so a scan's correlation
result is reproducible (docs/spec/04- §4) and the whole thing is unit-testable without a
scan at all.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from importlib.resources import files
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.conditions import FactSpace, parse_expression
from arachne.analyzer.model import (
    SEVERITY_ORDER,
    Analysis,
    Candidate,
    EvidenceFact,
    Provenance,
    RuleTraceEntry,
    ScoreBreakdown,
    raise_severity,
    severity_rank,
    worst_severity,
)
from arachne.analyzer.narrative import NarrativeSynthesizer
from arachne.analyzer.remediation import RemediationCatalog
from arachne.analyzer.scoring import ScoringModel
from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_CORRELATION_RESOURCE",
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationOutcome",
    "CorrelationRule",
    "CorrelationRuleSet",
    "DedupePolicy",
    "SignalMatcher",
    "load_correlation_rules",
    "parse_correlation_rules",
]

#: Where the shipped correlation rules live inside the package.
DEFAULT_CORRELATION_RESOURCE: Final = ("correlation", "correlation-rules.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: Module specificity order for dedupe (docs/spec/05- "keep the most specific module as
#: owner"): the exposure/misconfiguration modules describe the *root cause* more precisely
#: than a generic service probe does, so they own the merged finding.
DEFAULT_OWNER_PREFERENCE: Final[tuple[str, ...]] = ("M4", "M3", "M6", "M5", "M2", "M1")

#: Group keys a correlation rule may use.
GROUP_KEYS: Final[tuple[str, ...]] = ("asset", "host", "asset_kind", "module")


class SignalMatcher(BaseModel):
    """One weak signal: which analysed findings count as its evidence."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=2, max_length=64)
    check: tuple[str, ...] = ()
    module: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    name_token: tuple[str, ...] = ()
    severity: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> SignalMatcher:
        if not any((self.check, self.module, self.cwe, self.cve, self.name_token, self.severity)):
            raise ValueError(f"signal {self.id}: declare at least one match key")
        return self

    def matches(self, candidate: Candidate, analysis: Analysis) -> bool:
        """True when this candidate/analysis pair is the signal (all declared keys match)."""
        if self.check and not any(
            fnmatch.fnmatchcase(candidate.check_id or "", pattern) for pattern in self.check
        ):
            return False
        if self.module and candidate.check_module not in self.module:
            return False
        if self.cwe and not any(
            value in self.cwe for value in (analysis.cwe, candidate.cwe) if value is not None
        ):
            return False
        if self.cve and not any(
            value in self.cve for value in (analysis.cve, candidate.cve) if value is not None
        ):
            return False
        if self.severity and analysis.severity not in self.severity:
            return False
        if self.name_token:
            haystack = (candidate.check_name or candidate.check_id or candidate.title).lower()
            if not any(token.lower() in haystack for token in self.name_token):
                return False
        return True

    def describe(self) -> str:
        parts = [
            f"{key}={list(values)}"
            for key, values in (
                ("check", self.check),
                ("module", self.module),
                ("cwe", self.cwe),
                ("cve", self.cve),
                ("name_token", self.name_token),
                ("severity", self.severity),
            )
            if values
        ]
        return ", ".join(parts)


class CorrelationRule(BaseModel):
    """One correlation rule (docs/spec/04- §2.3): signals, threshold, upgrade."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=3, max_length=128)
    title: str = Field(min_length=3, max_length=512)
    group_by: str = "asset"
    min_weak_signals: int = Field(default=2, ge=2, le=16)
    signals: tuple[SignalMatcher, ...] = Field(min_length=2)
    upgrade_if: tuple[str, ...] = ()
    upgrade_levels: int = Field(default=1, ge=0, le=3)
    max_severity: str = "critical"
    merge_evidence: bool = True
    cwe: str | None = None
    remediation: str | None = None
    narrative: str | None = None
    category: str = "correlation"
    description: str = ""
    tags: tuple[str, ...] = ()
    enabled: bool = True

    @model_validator(mode="after")
    def _validate(self) -> CorrelationRule:
        if self.group_by not in GROUP_KEYS:
            raise ValueError(
                f"rule {self.id}: group_by {self.group_by!r} is not one of {GROUP_KEYS}"
            )
        if self.max_severity not in SEVERITY_ORDER:
            raise ValueError(f"rule {self.id}: unknown max_severity {self.max_severity!r}")
        for expression, _ in _split_clauses(self.upgrade_if, rule_id=self.id):
            parse_expression(expression)
        return self

    @property
    def signal_ids(self) -> tuple[str, ...]:
        return tuple(item.id for item in self.signals)

    def group_key(self, candidate: Candidate) -> str:
        """The grouping value for a candidate under this rule's ``group_by``."""
        if self.group_by == "asset":
            return candidate.asset_label
        if self.group_by == "host":
            # A URL asset groups with the bare host name of the same machine, which is what
            # makes "web finding" and "service finding" on one host meet.
            return candidate.asset_host or candidate.asset_value or candidate.asset_label
        if self.group_by == "asset_kind":
            return candidate.asset_kind or "unknown"
        return candidate.check_module or "unknown"


class DedupePolicy(BaseModel):
    """How findings that share a root cause are merged (docs/spec/05- dedupe rules)."""

    model_config = _MODEL_CONFIG

    enabled: bool = True
    key: str = "cwe_asset"
    owner_preference: tuple[str, ...] = DEFAULT_OWNER_PREFERENCE
    min_severity: str = "info"


class CorrelationRuleSet(BaseModel):
    """The whole correlation corpus."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    rules: tuple[CorrelationRule, ...] = ()
    dedupe: DedupePolicy = DedupePolicy()

    @model_validator(mode="after")
    def _validate_unique(self) -> CorrelationRuleSet:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate correlation rule id {rule.id!r}")
            seen.add(rule.id)
        return self


# --------------------------------------------------------------------------- parsing


def _split_clauses(clauses: Sequence[str], *, rule_id: str) -> tuple[tuple[str, str], ...]:
    """``upgrade_if`` entries are ``"<condition> -> <severity>"`` strings."""
    parsed: list[tuple[str, str]] = []
    for item in clauses:
        text = str(item).strip()
        when, separator, then = text.rpartition("->")
        if not separator or not when.strip() or not then.strip():
            raise ConfigurationError(
                f"correlation rule {rule_id}: upgrade_if entry {item!r} is not "
                "'<condition> -> <severity>'"
            )
        severity = then.strip().lower()
        if severity not in SEVERITY_ORDER:
            raise ConfigurationError(
                f"correlation rule {rule_id}: upgrade_if entry {item!r} names unknown severity "
                f"{severity!r}"
            )
        parsed.append((when.strip(), severity))
    return tuple(parsed)


def parse_correlation_rules(data: Any, *, source: str = "<memory>") -> CorrelationRuleSet:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    document = dict(data)
    # ``signals`` may be written as a list of ids referring to a shared library, which is how
    # a rule reads when several patterns reuse the same signals.
    library = document.pop("signals", None) or {}
    raw_rules = document.get("rules")
    if isinstance(library, Mapping) and isinstance(raw_rules, list):
        expanded_rules: list[Any] = []
        for rule in raw_rules:
            if not isinstance(rule, Mapping):
                expanded_rules.append(rule)
                continue
            body = dict(rule)
            raw_signals = body.get("signals")
            if raw_signals is not None:
                expanded: list[Any] = []
                for item in raw_signals:
                    if isinstance(item, str):
                        if item not in library:
                            raise ConfigurationError(
                                f"{source}: rule {body.get('id')!r} refers to unknown signal "
                                f"{item!r}"
                            )
                        definition = dict(library[item])
                        definition.setdefault("id", item)
                        expanded.append(definition)
                    else:
                        expanded.append(item)
                body["signals"] = expanded
            expanded_rules.append(body)
        document["rules"] = expanded_rules
    try:
        return CorrelationRuleSet.model_validate(document)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(
            f"{source}: invalid correlation rules: {'; '.join(parts)}"
        ) from exc


def load_correlation_rules(path: str | None = None) -> CorrelationRuleSet:
    """Load the correlation rules from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"correlation rule file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_correlation_rules(_safe_yaml(text, source=str(resolved)), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_CORRELATION_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled correlation rules are missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_CORRELATION_RESOURCE)
    return parse_correlation_rules(_safe_yaml(text, source=source), source=source)


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


# --------------------------------------------------------------------------- outcome


@dataclass(frozen=True, slots=True)
class CorrelationGroup:
    """One group a rule fired on, for step statistics and the narrative trace."""

    rule_id: str
    group_key: str
    signal_ids: tuple[str, ...]
    contributor_ids: tuple[int, ...]
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "group": self.group_key,
            "signals": list(self.signal_ids),
            "contributors": list(self.contributor_ids),
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    """The result of a correlation run."""

    analyses: tuple[Analysis, ...]
    compounds: tuple[Analysis, ...] = ()
    merged: tuple[Analysis, ...] = ()
    groups: tuple[CorrelationGroup, ...] = ()
    evidence_owner: Mapping[int, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyses": len(self.analyses),
            "compounds": len(self.compounds),
            "merged": len(self.merged),
            "groups": [group.to_dict() for group in self.groups],
        }


class CorrelationEngine:
    """Applies dedupe and the correlation rules to a set of analyses (F-05-03)."""

    def __init__(
        self,
        rules: CorrelationRuleSet | None = None,
        *,
        scoring: ScoringModel | None = None,
        narratives: NarrativeSynthesizer | None = None,
        remediation: RemediationCatalog | None = None,
        minimum_severity: str = "info",
    ) -> None:
        self.rules = rules or load_correlation_rules()
        self._scoring = scoring
        self._narratives = narratives
        self._remediation = remediation
        self.minimum_severity = minimum_severity

    @property
    def version(self) -> str:
        return self.rules.version

    # ------------------------------------------------------------------ entry point
    def correlate(
        self,
        analyses: Sequence[Analysis],
        candidates: Mapping[int, Candidate] | Sequence[Candidate],
    ) -> CorrelationOutcome:
        """Dedupe then correlate.

        ``candidates`` is keyed by ``finding_id`` when a mapping is supplied (the handler's
        natural shape) and matched positionally otherwise.
        """
        pairs = _pair(analyses, candidates)
        active = tuple(pair for pair in pairs if pair[0].verdict == "analyzed")
        if self.rules.dedupe.enabled:
            deduped, merged, owner_map = self._dedupe(active)
        else:
            deduped = active
            merged = ()
            owner_map = {}
        compounds, groups = self._correlate(deduped)
        final = tuple(analysis for analysis, _ in deduped) + compounds
        # The dropped analyses are kept in the result: a report must be able to say why a
        # finding was not reported (docs/spec/04- §2.6).
        dropped = tuple(analysis for analysis, _ in pairs if analysis.verdict == "dropped")
        return CorrelationOutcome(
            analyses=final + dropped + tuple(analysis for analysis, _ in merged),
            compounds=compounds,
            merged=tuple(analysis for analysis, _ in merged),
            groups=groups,
            evidence_owner=owner_map,
        )

    # ------------------------------------------------------------------ dedupe
    def _dedupe(
        self, pairs: Sequence[tuple[Analysis, Candidate]]
    ) -> tuple[
        tuple[tuple[Analysis, Candidate], ...],
        tuple[tuple[Analysis, Candidate], ...],
        dict[int, int],
    ]:
        # A proof-ladder artifact (S15) is distinct evidence of exploitability, not a
        # duplicate detection: the finding that carries it must survive the fold with its
        # own Proof section, so proof-bearing candidates never merge into an owner. The
        # same holds for a posture artifact (S23): each names *one resource* (a drift
        # delta with its before/after, a policy breach with what was observed), and
        # folding it into an owner would hide which resource changed or breached.
        unmergeable = tuple(
            (analysis, candidate)
            for analysis, candidate in pairs
            if _carries_proof(candidate) or _carries_posture_artifact(candidate)
        )
        dedupable = tuple(
            (analysis, candidate)
            for analysis, candidate in pairs
            if not (_carries_proof(candidate) or _carries_posture_artifact(candidate))
        )
        groups: dict[tuple[str, str], list[tuple[Analysis, Candidate]]] = {}
        for analysis, candidate in dedupable:
            key = (_dedupe_cwe(analysis, candidate), candidate.asset_label)
            groups.setdefault(key, []).append((analysis, candidate))

        kept: list[tuple[Analysis, Candidate]] = list(unmergeable)
        merged: list[tuple[Analysis, Candidate]] = []
        owner_map: dict[int, int] = {}
        for key in sorted(groups, key=lambda item: (item[0], item[1])):
            members = groups[key]
            if len(members) == 1:
                kept.extend(members)
                continue
            owner = self._pick_owner(members)
            owner_analysis, owner_candidate = owner
            contributors = tuple(
                analysis.finding_id
                for analysis, _ in members
                if analysis is not owner_analysis and analysis.finding_id is not None
            )
            merged_refs = tuple(
                sorted(
                    {
                        evidence.id
                        for analysis, candidate in members
                        if analysis is not owner_analysis
                        for evidence in candidate.evidence
                        if evidence.id is not None
                    }
                )
            )
            updated = replace(
                owner_analysis,
                contributors=tuple(sorted({*owner_analysis.contributors, *contributors})),
                merged_evidence_refs=tuple(
                    sorted({*owner_analysis.merged_evidence_refs, *merged_refs})
                ),
                risk_notes=_merge_note(owner_analysis.risk_notes, members, owner_analysis),
                provenance=_with_rule(owner_analysis.provenance, "dedupe:cwe-asset"),
            )
            kept.append((updated, owner_candidate))
            for analysis, candidate in members:
                if analysis is owner_analysis:
                    continue
                merged.append(
                    (
                        replace(
                            analysis,
                            verdict="merged",
                            merged_into=owner_analysis.finding_id,
                            drop_reason=(
                                "merged into finding "
                                f"{owner_analysis.finding_id} (same CWE and asset, "
                                "docs/spec/05- dedupe rules)"
                            ),
                        ),
                        candidate,
                    )
                )
                if analysis.finding_id is not None and owner_analysis.finding_id is not None:
                    owner_map[analysis.finding_id] = owner_analysis.finding_id
        return tuple(kept), tuple(merged), owner_map

    def _pick_owner(
        self, members: Sequence[tuple[Analysis, Candidate]]
    ) -> tuple[Analysis, Candidate]:
        """Most specific module first, then highest severity, then lowest finding id."""
        preference = list(self.rules.dedupe.owner_preference)

        def rank(pair: tuple[Analysis, Candidate]) -> tuple[int, int, int, str]:
            analysis, candidate = pair
            module = candidate.check_module or "M9"
            position = preference.index(module) if module in preference else len(preference)
            return (
                position,
                -severity_rank(analysis.severity),
                analysis.finding_id if analysis.finding_id is not None else 1 << 30,
                analysis.check_id or "",
            )

        return min(members, key=rank)

    # ------------------------------------------------------------------ correlation
    def _correlate(
        self, pairs: Sequence[tuple[Analysis, Candidate]]
    ) -> tuple[tuple[Analysis, ...], tuple[CorrelationGroup, ...]]:
        compounds: list[Analysis] = []
        groups: list[CorrelationGroup] = []
        for rule in sorted(self.rules.rules, key=lambda item: item.id):
            if not rule.enabled:
                continue
            buckets: dict[str, list[tuple[Analysis, Candidate]]] = {}
            for analysis, candidate in pairs:
                if severity_rank(analysis.severity) < severity_rank(self.minimum_severity):
                    continue
                buckets.setdefault(rule.group_key(candidate), []).append((analysis, candidate))
            for key in sorted(buckets):
                members = buckets[key]
                present, signal_pairs = _signals_present(rule, members)
                if len(present) < rule.min_weak_signals:
                    continue
                compound = self._compound(rule, key, members, present, signal_pairs)
                compounds.append(compound)
                groups.append(
                    CorrelationGroup(
                        rule_id=rule.id,
                        group_key=key,
                        signal_ids=tuple(present),
                        contributor_ids=compound.contributors,
                        severity=compound.severity,
                    )
                )
        return tuple(compounds), tuple(groups)

    def _compound(
        self,
        rule: CorrelationRule,
        group_key: str,
        members: Sequence[tuple[Analysis, Candidate]],
        present: Sequence[str],
        signal_pairs: Mapping[str, tuple[Analysis, Candidate]],
    ) -> Analysis:
        contributor_ids = tuple(
            sorted(
                {analysis.finding_id for analysis, _ in members if analysis.finding_id is not None}
            )
        )
        evidence: list[EvidenceFact] = []
        for signal in present:
            _, candidate = signal_pairs[signal]
            evidence.extend(candidate.evidence)
        base_severity = worst_severity(*(analysis.severity for analysis, _ in members))
        severity, upgrade_trace = self._upgrade(rule, present, base_severity, signal_pairs, members)
        confidence = max(analysis.confidence for analysis, _ in members)
        primary = signal_pairs[present[0]][1]
        compound_candidate = Candidate(
            scan_id=primary.scan_id,
            title=rule.title,
            # The compound's identity *is* the correlation rule: a report shows it as the check
            # that produced the finding, and no ``checks`` row exists for it (NULL FK).
            check_id=rule.id,
            check_name=rule.id.rsplit(".", 1)[-1],
            check_module=primary.check_module,
            research_ref=primary.research_ref,
            cwe=rule.cwe or _dominant_cwe(members),
            severity_hint=severity,
            asset_id=primary.asset_id,
            asset_kind=primary.asset_kind,
            asset_value=primary.asset_value,
            evidence=tuple(_unique_evidence(evidence)) if rule.merge_evidence else primary.evidence,
        )
        remediation = (
            self._remediation.resolve(compound_candidate, reference=rule.remediation)
            if self._remediation is not None
            else None
        )
        if remediation is None:
            from arachne.analyzer.remediation import default_remediation

            remediation = default_remediation(
                cwe=compound_candidate.cwe, check_id=compound_candidate.check_id
            )
        score = (
            self._scoring.score(
                compound_candidate,
                cwe=compound_candidate.cwe,
                base_confidence=confidence,
            )
            if self._scoring is not None
            else ScoreBreakdown(confidence=confidence)
        )
        score = replace(
            score,
            derived_severity=severity,
            confidence=confidence,
            confidence_reasons=(
                *score.confidence_reasons,
                f"compound of {len(present)} correlated signal(s)",
            ),
        )
        narrative_text = ""
        template_id = rule.narrative
        if self._narratives is not None:
            facts = _compound_facts(compound_candidate, present, members)
            narrative = self._narratives.render(
                compound_candidate,
                severity=severity,
                confidence=confidence,
                score=score,
                remediation=remediation,
                facts=facts,
                rule_ids=(rule.id,),
                trace=upgrade_trace,
                template_id=template_id,
            )
            narrative_text = narrative.text
            template_id = narrative.template_id
        else:
            narrative_text = (
                f"{rule.title}: {len(present)} weak signals on {group_key} "
                f"({', '.join(present)}) combine into one {severity}-severity exposure."
            )
        return Analysis(
            title=rule.title,
            severity=severity,
            confidence=confidence,
            narrative=narrative_text,
            remediation=remediation,
            check_id=compound_candidate.check_id,
            asset=group_key,
            cwe=compound_candidate.cwe,
            risk_notes=(
                f"compound finding: signals {', '.join(present)}; "
                f"contributors {list(contributor_ids)}"
            ),
            score=score,
            provenance=Provenance(
                engine="heuristic",
                rule_ids=(rule.id,),
                template_version=self._narratives.version if self._narratives else None,
                prompt_template=template_id,
            ),
            rule_trace=upgrade_trace,
            contributors=contributor_ids,
            merged_evidence_refs=tuple(
                sorted({item.id for item in compound_candidate.evidence if item.id is not None})
            ),
            correlated=True,
        )

    def _upgrade(
        self,
        rule: CorrelationRule,
        present: Sequence[str],
        base_severity: str,
        signal_pairs: Mapping[str, tuple[Analysis, Candidate]],
        members: Sequence[tuple[Analysis, Candidate]],
    ) -> tuple[str, tuple[RuleTraceEntry, ...]]:
        """Promote the compound's severity (``upgrade_if`` first, else ``upgrade_levels``)."""
        facts, conditions = _signal_facts(rule, present, signal_pairs, members)
        trace: list[RuleTraceEntry] = []
        severity = base_severity
        for expression, target in _split_clauses(rule.upgrade_if, rule_id=rule.id):
            if parse_expression(expression).evaluate(facts, conditions):
                severity = target
                trace.append(
                    RuleTraceEntry(
                        rule_id=rule.id,
                        clause="upgrade_if",
                        expression=expression,
                        value=target,
                    )
                )
                break
        else:
            severity = raise_severity(base_severity, rule.upgrade_levels)
            trace.append(
                RuleTraceEntry(
                    rule_id=rule.id,
                    clause="upgrade_levels",
                    expression=f"{len(present)} signal(s) >= {rule.min_weak_signals}",
                    value=severity,
                )
            )
        if severity_rank(severity) > severity_rank(rule.max_severity):
            severity = rule.max_severity
        if severity_rank(severity) < severity_rank(base_severity):
            # A rule never *lowers* the severity of what it correlates; it explains a pattern.
            severity = base_severity
        return severity, tuple(trace)


# --------------------------------------------------------------------------- helpers


def _pair(
    analyses: Sequence[Analysis], candidates: Mapping[int, Candidate] | Sequence[Candidate]
) -> tuple[tuple[Analysis, Candidate], ...]:
    if isinstance(candidates, Mapping):
        pairs: list[tuple[Analysis, Candidate]] = []
        for analysis in analyses:
            candidate = None
            if analysis.finding_id is not None:
                candidate = candidates.get(analysis.finding_id)
            if candidate is None:
                candidate = _synthetic(analysis)
            pairs.append((analysis, candidate))
        return tuple(pairs)
    sequence = list(candidates)
    return tuple(
        (analysis, sequence[index] if index < len(sequence) else _synthetic(analysis))
        for index, analysis in enumerate(analyses)
    )


def _synthetic(analysis: Analysis) -> Candidate:
    """A candidate stand-in for an analysis whose candidate the caller did not supply."""
    return Candidate(
        scan_id=0,
        title=analysis.title,
        finding_id=analysis.finding_id,
        check_id=analysis.check_id,
        cwe=analysis.cwe,
        cve=analysis.cve,
        asset_value=analysis.asset,
    )


def _dedupe_cwe(analysis: Analysis, candidate: Candidate) -> str:
    return analysis.cwe or candidate.cwe or "UNCLASSIFIED"


def _carries_proof(candidate: Candidate) -> bool:
    """True when the candidate carries a proof-ladder artifact (S15, area PROOF)."""
    return any(evidence.kind == "proof" for evidence in candidate.evidence)


#: The artifact signals that make a candidate unmergeable (S23, area POSTURE): each names
#: one resource of the estate, which is exactly the detail a fold would erase.
_POSTURE_SIGNALS = frozenset({"cloud-config-drift", "cloud-posture"})


def _carries_posture_artifact(candidate: Candidate) -> bool:
    """True when the candidate carries a continuous-posture artifact (S23, REQ-POSTURE-001)."""
    return any(
        evidence.kind == "artifact"
        and str(evidence.payload.get("signal") or "") in _POSTURE_SIGNALS
        for evidence in candidate.evidence
    )


def _dominant_cwe(members: Sequence[tuple[Analysis, Candidate]]) -> str | None:
    counts: dict[str, int] = {}
    for analysis, candidate in members:
        value = analysis.cwe or candidate.cwe
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _signals_present(
    rule: CorrelationRule, members: Sequence[tuple[Analysis, Candidate]]
) -> tuple[list[str], dict[str, tuple[Analysis, Candidate]]]:
    present: list[str] = []
    pairs: dict[str, tuple[Analysis, Candidate]] = {}
    for signal in rule.signals:
        for analysis, candidate in members:
            if signal.matches(candidate, analysis):
                present.append(signal.id)
                pairs[signal.id] = (analysis, candidate)
                break
    return present, pairs


def _signal_facts(
    rule: CorrelationRule,
    present: Sequence[str],
    signal_pairs: Mapping[str, tuple[Analysis, Candidate]],
    members: Sequence[tuple[Analysis, Candidate]],
) -> tuple[FactSpace, dict[str, bool]]:
    """The fact space and condition environment ``upgrade_if`` expressions are read against.

    Every signal id is a boolean condition (true when present), so a rule can write either
    ``signal_count >= 3`` or ``admin-panel and cors-wildcard`` — the same two spellings the
    severity clauses of a rule accept.
    """
    severities = [analysis.severity for analysis, _ in members]
    facts = FactSpace(
        {
            "signal_count": len(present),
            "signals": list(present),
            "severity_max": worst_severity(*severities),
            "severity_rank": max((severity_rank(item) for item in severities), default=0),
            "contributors": len(members),
            "confidence_max": max((analysis.confidence for analysis, _ in members), default=0),
            "modules": sorted(
                {
                    candidate.check_module
                    for _, candidate in members
                    if candidate.check_module is not None
                }
            ),
            "assets": sorted({candidate.asset_label for _, candidate in members}),
        }
    )
    conditions = dict.fromkeys(rule.signal_ids, False)
    conditions.update(dict.fromkeys(present, True))
    conditions.update(dict.fromkeys(signal_pairs, True))
    return facts, conditions


def _compound_facts(
    candidate: Candidate,
    present: Sequence[str],
    members: Sequence[tuple[Analysis, Candidate]],
) -> FactSpace:
    from arachne.analyzer.conditions import build_facts

    facts = build_facts(candidate, signatures=())
    extra = facts.as_mapping()
    extra["signal"] = {"ids": list(present), "count": len(present)}
    severities = [analysis.severity for analysis, _ in members]
    extra["signal"]["severity_max"] = worst_severity(*severities)
    extra["signal"]["titles"] = [analysis.title for analysis, _ in members]
    extra["signal"]["checks"] = sorted(
        {candidate_item.check_id for _, candidate_item in members if candidate_item.check_id}
    )
    return FactSpace(extra)


def _unique_evidence(items: Iterable[EvidenceFact]) -> list[EvidenceFact]:
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[EvidenceFact] = []
    for item in items:
        key = (item.kind, item.sha256, item.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _merge_note(
    existing: str,
    members: Sequence[tuple[Analysis, Candidate]],
    owner: Analysis,
) -> str:
    others = ", ".join(
        sorted(
            f"{candidate.check_id or candidate.title}"
            for analysis, candidate in members
            if analysis is not owner
        )
    )
    note = f"merged duplicate finding(s) from: {others}" if others else ""
    return f"{existing}; {note}".strip("; ") if existing else note


def _with_rule(provenance: Provenance, rule_id: str) -> Provenance:
    return replace(provenance, rule_ids=tuple(sorted({*provenance.rule_ids, rule_id})))
