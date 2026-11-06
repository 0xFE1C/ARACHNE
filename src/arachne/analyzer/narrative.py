"""Explanation synthesis — "the AI-like voice" without an AI (F-05-05).

Every finding gets a narrative, and the narrative is generated from **templates, facts and
the rule trace** — never from a model. The templates are data
(``templates/narrative/narrative-templates.yaml``) keyed to (severity, CWE, check class),
with conditional sections so one template can cover "file exists" and "file exists *and*
holds secrets" without a sentence that lies about the weaker case.

A narrative answers the four questions the templates name — *what is this, how bad is
it, how sure are we, what should be done* — plus *why*: the closing justification cites the
rule that fired and the corpus method it maps to, which is exactly the trace a report must
be able to defensible-ly reproduce.

Two rules keep it honest:

* **Interpolation never executes anything.** ``{path}`` references are resolved by this
  module against the fact space, with a hand-written scanner — not ``str.format``, which
  would let a template reach into object attributes (``{0.__class__}``) and would raise on
  any evidence key it did not expect.
* **An unresolvable reference degrades, it does not crash.** A section that needs a fact the
  candidate does not carry is dropped (or, when it is marked ``required``, the template
  steps aside for the next one), and the generic fallback template always renders — so a
  finding can never reach a report without prose.
"""

from __future__ import annotations

import fnmatch
import functools
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.conditions import ConditionError, FactSpace, parse_expression
from arachne.analyzer.model import (
    Candidate,
    Provenance,
    Remediation,
    RuleTraceEntry,
    ScoreBreakdown,
)
from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_NARRATIVE_RESOURCE",
    "NarrativeSynthesizer",
    "NarrativeTemplate",
    "TemplateSet",
    "load_narrative_templates",
    "parse_narrative_templates",
]

#: Where the shipped narrative templates live inside the package.
DEFAULT_NARRATIVE_RESOURCE: Final = ("narrative", "narrative-templates.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: ``{path}`` — a dot/bracket reference into the render namespace.
_REFERENCE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.\[\]-]*)\}")

#: Match keys a template may use, and the candidate attribute or fact each reads.
_MATCH_KEYS: Final[tuple[str, ...]] = (
    "check",
    "module",
    "cwe",
    "cve",
    "severity",
    "name_token",
    "signature",
    "category",
)

#: ``confidence`` wording bands .
_CONFIDENCE_BANDS: Final[tuple[tuple[int, str], ...]] = (
    (85, "high"),
    (70, "moderate"),
    (55, "fair"),
    (0, "low"),
)


class _Section(BaseModel):
    """One paragraph of a narrative."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    text: str = Field(min_length=1)
    when: str | None = None
    required: bool = False


class NarrativeTemplate(BaseModel):
    """One narrative template: what it applies to, and its sections in reading order."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    id: str = Field(min_length=3, max_length=128)
    sections: tuple[_Section, ...] = Field(min_length=1)
    match: dict[str, list[str]] = Field(default_factory=dict)
    category: str | None = Field(default=None, alias="class")
    #: A rule id that must have fired for this template to be eligible (lets a precise rule
    #: own its own prose without repeating the whole match block).
    rule: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> NarrativeTemplate:
        unknown = sorted(set(self.match) - set(_MATCH_KEYS))
        if unknown:
            msg = f"template {self.id}: unknown match key(s) {unknown}; allowed: {_MATCH_KEYS}"
            raise ValueError(msg)
        for key, values in self.match.items():
            if not values:
                raise ValueError(f"template {self.id}: match.{key} is empty")
        for section in self.sections:
            if section.when is not None:
                parse_expression(section.when)
        return self

    @property
    def specificity(self) -> int:
        """More match keys (and a rule pin) win; ties break on the template id."""
        return len(self.match) * 2 + (1 if self.rule else 0)

    def matches(
        self,
        *,
        candidate: Candidate,
        severity: str,
        rule_ids: Sequence[str],
        signatures: Sequence[str],
    ) -> bool:
        if self.rule is not None and self.rule not in rule_ids:
            return False
        for key, wanted in self.match.items():
            actual = _match_value(
                key, candidate=candidate, severity=severity, signatures=signatures
            )
            if actual is None or not _value_matches(key, actual, wanted):
                return False
        return True


def _value_matches(key: str, actual: str, wanted: Sequence[str]) -> bool:
    """Match one template key: ``name_token`` is a substring, everything else a glob/equality."""
    if key == "name_token":
        lowered = actual.lower()
        return any(token.lower() in lowered for token in wanted)
    return any(fnmatch.fnmatchcase(actual, value) for value in wanted)


def _match_value(
    key: str, *, candidate: Candidate, severity: str, signatures: Sequence[str]
) -> str | None:
    if key == "check":
        return candidate.check_id
    if key == "module":
        return candidate.check_module
    if key == "cwe":
        return candidate.cwe
    if key == "cve":
        return candidate.cve
    if key == "severity":
        return severity
    if key == "name_token":
        # A substring of the check name, or of the check id when the name is absent.
        return candidate.check_name or candidate.check_id
    if key == "signature":
        return signatures[0] if signatures else None
    if key == "category":
        return None  # categories are resolved by the caller, not from the candidate
    return None


class TemplateSet(BaseModel):
    """The whole narrative corpus."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    templates: tuple[NarrativeTemplate, ...] = Field(min_length=1)

    def ranked(self) -> tuple[NarrativeTemplate, ...]:
        return tuple(sorted(self.templates, key=lambda item: (-item.specificity, item.id)))

    def by_id(self, template_id: str) -> NarrativeTemplate | None:
        for template in self.templates:
            if template.id == template_id:
                return template
        return None


def parse_narrative_templates(data: Any, *, source: str = "<memory>") -> TemplateSet:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return TemplateSet.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(
            f"{source}: invalid narrative templates: {'; '.join(parts)}"
        ) from exc


def load_narrative_templates(path: str | None = None) -> TemplateSet:
    """Load the narrative templates from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"narrative template file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_narrative_templates(
            _safe_yaml(text, source=str(resolved)), source=str(resolved)
        )
    return _shipped_narrative_templates()


@functools.cache
def _shipped_narrative_templates() -> TemplateSet:
    """The packaged narrative templates, parsed once per process.

    A frozen model over a file that ships inside the package; it is ~0.3 s to parse and one
    scan parsed it four times, once per analysis phase. No arguments: the shipped resource is a
    constant of the installation. An explicit ``path`` is never cached.
    """
    resource = files("arachne.templates")
    for part in DEFAULT_NARRATIVE_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled narrative templates are missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_NARRATIVE_RESOURCE)
    return parse_narrative_templates(_safe_yaml(text, source=source), source=source)


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


# --------------------------------------------------------------------------- render


@dataclass(frozen=True, slots=True)
class Narrative:
    """The rendered prose plus the template that produced it (kept for provenance)."""

    text: str
    template_id: str
    template_version: str


def confidence_band(confidence: int) -> str:
    for threshold, label in _CONFIDENCE_BANDS:
        if confidence >= threshold:
            return label
    return "low"  # pragma: no cover - the last band is 0


class _Namespace:
    """Resolves ``{path}`` references for one render: overlay first, then the fact space."""

    def __init__(self, overlay: Mapping[str, Any], facts: FactSpace) -> None:
        self._overlay = dict(overlay)
        self._facts = facts

    def resolve(self, path: str) -> str | None:
        if path in self._overlay:
            return _render_value(self._overlay[path])
        # ``FactSpace.get`` yields the *first* value of a path, which is what a comparison
        # wants; a narrative wants the whole set, so a multi-valued fact (several ``missing``
        # headers, several enumerated identifiers) renders as a list rather than its first
        # element. Empty means "absent" — the section is dropped or the template steps aside.
        values = self._facts.values(path)
        if not values:
            return None
        return _render_value(values[0] if len(values) == 1 else values)


def _render_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [str(item) for item in list(value)[:5]]
        rendered = ", ".join(items)
        if len(value) > 5:
            rendered += f", … (+{len(value) - 5} more)"
        return rendered or None
    if isinstance(value, Mapping):
        return None
    text = str(value).strip()
    return text or None


class NarrativeSynthesizer:
    """Renders narratives from the template corpus (F-05-05)."""

    def __init__(self, templates: TemplateSet | None = None) -> None:
        self.templates = templates or load_narrative_templates()

    @property
    def version(self) -> str:
        return self.templates.version

    def render(
        self,
        candidate: Candidate,
        *,
        severity: str,
        confidence: int,
        score: ScoreBreakdown,
        remediation: Remediation,
        facts: FactSpace,
        rule_ids: Sequence[str] = (),
        trace: Sequence[RuleTraceEntry] = (),
        signatures: Sequence[str] = (),
        conditions: Mapping[str, bool] | None = None,
        template_id: str | None = None,
    ) -> Narrative:
        """Render the narrative for one analysed candidate.

        ``template_id`` (from a rule's ``narrative:`` key) pins a specific template; the
        most specific matching template is used otherwise; the generic fallback always
        renders, so the result is never empty. ``conditions`` carries the firing rule's
        resolved condition names, so a section can be gated on the same signal the rule was.
        """
        overlay = _overlay(
            candidate=candidate,
            severity=severity,
            confidence=confidence,
            score=score,
            remediation=remediation,
            rule_ids=rule_ids,
            trace=trace,
            signatures=signatures,
        )
        namespace = _Namespace(overlay, facts)
        local = dict(conditions or {})
        for template in self._candidates(template_id, candidate, severity, rule_ids, signatures):
            text = self._render_template(template, namespace, facts, local)
            if text is not None:
                return Narrative(text=text, template_id=template.id, template_version=self.version)
        return Narrative(
            text=self._fallback(candidate, overlay),
            template_id="builtin.generic",
            template_version=self.version,
        )

    # ------------------------------------------------------------------ internals
    def _candidates(
        self,
        template_id: str | None,
        candidate: Candidate,
        severity: str,
        rule_ids: Sequence[str],
        signatures: Sequence[str],
    ) -> Iterable[NarrativeTemplate]:
        if template_id is not None:
            pinned = self.templates.by_id(template_id)
            if pinned is not None:
                yield pinned
            return
        for template in self.templates.ranked():
            if template.id == "builtin.generic":
                continue
            if template.matches(
                candidate=candidate, severity=severity, rule_ids=rule_ids, signatures=signatures
            ):
                yield template

    def _render_template(
        self,
        template: NarrativeTemplate,
        namespace: _Namespace,
        facts: FactSpace,
        conditions: Mapping[str, bool],
    ) -> str | None:
        parts: list[str] = []
        for section in template.sections:
            if section.when is not None:
                try:
                    if not parse_expression(section.when).evaluate(facts, conditions):
                        continue
                except ConditionError:  # a broken template must not break a scan
                    continue
            rendered = _interpolate(section.text, namespace)
            if rendered is None:
                if section.required:
                    return None
                continue
            if rendered.strip():
                parts.append(rendered.strip())
        return " ".join(parts) if parts else None

    def _fallback(self, candidate: Candidate, overlay: Mapping[str, Any]) -> str:
        """The always-available synthesis: what, how bad, how sure, what to do, why."""
        asset = overlay.get("asset.label") or candidate.asset_label
        severity = overlay.get("severity")
        confidence_band_text = overlay.get("confidence.band")
        remediation_summary = overlay.get("remediation.summary")
        research = overlay.get("check.research_ref")
        sentences = [
            f"{candidate.title} on {asset}.",
            f"ARACHNE rates this {severity} with {confidence_band_text} confidence "
            f"({overlay.get('confidence.value')}/100).",
        ]
        if research:
            sentences.append(
                f"The check maps to research corpus method {research}, so the technique is "
                "documented and routinely used against exposed systems."
            )
        if remediation_summary:
            sentences.append(f"Recommended action: {remediation_summary}")
        basis = overlay.get("confidence.basis")
        if basis:
            sentences.append(f"Evidence basis: {basis}.")
        return " ".join(str(item) for item in sentences)


def _overlay(
    *,
    candidate: Candidate,
    severity: str,
    confidence: int,
    score: ScoreBreakdown,
    remediation: Remediation,
    rule_ids: Sequence[str],
    trace: Sequence[RuleTraceEntry],
    signatures: Sequence[str],
) -> dict[str, Any]:
    """The computed part of the render namespace (facts supply the rest)."""
    basis = _confidence_basis(score)
    justification = _justification(trace, rule_ids)
    return {
        "asset": candidate.asset_label,
        "asset.label": candidate.asset_label,
        "check.title": candidate.check_name or candidate.check_id,
        "severity": severity,
        "confidence.value": confidence,
        "confidence.band": confidence_band(confidence),
        "confidence.basis": basis,
        "confidence.reasons": "; ".join(score.confidence_reasons),
        "confidence.reasons_list": list(score.confidence_reasons),
        "score.cvss": f"{score.cvss_base:.1f}",
        "score.cvss_vector": score.cvss_vector,
        "score.owasp_risk": score.owasp_risk,
        "score.epss": score.epss,
        "remediation.summary": remediation.summary,
        "remediation.id": remediation.id,
        "remediation.steps": list(remediation.steps),
        "remediation.verification": list(remediation.verification),
        "remediation.references": list(remediation.references),
        "rule.ids": list(rule_ids),
        "rule.justification": justification,
        "signature.ids": list(signatures),
    }


def _confidence_basis(score: ScoreBreakdown) -> str:
    positive = [
        reason for reason in score.confidence_reasons if "+" in reason and "base" not in reason
    ]
    negative = [
        reason for reason in score.confidence_reasons if reason.count("-") and "base" not in reason
    ]
    parts: list[str] = []
    if positive:
        parts.append("raised by " + ", ".join(item.split(" +")[0] for item in positive))
    if negative:
        parts.append("reduced by " + ", ".join(item.split(" -")[0] for item in negative))
    return "; ".join(parts) if parts else "no evidence-quality adjustments applied"


def _justification(trace: Sequence[RuleTraceEntry], rule_ids: Sequence[str]) -> str:
    clauses = [entry.describe() for entry in trace if entry.clause == "severity_if"]
    if clauses:
        return "matched " + "; ".join(clauses)
    if rule_ids:
        return "matched rule " + ", ".join(rule_ids)
    return "no rule matched; scored from the check's declared severity hint"


def _interpolate(text: str, namespace: _Namespace) -> str | None:
    """Substitute ``{path}`` references; ``None`` when one cannot be resolved."""
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        value = namespace.resolve(match.group(1))
        if value is None:
            missing.append(match.group(1))
            return ""
        return value

    rendered = _REFERENCE.sub(replace, text)
    if missing:
        return None
    return re.sub(r"\s+", " ", rendered)


def provenance_for(narrative: Narrative, *, engine: str = "heuristic") -> Provenance:
    """The provenance record an analysis carries (F-03-05)."""
    return Provenance(
        engine=engine,
        template_version=narrative.template_version,
        prompt_template=narrative.template_id,
    )
