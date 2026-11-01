"""The six AI analysis stages of as data plus input builders.

Each stage is three things and nothing more: a **name**, a **pydantic output model** (which is
also its JSON schema, via :mod:`arachne.ai.structured`) and a **builder** that turns analyzer
objects into the two prompt payloads — ``context`` (trusted: the check, the asset, the
deterministic verdict) and ``target_data`` (untrusted: everything the scan observed at the
target). The builders are where that split is decided, and it is decided once, per stage,
rather than by whichever code happens to render a prompt.

The stage set is exactly the spec's table:

=============  =========================================================
``triage``     severity, confidence, fp suggestion, reason
``correlate``  a compound finding's title, reasoning, shared root cause
``remediate``  numbered, copy-ready remediation steps + references
``narrative``  the per-finding prose for the report
``explain``    a condensed evidence summary for a long capture
``prioritize`` a recommended fix order over the whole finding set
``hypothesize`` which *registered* checks to run next, and why (S21, area AGENT)
=============  =========================================================

``hypothesize`` is the agentic stage: it is not part of the per-candidate pipeline (the
analyzer already decided everything it needs), and its output is a list of check ids to run
rather than prose about a finding. It shares the stage machinery — versioned prompt, JSON
schema, ledger, retries, cache, redaction — because that machinery is what makes an AI proposal
auditable, and it is the only part of area AGENT that talks to a model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arachne.ai.structured import SchemaSpec
from arachne.analyzer.model import SEVERITY_ORDER, Analysis, Candidate
from arachne.core.redaction import redact_text

__all__ = [
    "CANDIDATE_STAGES",
    "HYPOTHESIZE_MAX_TARGET_CHARS",
    "SCHEMAS",
    "STAGES",
    "CorrelateOutput",
    "ExplainOutput",
    "HypothesizeItem",
    "HypothesizeOutput",
    "NarrativeOutput",
    "PrioritizeOutput",
    "RemediateOutput",
    "StageInput",
    "TriageOutput",
    "build_correlate_input",
    "build_explain_input",
    "build_hypothesize_input",
    "build_narrative_input",
    "build_prioritize_input",
    "build_remediate_input",
    "build_triage_input",
    "schema_for",
]

#: The stage vocabulary, in pipeline order.
STAGES: Final[tuple[str, ...]] = (
    "triage",
    "explain",
    "remediate",
    "narrative",
    "correlate",
    "prioritize",
    "hypothesize",
)

#: Per-candidate stages (the ones the analysis step runs once per finding).
CANDIDATE_STAGES: Final[tuple[str, ...]] = ("triage", "explain", "remediate", "narrative")

_MODEL = ConfigDict(frozen=True, extra="forbid")

#: How much captured evidence one stage may see. Small on purpose: the model is being asked to
#: judge a finding, not to re-read the target (and the budget is per scan).
EVIDENCE_CHARS: Final = 1200


#: The severity vocabulary a model may answer with, as a schema enum.
_SEVERITY_ENUM: Final[dict[str, Any]] = {"enum": list(SEVERITY_ORDER)}


class TriageOutput(BaseModel):
    """``triage`` — the verdict a model proposes for one candidate .

    Every field the merge reads is **required**: a model that leaves the severity out has not
    answered, and a missing field must fail validation (and be repaired) rather than
    defaulting to a value nobody chose.
    """

    model_config = _MODEL

    severity: str = Field(json_schema_extra=_SEVERITY_ENUM)
    confidence: int = Field(ge=0, le=100)
    fp_likely: bool
    reason: str = Field(max_length=2000)
    categories: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        lowered = value.strip().lower()
        if lowered not in SEVERITY_ORDER:
            raise ValueError(f"severity {value!r} is not one of {list(SEVERITY_ORDER)}")
        return lowered


class ExplainOutput(BaseModel):
    """``explain`` — a condensed reading of a long capture ."""

    model_config = _MODEL

    summary: str = Field(max_length=2000)
    key_facts: list[str] = Field(default_factory=list, max_length=10)


class RemediateOutput(BaseModel):
    """``remediate`` — numbered, copy-ready steps (06- §6)."""

    model_config = _MODEL

    summary: str = Field(max_length=2000)
    steps: list[str] = Field(default_factory=list, max_length=12)
    references: list[str] = Field(default_factory=list, max_length=10)


class NarrativeOutput(BaseModel):
    """``narrative`` — the per-finding prose for the report ."""

    model_config = _MODEL

    narrative: str = Field(max_length=4000)
    headline: str = Field(default="", max_length=300)


class CorrelateOutput(BaseModel):
    """``correlate`` — how a group of candidates compounds ."""

    model_config = _MODEL

    title: str = Field(max_length=300)
    reasoning: str = Field(max_length=3000)
    shared_root_cause: str = Field(default="", max_length=300)
    severity: str | None = Field(default=None, json_schema_extra=_SEVERITY_ENUM)

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered not in SEVERITY_ORDER:
            raise ValueError(f"severity {value!r} is not one of {list(SEVERITY_ORDER)}")
        return lowered


class PrioritizeOutput(BaseModel):
    """``prioritize`` — a recommended fix order with rationale ."""

    model_config = _MODEL

    order: list[str] = Field(max_length=200)
    rationale: str = Field(default="", max_length=3000)


class HypothesizeItem(BaseModel):
    """One proposed probe: a **registered** check id and the asset to run it against.

    The model may not invent a check or an asset — it may only name one it was shown. A
    proposal that names something else is dropped by the executor and recorded, which is the
    structural half of REQ-AGENT-005 (an AI output cannot widen the executable surface).
    """

    model_config = _MODEL

    check_id: str = Field(min_length=3, max_length=128)
    asset: str = Field(default="", max_length=2048)
    rationale: str = Field(default="", max_length=1000)
    confidence: int = Field(default=50, ge=0, le=100)


class HypothesizeOutput(BaseModel):
    """``hypothesize`` — the ranked proposals for the next slice of the scan (REQ-AGENT-001).

    ``hypotheses`` is **required** (every stage's schema requires its answer, so a model that
    returns an empty object has not answered and must be repaired rather than read as "nothing
    to do"); an empty list is a valid, explicit answer.
    """

    model_config = _MODEL

    hypotheses: list[HypothesizeItem] = Field(max_length=12)


#: stage name → its output contract. One table, so a new stage is one entry plus a template.
SCHEMAS: Final[dict[str, SchemaSpec]] = {
    "triage": SchemaSpec("triage", TriageOutput),
    "explain": SchemaSpec("explain", ExplainOutput),
    "remediate": SchemaSpec("remediate", RemediateOutput),
    "narrative": SchemaSpec("narrative", NarrativeOutput),
    "correlate": SchemaSpec("correlate", CorrelateOutput),
    "prioritize": SchemaSpec("prioritize", PrioritizeOutput),
    "hypothesize": SchemaSpec("hypothesize", HypothesizeOutput),
}


def schema_for(stage: str) -> SchemaSpec:
    """The output contract of ``stage`` (a ``KeyError`` is a programming error, not data)."""
    try:
        return SCHEMAS[stage]
    except KeyError as exc:  # pragma: no cover - guarded by the stage vocabulary
        msg = f"unknown AI stage {stage!r}"
        raise KeyError(msg) from exc


@dataclass(frozen=True, slots=True)
class StageInput:
    """The two prompt payloads of one stage call, before privacy is applied.

    ``context`` is trusted (our own analysis), ``target_data`` is everything the scan observed
    at the target . Keeping them separate here is what lets the engine apply
    the privacy mode to each with one rule: context is tokenized too, because it embeds the
    asset value.
    """

    context_lines: tuple[str, ...] = ()
    target_data: str = ""
    values: Mapping[str, Any] = field(default_factory=dict)

    def with_privacy(self, transform: Any) -> StageInput:
        """Return a copy with every payload passed through ``transform``."""
        return StageInput(
            context_lines=tuple(transform(line) for line in self.context_lines),
            target_data=transform(self.target_data),
            values={key: transform(value) for key, value in self.values.items()},
        )


# --------------------------------------------------------------------------- builders


def _assets(candidate: Candidate) -> str:
    return candidate.asset_label


def _evidence_text(candidate: Candidate, *, limit: int = EVIDENCE_CHARS) -> str:
    """The captured evidence, as text for the prompt (already redacted at capture)."""
    lines: list[str] = []
    for item in candidate.evidence:
        payload = _payload_summary(item.payload)
        if payload:
            lines.append(f"- {item.kind} ({item.source or 'no source'}): {payload}")
    return "\n".join(lines)[:limit]


def _payload_summary(payload: Mapping[str, Any], *, depth: int = 0) -> str:
    """A one-line, bounded rendering of an evidence payload's interesting fields."""
    interesting = (
        "status_code",
        "method",
        "reason",
        "detail",
        "title",
        "notable",
        "signals",
        "missing",
        "headers",
        "service",
        "version",
        "cve",
        "cwe",
        "body",
    )
    parts: list[str] = []
    for key, value in payload.items():
        if key not in interesting:
            continue
        parts.append(f"{key}={_render(value)}")
    if not parts and depth == 0:
        parts.append(_render(payload))
    return "; ".join(parts)[:600]


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value[:400]
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        rendered = ", ".join(_render(item) for item in list(value)[:8])
        return f"[{rendered}]"
    if isinstance(value, Mapping):
        rendered = ", ".join(f"{key}: {_render(item)}" for key, item in list(value.items())[:8])
        return f"{{{rendered}}}"
    return str(value)


def _verdict_lines(anchor: Analysis | None) -> list[str]:
    if anchor is None:
        return ["deterministic verdict: (none)"]
    return [
        f"deterministic verdict: {anchor.severity} (confidence {anchor.confidence}/100, "
        f"{anchor.score.owasp_risk} risk)",
        f"deterministic score: cvss {anchor.score.cvss_base:.1f}"
        + (f" {anchor.score.cvss_vector}" if anchor.score.cvss_vector else ""),
    ]


def build_triage_input(candidate: Candidate, anchor: Analysis | None) -> StageInput:
    """``triage``: the candidate's identity, its check's claim, and its evidence."""
    context = [
        f"scan: {candidate.scan_id}",
        f"module: {candidate.check_module or 'unknown'}, check: {candidate.check_id or 'unknown'}",
        f"asset: {_assets(candidate)}",
        f"check title: {candidate.title}",
        f"check cwe: {candidate.cwe or 'none'}"
        + (f", cve: {candidate.cve}" if candidate.cve else ""),
        f"check severity hint: {candidate.severity_hint or 'none'}",
        "check confidence: "
        f"{candidate.check_confidence if candidate.check_confidence is not None else 'n/a'}",
        *_verdict_lines(anchor),
    ]
    target = _evidence_text(candidate)
    return StageInput(context_lines=tuple(context), target_data=target)


def build_explain_input(candidate: Candidate, anchor: Analysis | None) -> StageInput:
    """``explain``: a long capture, to be condensed for the report (F-04-06 token discipline)."""
    context = [
        f"finding: {candidate.title}",
        f"asset: {_assets(candidate)}",
        f"check: {candidate.check_id or 'unknown'}",
        *_verdict_lines(anchor),
    ]
    return StageInput(context_lines=tuple(context), target_data=_evidence_text(candidate))


def build_remediate_input(candidate: Candidate, anchor: Analysis | None) -> StageInput:
    """``remediate``: the finding, its CWE and whatever product context the evidence carries."""
    product = _product_context(candidate)
    context = [
        f"finding: {candidate.title}",
        f"cwe: {candidate.cwe or 'unknown'}",
        f"asset kind: {candidate.asset_kind or 'unknown'}",
        f"product context: {product or 'none observed'}",
        f"existing catalog guidance: "
        f"{anchor.remediation.summary if anchor is not None else 'none'}",
    ]
    return StageInput(context_lines=tuple(context), target_data=_evidence_text(candidate))


def build_narrative_input(candidate: Candidate, anchor: Analysis | None) -> StageInput:
    """``narrative``: the finding's verdict and its remediation, for the report prose."""
    context = [
        f"finding: {candidate.title}",
        f"asset: {candidate.asset_label}",
        f"module: {candidate.check_module or 'unknown'}",
        f"cwe: {candidate.cwe or 'none'}",
        *_verdict_lines(anchor),
        f"remediation: {anchor.remediation.summary if anchor is not None else 'none'}",
    ]
    return StageInput(context_lines=tuple(context), target_data=_evidence_text(candidate))


def build_correlate_input(
    *,
    host: str,
    members: Sequence[tuple[str, str, str]],
    trigger: str,
) -> StageInput:
    """``correlate``: the members of one correlation group and why they were grouped."""
    context = [
        f"correlation trigger: {trigger}",
        f"shared host: {host}",
        f"member count: {len(members)}",
    ]
    lines = [f"- {label} — {severity}: {title}" for label, severity, title in members]
    return StageInput(
        context_lines=tuple(context),
        target_data="\n".join(lines),
        values={"members": "\n".join(lines)},
    )


def build_prioritize_input(findings: Sequence[Analysis]) -> StageInput:
    """``prioritize``: the whole finding set, for a recommended fix order."""
    context = [f"finding count: {len(findings)}", "order: worst first, then by effort"]
    lines = [
        f"- {item.asset or 'unknown'} | {item.severity} | confidence {item.confidence} | "
        f"{item.title}"
        for item in findings
    ]
    return StageInput(
        context_lines=tuple(context),
        target_data="\n".join(lines),
        values={"members": "\n".join(lines)},
    )


#: How much untrusted reasoning material one ``hypothesize`` call may see. Larger than the
#: per-candidate stages on purpose: the model is being asked about the *whole* scan so far,
#: not one finding — and still bounded, so a target cannot flood the call.
HYPOTHESIZE_MAX_TARGET_CHARS: Final = 4000

#: How many catalogue check ids are shown as the closed vocabulary a proposal may name.
_HYPOTHESIZE_CHECK_LIST: Final = 200


def build_hypothesize_input(
    *,
    scan_id: int,
    check_ids: Sequence[str],
    finding_lines: Sequence[str],
    group_lines: Sequence[str],
    covered: Sequence[str] = (),
    observations: Sequence[str] = (),
    max_hypotheses: int = 5,
) -> StageInput:
    """``hypothesize``: the scan's state, and the closed list of checks a proposal may name.

    The check list is *trusted context* (ours, from the catalogue) and the findings/groups/
    observations are *untrusted target data*. The split is the whole point: the model is told
    which ids exist before it reads anything a target influenced, so "name a check that exists"
    is a rule it can follow rather than a trap it can fall into.
    """
    vocabulary = ", ".join(sorted(check_ids)[:_HYPOTHESIZE_CHECK_LIST])
    context = [
        f"scan: {scan_id}",
        f"propose at most {max_hypotheses} hypotheses",
        f"already-run checks: {', '.join(sorted(set(covered))) or 'none'}",
        f"check ids you may name (nothing else is executable): {vocabulary}",
        "each hypothesis is one check id and one asset from the findings below",
    ]
    target = "\n".join(
        [
            *(f"finding: {line}" for line in finding_lines),
            *(f"correlation group: {line}" for line in group_lines),
            *(f"observation: {line}" for line in observations),
        ]
    )[:HYPOTHESIZE_MAX_TARGET_CHARS]
    return StageInput(context_lines=tuple(context), target_data=target)


def _product_context(candidate: Candidate) -> str:
    """Whatever product/version the evidence mentions (remediation is (cwe, product) keyed)."""
    parts: list[str] = []
    for item in candidate.evidence:
        payload = item.payload
        for key in ("service", "product", "server", "version", "banner"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                parts.append(redact_text(value)[:120])
            elif isinstance(value, Mapping):
                parts.extend(redact_text(str(entry))[:80] for entry in value.values())
    return "; ".join(dict.fromkeys(parts))[:300]
