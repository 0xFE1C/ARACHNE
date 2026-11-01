"""Executive-summary synthesis — the heuristic engine's report voice (06- §3 section 2).

The executive summary is not a second analysis; it is a *reading* of the report the analysis
already produced. This module writes it without a model, from the same three inputs an
analyst would use:

* the **counts** (severity histogram of confirmed findings, and the low-confidence count),
* the **headline findings** (worst severity, then confidence, then id — a stable order),
* the **priority order** (the distinct remediations behind the headline findings).

The prose comes from managed data (``templates/report/executive-summary.yaml``) and is
interpolated with a hand-written ``{path}`` scanner — never ``str.format``/``eval`` — for the
same reason :mod:`arachne.analyzer.narrative` does it: a template must not be able to reach
into an object graph, and an unresolvable reference must drop a paragraph rather than raise.
A paragraph with ``when:`` is gated on a boolean the renderer computes, so "no findings" and
"three critical findings" read differently without the weaker sentence lying.

The section always carries the counts table (as data on
:class:`~arachne.report.model.ExecutiveSummary`), which is what the report QA gate compares
against the findings tables.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Final

import yaml
from pydantic import BaseModel, ConfigDict, Field

from arachne.analyzer.model import severity_rank
from arachne.core.errors import ConfigurationError
from arachne.report.model import (
    ExecutiveSummary,
    Provenance,
    ReportFinding,
    SeverityCounts,
)

__all__ = [
    "DEFAULT_SUMMARY_RESOURCE",
    "SummaryTemplate",
    "SummaryTemplateSet",
    "build_executive_summary",
    "load_summary_templates",
    "render_paragraphs",
]

DEFAULT_SUMMARY_RESOURCE: Final = ("report", "executive-summary.yaml")

_REFERENCE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.\-]*)\}")
_MODEL = ConfigDict(frozen=True, extra="forbid")


class SummaryTemplate(BaseModel):
    """One paragraph of the executive summary."""

    model_config = _MODEL

    id: str = Field(min_length=2, max_length=64)
    text: str = Field(min_length=1)
    when: str | None = None


class SummaryTemplateSet(BaseModel):
    """The executive-summary corpus."""

    model_config = _MODEL

    version: str = Field(min_length=1, max_length=32)
    paragraphs: tuple[SummaryTemplate, ...] = Field(min_length=1)


def load_summary_templates(path: str | None = None) -> SummaryTemplateSet:
    """Load the summary templates from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"executive-summary template {resolved} does not exist"
            raise ConfigurationError(msg)
        text = resolved.read_text(encoding="utf-8")
        return _parse(text, source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_SUMMARY_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled executive-summary template is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return _parse(text, source="/".join(DEFAULT_SUMMARY_RESOURCE))


def _parse(text: str, *, source: str) -> SummaryTemplateSet:
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{source}: expected a mapping")
    try:
        return SummaryTemplateSet.model_validate(data)
    except Exception as exc:  # pydantic's ValidationError
        raise ConfigurationError(f"{source}: invalid summary templates: {exc}") from exc


def _human_duration(seconds: float | None) -> str:
    if seconds is None or seconds <= 0:
        return "an unknown duration"
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f} minutes"
    return f"{minutes / 60:.1f} hours"


def _posture(counts: SeverityCounts, low_confidence: int) -> str:
    if counts.critical:
        return "critical"
    if counts.high:
        return "elevated"
    if counts.medium:
        return "moderate"
    if counts.low or counts.info or low_confidence:
        return "low"
    return "clean (no confirmed findings)"


def _counts_summary(counts: SeverityCounts) -> str:
    parts = [f"{count} {label.lower()}" for label, count in counts.as_rows() if count]
    return ", ".join(parts) if parts else "none"


def _headline_order(findings: Sequence[ReportFinding]) -> tuple[ReportFinding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                -severity_rank(item.severity),
                -item.score.confidence,
                item.id,
            ),
        )
    )


def _finding_label(finding: ReportFinding) -> str:
    classification = f" ({finding.classification.cwe})" if finding.classification.cwe else ""
    return f"{finding.id} · {finding.title}{classification} on {finding.asset.value}"


def _priority_order(findings: Sequence[ReportFinding]) -> tuple[str, ...]:
    """Distinct remediation summaries, in headline order, at most three."""
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in _headline_order(findings):
        summary = finding.remediation.summary.strip()
        if not summary or summary in seen:
            continue
        seen.add(summary)
        ordered.append(summary)
        if len(ordered) == 3:
            break
    return tuple(ordered)


@dataclass(frozen=True, slots=True)
class _Namespace:
    values: Mapping[str, str]

    def resolve(self, path: str) -> str | None:
        value = self.values.get(path)
        return value if value else None


def _interpolate(text: str, namespace: _Namespace) -> str | None:
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
    return re.sub(r"\s+", " ", rendered).strip()


def render_paragraphs(
    templates: SummaryTemplateSet,
    *,
    values: Mapping[str, str],
    flags: Mapping[str, bool],
) -> tuple[str, ...]:
    """Render the paragraphs whose ``when`` holds and whose references resolve."""
    namespace = _Namespace(values)
    paragraphs: list[str] = []
    for template in templates.paragraphs:
        if template.when is not None and not flags.get(template.when, False):
            continue
        rendered = _interpolate(template.text, namespace)
        if rendered:
            paragraphs.append(rendered)
    return tuple(paragraphs)


def build_executive_summary(
    *,
    findings: Sequence[ReportFinding],
    low_confidence: Sequence[ReportFinding],
    counts: SeverityCounts,
    threshold: int,
    asset_count: int,
    host_count: int,
    url_count: int,
    modules: Sequence[str],
    duration_seconds: float | None,
    engine: str = "heuristic",
    templates: SummaryTemplateSet | None = None,
    diff_counts: Mapping[str, int] | None = None,
    compared_scan: str | None = None,
) -> ExecutiveSummary:
    """Synthesise the executive section from the report's own data."""
    corpus = templates or load_summary_templates()
    headline = _headline_order(findings)
    priority = _priority_order(findings)
    headline_ids = tuple(item.id for item in headline[:3])
    posture = _posture(counts, len(low_confidence))

    values: dict[str, str] = {
        "asset.count": str(asset_count),
        "host.count": str(host_count),
        "url.count": str(url_count),
        "modules.list": ", ".join(modules) if modules else "no modules",
        "duration.human": _human_duration(duration_seconds),
        "posture": posture,
        "findings.count": str(len(findings)),
        "counts.summary": _counts_summary(counts),
        "low_confidence.count": str(len(low_confidence)),
        "threshold": str(threshold),
        "engine": engine,
        "template.version": corpus.version,
        "headline.list": "; ".join(_finding_label(item) for item in headline[:3]),
        "priority.list": "; ".join(priority),
    }
    if headline:
        first = headline[0]
        values["headline.first"] = _finding_label(first)
        values["headline.first.severity"] = first.severity
        values["headline.first.confidence"] = str(first.score.confidence)

    flags = {
        "has_findings": bool(findings),
        "no_findings": not findings,
        "has_headlines": bool(headline),
        "has_priority": bool(priority),
        "has_low_confidence": bool(low_confidence),
        "has_trend": diff_counts is not None and compared_scan is not None,
    }
    if diff_counts is not None and compared_scan is not None:
        values["trend.compared_scan"] = compared_scan
        values["trend.new"] = str(diff_counts.get("new", 0))
        values["trend.fixed"] = str(diff_counts.get("fixed", 0))
        values["trend.regressed"] = str(diff_counts.get("regressed", 0))
        values["trend.recurring"] = str(diff_counts.get("recurring", 0))

    return ExecutiveSummary(
        posture=posture,
        paragraphs=render_paragraphs(corpus, values=values, flags=flags),
        counts=counts,
        low_confidence_count=len(low_confidence),
        headline_finding_ids=headline_ids,
        priority_order=priority,
        provenance=Provenance(
            engine=engine,
            template_version=corpus.version,
            analysis_log_id=None,
        ),
        synthesized=True,
    )
