"""The CI delivery-surface document producer (S26, REQ-ECOS-003).

A CI gate is only useful if its verdict lands where a reviewer reads it: on the pull
request. This module is the pure, deterministic half of that — it turns a list of findings
into the three review artefacts a forge understands, and it is deliberately **pure**: no
filesystem, no network, no subprocess, no clock. Everything it prints is a function of its
arguments, so a test can pin the exact bytes, and the DB-backed runner
(:mod:`arachne.tools.ci_annotate`) decides *what* the findings are.

Three artefacts, three audiences:

* **GitHub workflow commands** (``::error`` / ``::warning`` / ``::notice``) — the lines
  GitHub turns into annotations on the diff. They are emitted at or above a
  ``severity_threshold`` (default ``high``) so a review is not drowned in ``info`` notes,
  and capped at ``max_annotations`` because GitHub silently drops annotations past a
  per-step limit (10 warning/error annotations per step, plus a cheaper per-run budget) —
  the cap makes the truncation *ours*, ordered worst-first, instead of GitHub's.
* **GitLab Code Quality JSON** — the ``codequality`` artifact GitLab renders in the merge
  request widget: one object per finding with a stable ``fingerprint`` so the same finding
  is the same issue across pipelines.
* **SARIF** — a thin passthrough to :func:`arachne.report.sarif.render_sarif`, so the tree
  keeps exactly one SARIF implementation (the Code Scanning importer also does real
  deduplication, so it is the better path when the forge supports it).

The gate's *verdict* (0/1/2 and the counts block) is not re-implemented here either: the
policy lives in :mod:`arachne.cli.ci` and this module only re-exports it under the names the
delivery surface uses.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from arachne.cli.ci import SEVERITY_LEVELS, gate_summary, parse_threshold
from arachne.report.model import ReportData, ReportFinding
from arachne.report.sarif import render_sarif

__all__ = [
    "DEFAULT_MAX_ANNOTATIONS",
    "DEFAULT_SEVERITY_THRESHOLD",
    "GITLAB_SEVERITIES",
    "GateFinding",
    "annotation_lines",
    "code_quality_issues",
    "findings_from_report",
    "fingerprint",
    "github_annotations",
    "gitlab_code_quality",
    "render_github_annotations",
    "render_gitlab_code_quality",
    "sarif_report",
    "severity_counts",
    "summary",
]

#: Annotations are emitted at or above this severity unless the caller says otherwise.
DEFAULT_SEVERITY_THRESHOLD: Final = "high"

#: Cap on emitted annotations (the worst findings, worst-first). GitHub drops annotations
#: past its own per-step budget; capping deterministically makes the loss explicit.
DEFAULT_MAX_ANNOTATIONS: Final = 50

#: ARACHNE's severity ladder → the GitHub workflow-command level it maps onto.
_LEVELS: Final[dict[str, str]] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}

#: ARACHNE's severity ladder → GitLab Code Quality's documented severity vocabulary
#: (``info``/``minor``/``major``/``critical``/``blocker``). The mapping is monotone: a
#: more severe ARACHNE finding is never a *less* severe GitLab row.
GITLAB_SEVERITIES: Final[dict[str, str]] = {
    "info": "info",
    "low": "minor",
    "medium": "major",
    "high": "critical",
    "critical": "blocker",
}


@dataclass(frozen=True, slots=True)
class GateFinding:
    """One finding as a review surface needs it — the plainest possible input.

    ``path`` is the file the annotation points at (a repo-relative path where the scanner
    learned one) and ``line``/``column`` are 1-based. ARACHNE's findings are about
    artefacts, so a scanner that has no honest line reports ``1``: a real, reviewable
    anchor that does not pretend to a source line the scanner never saw.
    """

    check_id: str
    title: str
    severity: str
    path: str
    line: int = 1
    column: int = 1
    description: str = ""


def _rank(severity: str) -> int:
    """Severity ladder position (``info`` 0 … ``critical`` 4); unknown sorts last."""
    try:
        return SEVERITY_LEVELS.index(severity.strip().lower())
    except ValueError:
        return len(SEVERITY_LEVELS)


def _normalized(findings: Iterable[GateFinding]) -> list[GateFinding]:
    """Findings in a deterministic worst-first order (severity, path, line, check, title)."""
    return sorted(
        findings,
        key=lambda item: (
            -_rank(item.severity),
            item.path,
            item.line,
            item.column,
            item.check_id,
            item.title,
        ),
    )


def _selected(findings: Iterable[GateFinding], threshold: str) -> list[GateFinding]:
    """Findings at or above ``threshold``, worst-first (``none`` disables the filter)."""
    ordered = _normalized(findings)
    if threshold == "none":
        return ordered
    floor = SEVERITY_LEVELS.index(threshold)
    return [item for item in ordered if _rank(item.severity) >= floor]


def severity_counts(findings: Iterable[GateFinding]) -> dict[str, int]:
    """``{severity: count}`` over ``findings`` — the input :func:`summary` wants."""
    counts = dict.fromkeys(SEVERITY_LEVELS, 0)
    for item in findings:
        severity = item.severity.strip().lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def summary(counts: Mapping[str, int], threshold: str) -> dict[str, object]:
    """The machine-readable gate block — re-exported from :mod:`arachne.cli.ci`."""
    return gate_summary(counts, threshold)


def fingerprint(check_id: str, asset: str) -> str:
    """The stable GitLab Code Quality fingerprint (sha256 of ``check_id`` + ``asset``).

    The check id is length-prefixed so the two parts cannot be re-split ambiguously
    ("a:b"+"c" and "a"+"b:c" must not collide, and neither may any other pair whose
    concatenation lands on the same bytes). The same check on the same asset is therefore
    the same issue across pipelines, while a different rule or file is a different one.
    """
    return hashlib.sha256(f"{len(check_id)}:{check_id}:{asset}".encode()).hexdigest()


# ------------------------------------------------------------------ GitHub workflow commands
def _escape_data(value: str) -> str:
    """Escape a workflow-command *message* (``%``, CR, LF — GitHub's data rules)."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    """Escape a workflow-command *property* value (data rules plus ``:`` and ``,``)."""
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _annotation(item: GateFinding) -> str:
    level = _LEVELS.get(item.severity.strip().lower(), "warning")
    message = item.title
    if item.description and item.description != item.title:
        message = f"{item.title}: {item.description}"
    return (
        f"::{level} file={_escape_property(item.path)},"
        f"line={item.line},col={item.column}::{_escape_data(message)}"
    )


def annotation_lines(
    findings: Iterable[GateFinding],
    *,
    severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD,
    max_annotations: int = DEFAULT_MAX_ANNOTATIONS,
) -> tuple[str, ...]:
    """The GitHub annotation lines for ``findings``, worst-first and deterministic.

    Only findings at or above ``severity_threshold`` are annotated, and at most
    ``max_annotations`` lines are produced (GitHub truncates silently past its own limit;
    the worst-first order means what survives is what a reviewer most needs).
    """
    threshold = parse_threshold(severity_threshold)
    selected = _selected(findings, threshold)
    cap = max(0, int(max_annotations))
    return tuple(_annotation(item) for item in selected[:cap])


def render_github_annotations(
    findings: Iterable[GateFinding],
    *,
    severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD,
    max_annotations: int = DEFAULT_MAX_ANNOTATIONS,
) -> str:
    """The annotation stream, newline-terminated (empty string when nothing qualifies)."""
    lines = annotation_lines(
        findings,
        severity_threshold=severity_threshold,
        max_annotations=max_annotations,
    )
    return "".join(f"{line}\n" for line in lines)


# Alias kept for callers that prefer the noun form.
github_annotations = render_github_annotations


# ------------------------------------------------------------------ GitLab Code Quality JSON
def code_quality_issues(
    findings: Iterable[GateFinding], *, threshold: str = "none"
) -> list[dict[str, Any]]:
    """The GitLab Code Quality array for ``findings`` (all of them by default).

    GitLab renders the whole report rather than a thresholded subset, so no severity filter
    is applied unless one is asked for; the rows are worst-first and byte-deterministic.
    """
    ordered = tuple(findings)
    selected = _normalized(ordered)
    if threshold != "none":
        selected = _selected(ordered, parse_threshold(threshold))
    issues: list[dict[str, Any]] = []
    for item in selected:
        description = item.title
        if item.description and item.description != item.title:
            description = f"{item.title}: {item.description}"
        issues.append(
            {
                "description": description,
                "check_name": item.check_id,
                "fingerprint": fingerprint(item.check_id, item.path),
                "severity": GITLAB_SEVERITIES.get(item.severity.strip().lower(), "info"),
                "location": {"path": item.path, "lines": {"begin": max(1, item.line)}},
            }
        )
    return issues


def render_gitlab_code_quality(findings: Iterable[GateFinding], *, threshold: str = "none") -> str:
    """The GitLab Code Quality document as deterministic, indented JSON."""
    issues = code_quality_issues(findings, threshold=threshold)
    return json.dumps(issues, indent=2, ensure_ascii=False) + "\n"


# Alias kept for callers that prefer the noun form.
gitlab_code_quality = render_gitlab_code_quality


# ------------------------------------------------------------------ SARIF (passthrough)
def sarif_report(report: ReportData) -> str:
    """Render ``report`` as SARIF via the report package's one emitter."""
    return render_sarif(report)


# ------------------------------------------------------------------ report → findings
def findings_from_report(report: ReportData) -> tuple[GateFinding, ...]:
    """Adapt a :class:`~arachne.report.model.ReportData`'s findings to :class:`GateFinding`.

    The asset value is the best file/anchoring identity a report carries (a report has no
    notion of a source line), so it is the ``path`` and the region is the constant 1:1 —
    the same honest choice the SARIF emitter makes.
    """
    return tuple(_from_report_finding(finding) for finding in report.findings)


def _from_report_finding(finding: ReportFinding) -> GateFinding:
    return GateFinding(
        check_id=finding.check_id,
        title=finding.title,
        severity=finding.severity,
        path=finding.asset.value or finding.asset.kind,
        line=1,
        column=1,
        description=finding.description,
    )
