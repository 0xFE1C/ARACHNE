"""The defender report: detection gaps joined to attack paths (S24, REQ-VALID-005).

Two halves of one sentence — *what an attacker could do unseen*:

**What the defender missed.** The control-coverage gaps (techniques ARACHNE replayed
inside the coordinated window that nothing reported) and the Sigma rule-misses (techniques
the shipped hunt library has no rule for).

**What that would mean.** The attack paths (S21) composed from the scan's own verified
findings, each hop annotated with the technique its check exercises and whether that
technique is *known-unseen*, *seen*, *untested* or *unmapped*. A path counts as unseen
only when a hop's technique is **known** to be unseen — an untested or unmapped hop is
reported as such, because "we did not test it" is not the same claim as "they cannot see
it", and a defender report that blurs the two is worse than no report.

Rendering is deterministic (no clock reads, no set iteration) because the golden-file test
compares the markdown byte for byte.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from arachne.analyzer.paths import AttackPath
from arachne.purple.attack import TACTIC_LABELS, TechniqueMap
from arachne.purple.coverage import CoverageReport
from arachne.purple.sigma import RuleAlignment

__all__ = ["DefenderReport", "HopDetection", "PathDetection", "build_defender_report"]

#: How a path hop's technique stands against what the defender was shown.
SEEN = "seen"
UNSEEN = "unseen"
UNTESTED = "untested"
UNMAPPED = "unmapped"


@dataclass(frozen=True, slots=True)
class HopDetection:
    """One attack-path hop, with the detection verdict for the technique it exercises."""

    check_id: str
    stage: str
    description: str
    technique: str | None
    status: str
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "stage": self.stage,
            "description": self.description,
            "technique": self.technique,
            "status": self.status,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class PathDetection:
    """One attack path annotated for the defender."""

    path_id: str
    asset: str
    severity: str
    narrative: str
    hops: tuple[HopDetection, ...] = ()
    #: Techniques on this path that the defender is *known* not to see.
    unseen: tuple[str, ...] = ()
    seen: tuple[str, ...] = ()
    #: Techniques on this path nothing tested (not in the campaign) or that no ATT&CK
    #: technique is mapped to. Reported distinctly: they are not evidence of blindness.
    untested: tuple[str, ...] = ()
    unmapped: tuple[str, ...] = ()
    cheapest_reason: str = ""

    @property
    def is_unseen(self) -> bool:
        return bool(self.unseen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "asset": self.asset,
            "severity": self.severity,
            "narrative": self.narrative,
            "hops": [hop.to_dict() for hop in self.hops],
            "unseen": list(self.unseen),
            "seen": list(self.seen),
            "untested": list(self.untested),
            "unmapped": list(self.unmapped),
            "cheapest_break": self.cheapest_reason,
            "is_unseen": self.is_unseen,
        }


@dataclass(frozen=True, slots=True)
class DefenderReport:
    """The purple-team report: coverage, Sigma alignment and unseen attack paths."""

    campaign: str
    generated_at: datetime
    run_id: int | None
    scan_id: int | None
    nonce: str
    window: dict[str, Any] = field(default_factory=dict)
    coverage: CoverageReport | None = None
    sigma: tuple[RuleAlignment, ...] = ()
    paths: tuple[PathDetection, ...] = ()
    alerts_ingested: int = 0
    notes: tuple[str, ...] = ()

    @property
    def unseen_paths(self) -> tuple[PathDetection, ...]:
        return tuple(path for path in self.paths if path.is_unseen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign,
            "generated_at": self.generated_at.isoformat(),
            "run_id": self.run_id,
            "scan_id": self.scan_id,
            "nonce": self.nonce,
            "window": dict(self.window),
            "coverage": self.coverage.to_dict() if self.coverage is not None else None,
            "sigma": [item.to_dict() for item in self.sigma],
            "paths": [item.to_dict() for item in self.paths],
            "unseen_paths": [item.path_id for item in self.unseen_paths],
            "alerts_ingested": self.alerts_ingested,
            "notes": list(self.notes),
        }

    # ------------------------------------------------------------------ rendering
    def render_markdown(self) -> str:
        """The defender-facing markdown (the golden-file target)."""
        lines: list[str] = []
        lines.append(f"# Defender report — {self.campaign}")
        lines.append("")
        lines.append(
            f"Generated {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')} · "
            f"run #{self.run_id if self.run_id is not None else '—'} · "
            f"scan {self.scan_id if self.scan_id is not None else '—'}"
        )
        lines.append("")
        lines.append(f"- Run nonce: `{self.nonce}`")
        if self.window:
            lines.append(
                f"- Detection window: {self.window.get('starts_at', '—')} .. "
                f"{self.window.get('ends_at', '—')} "
                f"(coordinated with {self.window.get('coordinator', '—')})"
            )
        else:
            lines.append("- Detection window: _none recorded_")
        lines.append("")

        lines.extend(self._coverage_lines())
        lines.extend(self._sigma_lines())
        lines.extend(self._paths_lines())
        lines.extend(self._alerts_lines())
        if self.notes:
            lines.append("## Notes")
            lines.append("")
            for note in self.notes:
                lines.append(f"- {note}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _coverage_lines(self) -> list[str]:
        lines: list[str] = ["## 1. Control coverage", ""]
        report = self.coverage
        if report is None:
            lines.append("_No coverage was scored for this run._")
            lines.append("")
            return lines
        lines.append(
            f"**{report.seen_count} of {report.total} technique(s) seen "
            f"({report.coverage_pct:.1f}%)** — an emission counts as seen only when an "
            "alert carries this run's nonce inside the detection window."
        )
        lines.append("")
        lines.append("| Tactic | Techniques | Seen | Coverage |")
        lines.append("|---|---|---|---|")
        for tactic in report.tactics:
            lines.append(
                f"| {tactic.label} | {tactic.total} | {tactic.seen_count} "
                f"| {tactic.coverage_pct:.1f}% |"
            )
        lines.append("")
        lines.append("### Coverage gaps")
        lines.append("")
        gaps = report.gaps
        if not gaps:
            lines.append("_Every replayable technique was seen._")
            lines.append("")
            return lines
        lines.append("| Technique | Tactic | Severity | Action | Unlinked alerts |")
        lines.append("|---|---|---|---|---|")
        for gap in gaps:
            lines.append(
                f"| {gap.technique} | {TACTIC_LABELS.get(gap.tactic, gap.tactic)} "
                f"| {gap.severity} | {', '.join(gap.actions)} "
                f"| {len(gap.unlinked_alert_ids)} |"
            )
        lines.append("")
        return lines

    def _sigma_lines(self) -> list[str]:
        lines: list[str] = ["## 2. Sigma alignment (M6 hunt library)", ""]
        if not self.sigma:
            lines.append("_No actions were aligned._")
            lines.append("")
            return lines
        lines.append("| Action | Technique(s) | Verdict | Matching rules |")
        lines.append("|---|---|---|---|")
        for item in self.sigma:
            matched = (
                ", ".join(f"{title} ({level})" for _, title, level, _ in item.hits) or "none"
            )
            lines.append(
                f"| {item.check_id} | {', '.join(item.techniques)} | {item.verdict} "
                f"| {matched} |"
            )
        lines.append("")
        misses = [item for item in self.sigma if not item.matched]
        if misses:
            listed = ", ".join(f"{item.check_id} ({', '.join(item.techniques)})" for item in misses)
            lines.append(
                f"Rule-miss: the shipped hunt library has no rule matching the telemetry of "
                f"{listed}. A rule-miss is a gap in the rule set, not a failure of the test."
            )
            lines.append("")
        return lines

    def _paths_lines(self) -> list[str]:
        lines: list[str] = ["## 3. What an attacker could do unseen", ""]
        if not self.paths:
            lines.append("_No multi-hop attack paths were composed for this run._")
            lines.append("")
            return lines
        unseen = self.unseen_paths
        if not unseen:
            lines.append(
                "Every composed attack path crosses at least one technique the defender "
                "reported seeing. No unseen path was found in this run."
            )
            lines.append("")
        for path in unseen:
            lines.append(f"### {path.path_id} — {path.asset} (terminal impact: {path.severity})")
            lines.append("")
            lines.append(path.narrative)
            lines.append("")
            for hop in path.hops:
                technique = hop.technique or "—"
                lines.append(
                    f"- {hop.stage}: `{hop.check_id}` {hop.description} — "
                    f"{technique} ({hop.status})"
                )
            if path.cheapest_reason:
                lines.append(f"- Cheapest break: {path.cheapest_reason}")
            lines.append("")
        rest = [path for path in self.paths if not path.is_unseen]
        if rest:
            lines.append("### Other composed paths")
            lines.append("")
            lines.append("| Path | Asset | Terminal impact | Unseen | Untested | Unmapped |")
            lines.append("|---|---|---|---|---|---|")
            for path in rest:
                lines.append(
                    f"| {path.path_id} | {path.asset} | {path.severity} "
                    f"| {len(path.unseen)} | {len(path.untested)} | {len(path.unmapped)} |"
                )
            lines.append("")
        return lines

    def _alerts_lines(self) -> list[str]:
        lines: list[str] = ["## 4. Defender alerts", ""]
        report = self.coverage
        if report is None:
            lines.append("_No alerts were scored._")
            lines.append("")
            return lines
        lines.append(
            f"- {report.alerts_ingested} ingested · {report.alerts_linked} linked to this run "
            f"· {report.alerts_unlinked} named a technique without this run's nonce "
            f"· {report.alerts_out_of_window} outside the window "
            f"· {report.alerts_without_technique} without a technique "
            f"· {report.alerts_other_technique} for other techniques"
        )
        if report.other_techniques:
            lines.append(
                f"- The defender reported techniques this run did not emit: "
                f"{', '.join(report.other_techniques)}"
            )
        lines.append("")
        return lines


def _hop_status(
    technique: str | None,
    *,
    gaps: frozenset[str],
    seen: frozenset[str],
) -> str:
    if technique is None:
        return UNMAPPED
    if technique in gaps:
        return UNSEEN
    if technique in seen:
        return SEEN
    return UNTESTED


def build_defender_report(
    *,
    campaign: str,
    run: Any,
    coverage: CoverageReport | None,
    sigma: Sequence[RuleAlignment],
    attack_paths: Sequence[AttackPath],
    technique_map: TechniqueMap,
    generated_at: datetime,
) -> DefenderReport:
    """Compose the defender report from a stored run and the scan's attack paths.

    ``run`` is the stored :class:`~arachne.data.purple_store.RunRecord`; ``attack_paths``
    are the S21 paths composed from the same scan's findings. A hop whose check is in the
    technique map is annotated with its technique; a hop whose check is not is ``unmapped``.
    """
    report = coverage
    gaps = frozenset(item.technique for item in report.gaps) if report is not None else frozenset()
    seen = (
        frozenset(item.technique for item in report.techniques if item.seen)
        if report is not None
        else frozenset()
    )
    paths: list[PathDetection] = []
    for path in attack_paths:
        hops: list[HopDetection] = []
        unseen: list[str] = []
        saw: list[str] = []
        untested: list[str] = []
        unmapped: list[str] = []
        for hop in path.hops:
            action = technique_map.get(hop.check_id)
            technique = action.techniques[0] if action is not None else None
            status = _hop_status(technique, gaps=gaps, seen=seen)
            if status == UNSEEN and technique is not None:
                unseen.append(technique)
            elif status == SEEN and technique is not None:
                saw.append(technique)
            elif status == UNTESTED and technique is not None:
                untested.append(technique)
            elif status == UNMAPPED:
                unmapped.append(hop.check_id)
            hops.append(
                HopDetection(
                    check_id=hop.check_id,
                    stage=str(getattr(hop.stage, "value", hop.stage)),
                    description=hop.title,
                    technique=technique,
                    status=status,
                    verified=bool(hop.verified),
                )
            )
        paths.append(
            PathDetection(
                path_id=path.id,
                asset=path.asset,
                severity=path.business_severity or path.severity,
                narrative=path.narrative(),
                hops=tuple(hops),
                unseen=tuple(dict.fromkeys(unseen)),
                seen=tuple(dict.fromkeys(saw)),
                untested=tuple(dict.fromkeys(untested)),
                unmapped=tuple(dict.fromkeys(unmapped)),
                cheapest_reason=path.cheapest_reason,
            )
        )
    notes = list(report.notes) if report is not None else []
    return DefenderReport(
        campaign=campaign,
        generated_at=generated_at,
        run_id=getattr(run, "id", None),
        scan_id=getattr(run, "scan_id", None),
        nonce=str(getattr(run, "nonce", "")),
        window=dict(getattr(run, "window", None) or {}),
        coverage=report,
        sigma=tuple(sigma),
        paths=tuple(paths),
        alerts_ingested=report.alerts_ingested if report is not None else 0,
        notes=tuple(notes),
    )


def alignments_from_run(run: Any) -> tuple[RuleAlignment, ...]:
    """Rebuild the Sigma alignment recorded with a stored run."""
    rebuilt: list[RuleAlignment] = []
    for item in getattr(run, "sigma", None) or ():
        payload: Mapping[str, Any] = item
        hits = tuple(
            (
                str(entry.get("rule_id", "")),
                str(entry.get("title", "")),
                str(entry.get("level", "")),
                tuple(str(tag) for tag in entry.get("techniques") or ()),
            )
            for entry in payload.get("hits") or ()
        )
        event = payload.get("event") or {}
        rebuilt.append(
            RuleAlignment(
                check_id=str(payload.get("check_id", "")),
                techniques=tuple(str(item) for item in payload.get("techniques") or ()),
                event_summary=str(event.get("summary", "")),
                logsource={str(k): str(v) for k, v in (event.get("logsource") or {}).items()},
                fields=dict(event.get("fields") or {}),
                hits=hits,
                rule_count=int(payload.get("rules_evaluated") or 0),
            )
        )
    return tuple(rebuilt)
