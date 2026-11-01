"""Control-coverage scoring (S24, REQ-VALID-002/006).

The question this answers is the enterprise's hardest one: *would the defender have seen
it?* Two inputs, one verdict:

**What ARACHNE emitted** — one :class:`TechniqueEmission` per replayed action, carrying the
technique, the tactic, the run nonce and the moment it fired.

**What the defender reported** — the normalized :class:`~arachne.purple.alerts.DefenderAlert`
set, ingested from a webhook, a pull or an export.

An emission is **seen** when an alert names a matching technique *and* is linked to this
run: it carries the run's nonce and falls inside the coordinated window. Anything less is
not evidence that the defender saw *this test*:

* an alert on the technique but without this run's nonce is *unlinked* — the defender may
  well have detected unrelated traffic, and counting that as coverage would flatter the
  number (it is reported separately, which is where it belongs);
* an alert outside the window is out of window — the defender was not told to watch yet;
* an alert naming no technique is *unmatched*.

Coverage is therefore reported three ways, all from the same pass: per technique, per
tactic (the REQ-VALID-002 percentage), and as an explicit gap list.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arachne.core.target import DetectionWindow
from arachne.purple.alerts import DefenderAlert
from arachne.purple.attack import TACTIC_LABELS, normalize_technique, technique_matches

__all__ = [
    "CoveragePoint",
    "CoverageReport",
    "Emission",
    "TacticCoverage",
    "TechniqueCoverage",
    "coverage_points",
    "detect_regressions",
    "score_coverage",
]


@dataclass(frozen=True, slots=True)
class Emission:
    """One emitted test artifact: what was replayed, where, when, under which tag."""

    check_id: str
    title: str
    technique: str
    tactic: str
    severity: str
    nonce: str
    emitted_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "technique": self.technique,
            "tactic": self.tactic,
            "severity": self.severity,
            "nonce": self.nonce,
            "emitted_at": self.emitted_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Emission:
        return cls(
            check_id=str(payload["check_id"]),
            title=str(payload.get("title") or payload["check_id"]),
            technique=normalize_technique(str(payload["technique"])),
            tactic=str(payload.get("tactic") or ""),
            severity=str(payload.get("severity") or "medium"),
            nonce=str(payload["nonce"]),
            emitted_at=datetime.fromisoformat(str(payload["emitted_at"])).astimezone(UTC),
        )


def emissions_from_payloads(payloads: Iterable[Mapping[str, Any]]) -> tuple[Emission, ...]:
    """Rebuild the emissions a run recorded (the stored ``scans.stats["purple"]`` form)."""
    return tuple(Emission.from_dict(item) for item in payloads)


@dataclass(frozen=True, slots=True)
class TechniqueCoverage:
    """One emitted technique's verdict."""

    technique: str
    tactic: str
    severity: str
    actions: tuple[str, ...]
    seen: bool
    #: Alerts that named a matching technique and carried this run's nonce, inside the window.
    alert_ids: tuple[str, ...] = ()
    #: Alerts that named a matching technique but could not be linked to this run (no nonce,
    #: the wrong nonce, or outside the window).
    unlinked_alert_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "tactic": self.tactic,
            "tactic_label": TACTIC_LABELS.get(self.tactic, self.tactic or "—"),
            "severity": self.severity,
            "actions": list(self.actions),
            "seen": self.seen,
            "alerts": list(self.alert_ids),
            "unlinked_alerts": list(self.unlinked_alert_ids),
        }


@dataclass(frozen=True, slots=True)
class TacticCoverage:
    """Coverage rolled up per ATT&CK tactic — the REQ-VALID-002 percentage."""

    tactic: str
    techniques: tuple[str, ...]
    seen: tuple[str, ...]

    @property
    def total(self) -> int:
        return len(self.techniques)

    @property
    def seen_count(self) -> int:
        return len(self.seen)

    @property
    def coverage_pct(self) -> float:
        """Seen techniques as a percentage, one decimal; a tactic with no emissions is 100%.

        An empty tactic is *not* a gap: nothing was tested there, and reporting "0% of
        nothing" would drag the estate's number down for a decision nobody made.
        """
        if not self.total:
            return 100.0
        return round(100.0 * self.seen_count / self.total, 1)

    @property
    def label(self) -> str:
        return TACTIC_LABELS.get(self.tactic, self.tactic or "—")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic": self.tactic,
            "label": self.label,
            "techniques": list(self.techniques),
            "seen": list(self.seen),
            "total": self.total,
            "seen_count": self.seen_count,
            "coverage_pct": self.coverage_pct,
        }


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """The whole scoring result for one campaign run."""

    campaign: str
    nonce: str
    window: DetectionWindow | None
    scored_at: datetime
    techniques: tuple[TechniqueCoverage, ...]
    tactics: tuple[TacticCoverage, ...]
    #: Alerts the run ingested, and how each was classified.
    alerts_ingested: int = 0
    alerts_linked: int = 0
    alerts_unlinked: int = 0
    alerts_out_of_window: int = 0
    alerts_without_technique: int = 0
    #: Alerts that named a matching technique but carried a different run's nonce.
    alerts_other_run: int = 0
    #: Alerts naming an ATT&CK technique that nothing in this run emitted — the defender's
    #: other traffic. Counted so a report can say "the SIEM fired, just not for us".
    alerts_other_technique: int = 0
    #: The techniques those alerts named, deduplicated and sorted.
    other_techniques: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.techniques)

    @property
    def seen_count(self) -> int:
        return sum(1 for item in self.techniques if item.seen)

    @property
    def coverage_pct(self) -> float:
        if not self.total:
            return 100.0
        return round(100.0 * self.seen_count / self.total, 1)

    @property
    def gaps(self) -> tuple[TechniqueCoverage, ...]:
        """Techniques nothing linked detected — the explicit gap list (REQ-VALID-002)."""
        return tuple(item for item in self.techniques if not item.seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign,
            "nonce": self.nonce,
            "window": self.window.to_dict() if self.window is not None else None,
            "scored_at": self.scored_at.isoformat(),
            "coverage_pct": self.coverage_pct,
            "seen": self.seen_count,
            "total": self.total,
            "tactics": [item.to_dict() for item in self.tactics],
            "techniques": [item.to_dict() for item in self.techniques],
            "gaps": [item.to_dict() for item in self.gaps],
            # Flat id lists for the trend reader: the per-row forms above carry prose and
            # counts, which a trend point does not need and would have to re-parse.
            "technique_ids": [item.technique for item in self.techniques],
            "seen_ids": [item.technique for item in self.techniques if item.seen],
            "gap_ids": [item.technique for item in self.gaps],
            "alerts": {
                "ingested": self.alerts_ingested,
                "linked": self.alerts_linked,
                "unlinked": self.alerts_unlinked,
                "out_of_window": self.alerts_out_of_window,
                "without_technique": self.alerts_without_technique,
                "other_run": self.alerts_other_run,
                "other_technique": self.alerts_other_technique,
            },
            "other_techniques": list(self.other_techniques),
            "notes": list(self.notes),
        }


def score_coverage(
    emissions: Sequence[Emission],
    alerts: Sequence[DefenderAlert],
    *,
    campaign: str,
    nonce: str,
    window: DetectionWindow | None,
    now: datetime | None = None,
    extra_notes: Iterable[str] = (),
) -> CoverageReport:
    """Score emitted techniques against defender alerts.

    Deterministic: same inputs, same report. Unlinked, out-of-window and techniqueless
    alerts are counted, never discarded — "the SIEM fired 40 times and none of it was our
    test" is the most useful sentence in a purple-team report.
    """
    notes: list[str] = list(extra_notes)
    linked: dict[str, list[str]] = {}
    unlinked: dict[str, list[str]] = {}
    out_of_window = 0
    other_run = 0
    without_technique = 0
    other_techniques: list[str] = []

    for alert in alerts:
        if alert.technique is None:
            without_technique += 1
            continue
        in_window = window is None or window.contains(alert.observed_at)
        if not in_window:
            out_of_window += 1
        matched = [item for item in emissions if technique_matches(item.technique, alert.technique)]
        if not matched:
            # A technique nobody emitted: the defender's other traffic, not our test. It is
            # not coverage of anything we ran, and it is still worth stating.
            other_techniques.append(alert.technique)
            continue
        if alert.nonce is not None and alert.nonce != nonce:
            other_run += 1
        is_link = alert.nonce == nonce and in_window
        for item in matched:
            bucket = linked if is_link else unlinked
            bucket.setdefault(item.technique, []).append(alert.alert_id)

    by_technique: dict[str, dict[str, Any]] = {}
    for item in emissions:
        entry = by_technique.setdefault(
            item.technique,
            {
                "tactic": item.tactic,
                "severity": item.severity,
                "actions": [],
                "alert_ids": [],
                "unlinked": [],
            },
        )
        if item.check_id not in entry["actions"]:
            entry["actions"].append(item.check_id)
    for technique, ids in linked.items():
        if technique in by_technique:
            by_technique[technique]["alert_ids"].extend(sorted(set(ids)))
    for technique, ids in unlinked.items():
        if technique in by_technique:
            by_technique[technique]["unlinked"].extend(sorted(set(ids)))

    # A technique may also be named by an alert that matched *another* emitted technique's
    # family (parent/sub-technique): the per-emission rule above already handled it, so the
    # table is complete here.
    coverage = tuple(
        TechniqueCoverage(
            technique=technique,
            tactic=str(entry["tactic"]),
            severity=str(entry["severity"]),
            actions=tuple(entry["actions"]),
            seen=bool(entry["alert_ids"]),
            alert_ids=tuple(entry["alert_ids"]),
            unlinked_alert_ids=tuple(entry["unlinked"]),
        )
        for technique, entry in sorted(by_technique.items())
    )

    tactics: list[TacticCoverage] = []
    for tactic in sorted({item.tactic for item in coverage}):
        members = tuple(item for item in coverage if item.tactic == tactic)
        tactics.append(
            TacticCoverage(
                tactic=tactic,
                techniques=tuple(item.technique for item in members),
                seen=tuple(item.technique for item in members if item.seen),
            )
        )

    if out_of_window:
        notes.append(
            f"{out_of_window} alert(s) fell outside the coordinated window and were not "
            "counted as coverage"
        )
    if other_run:
        notes.append(f"{other_run} alert(s) carried a different run's nonce")
    if without_technique:
        notes.append(f"{without_technique} alert(s) named no ATT&CK technique")
    if other_techniques:
        notes.append(
            "the defender reported techniques this run did not emit: "
            + ", ".join(sorted(set(other_techniques)))
        )
    gaps = [item.technique for item in coverage if not item.seen]
    if gaps:
        notes.append(f"unseen techniques: {', '.join(gaps)}")

    linked_count = sum(len(item.alert_ids) for item in coverage)
    return CoverageReport(
        campaign=campaign,
        nonce=nonce,
        window=window,
        scored_at=(now or datetime.now(UTC)).astimezone(UTC),
        techniques=coverage,
        tactics=tuple(tactics),
        alerts_ingested=len(alerts),
        alerts_linked=linked_count,
        alerts_unlinked=sum(len(item.unlinked_alert_ids) for item in coverage),
        alerts_out_of_window=out_of_window,
        alerts_without_technique=without_technique,
        alerts_other_run=other_run,
        alerts_other_technique=len(other_techniques),
        other_techniques=tuple(sorted(set(other_techniques))),
        notes=tuple(notes),
    )


@dataclass(frozen=True, slots=True)
class CoveragePoint:
    """One campaign run's coverage, as the trend reads it back from the store."""

    run_id: int
    scan_id: int | None
    started_at: datetime
    coverage_pct: float
    seen: tuple[str, ...]
    total: tuple[str, ...]
    gaps: tuple[str, ...] = ()

    @property
    def unseen_count(self) -> int:
        return len(self.gaps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "coverage_pct": self.coverage_pct,
            "seen": list(self.seen),
            "total": list(self.total),
            "gaps": list(self.gaps),
        }


def coverage_points(payloads: Iterable[Mapping[str, Any]]) -> tuple[CoveragePoint, ...]:
    """Rebuild the trend from stored run summaries, oldest first."""
    points: list[CoveragePoint] = []
    for payload in payloads:
        coverage = payload.get("coverage") or {}
        points.append(
            CoveragePoint(
                run_id=int(payload["run_id"]),
                scan_id=payload.get("scan_id"),
                started_at=datetime.fromisoformat(str(payload["started_at"])).astimezone(UTC),
                coverage_pct=float(coverage.get("coverage_pct", 0.0)),
                seen=tuple(str(item) for item in coverage.get("seen_ids") or ()),
                total=tuple(str(item) for item in coverage.get("technique_ids") or ()),
                gaps=tuple(str(item) for item in coverage.get("gap_ids") or ()),
            )
        )
    points.sort(key=lambda item: (item.started_at, item.run_id))
    return tuple(points)


def detect_regressions(
    previous: CoveragePoint | None, current: CoveragePoint
) -> tuple[str, ...]:
    """Techniques seen in ``previous`` and unseen in ``current`` (REQ-VALID-006).

    The regression alert is deliberately narrow: only a technique that was *seen* before
    and is *not seen* now counts. A technique that was never seen cannot regress, and one
    that is newly seen is an improvement — it belongs in the trend, not in an alert.
    """
    if previous is None:
        return ()
    return tuple(sorted(set(previous.seen) & set(current.gaps)))
