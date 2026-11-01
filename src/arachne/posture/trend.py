"""The estate posture & trend report (S23, REQ-POSTURE-004).

An executive asks three questions of a continuous program, and this report answers them
from stored data only — no re-scan, no network:

* **What is the trend?** severity counts per scan of the estate (the newest ``limit``
  scans of one project, oldest → newest), so "are we getting better?" is a line, not a
  vibe.
* **What changed since last period?** the drift between consecutive scans — new, fixed,
  regressed, recurring — computed with the same identity (``(check, asset)``) and the
  same suppression awareness as the scheduled diff.
* **Is the loop working?** the fix-verification history: how many findings were closed
  by verification, how many re-opened (regressions), and the current closed/open split.

The builder is pure (precomputed inputs, deterministic output); the assembly from
services lives in :func:`build_estate_posture` and the renderers are
:func:`render_estate_markdown` (operator/executive) and :func:`estate_payload` (JSON for
a dashboard). Golden-file tests pin the markdown so executive-facing rendering cannot
drift silently.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from arachne.analyzer.model import SEVERITY_ORDER, severity_rank

if TYPE_CHECKING:  # S28: the simulation trend type, for the optional series below.
    # Imported for typing only: area SIM may not import this package (it owns a re-scan
    # path), so the dependency runs one way and only in the annotation.
    from arachne.sim.trend import SimulationTrend

__all__ = [
    "DriftPeriod",
    "EstatePosture",
    "ScanPoint",
    "build_estate_posture",
    "estate_payload",
    "render_estate_markdown",
]

#: Finding rows the drift section shows per period before truncating ("…" for the rest).
_MAX_DRIFT_ROWS: Final = 8


@dataclass(frozen=True, slots=True)
class ScanPoint:
    """One scan of the estate: when, and what it found (by severity)."""

    scan_id: int
    target_name: str
    created_at: datetime | None
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(count for key, count in self.counts.items() if key in SEVERITY_ORDER)

    @property
    def unanalysed(self) -> int:
        return int(self.counts.get("unanalysed", 0))


@dataclass(frozen=True, slots=True)
class DriftPeriod:
    """The drift between two consecutive scans of the estate."""

    earlier_scan_id: int
    later_scan_id: int
    new: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()
    regressed: tuple[str, ...] = ()
    recurring: tuple[str, ...] = ()
    #: Brief rows for the report: ``(check, asset, severity, bucket)`` — capped.
    rows: tuple[tuple[str, str, str, str], ...] = ()

    @property
    def quiet(self) -> bool:
        return not (self.new or self.fixed or self.regressed)


@dataclass(frozen=True, slots=True)
class EstatePosture:
    """The whole report document (renderers consume exactly this)."""

    project: str
    generated_at: datetime
    points: tuple[ScanPoint, ...] = ()
    periods: tuple[DriftPeriod, ...] = ()
    #: Current open findings by severity (the newest scan's counts).
    open_counts: dict[str, int] = field(default_factory=dict)
    #: Findings auto-closed by fix verification (and how many re-opened).
    closed_by_verification: int = 0
    reopened_regressions: int = 0
    still_open_verifications: int = 0
    #: The watched estate inventory: ``service → resource count`` (continuous scopes).
    inventory: dict[str, int] = field(default_factory=dict)
    #: The watched scopes, with their baseline sizes.
    watched_scopes: tuple[tuple[str, int], ...] = ()

    @property
    def open_total(self) -> int:
        return sum(count for key, count in self.open_counts.items() if key in SEVERITY_ORDER)


def _identity_rows(findings: Sequence[Any]) -> dict[str, Any]:
    """``(check_id, asset)`` → the finding view, from candidate/report-shaped rows.

    Anything with ``check_id``/``asset``/``severity``/``id``/``title`` works — the same
    identity the scheduled diff uses (F-06-05), so the executive drift and the operator
    diff cannot disagree.
    """
    out: dict[str, Any] = {}
    for finding in findings:
        asset = getattr(finding.asset, "value", None) if hasattr(finding, "asset") else None
        key = f"{finding.check_id}|{asset}"
        out.setdefault(key, finding)
    return out


def _brief(finding: Any) -> tuple[str, str, str]:
    asset = getattr(finding.asset, "value", "") if hasattr(finding, "asset") else ""
    return (str(finding.check_id), str(asset), str(finding.severity))


def _drift_between(
    earlier: Mapping[str, Any],
    later: Mapping[str, Any],
    *,
    earlier_scan_id: int,
    later_scan_id: int,
) -> DriftPeriod:
    new_keys = sorted(key for key in later if key not in earlier)
    fixed_keys = sorted(key for key in earlier if key not in later)
    regressed: list[str] = []
    recurring: list[str] = []
    for key in sorted(set(earlier) & set(later)):
        before = severity_rank(str(getattr(earlier[key], "severity", "")))
        after = severity_rank(str(getattr(later[key], "severity", "")))
        (regressed if after > before else recurring).append(key)
    rows: list[tuple[str, str, str, str]] = []
    for bucket, keys in (
        ("new", new_keys),
        ("regressed", regressed),
        ("fixed", fixed_keys),
        ("recurring", recurring),
    ):
        for key in keys[:_MAX_DRIFT_ROWS]:
            finding = later.get(key) if bucket != "fixed" else earlier.get(key)
            check, asset, severity = (
                _brief(finding) if finding is not None else (*key.split("|", 1), "")
            )
            rows.append((check, asset, severity, bucket))
    return DriftPeriod(
        earlier_scan_id=earlier_scan_id,
        later_scan_id=later_scan_id,
        new=tuple(new_keys),
        fixed=tuple(fixed_keys),
        regressed=tuple(regressed),
        recurring=tuple(recurring),
        rows=tuple(rows[:_MAX_DRIFT_ROWS]),
    )


def build_estate_posture(
    *,
    project: str,
    points: Sequence[ScanPoint],
    finding_sets: Sequence[Mapping[str, Any]],
    open_counts: Mapping[str, int],
    closed_by_verification: int = 0,
    reopened_regressions: int = 0,
    still_open_verifications: int = 0,
    inventory: Mapping[str, int] | None = None,
    watched_scopes: Sequence[tuple[str, int]] = (),
    now: datetime | None = None,
) -> EstatePosture:
    """Assemble the report from precomputed inputs (pure; golden-file friendly).

    ``points`` and ``finding_sets`` are parallel sequences, oldest → newest: one
    :class:`ScanPoint` per scan, and the scan's identity-projected findings for the drift
    computation.
    """
    periods = tuple(
        _drift_between(
            finding_sets[index - 1],
            finding_sets[index],
            earlier_scan_id=points[index - 1].scan_id,
            later_scan_id=points[index].scan_id,
        )
        for index in range(1, min(len(finding_sets), len(points)))
    )
    return EstatePosture(
        project=project,
        generated_at=(now or datetime.now(UTC)).astimezone(UTC),
        points=tuple(points),
        periods=periods,
        open_counts={severity: int(open_counts.get(severity, 0)) for severity in SEVERITY_ORDER},
        closed_by_verification=closed_by_verification,
        reopened_regressions=reopened_regressions,
        still_open_verifications=still_open_verifications,
        inventory=dict(inventory or {}),
        watched_scopes=tuple(watched_scopes),
    )


def estate_payload(
    posture: EstatePosture, *, simulation: SimulationTrend | None = None
) -> dict[str, Any]:
    """The JSON form (deterministic: sorted keys, ISO timestamps).

    ``simulation`` is the S28 re-simulation series (REQ-SIM-006): when one is supplied and
    has points, it joins the payload under its own ``"simulation"`` key, carrying
    ``provenance: "simulated"``. It is a *separate* key on purpose — nothing here merges a
    simulated point into the scan trend, because a trend an operator reads as "exposure" and
    one computed over hypotheticals are different claims.
    """
    payload: dict[str, Any] = {
        "project": posture.project,
        "generated_at": posture.generated_at.isoformat(),
        "scans": [
            {
                "scan_id": point.scan_id,
                "target": point.target_name,
                "created_at": point.created_at.isoformat() if point.created_at else None,
                "counts": {
                    severity: int(point.counts.get(severity, 0)) for severity in SEVERITY_ORDER
                },
                "total": point.total,
                "unanalysed": point.unanalysed,
            }
            for point in posture.points
        ],
        "drift": [
            {
                "earlier_scan_id": period.earlier_scan_id,
                "later_scan_id": period.later_scan_id,
                "new": len(period.new),
                "fixed": len(period.fixed),
                "regressed": len(period.regressed),
                "recurring": len(period.recurring),
                "rows": [list(row) for row in period.rows],
            }
            for period in posture.periods
        ],
        "open": dict(posture.open_counts),
        "open_total": posture.open_total,
        "fix_loop": {
            "closed_by_verification": posture.closed_by_verification,
            "reopened_regressions": posture.reopened_regressions,
            "still_open_verifications": posture.still_open_verifications,
        },
        "inventory": dict(sorted(posture.inventory.items())),
        "watched_scopes": [
            {"scope": scope, "resources": count} for scope, count in posture.watched_scopes
        ],
    }
    if simulation is not None and simulation.points:
        payload["simulation"] = simulation.payload()
    return payload


def render_estate_markdown(
    posture: EstatePosture, *, simulation: SimulationTrend | None = None
) -> str:
    """The executive markdown (the golden-file target)."""
    lines: list[str] = []
    lines.append(f"# Estate posture — {posture.project}")
    lines.append("")
    lines.append(f"Generated {posture.generated_at.strftime('%Y-%m-%d %H:%M UTC')} · "
                 f"{len(posture.points)} scan(s) considered")
    lines.append("")

    lines.append("## Trend")
    lines.append("")
    if posture.points:
        lines.append("| Scan | Target | Critical | High | Medium | Low | Info | Total |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for point in posture.points:
            counts = point.counts
            lines.append(
                f"| {point.scan_id} | {point.target_name} | {counts.get('critical', 0)} "
                f"| {counts.get('high', 0)} | {counts.get('medium', 0)} "
                f"| {counts.get('low', 0)} | {counts.get('info', 0)} | {point.total} |"
            )
    else:
        lines.append("_No scans recorded for this estate yet._")
    lines.append("")

    lines.append("## Drift since last period")
    lines.append("")
    if not posture.periods:
        lines.append("_One scan on record; drift needs a previous period._")
    else:
        for period in posture.periods:
            if period.quiet:
                lines.append(
                    f"- Scans {period.earlier_scan_id} → {period.later_scan_id}: "
                    "no change — the estate held steady."
                )
                continue
            lines.append(
                f"- Scans {period.earlier_scan_id} → {period.later_scan_id}: "
                f"{len(period.new)} new, {len(period.fixed)} fixed, "
                f"{len(period.regressed)} regressed, {len(period.recurring)} recurring."
            )
            for check, asset, severity, bucket in period.rows:
                lines.append(f"  - {bucket}: **{severity}** {check} on {asset}")
    lines.append("")

    lines.append("## Fix-verification loop")
    lines.append("")
    lines.append(
        f"- {posture.closed_by_verification} finding(s) closed by verified fix; "
        f"{posture.reopened_regressions} regression(s) re-opened; "
        f"{posture.still_open_verifications} verification(s) found the finding still present."
    )
    lines.append(f"- Currently open: **{posture.open_total}** "
                 f"({posture.open_counts.get('critical', 0)} critical, "
                 f"{posture.open_counts.get('high', 0)} high).")
    lines.append("")

    lines.append("## Estate inventory")
    lines.append("")
    if posture.watched_scopes:
        for scope, count in posture.watched_scopes:
            lines.append(f"- `{scope}` — {count} resource(s) under continuous watch")
        lines.append("")
        lines.append("Resources by service: " + ", ".join(
            f"{service} ({count})" for service, count in sorted(posture.inventory.items())
        ) + ".")
    else:
        lines.append("_No continuous scope is watched yet — declare a continuous schedule "
                     "targeting a cloud-config endpoint._")
    lines.append("")
    if simulation is not None and simulation.points:
        lines.append("## Simulated outlook (what-if)")
        lines.append("")
        lines.append(
            "**Simulated.** These points come from re-simulations of the estate model "
            "(area SIM), not from observations of a target: nothing in this section was "
            "measured on the estate, and none of it counts towards the exposure above."
        )
        lines.append("")
        lines.append(simulation.markdown())
        lines.append("")
        lines.append(
            f"Direction across {len(simulation.points)} re-simulation(s): "
            f"**{simulation.trend_direction}**."
        )
        lines.append("")
    return "\n".join(lines)
