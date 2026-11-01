"""The simulation trend: what the model's outlook did over time (REQ-SIM-006).

REQ-POSTURE-004's trend answers "how is the estate moving, scan by scan?" from the scans
themselves. This is its simulation twin: one point per re-simulation, carrying the exposure
score and the path counts of *that* moment, so the posture view can show the outlook next to
the exposure and an operator can see whether a change made things better.

A point is a stored observation of a computation, never a scan result. It is written by the
re-simulator (:mod:`arachne.sim.resim`) under its own table, it is labelled ``simulated``,
and nothing reads it as a finding: the trend renderer keeps it in its own series, and the
gate verdicts never see it (REQ-SIM-004).

The store is a protocol with two implementations (in-memory for tests, SQL for deployments)
declared in the data layer — this module is storage-free by design, like the rest of area SIM.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from arachne.sim.whatif import SIM_PROVENANCE, SimulationRun

__all__ = [
    "SimulationPoint",
    "SimulationStore",
    "SimulationTrend",
    "build_simulation_trend",
    "point_from_run",
]

#: How many points a trend read returns by default.
DEFAULT_TREND_LIMIT: Final = 50


@dataclass(frozen=True, slots=True)
class SimulationPoint:
    """One re-simulation's headline numbers, at one moment."""

    estate_key: str
    created_at: datetime | None = None
    scan_id: int | None = None
    hypotheses: int = 0
    path_count: int = 0
    introduced: int = 0
    severity_counts: Mapping[str, int] = field(default_factory=dict)
    exposure_score: int = 0
    provenance: str = SIM_PROVENANCE

    @property
    def simulated(self) -> bool:
        return self.provenance == SIM_PROVENANCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "estate_key": self.estate_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "scan_id": self.scan_id,
            "hypotheses": self.hypotheses,
            "path_count": self.path_count,
            "introduced": self.introduced,
            "severity_counts": dict(self.severity_counts),
            "exposure_score": self.exposure_score,
            "provenance": self.provenance,
        }


class SimulationStore(Protocol):
    """Where simulation trend points live (S28, REQ-SIM-006)."""

    def record_point(self, point: SimulationPoint) -> SimulationPoint: ...

    def points(
        self, *, estate_key: str | None = None, limit: int = DEFAULT_TREND_LIMIT
    ) -> tuple[SimulationPoint, ...]: ...

    def latest(self, estate_key: str) -> SimulationPoint | None: ...


def point_from_run(
    run: SimulationRun, *, created_at: datetime | None = None, scan_id: int | None = None
) -> SimulationPoint:
    """The trend point a run contributes."""
    counts: dict[str, int] = {}
    for path in run.result:
        severity = (path.path.business_severity or path.path.severity or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return SimulationPoint(
        estate_key=run.estate_key,
        created_at=created_at or datetime.now(UTC),
        scan_id=scan_id,
        hypotheses=len(run.hypotheses),
        path_count=len(run.result),
        introduced=len(run.introduced),
        severity_counts=dict(sorted(counts.items())),
        exposure_score=run.exposure_after,
        provenance=run.provenance,
    )


@dataclass(frozen=True, slots=True)
class SimulationTrend:
    """A series of simulation points, oldest first, with the deltas between them."""

    estate_key: str
    points: tuple[SimulationPoint, ...] = ()
    provenance: str = SIM_PROVENANCE

    @property
    def exposure_scores(self) -> tuple[int, ...]:
        return tuple(point.exposure_score for point in self.points)

    @property
    def deltas(self) -> tuple[int, ...]:
        """Point-to-point exposure change (``len(points) - 1`` values, oldest first)."""
        scores = self.exposure_scores
        return tuple(b - a for a, b in itertools.pairwise(scores))

    @property
    def latest(self) -> SimulationPoint | None:
        return self.points[-1] if self.points else None

    @property
    def trend_direction(self) -> str:
        """``rising``/``falling``/``flat``/``unknown`` — a word, not a score."""
        deltas = self.deltas
        if not deltas:
            return "unknown"
        total = sum(deltas)
        if total > 0:
            return "rising"
        if total < 0:
            return "falling"
        return "flat"

    def payload(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance,
            "estate_key": self.estate_key,
            "trend_direction": self.trend_direction,
            "points": [point.to_dict() for point in self.points],
            "deltas": list(self.deltas),
        }

    def markdown(self) -> str:
        """A compact, clearly-labelled series for the posture view (REQ-SIM-006)."""
        if not self.points:
            return "No simulation has been re-run for this estate yet."
        lines = [
            "| Re-simulation | Paths | New under hypotheses | Exposure score | Change |",
            "|---|---|---|---|---|",
        ]
        deltas = (0, *self.deltas)
        for point, delta in zip(self.points, deltas, strict=False):
            when = point.created_at.strftime("%Y-%m-%d %H:%M") if point.created_at else "—"
            change = "—" if not delta else f"{delta:+d}"
            lines.append(
                f"| {when} | {point.path_count} | {point.introduced} | "
                f"{point.exposure_score} | {change} |"
            )
        return "\n".join(lines)


def build_simulation_trend(
    points: Sequence[SimulationPoint], *, estate_key: str = ""
) -> SimulationTrend:
    """The trend for ``points``, oldest first (``None`` timestamps sort first, stably)."""
    ordered = tuple(
        sorted(
            points,
            key=lambda point: (
                point.created_at or datetime.min.replace(tzinfo=UTC),
                point.scan_id if point.scan_id is not None else -1,
            ),
        )
    )
    key = estate_key or (ordered[0].estate_key if ordered else "")
    return SimulationTrend(estate_key=key, points=ordered)
