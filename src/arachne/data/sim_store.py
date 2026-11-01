"""Persistence for the simulation trend (S28, area SIM, REQ-SIM-006).

One table, one purpose: the re-simulation trend. Both implementations live here with the same
behaviour, because a trend that only works against Postgres is a trend nobody tests.

The store is deliberately *not* part of any other subsystem's write path. It has no method
that touches ``findings``, ``evidences`` or ``analysis_log``, and the row it writes carries
``provenance`` so a reader can tell a simulated point from an observed one without trusting
the caller (REQ-SIM-004). A gate verdict reads severity counts from the ``findings`` table; it
cannot reach these rows.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.data import models
from arachne.data.scan_store import as_utc
from arachne.sim.trend import DEFAULT_TREND_LIMIT, SimulationPoint

__all__ = ["MemorySimulationStore", "SqlSimulationStore"]


def _ordering(point: SimulationPoint) -> tuple[bool, datetime | None, int]:
    """Oldest first; a point with no timestamp sorts before one that has it."""
    return (point.created_at is None, point.created_at, point.scan_id or -1)


class MemorySimulationStore:
    """An in-process simulation trend: the store a test drives, and the reference semantics."""

    def __init__(self) -> None:
        self._points: list[SimulationPoint] = []

    def record_point(self, point: SimulationPoint) -> SimulationPoint:
        self._points.append(point)
        return point

    def points(
        self, *, estate_key: str | None = None, limit: int = DEFAULT_TREND_LIMIT
    ) -> tuple[SimulationPoint, ...]:
        selected = [
            item for item in self._points if estate_key is None or item.estate_key == estate_key
        ]
        selected.sort(key=_ordering)
        return tuple(selected[-limit:])

    def latest(self, estate_key: str) -> SimulationPoint | None:
        found = self.points(estate_key=estate_key, limit=1)
        return found[-1] if found else None


class SqlSimulationStore:
    """``SimulationStore`` over the ``simulation_points`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_point(self, point: SimulationPoint) -> SimulationPoint:
        with self._session_factory() as session:
            row = models.SimulationPointRecord(
                estate_key=point.estate_key,
                scan_id=point.scan_id,
                provenance=point.provenance,
                hypotheses=point.hypotheses,
                path_count=point.path_count,
                introduced=point.introduced,
                exposure_score=point.exposure_score,
                severity_counts_json=dict(point.severity_counts),
                created_at=point.created_at or models.utcnow(),
            )
            session.add(row)
            session.commit()
            return _to_point(row)

    def points(
        self, *, estate_key: str | None = None, limit: int = DEFAULT_TREND_LIMIT
    ) -> tuple[SimulationPoint, ...]:
        query = select(models.SimulationPointRecord)
        if estate_key is not None:
            query = query.where(models.SimulationPointRecord.estate_key == estate_key)
        # Newest first in SQL (so the limit keeps the most recent), oldest first in the result.
        query = query.order_by(
            models.SimulationPointRecord.created_at.desc(),
            models.SimulationPointRecord.id.desc(),
        ).limit(limit)
        with self._session_factory() as session:
            rows = list(session.scalars(query).all())
        return tuple(_to_point(row) for row in reversed(rows))

    def latest(self, estate_key: str) -> SimulationPoint | None:
        query = (
            select(models.SimulationPointRecord)
            .where(models.SimulationPointRecord.estate_key == estate_key)
            .order_by(
                models.SimulationPointRecord.created_at.desc(),
                models.SimulationPointRecord.id.desc(),
            )
            .limit(1)
        )
        with self._session_factory() as session:
            row = session.scalars(query).first()
        return _to_point(row) if row is not None else None


def _to_point(row: models.SimulationPointRecord) -> SimulationPoint:
    return SimulationPoint(
        estate_key=row.estate_key,
        created_at=as_utc(row.created_at),
        scan_id=row.scan_id,
        hypotheses=int(row.hypotheses),
        path_count=int(row.path_count),
        introduced=int(row.introduced),
        severity_counts=dict(row.severity_counts_json or {}),
        exposure_score=int(row.exposure_score),
        provenance=row.provenance,
    )
