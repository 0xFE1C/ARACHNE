"""SQLite/Postgres-backed scan state (F-01-04, F-09-02).

The stage the orchestration state lives in, so a restart loses nothing: every mutation the
:class:`~arachne.core.lifecycle.ScanMachine` makes goes through here and is committed
before the machine continues.

Timestamp handling follows ADR-050.6 (SQLite stores naive UTC) with the S2 refinement from
ADR-060.4: the *repository boundary* re-attaches UTC, so nothing above this layer has to
remember whether a timestamp came from SQLite or Postgres.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ScanStateError
from arachne.core.lifecycle import (
    AssetRecord,
    ScanRecord,
    ScanStateStore,
    ScanStatus,
    StepState,
    StepStatus,
)
from arachne.core.planner import ScanStep
from arachne.data.models import Asset, Scan, ScanStepRecord

__all__ = ["SqlScanStateStore"]


def as_utc(value: datetime | None) -> datetime | None:
    """Re-attach UTC to a naive database timestamp (ADR-050.6 / ADR-060.4)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class SqlScanStateStore(ScanStateStore):
    """``ScanStateStore`` over the ``scans``/``scan_steps``/``assets`` tables."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ scans
    def create_scan(
        self,
        *,
        target_id: int | None,
        engine: str,
        plan: dict[str, Any],
        stats: dict[str, Any] | None = None,
        status: ScanStatus = ScanStatus.PENDING,
        project_id: int | None = None,
        request_json: dict[str, Any] | None = None,
    ) -> ScanRecord:
        with self._session_factory() as session:
            scan = Scan(
                target_id=target_id,
                engine=engine,
                plan_json=plan,
                stats_json=dict(stats or {}),
                status=status.value,
                project_id=project_id,
                request_json=dict(request_json) if request_json is not None else None,
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return _to_record(scan, ())

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return None
            return _to_record(scan, self._steps(session, scan_id))

    def list_scans(
        self,
        *,
        limit: int = 50,
        project_id: int | None = None,
        include_unassigned: bool = False,
    ) -> tuple[ScanRecord, ...]:
        """Recent scans; ``project_id`` filters, ``include_unassigned`` adds pre-S14 rows."""
        with self._session_factory() as session:
            query = select(Scan).order_by(Scan.id.desc()).limit(limit)
            if project_id is not None:
                condition = Scan.project_id == project_id
                if include_unassigned:
                    condition = condition | Scan.project_id.is_(None)
                query = query.where(condition)
            rows = session.scalars(query).all()
            return tuple(_to_record(row, self._steps(session, row.id)) for row in rows)

    def update_scan(
        self,
        scan_id: int,
        *,
        status: ScanStatus | None = None,
        stats: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        mark_started: bool = False,
        mark_finished: bool = False,
    ) -> ScanRecord:
        with self._session_factory() as session:
            scan = self._require(session, scan_id)
            if status is not None:
                scan.status = status.value
            if stats is not None:
                scan.stats_json = dict(stats)
            if plan is not None:
                scan.plan_json = dict(plan)
            if mark_started and scan.started_at is None:
                scan.started_at = datetime.now(UTC)
            if mark_finished:
                scan.finished_at = datetime.now(UTC)
            session.commit()
            return _to_record(scan, self._steps(session, scan_id))

    # ------------------------------------------------------------------ steps
    def save_step(self, scan_id: int, state: StepState) -> StepState:
        with self._session_factory() as session:
            self._require(session, scan_id)
            row = session.scalar(
                select(ScanStepRecord).where(
                    ScanStepRecord.scan_id == scan_id, ScanStepRecord.step == state.step.value
                )
            )
            if row is None:
                row = ScanStepRecord(scan_id=scan_id, step=state.step.value)
                session.add(row)
            row.status = state.status.value
            row.attempts = state.attempts
            row.started_at = state.started_at
            row.finished_at = state.finished_at
            row.error = state.error
            row.stats_json = dict(state.stats)
            row.updated_at = datetime.now(UTC)
            session.commit()
            return _to_step(row)

    # ------------------------------------------------------------------ assets
    def add_asset(
        self,
        scan_id: int,
        *,
        kind: str,
        value: str,
        meta: Mapping[str, Any] | None = None,
    ) -> AssetRecord:
        with self._session_factory() as session:
            self._require(session, scan_id)
            asset = Asset(scan_id=scan_id, kind=kind, value=value, meta_json=dict(meta or {}))
            session.add(asset)
            session.commit()
            session.refresh(asset)
            return AssetRecord(
                id=asset.id,
                scan_id=scan_id,
                kind=asset.kind,
                value=asset.value,
                meta=asset.meta_json,
            )

    def list_assets(self, scan_id: int) -> tuple[AssetRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(Asset).where(Asset.scan_id == scan_id).order_by(Asset.id)
            ).all()
            return tuple(
                AssetRecord(
                    id=row.id,
                    scan_id=row.scan_id,
                    kind=row.kind,
                    value=row.value,
                    meta=row.meta_json,
                )
                for row in rows
            )

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _require(session: Session, scan_id: int) -> Scan:
        scan = session.get(Scan, scan_id)
        if scan is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        return scan

    @staticmethod
    def _steps(session: Session, scan_id: int) -> tuple[StepState, ...]:
        rows = session.scalars(
            select(ScanStepRecord)
            .where(ScanStepRecord.scan_id == scan_id)
            .order_by(ScanStepRecord.id)
        ).all()
        return tuple(_to_step(row) for row in rows)


def _to_record(scan: Scan, steps: tuple[StepState, ...]) -> ScanRecord:
    return ScanRecord(
        id=scan.id,
        target_id=scan.target_id,
        status=ScanStatus(scan.status),
        engine=scan.engine,
        plan=dict(scan.plan_json or {}),
        stats=dict(scan.stats_json or {}),
        started_at=as_utc(scan.started_at),
        finished_at=as_utc(scan.finished_at),
        created_at=as_utc(scan.created_at),
        steps=steps,
        project_id=scan.project_id,
        request_json=dict(scan.request_json) if scan.request_json is not None else None,
    )


def _to_step(row: ScanStepRecord) -> StepState:
    return StepState(
        step=ScanStep(row.step),
        status=StepStatus(row.status),
        attempts=row.attempts,
        started_at=as_utc(row.started_at),
        finished_at=as_utc(row.finished_at),
        error=row.error,
        stats=dict(row.stats_json or {}),
    )
