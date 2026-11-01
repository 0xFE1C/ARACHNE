"""Report-side persistence: the audit trail and the ``scans_diff`` table (F-06-05, F-01-08).

Two small readers/writers the report engine needs, kept in :mod:`arachne.data` because the
report layer must not own SQL:

* :class:`SqlAuditReader` — the appendix's audit summary (action counts, blocked events,
  out-of-scope events). ``audit_log`` has no ``scan_id`` column (the schema is the spec's),
  so the row's ``meta_json`` carries it; the reader selects by the scan's time window and
  then confirms the id, which keeps a busy database from being scanned in full.
* :class:`SqlScanDiffStore` — writes/reads one ``scans_diff`` row per scan pair. The table
  is one of the spec's nine (``0001``), so S8 adds a writer, not a migration. ``UNIQUE``-like
  behaviour is enforced here by updating the existing pair rather than appending, because a
  re-run of the same comparison must not grow the table.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.data.models import AuditLog, ScanDiff
from arachne.data.scan_store import as_utc

__all__ = [
    "AuditRecord",
    "SqlAuditReader",
    "SqlScanDiffStore",
    "StoredDiff",
]


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One audit event as the report renders it."""

    ts: datetime | None
    action: str
    outcome: str = "allowed"
    target: str | None = None
    reason: str | None = None
    meta: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat() if self.ts else None,
            "action": self.action,
            "outcome": self.outcome,
            "target": self.target,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class StoredDiff:
    """One persisted ``scans_diff`` row."""

    id: int
    scan_id_a: int
    scan_id_b: int
    changes: Mapping[str, Any]
    created_at: datetime | None = None


class SqlAuditReader:
    """Read the audit trail for one scan out of the ``audit_log`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def events_for_scan(
        self,
        scan_id: int,
        *,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        limit: int = 5000,
    ) -> tuple[AuditRecord, ...]:
        """The scan's audit events, oldest first.

        When the scan's window is known the query is bounded by it; rows whose ``meta``
        names a different scan are dropped. A missing window falls back to the newest
        ``limit`` rows, which is what the CLI uses for an unfinished scan.
        """
        query = select(AuditLog).order_by(AuditLog.id)
        if started_at is not None:
            query = query.where(AuditLog.ts >= started_at - timedelta(seconds=1))
        if finished_at is not None:
            query = query.where(AuditLog.ts <= finished_at + timedelta(seconds=1))
        with self._session_factory() as session:
            rows = session.scalars(query.limit(limit)).all()
        out: list[AuditRecord] = []
        for row in rows:
            meta = dict(row.meta_json or {})
            recorded_scan = meta.get("scan_id")
            if recorded_scan is not None and str(recorded_scan) != str(scan_id):
                continue
            out.append(
                AuditRecord(
                    ts=as_utc(row.ts),
                    action=str(row.action),
                    outcome=str(meta.get("outcome") or "allowed"),
                    target=meta.get("target"),
                    reason=meta.get("reason"),
                    meta=meta,
                )
            )
        return tuple(out)


class SqlScanDiffStore:
    """Persist and read scan-to-scan diffs (F-06-05)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, scan_a: int, scan_b: int, changes: Mapping[str, Any]) -> StoredDiff:
        """Upsert the ``(scan_a, scan_b)`` diff and return the stored row."""
        with self._session_factory() as session:
            row = session.scalar(
                select(ScanDiff).where(ScanDiff.scan_id_a == scan_a, ScanDiff.scan_id_b == scan_b)
            )
            if row is None:
                row = ScanDiff(scan_id_a=scan_a, scan_id_b=scan_b, changes_json=dict(changes))
                session.add(row)
            else:
                row.changes_json = dict(changes)
            session.commit()
            session.refresh(row)
            return _to_stored(row)

    def get(self, scan_a: int, scan_b: int) -> StoredDiff | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(ScanDiff).where(ScanDiff.scan_id_a == scan_a, ScanDiff.scan_id_b == scan_b)
            )
            return None if row is None else _to_stored(row)

    def list_for_scan(self, scan_id: int) -> tuple[StoredDiff, ...]:
        """Every diff whose *newer* scan is ``scan_id`` (what a trend section reads)."""
        with self._session_factory() as session:
            rows = session.scalars(
                select(ScanDiff).where(ScanDiff.scan_id_b == scan_id).order_by(ScanDiff.id)
            ).all()
            return tuple(_to_stored(row) for row in rows)


def _to_stored(row: ScanDiff) -> StoredDiff:
    return StoredDiff(
        id=int(row.id),
        scan_id_a=int(row.scan_id_a),
        scan_id_b=int(row.scan_id_b),
        changes=dict(row.changes_json or {}),
        created_at=as_utc(row.created_at) or datetime.now(UTC),
    )
