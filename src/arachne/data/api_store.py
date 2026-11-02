"""Interface-side read queries over the evidence store (F-07-02/03, S12).

The report layer must not own SQL, and neither must the API: every query the REST API and
the web UI need lives here, next to the writer of the table it reads. Three ideas shape it:

* **One row type per view.** :class:`FindingRow` is what a finding list renders,
  :class:`CheckRow` what the module-config page shows, :class:`ScanTrendRow` one point of
  the dashboard's severity trend. None of them is an ORM object, so a router cannot lazily
  load half the database from a template.
* **Filters are data, not SQL from the caller.** A finding query takes named filters
  (module, severity, CWE, status, asset substring, title substring, plus the cursor
  boundary) and applies them here; the API's query string maps onto them one-to-one.
* **Writes are narrow.** The API may flip a finding's ``status`` (the F-05-07 review verb),
  delete a finding, or delete a scan. It never writes ``severity``/``confidence`` — that is
  the analyzer's column (ADR-02).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.data.keyset import PageWindow, with_finding_page
from arachne.data.models import Asset as AssetRow
from arachne.data.models import Check, Evidence, Finding, Scan
from arachne.data.scan_store import as_utc

__all__ = [
    "ApiQueryStore",
    "CheckRow",
    "FindingRow",
    "ScanTrendRow",
    "SeverityCounts",
    "finding_to_dict",
]

SeverityCounts = dict[str, int]

#: Every severity a stored finding may carry .
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: Statuses the API may set on a finding (F-05-07).
FINDING_STATUSES: frozenset[str] = frozenset({"open", "verified", "fp", "merged"})

#: The API's ``sort`` vocabulary for ``/findings`` (REQ-UIX-002) lives in
#: :mod:`arachne.data.keyset` as a closed enum; only ``id`` is indexed, and the endpoint
#: documents the other fields as a full scan.


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One finding as the API/UI lists it."""

    id: int
    scan_id: int
    title: str
    severity: str | None = None
    confidence: float | None = None
    status: str = "open"
    module: str | None = None
    check_id: str | None = None
    cwe: str | None = None
    research_ref: str | None = None
    remediation_id: str | None = None
    asset_kind: str | None = None
    asset_value: str | None = None
    created_at: datetime | None = None

    @property
    def severity_label(self) -> str:
        return self.severity or "unanalysed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "module": self.module,
            "check_id": self.check_id,
            "cwe": self.cwe,
            "research_ref": self.research_ref,
            "remediation_id": self.remediation_id,
            "asset": {"kind": self.asset_kind, "value": self.asset_value},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass(frozen=True, slots=True)
class CheckRow:
    """One row of the ``checks`` table — the module-config view's inventory."""

    id: int
    module: str
    name: str
    version: str
    description: str | None = None
    cwe: str | None = None
    research_ref: str | None = None

    @property
    def key(self) -> str:
        return f"{self.module}/{self.name}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module": self.module,
            "name": self.name,
            "version": self.version,
            "check_id": f"{self.module.lower()}.{self.name}",
            "description": self.description,
            "cwe": self.cwe,
            "research_ref": self.research_ref,
        }


@dataclass(frozen=True, slots=True)
class ScanTrendRow:
    """One point of the dashboard's severity trend."""

    scan_id: int
    status: str
    created_at: datetime | None = None
    counts: SeverityCounts = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "counts": dict(self.counts),
            "total": self.total,
        }


def finding_to_dict(row: FindingRow) -> dict[str, Any]:
    """Alias kept for callers that prefer a function to a method."""
    return row.to_dict()


class ApiQueryStore:
    """Read/limited-write queries for the API and the web UI."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ severity
    def severity_counts(self, scan_id: int) -> SeverityCounts:
        """``{severity: count}`` for one scan's *confirmed* findings.

        Findings whose status is ``fp`` or ``merged`` are excluded, and a row the analyzer
        has not touched (``severity IS NULL``) counts as ``unanalysed`` so a scan mid-flight
        still reports something honest.
        """
        return self.severity_counts_for((scan_id,)).get(scan_id, {})

    def severity_counts_for(self, scan_ids: Sequence[int]) -> dict[int, SeverityCounts]:
        """Severity counts for several scans in one query (the dashboard's list)."""
        wanted = [int(item) for item in scan_ids]
        if not wanted:
            return {}
        query = (
            select(Finding.scan_id, Finding.severity, func.count())
            .where(Finding.scan_id.in_(wanted))
            .where(Finding.status.notin_(("fp", "merged")))
            .group_by(Finding.scan_id, Finding.severity)
        )
        with self._session_factory() as session:
            rows = session.execute(query).all()
        out: dict[int, SeverityCounts] = {scan_id: {} for scan_id in wanted}
        for scan_id, severity, count in rows:
            key = str(severity) if severity else "unanalysed"
            out[int(scan_id)][key] = int(count)
        return out

    def scan_trend(
        self,
        *,
        limit: int = 20,
        target_id: int | None = None,
        project_id: int | None = None,
        include_unassigned: bool = False,
    ) -> tuple[ScanTrendRow, ...]:
        """The newest ``limit`` scans (oldest → newest) with their severity counts."""
        with self._session_factory() as session:
            query = select(Scan).order_by(Scan.id.desc()).limit(limit)
            if target_id is not None:
                query = query.where(Scan.target_id == target_id)
            if project_id is not None:
                condition = Scan.project_id == project_id
                if include_unassigned:
                    condition = condition | Scan.project_id.is_(None)
                query = query.where(condition)
            scans = session.scalars(query).all()
        ordered = list(reversed(scans))
        counts = self.severity_counts_for([int(scan.id) for scan in ordered])
        return tuple(
            ScanTrendRow(
                scan_id=int(scan.id),
                status=str(scan.status),
                created_at=as_utc(scan.created_at),
                counts=counts.get(int(scan.id), {}),
            )
            for scan in ordered
        )

    # ------------------------------------------------------------------ findings
    def finding_rows(
        self,
        *,
        scan_id: int | None = None,
        module: str | None = None,
        severity: str | None = None,
        cwe: str | None = None,
        status: str | None = None,
        asset: str | None = None,
        query: str | None = None,
        limit: int = 200,
        offset: int = 0,
        project_id: int | None = None,
        include_unassigned: bool = False,
        window: PageWindow | None = None,
    ) -> tuple[FindingRow, ...]:
        """Findings matching the filters, ordered by ``window`` with an ``id`` tiebreaker.

        ``window`` carries the validated sort vocabulary and, when a cursor was supplied, the
        keyset boundary it decodes to: rows strictly after that boundary are returned
        (``limit + 1`` of them, so the caller can detect a next page without a count query).
        It is typed and closed — never a raw query string.
        """
        check_alias = Check
        query_stmt: Any = (
            select(Finding, Check, AssetRow)
            .outerjoin(check_alias, Finding.check_id == check_alias.id)
            .outerjoin(AssetRow, Finding.asset_id == AssetRow.id)
        )
        query_stmt = with_finding_page(query_stmt, window=window, limit=limit)
        if project_id is not None:
            # The tenant lives on ``scans`` (F-07-06); filter through it rather than
            # denormalising project_id onto every child row.
            query_stmt = query_stmt.join(Scan, Finding.scan_id == Scan.id)
            condition = Scan.project_id == project_id
            if include_unassigned:
                condition = condition | Scan.project_id.is_(None)
            query_stmt = query_stmt.where(condition)
        if scan_id is not None:
            query_stmt = query_stmt.where(Finding.scan_id == scan_id)
        if module:
            query_stmt = query_stmt.where(func.lower(check_alias.module) == module.strip().lower())
        if severity:
            if severity.strip().lower() == "unanalysed":
                query_stmt = query_stmt.where(Finding.severity.is_(None))
            else:
                query_stmt = query_stmt.where(
                    func.lower(Finding.severity) == severity.strip().lower()
                )
        if cwe:
            query_stmt = query_stmt.where(func.lower(check_alias.cwe) == cwe.strip().lower())
        if status:
            query_stmt = query_stmt.where(func.lower(Finding.status) == status.strip().lower())
        if asset:
            query_stmt = query_stmt.where(AssetRow.value.contains(asset.strip()))
        if query:
            query_stmt = query_stmt.where(Finding.title.contains(query.strip()))
        query_stmt = query_stmt.limit(max(1, limit)).offset(max(0, offset))
        with self._session_factory() as session:
            rows = session.execute(query_stmt).all()
        return tuple(_finding_row(finding, check, asset_row) for finding, check, asset_row in rows)

    def finding_row(self, finding_id: int) -> FindingRow | None:
        with self._session_factory() as session:
            row = session.execute(
                select(Finding, Check, AssetRow)
                .outerjoin(Check, Finding.check_id == Check.id)
                .outerjoin(AssetRow, Finding.asset_id == AssetRow.id)
                .where(Finding.id == finding_id)
            ).first()
        if row is None:
            return None
        return _finding_row(row[0], row[1], row[2])

    def finding_scan_id(self, finding_id: int) -> int | None:
        """The scan a finding belongs to (the tenant check's first hop, F-07-06)."""
        with self._session_factory() as session:
            finding = session.get(Finding, finding_id)
            return None if finding is None else int(finding.scan_id)

    def evidence_rows(self, finding_id: int) -> tuple[dict[str, Any], ...]:
        """The finding's evidence rows, oldest first (the report viewer's evidence pane)."""
        with self._session_factory() as session:
            rows = session.scalars(
                select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.id)
            ).all()
        return tuple(
            {
                "id": int(row.id),
                "kind": str(row.kind),
                "sha256": row.sha256,
                "payload": dict(row.payload_json or {}),
                "created_at": _iso(as_utc(row.created_at)),
            }
            for row in rows
        )

    def evidence_row(self, evidence_id: int) -> dict[str, Any] | None:
        """One evidence row by id (S20): the download route's lookup, including where the
        payload physically lives so the route can presign or stream it."""
        with self._session_factory() as session:
            row = session.get(Evidence, evidence_id)
            if row is None:
                return None
            return {
                "id": int(row.id),
                "finding_id": row.finding_id,
                "kind": str(row.kind),
                "sha256": row.sha256,
                "payload": dict(row.payload_json or {}),
                "size_bytes": row.size_bytes,
                "storage": row.storage,
                "storage_key": row.storage_key,
                # S25 (REQ-RESIL-004): the region the payload is pinned to, so the download
                # route can refuse a cross-region read instead of serving it.
                "region": row.region,
                "created_at": _iso(as_utc(row.created_at)),
            }

    def set_finding_status(self, finding_id: int, status: str) -> FindingRow | None:
        """Set a finding's ``status`` (F-05-07 review verb). ``None`` if it does not exist."""
        if status not in FINDING_STATUSES:
            msg = f"unknown finding status {status!r}"
            raise ValueError(msg)
        with self._session_factory() as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return None
            finding.status = status
            session.commit()
            session.refresh(finding)
            check = session.get(Check, finding.check_id) if finding.check_id else None
            asset = session.get(AssetRow, finding.asset_id) if finding.asset_id else None
            return _finding_row(finding, check, asset)

    def delete_finding(self, finding_id: int) -> bool:
        with self._session_factory() as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return False
            session.delete(finding)
            session.commit()
            return True

    # ------------------------------------------------------------------ scans
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and everything that cascades from it (steps, assets, findings)."""
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return False
            session.delete(scan)
            session.commit()
            return True

    def count_findings(self, scan_id: int) -> int:
        with self._session_factory() as session:
            total = session.scalar(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
        return int(total or 0)

    def delete_all_findings(self, scan_id: int) -> int:
        """Remove every finding of a scan (kept for operational cleanup); returns the count."""
        with self._session_factory() as session:
            result = session.execute(delete(Finding).where(Finding.scan_id == scan_id))
            session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ checks
    def list_checks(self, *, module: str | None = None) -> tuple[CheckRow, ...]:
        query = select(Check).order_by(Check.module, Check.name)
        if module:
            query = query.where(func.lower(Check.module) == module.strip().lower())
        with self._session_factory() as session:
            rows = session.scalars(query).all()
        return tuple(
            CheckRow(
                id=int(row.id),
                module=str(row.module),
                name=str(row.name),
                version=str(row.version),
                description=row.description,
                cwe=row.cwe,
                research_ref=row.research_ref,
            )
            for row in rows
        )


def _finding_row(finding: Finding, check: Check | None, asset: AssetRow | None) -> FindingRow:
    module: str | None = None
    check_id: str | None = None
    cwe: str | None = None
    research_ref: str | None = None
    if check is not None:
        module = str(check.module)
        check_id = f"{check.module}/{check.name}@{check.version}"
        cwe = check.cwe
        research_ref = check.research_ref
    return FindingRow(
        id=int(finding.id),
        scan_id=int(finding.scan_id),
        title=str(finding.title),
        severity=finding.severity,
        confidence=finding.confidence,
        status=str(finding.status),
        module=module,
        check_id=check_id,
        cwe=cwe,
        research_ref=research_ref,
        remediation_id=finding.remediation_id,
        asset_kind=str(asset.kind) if asset is not None else None,
        asset_value=str(asset.value) if asset is not None else None,
        created_at=as_utc(finding.created_at),
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
