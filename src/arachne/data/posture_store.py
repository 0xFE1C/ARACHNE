"""Persistence for continuous exposure management (S23, area POSTURE).

Three views of one dataset — the *estate's* memory between continuous runs:

* **baselines** (REQ-POSTURE-001) — the last-seen configuration of every cloud resource
  of one watched scope. The M5 continuous check diffs its snapshot against these rows
  (the drift delta), then replaces them; a scope with no rows is a first observation and
  produces no deltas by definition.
* **verifications** (REQ-POSTURE-003) — one row per fix-verification act, plus the
  finding-status transitions the loop applies: a verified-absent finding is *closed*
  (with evidence linked to the original finding), a regression is *reopened*. Both the
  memory and the SQL stores apply the same transitions so tests drive one behaviour.
* **criticality** (REQ-POSTURE-006) — the CMDB-imported business criticality per host,
  read back as a plain ``host → tier`` mapping for the attack-path composer.

Both implementations live here with the same behaviour, because a workflow that only
works against Postgres is a workflow nobody tests. The store never invents policy: what
counts as "verified absence" is decided by :mod:`arachne.posture.verify`, what criticality
does to a path by :mod:`arachne.analyzer.paths`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, Auditor
from arachne.data import models
from arachne.data.models import utcnow
from arachne.data.scan_store import as_utc
from arachne.posture.state import CloudSnapshot

__all__ = [
    "BaselineRecord",
    "CriticalityEntry",
    "MemoryPostureStore",
    "PostureStore",
    "SqlPostureStore",
    "VerificationRecord",
]

#: Finding status marking "closed by fix verification" (S23). The rest of the vocabulary
#: (``open``/``verified``/``fp``/``merged``) is the analyzer's (ADR-02).
FINDING_CLOSED = "closed"

VERIFICATION_OUTCOMES = ("verified", "still-open", "reopened")


def _now(moment: datetime | None) -> datetime:
    return (moment or datetime.now(UTC)).astimezone(UTC)


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    """One stored baseline row: the last-seen state of one resource."""

    scope_key: str
    resource_key: str
    provider: str
    service: str
    config: dict[str, Any]
    config_hash: str
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    """One fix-verification act (see :mod:`arachne.posture.verify`)."""

    id: int | None
    finding_id: int | None
    scan_id: int | None
    outcome: str
    detail: str | None = None
    evidence_id: int | None = None
    actor: str = "system"
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class CriticalityEntry:
    """One CMDB-imported criticality row (REQ-POSTURE-006)."""

    host: str
    tier: int
    name: str | None = None
    source: str = "import"
    note: str | None = None


class PostureStore(Protocol):
    """The continuous-posture persistence boundary."""

    # ------------------------------------------------------------------ baselines
    def baselines(self, scope_key: str) -> tuple[BaselineRecord, ...]: ...

    def save_baselines(
        self, scope_key: str, snapshot: CloudSnapshot, *, now: datetime | None = None
    ) -> int: ...

    def forget_scope(self, scope_key: str) -> int: ...

    # ------------------------------------------------------------------ verifications
    def finding(self, finding_id: int) -> dict[str, Any] | None: ...

    def set_finding_status(
        self, finding_id: int, status: str, *, evidence: dict[str, Any] | None = None
    ) -> int | None: ...

    def record_verification(
        self,
        *,
        finding_id: int | None,
        scan_id: int | None,
        outcome: str,
        detail: str | None = None,
        evidence_id: int | None = None,
        actor: str = "system",
        now: datetime | None = None,
    ) -> VerificationRecord: ...

    def verifications_for(self, finding_id: int) -> tuple[VerificationRecord, ...]: ...

    def closed_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]: ...

    def open_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]: ...

    # ------------------------------------------------------------------ criticality
    def import_criticality(
        self, entries: Iterable[CriticalityEntry], *, actor: str = "system"
    ) -> int: ...

    def criticality_index(self) -> dict[str, int]: ...

    # ------------------------------------------------------------------ reporting reads
    def verification_counts(self) -> dict[str, int]: ...

    def baseline_inventory(self) -> dict[str, Any]: ...


# --------------------------------------------------------------------------- memory


class MemoryPostureStore:
    """An in-process posture store: the same behaviour without a database (tests)."""

    def __init__(self, *, auditor: Auditor | None = None) -> None:
        self.auditor = auditor
        self._baselines: dict[str, dict[str, BaselineRecord]] = {}
        self._findings: dict[int, dict[str, Any]] = {}
        self._verifications: list[VerificationRecord] = []
        self._criticality: dict[str, CriticalityEntry] = {}
        self._next_verification = 1
        #: Evidence rows the store wrote (finding_id → payloads), mirroring the SQL store's
        #: evidence linkage so tests can assert on the same shape.
        self.evidence: dict[int, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------ baselines
    def baselines(self, scope_key: str) -> tuple[BaselineRecord, ...]:
        return tuple(self._baselines.get(scope_key, {}).values())

    def save_baselines(
        self, scope_key: str, snapshot: CloudSnapshot, *, now: datetime | None = None
    ) -> int:
        from arachne.posture.state import config_hash as hash_of

        moment = _now(now)
        existing_rows = self._baselines.get(scope_key, {})
        current = {record.resource_key: record for record in existing_rows.values()}
        for resource in snapshot.resources:
            existing = current.get(resource.key)
            self._baselines.setdefault(scope_key, {})[resource.key] = BaselineRecord(
                scope_key=scope_key,
                resource_key=resource.key,
                provider=resource.provider,
                service=resource.service,
                config=dict(resource.config),
                config_hash=hash_of(resource.config),
                first_seen_at=existing.first_seen_at if existing else moment,
                last_seen_at=moment,
            )
        for key in [key for key in current if key not in {r.key for r in snapshot.resources}]:
            del self._baselines[scope_key][key]
        return len(snapshot.resources)

    def forget_scope(self, scope_key: str) -> int:
        return len(self._baselines.pop(scope_key, {}))

    # ------------------------------------------------------------------ findings
    def seed_finding(self, record: dict[str, Any]) -> dict[str, Any]:
        """Register a finding the memory store can act on (the SQL store reads rows)."""
        finding_id = int(record["id"])
        self._findings[finding_id] = dict(record)
        return self._findings[finding_id]

    def finding(self, finding_id: int) -> dict[str, Any] | None:
        row = self._findings.get(finding_id)
        return dict(row) if row else None

    def set_finding_status(
        self, finding_id: int, status: str, *, evidence: dict[str, Any] | None = None
    ) -> int | None:
        row = self._findings.get(finding_id)
        if row is None:
            return None
        row["status"] = status
        evidence_id: int | None = None
        if evidence is not None:
            evidence_id = len(self.evidence.get(finding_id, ())) + 1
            self.evidence.setdefault(finding_id, []).append(dict(evidence))
            refs = [item for item in row.get("evidence_refs", []) if item is not None]
            refs.append(evidence_id)
            row["evidence_refs"] = refs
        return evidence_id

    # ------------------------------------------------------------------ verifications
    def record_verification(
        self,
        *,
        finding_id: int | None,
        scan_id: int | None,
        outcome: str,
        detail: str | None = None,
        evidence_id: int | None = None,
        actor: str = "system",
        now: datetime | None = None,
    ) -> VerificationRecord:
        if outcome not in VERIFICATION_OUTCOMES:
            msg = f"verification outcome must be one of {VERIFICATION_OUTCOMES}, got {outcome!r}"
            raise ValueError(msg)
        record = VerificationRecord(
            id=self._next_verification,
            finding_id=finding_id,
            scan_id=scan_id,
            outcome=outcome,
            detail=detail,
            evidence_id=evidence_id,
            actor=actor,
            created_at=_now(now),
        )
        self._next_verification += 1
        self._verifications.append(record)
        return record

    def verifications_for(self, finding_id: int) -> tuple[VerificationRecord, ...]:
        return tuple(item for item in self._verifications if item.finding_id == finding_id)

    def closed_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        return self._by_status(FINDING_CLOSED, check_key=check_key, asset_value=asset_value)

    def open_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        return self._by_status("open", check_key=check_key, asset_value=asset_value)

    def _by_status(
        self, status: str, *, check_key: str | None, asset_value: str | None
    ) -> tuple[dict[str, Any], ...]:
        out = [
            dict(row)
            for row in self._findings.values()
            if row.get("status") == status
            and (check_key is None or row.get("check_key") == check_key)
            and (asset_value is None or row.get("asset_value") == asset_value)
        ]
        out.sort(key=lambda item: int(item["id"]))
        return tuple(out)

    # ------------------------------------------------------------------ criticality
    def import_criticality(
        self, entries: Iterable[CriticalityEntry], *, actor: str = "system"
    ) -> int:
        count = 0
        for entry in entries:
            if not 1 <= int(entry.tier) <= 4:
                msg = f"criticality tier must be 1..4, got {entry.tier!r} for {entry.host!r}"
                raise ValueError(msg)
            self._criticality[entry.host.strip().lower()] = entry
            count += 1
        if self.auditor is not None and count:
            self.auditor.record(
                AuditAction.POSTURE_CMDB_IMPORTED,
                target="cmdb",
                meta={"rows": count, "actor": actor},
            )
        return count

    def criticality_index(self) -> dict[str, int]:
        return {host: entry.tier for host, entry in self._criticality.items()}

    # ------------------------------------------------------------------ reporting reads
    def verification_counts(self) -> dict[str, int]:
        counts = {"verified": 0, "reopened": 0, "still-open": 0}
        for record in self._verifications:
            if record.outcome in counts:
                counts[record.outcome] += 1
        return counts

    def baseline_inventory(self) -> dict[str, Any]:
        scopes: dict[str, int] = {}
        by_service: dict[str, int] = {}
        for records in self._baselines.values():
            for record in records.values():
                scopes[record.scope_key] = scopes.get(record.scope_key, 0) + 1
                by_service[record.service] = by_service.get(record.service, 0) + 1
        return {
            "scopes": sorted(scopes.items()),
            "by_service": by_service,
        }


# --------------------------------------------------------------------------- sql


class SqlPostureStore:
    """``PostureStore`` over the three S23 tables (``posture_baselines`` et al)."""

    def __init__(self, session_factory: sessionmaker[Session], *, auditor: Auditor | None = None):
        self._session_factory = session_factory
        self.auditor = auditor

    # ------------------------------------------------------------------ baselines
    def baselines(self, scope_key: str) -> tuple[BaselineRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(models.PostureBaseline)
                .where(models.PostureBaseline.scope_key == scope_key)
                .order_by(models.PostureBaseline.resource_key)
            ).all()
            return tuple(
                BaselineRecord(
                    scope_key=row.scope_key,
                    resource_key=row.resource_key,
                    provider=row.provider,
                    service=row.service,
                    config=dict(row.config_json or {}),
                    config_hash=row.config_hash,
                    first_seen_at=as_utc(row.first_seen_at),
                    last_seen_at=as_utc(row.last_seen_at),
                )
                for row in rows
            )

    def save_baselines(
        self, scope_key: str, snapshot: CloudSnapshot, *, now: datetime | None = None
    ) -> int:
        from arachne.posture.state import config_hash as hash_of

        moment = _now(now)
        with self._session_factory() as session:
            rows = {
                row.resource_key: row
                for row in session.scalars(
                    select(models.PostureBaseline).where(
                        models.PostureBaseline.scope_key == scope_key
                    )
                ).all()
            }
            seen: set[str] = set()
            for resource in snapshot.resources:
                seen.add(resource.key)
                row = rows.get(resource.key)
                digest = hash_of(resource.config)
                if row is None:
                    session.add(
                        models.PostureBaseline(
                            scope_key=scope_key,
                            resource_key=resource.key,
                            provider=resource.provider,
                            service=resource.service,
                            config_json=dict(resource.config),
                            config_hash=digest,
                            first_seen_at=moment,
                            last_seen_at=moment,
                        )
                    )
                else:
                    row.provider = resource.provider
                    row.service = resource.service
                    row.config_json = dict(resource.config)
                    row.config_hash = digest
                    row.last_seen_at = moment
            stale = [row for key, row in rows.items() if key not in seen]
            for row in stale:
                session.delete(row)
            session.commit()
        return len(snapshot.resources)

    def forget_scope(self, scope_key: str) -> int:
        with self._session_factory() as session:
            rows = session.scalars(
                select(models.PostureBaseline).where(models.PostureBaseline.scope_key == scope_key)
            ).all()
            for row in rows:
                session.delete(row)
            session.commit()
        return len(rows)

    # ------------------------------------------------------------------ findings
    def finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(models.Finding, finding_id)
            if row is None:
                return None
            check_key: str | None = None
            asset_value: str | None = None
            if row.check_id is not None:
                check = session.get(models.Check, row.check_id)
                if check is not None:
                    check_key = f"{check.module}/{check.name}@{check.version}"
            if row.asset_id is not None:
                asset = session.get(models.Asset, row.asset_id)
                if asset is not None:
                    asset_value = str(asset.value)
            return {
                "id": int(row.id),
                "scan_id": int(row.scan_id),
                "title": str(row.title),
                "status": str(row.status),
                "severity": row.severity,
                "check_key": check_key,
                "asset_value": asset_value,
                "evidence_refs": list(row.evidence_refs_json or []),
            }

    def set_finding_status(
        self, finding_id: int, status: str, *, evidence: dict[str, Any] | None = None
    ) -> int | None:
        with self._session_factory() as session:
            row = session.get(models.Finding, finding_id)
            if row is None:
                return None
            row.status = status
            evidence_id: int | None = None
            if evidence is not None:
                item = models.Evidence(
                    finding_id=row.id,
                    kind=str(evidence.get("kind") or "note"),
                    payload_json=dict(evidence.get("payload") or {}),
                    sha256=evidence.get("sha256"),
                    size_bytes=evidence.get("size_bytes"),
                    storage="inline",
                )
                session.add(item)
                session.flush()
                evidence_id = int(item.id)
                refs = [ref for ref in (row.evidence_refs_json or []) if ref is not None]
                refs.append(evidence_id)
                row.evidence_refs_json = refs
            session.commit()
            return evidence_id

    # ------------------------------------------------------------------ verifications
    def record_verification(
        self,
        *,
        finding_id: int | None,
        scan_id: int | None,
        outcome: str,
        detail: str | None = None,
        evidence_id: int | None = None,
        actor: str = "system",
        now: datetime | None = None,
    ) -> VerificationRecord:
        if outcome not in VERIFICATION_OUTCOMES:
            msg = f"verification outcome must be one of {VERIFICATION_OUTCOMES}, got {outcome!r}"
            raise ValueError(msg)
        with self._session_factory() as session:
            row = models.PostureVerification(
                finding_id=finding_id,
                scan_id=scan_id,
                outcome=outcome,
                detail=detail,
                evidence_id=evidence_id,
                actor=actor,
                created_at=_now(now),
            )
            session.add(row)
            session.commit()
            return VerificationRecord(
                id=int(row.id),
                finding_id=finding_id,
                scan_id=scan_id,
                outcome=outcome,
                detail=detail,
                evidence_id=evidence_id,
                actor=actor,
                created_at=as_utc(row.created_at),
            )

    def verifications_for(self, finding_id: int) -> tuple[VerificationRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(models.PostureVerification)
                .where(models.PostureVerification.finding_id == finding_id)
                .order_by(models.PostureVerification.id)
            ).all()
            return tuple(
                VerificationRecord(
                    id=int(row.id),
                    finding_id=row.finding_id,
                    scan_id=row.scan_id,
                    outcome=row.outcome,
                    detail=row.detail,
                    evidence_id=row.evidence_id,
                    actor=row.actor,
                    created_at=as_utc(row.created_at),
                )
                for row in rows
            )

    def closed_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        return self._findings_by_status(FINDING_CLOSED, check_key, asset_value)

    def open_findings(
        self, *, check_key: str | None = None, asset_value: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        return self._findings_by_status("open", check_key, asset_value)

    def _findings_by_status(
        self, status: str, check_key: str | None, asset_value: str | None
    ) -> tuple[dict[str, Any], ...]:
        out: list[dict[str, Any]] = []
        with self._session_factory() as session:
            rows = session.scalars(
                select(models.Finding)
                .where(models.Finding.status == status)
                .order_by(models.Finding.id)
            ).all()
            for row in rows:
                resolved_key: str | None = None
                resolved_asset: str | None = None
                if row.check_id is not None:
                    check = session.get(models.Check, row.check_id)
                    if check is not None:
                        resolved_key = f"{check.module}/{check.name}@{check.version}"
                if row.asset_id is not None:
                    asset = session.get(models.Asset, row.asset_id)
                    if asset is not None:
                        resolved_asset = str(asset.value)
                if check_key is not None and resolved_key != check_key:
                    continue
                if asset_value is not None and resolved_asset != asset_value:
                    continue
                out.append(
                    {
                        "id": int(row.id),
                        "scan_id": int(row.scan_id),
                        "title": str(row.title),
                        "status": str(row.status),
                        "severity": row.severity,
                        "check_key": resolved_key,
                        "asset_value": resolved_asset,
                        "evidence_refs": list(row.evidence_refs_json or []),
                    }
                )
        return tuple(out)

    # ------------------------------------------------------------------ criticality
    def import_criticality(
        self, entries: Iterable[CriticalityEntry], *, actor: str = "system"
    ) -> int:
        count = 0
        with self._session_factory() as session:
            for entry in entries:
                tier = int(entry.tier)
                if not 1 <= tier <= 4:
                    msg = f"criticality tier must be 1..4, got {entry.tier!r} for {entry.host!r}"
                    raise ValueError(msg)
                host = entry.host.strip().lower()
                row = session.scalar(
                    select(models.AssetCriticality).where(models.AssetCriticality.host == host)
                )
                if row is None:
                    session.add(
                        models.AssetCriticality(
                            host=host,
                            tier=tier,
                            name=entry.name,
                            source=entry.source,
                            note=entry.note,
                            created_at=utcnow(),
                            updated_at=utcnow(),
                        )
                    )
                else:
                    row.tier = tier
                    row.name = entry.name
                    row.source = entry.source
                    row.note = entry.note
                    row.updated_at = utcnow()
                count += 1
            session.commit()
        if self.auditor is not None and count:
            self.auditor.record(
                AuditAction.POSTURE_CMDB_IMPORTED,
                target="cmdb",
                meta={"rows": count, "actor": actor},
            )
        return count

    def criticality_index(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = session.scalars(select(models.AssetCriticality)).all()
        return {row.host: int(row.tier) for row in rows}

    # ------------------------------------------------------------------ reporting reads
    def verification_counts(self) -> dict[str, int]:
        counts = {"verified": 0, "reopened": 0, "still-open": 0}
        with self._session_factory() as session:
            rows = session.scalars(select(models.PostureVerification.outcome)).all()
        for outcome in rows:
            if outcome in counts:
                counts[str(outcome)] += 1
        return counts

    def baseline_inventory(self) -> dict[str, Any]:
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    models.PostureBaseline.scope_key,
                    models.PostureBaseline.service,
                )
            ).all()
        scopes: dict[str, int] = {}
        by_service: dict[str, int] = {}
        for scope_key, service in rows:
            scopes[scope_key] = scopes.get(scope_key, 0) + 1
            by_service[service] = by_service.get(service, 0) + 1
        return {
            "scopes": sorted(scopes.items()),
            "by_service": by_service,
        }
