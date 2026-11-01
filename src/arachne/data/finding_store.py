"""Candidate findings and their evidence (F-02-08, F-09-02).

A detection check yields :class:`~arachne.core.results.CheckResult` objects; the checks step
(``arachne.modules.handlers``) turns each one into a durable row here. Two deliberate
choices:

* **Only the implemented checks are versioned in the ``checks`` table** — ``(module, name,
  version)`` is the key, so what a report says about a finding is what actually ran
  (F-02-10).
* **Severity is left NULL.** The module stack does not score (ADR-02); the analyzer (S5/S9)
  fills ``severity``, ``remediation_id`` and ``status`` transitions later. Writing a
  severity here would quietly move analysis into the checks.

The candidate's ``detail`` and its check provenance are stored as a ``note`` evidence row
rather than as a new column: the evidence store's schema is the spec's schema,
and "here is why this was reported, with its research reference" *is* evidence. Every
candidate therefore also satisfies F-02-08's "structured evidence" requirement even when the
check itself captured no request.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.integrity import EVIDENCE_DOMAIN, FINDING_DOMAIN, sign_row
from arachne.core.metrics import REGISTRY
from arachne.core.results import CheckResult, Evidence, confidence_percent
from arachne.core.signing import DeploymentSigner
from arachne.data.evidence_service import EVIDENCE_STUB_KEY, serialized_size
from arachne.data.models import Asset as AssetRow
from arachne.data.models import Check, Finding
from arachne.data.models import Evidence as EvidenceRow
from arachne.data.quota import StorageQuota
from arachne.data.scan_store import as_utc

__all__ = [
    "CandidateRecord",
    "EvidenceRecord",
    "FindingStore",
    "MemoryFindingStore",
    "SqlFindingStore",
]


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One stored evidence row."""

    id: int | None
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    sha256: str | None = None
    created_at: datetime | None = None
    #: Logical payload size in bytes (S20, REQ-DATA-003); ``None`` for rows written before S20.
    size_bytes: int | None = None
    #: ``inline`` / ``local`` / ``s3`` — where the payload physically lives (S20).
    storage: str | None = None
    #: The backend key when the payload is offloaded; the API's download route uses it.
    storage_key: str | None = None

    @property
    def offloaded(self) -> bool:
        """True when the payload is a stub pointing at an evidence object (S20)."""
        return bool(self.storage_key) and self.storage not in (None, "inline")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "payload": self.payload,
            "sha256": self.sha256,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "size_bytes": self.size_bytes,
            "storage": self.storage,
            "storage_key": self.storage_key,
        }


@dataclass(frozen=True, slots=True)
class CandidateRecord:
    """One stored candidate finding, with its check provenance and evidence.

    ``confidence`` is on the report's **0-100** scale even for a
    candidate the analyzer has not touched: the check's own 0-1 value is converted at this
    boundary, so the column has one meaning at every stage of a scan's life.
    """

    id: int | None
    scan_id: int
    title: str
    status: str
    confidence: float | None = None
    severity: str | None = None
    check_id: int | None = None
    asset_id: int | None = None
    #: The asset row's identity, carried alongside the id so the analyzer (which may not touch
    #: the ORM) sees ``asset.kind``/``asset.value`` without a second query.
    asset_kind: str | None = None
    asset_value: str | None = None
    check_key: str | None = None
    module: str | None = None
    research_ref: str | None = None
    #: When the candidate row was written. The report needs a ``first_seen`` and the store
    #: already has one; carrying it here saves the report layer a second query (S8).
    created_at: datetime | None = None
    evidence: tuple[EvidenceRecord, ...] = ()

    @property
    def is_candidate(self) -> bool:
        """True for a candidate exposure (the analyzer decides the final severity)."""
        return self.severity is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "status": self.status,
            "confidence": self.confidence,
            "severity": self.severity,
            "check": self.check_key,
            "module": self.module,
            "research_ref": self.research_ref,
            "asset": {"kind": self.asset_kind, "value": self.asset_value},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "evidence": [item.to_dict() for item in self.evidence],
        }


class FindingStore(Protocol):
    """Persistence boundary for candidates, so the orchestrator can run without a database."""

    def record_checks(self, metadata: Iterable[Any]) -> dict[str, int]:
        """Upsert ``checks`` rows keyed by ``module/name@version``; return key → row id."""
        ...

    def record_candidate(
        self,
        scan_id: int,
        *,
        result: CheckResult,
        check_id: int | None,
        asset_id: int | None,
        asset: tuple[str, str] | None = None,
    ) -> CandidateRecord: ...

    def count_candidates(self, scan_id: int) -> int: ...

    def list_candidates(self, scan_id: int) -> tuple[CandidateRecord, ...]: ...


def _note_payload(result: CheckResult, asset: str | None) -> dict[str, Any]:
    """The provenance note stored with every candidate (F-02-08)."""
    return {
        "detail": result.detail,
        "check": result.check,
        "module": result.module,
        "status": result.status,
        "asset": asset,
        "confidence": result.confidence,
    }


def _evidence_storage(item: Evidence) -> tuple[int, str, str | None]:
    """``(logical bytes, storage, storage_key)`` for one evidence item (S20, REQ-DATA-002).

    An inline payload is measured here; an *offloaded* one carries its logical size, backend
    and key in its stub (``EvidenceService.stage`` wrote them), and the size is the number the
    quota already counted — so the row and the ledger agree.
    """
    payload = item.payload
    if payload.get(EVIDENCE_STUB_KEY):
        declared = payload.get("size")
        size = int(declared) if isinstance(declared, int) and not isinstance(declared, bool) else 0
        backend = payload.get("backend")
        key = payload.get("key")
        return size, str(backend or "unknown"), str(key) if key else None
    return serialized_size(payload), "inline", None


def _count_proof(item: Evidence) -> None:
    """Proof-level counters (REQ-OPS-003): how many findings reached which rung."""
    if item.kind != "proof":
        return
    level = str(item.payload.get("level") or "unknown")
    REGISTRY.increment("arachne_proof_findings_total", {"level": level})
    if item.payload.get("change") or item.payload.get("cleanup"):
        cleanup = str(item.payload.get("cleanup") or "unknown")
        REGISTRY.increment("arachne_proof_state_changes_total", {"cleanup": cleanup})


def _evidence_rows(evidence: Iterable[Evidence]) -> tuple[EvidenceRecord, ...]:
    return tuple(
        EvidenceRecord(
            id=None,
            kind=item.kind,
            payload=dict(item.payload),
            sha256=item.sha256,
            created_at=item.captured_at,
        )
        for item in evidence
    )


class MemoryFindingStore:
    """In-memory candidate store (dry runs, unit tests, a scan with no database)."""

    def __init__(self) -> None:
        self._checks: dict[str, int] = {}
        self._candidates: dict[int, list[CandidateRecord]] = {}
        self._next_check = 1
        self._next_candidate = 1

    def record_checks(self, metadata: Iterable[Any]) -> dict[str, int]:
        for item in metadata:
            self._checks.setdefault(item.key, self._next_check)
            if self._checks[item.key] == self._next_check:
                self._next_check += 1
        return dict(self._checks)

    def record_candidate(
        self,
        scan_id: int,
        *,
        result: CheckResult,
        check_id: int | None,
        asset_id: int | None,
        asset: tuple[str, str] | None = None,
    ) -> CandidateRecord:
        record = CandidateRecord(
            id=self._next_candidate,
            scan_id=scan_id,
            title=result.title,
            status="open",
            confidence=confidence_percent(result.confidence),
            check_id=check_id,
            asset_id=asset_id,
            asset_kind=asset[0] if asset else None,
            asset_value=asset[1] if asset else None,
            check_key=result.check,
            module=result.module,
            created_at=(result.evidence[0].captured_at if result.evidence else datetime.now(UTC)),
            evidence=_evidence_rows(result.evidence),
        )
        self._next_candidate += 1
        self._candidates.setdefault(scan_id, []).append(record)
        return record

    def count_candidates(self, scan_id: int) -> int:
        return len(self._candidates.get(scan_id, ()))

    def list_candidates(self, scan_id: int) -> tuple[CandidateRecord, ...]:
        return tuple(self._candidates.get(scan_id, ()))


class SqlFindingStore:
    """``FindingStore`` over the ``checks``/``findings``/``evidences`` tables.

    ``signer`` (S25, REQ-TRUST-005) signs each finding and evidence row's identity as it is
    written; ``region`` (S25, REQ-RESIL-004) stamps each evidence row with the deployment's
    region so a later read from another region can be refused. Both default to off, which is
    the pre-S25 behaviour.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: DeploymentSigner | None = None,
        region: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signer = signer
        self._region = region

    # ------------------------------------------------------------------ checks
    def record_checks(self, metadata: Iterable[Any]) -> dict[str, int]:
        """Upsert the registry's checks, so a report can name the version that ran."""
        ids: dict[str, int] = {}
        with self._session_factory() as session:
            for item in metadata:
                row = session.scalar(
                    select(Check).where(
                        Check.module == item.module,
                        Check.name == item.name,
                        Check.version == item.version,
                    )
                )
                if row is None:
                    row = Check(
                        module=item.module,
                        name=item.name,
                        version=item.version,
                        description=item.description,
                        cwe=item.cwe,
                        research_ref=item.research_ref,
                    )
                    session.add(row)
                    session.flush()
                else:
                    # Metadata can be corrected between releases without a version bump of
                    # the scanner; the row is the live description of the check that ran.
                    row.description = item.description
                    row.cwe = item.cwe
                    row.research_ref = item.research_ref
                ids[item.key] = int(row.id)
            session.commit()
        return ids

    def check_ids(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = session.scalars(select(Check)).all()
        return {f"{row.module}/{row.name}@{row.version}": int(row.id) for row in rows}

    # ------------------------------------------------------------------ candidates
    def record_candidate(
        self,
        scan_id: int,
        *,
        result: CheckResult,
        check_id: int | None,
        asset_id: int | None,
        asset: tuple[str, str] | None = None,
    ) -> CandidateRecord:
        with self._session_factory() as session:
            if asset is None and asset_id is not None:
                asset_row = session.get(AssetRow, asset_id)
                if asset_row is not None:
                    asset = (str(asset_row.kind), str(asset_row.value))
            finding = Finding(
                scan_id=scan_id,
                check_id=check_id,
                asset_id=asset_id,
                title=result.title[:512],
                # ADR-02: the module does not score. severity stays NULL until the analyzer
                # runs (S5), which is also what makes "candidate" observable in the store.
                severity=None,
                confidence=confidence_percent(result.confidence),
                status="open",
                evidence_refs_json=[],
            )
            session.add(finding)
            session.flush()
            if self._signer is not None:
                # The signature covers the row's *identity* (id, provenance, title, when);
                # the fields that legitimately change later (severity, status) are covered by
                # the scan's seal instead — see core.integrity module docstring.
                finding.signature = sign_row(
                    self._signer,
                    FINDING_DOMAIN,
                    {
                        "id": finding.id,
                        "scan_id": scan_id,
                        "check_id": check_id,
                        "asset_id": asset_id,
                        "title": finding.title,
                        "created_at": finding.created_at,
                    },
                )

            stored: list[EvidenceRecord] = []
            rows: list[EvidenceRow] = []
            accounted = 0
            for item in result.evidence:
                size_bytes, storage, storage_key = _evidence_storage(item)
                accounted += size_bytes
                row = EvidenceRow(
                    finding_id=finding.id,
                    kind=item.kind,
                    payload_json=dict(item.payload),
                    sha256=item.sha256,
                    size_bytes=size_bytes,
                    storage=storage,
                    storage_key=storage_key,
                    region=self._region,
                )
                session.add(row)
                session.flush()
                if self._signer is not None:
                    row.signature = sign_row(
                        self._signer,
                        EVIDENCE_DOMAIN,
                        {
                            "id": row.id,
                            "finding_id": finding.id,
                            "kind": item.kind,
                            "payload_json": dict(item.payload),
                            "created_at": row.created_at,
                        },
                    )
                rows.append(row)
                _count_proof(item)
            note = EvidenceRow(
                finding_id=finding.id,
                kind="note",
                payload_json=_note_payload(result, None),
                sha256=None,
                size_bytes=len(json.dumps(_note_payload(result, None), default=str)),
                storage="inline",
                region=self._region,
            )
            session.add(note)
            session.flush()
            if self._signer is not None:
                note.signature = sign_row(
                    self._signer,
                    EVIDENCE_DOMAIN,
                    {
                        "id": note.id,
                        "finding_id": finding.id,
                        "kind": "note",
                        "payload_json": dict(note.payload_json),
                        "created_at": note.created_at,
                    },
                )
            rows.append(note)
            accounted += int(note.size_bytes or 0)
            session.flush()

            # The quota ledger (REQ-DATA-003) is maintained in the same transaction as the
            # rows it accounts for, so a committed finding always has its bytes counted and
            # a rolled-back one never does.
            project_id = StorageQuota.project_for_scan(session, scan_id)
            if project_id is not None:
                StorageQuota.add_usage(session, project_id, accounted)

            for row in rows:
                stored.append(
                    EvidenceRecord(
                        id=int(row.id),
                        kind=str(row.kind),
                        payload=dict(row.payload_json),
                        sha256=row.sha256,
                        created_at=as_utc(row.created_at),
                        size_bytes=row.size_bytes,
                        storage=row.storage,
                        storage_key=row.storage_key,
                    )
                )
            finding.evidence_refs_json = [item.id for item in stored]
            session.commit()
            return CandidateRecord(
                id=int(finding.id),
                scan_id=scan_id,
                title=str(finding.title),
                status=str(finding.status),
                confidence=finding.confidence,
                severity=finding.severity,
                check_id=check_id,
                asset_id=asset_id,
                asset_kind=asset[0] if asset else None,
                asset_value=asset[1] if asset else None,
                check_key=result.check,
                module=result.module,
                created_at=as_utc(finding.created_at),
                evidence=tuple(stored),
            )

    def count_candidates(self, scan_id: int) -> int:
        with self._session_factory() as session:
            total = session.scalar(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
        return int(total or 0)

    def list_candidates(self, scan_id: int) -> tuple[CandidateRecord, ...]:
        with self._session_factory() as session:
            findings = session.scalars(
                select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
            ).all()
            out: list[CandidateRecord] = []
            for finding in findings:
                evidence_rows = session.scalars(
                    select(EvidenceRow)
                    .where(EvidenceRow.finding_id == finding.id)
                    .order_by(EvidenceRow.id)
                ).all()
                check_key: str | None = None
                module: str | None = None
                research_ref: str | None = None
                asset_kind: str | None = None
                asset_value: str | None = None
                if finding.asset_id is not None:
                    identity = _asset_identity(self._session_factory, finding.asset_id)
                    if identity is not None:
                        asset_kind, asset_value = identity
                if finding.check_id is not None:
                    check = session.get(Check, finding.check_id)
                    if check is not None:
                        check_key = f"{check.module}/{check.name}@{check.version}"
                        module = str(check.module)
                        research_ref = check.research_ref
                out.append(
                    CandidateRecord(
                        id=int(finding.id),
                        scan_id=int(finding.scan_id),
                        title=str(finding.title),
                        status=str(finding.status),
                        confidence=finding.confidence,
                        severity=finding.severity,
                        check_id=finding.check_id,
                        asset_id=finding.asset_id,
                        asset_kind=asset_kind,
                        asset_value=asset_value,
                        check_key=check_key,
                        module=module,
                        research_ref=research_ref,
                        created_at=as_utc(finding.created_at),
                        evidence=tuple(
                            EvidenceRecord(
                                id=int(row.id),
                                kind=str(row.kind),
                                payload=dict(row.payload_json),
                                sha256=row.sha256,
                                created_at=as_utc(row.created_at),
                                size_bytes=row.size_bytes,
                                storage=row.storage,
                                storage_key=row.storage_key,
                            )
                            for row in evidence_rows
                        ),
                    )
                )
        return tuple(out)


def _asset_identity(
    session_factory: sessionmaker[Session], asset_id: int
) -> tuple[str, str] | None:
    """``(kind, value)`` of an asset row, or ``None`` when it has gone away."""
    from arachne.data.models import Asset as AssetRow

    with session_factory() as session:
        row = session.get(AssetRow, asset_id)
        if row is None:
            return None
        return str(row.kind), str(row.value)


def candidate_summary(records: Iterable[CandidateRecord]) -> Mapping[str, int]:
    """Count candidates by module — the shape a report's summary section wants."""
    counts: dict[str, int] = {}
    for record in records:
        key = record.module or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts
