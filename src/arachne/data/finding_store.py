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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, Auditor
from arachne.core.integrity import (
    EVIDENCE_DOMAIN,
    FINDING_DOMAIN,
    payload_digest,
    sign_row,
)
from arachne.core.metrics import REGISTRY
from arachne.core.results import CheckResult, Evidence, confidence_percent
from arachne.core.signing import DeploymentSigner
from arachne.data.evidence_service import EVIDENCE_STUB_KEY, serialized_size
from arachne.data.models import Asset as AssetRow
from arachne.data.models import Check, Finding
from arachne.data.models import Evidence as EvidenceRow
from arachne.data.models import FindingVerification as FindingVerificationRow
from arachne.data.quota import StorageQuota
from arachne.data.scan_store import as_utc
from arachne.data.verification import (
    VerificationRecord,
    append_verification,
    level_rank,
    record_for_result,
)

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
    #: The finding's current verification record (WP-13, REQ-PROOF-015). ``None`` means the
    #: finding carries none — which the report renders as ``unverified`` at severity ``info``.
    verification: VerificationRecord | None = None
    #: Every verification record for the finding, oldest first (REQ-PROOF-016's history).
    verifications: tuple[VerificationRecord, ...] = ()

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
            "verification": self.verification.to_dict() if self.verification else None,
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

    def find_candidate(self, finding_id: int) -> CandidateRecord | None:
        """One candidate by id, or ``None`` (WP-13's re-verification entry point)."""
        ...

    def record_verification(self, record: VerificationRecord) -> VerificationRecord:
        """Append a verification record and make it the finding's current one (WP-13)."""
        ...


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


def _capture_lines(rows: Iterable[EvidenceRow], *, scan_id: int) -> tuple[dict[str, Any], ...]:
    """The audit payload for one batch of stored evidence rows (WP-14, REQ-PROOF-018).

    One entry per row, built from the **stored** payload: ``sha256`` is the digest a verifier
    recomputes from ``payload_json`` (what ``verify-chain`` compares), and ``blob_sha256`` is
    the object digest an offloaded row's stub declares, so a rewritten claim about the object
    is detectable even though the object itself is not read here.
    """
    lines: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row.payload_json or {})
        declared = payload.get("sha256")
        lines.append(
            {
                "evidence_id": int(row.id),
                "scan_id": scan_id,
                "kind": str(row.kind),
                "storage": str(row.storage or "inline"),
                "size": int(row.size_bytes or 0),
                "sha256": payload_digest(payload),
                "blob_sha256": str(declared) if isinstance(declared, str) and declared else None,
            }
        )
    return tuple(lines)


def _evidence_rows(
    evidence: Iterable[Evidence], *, first_id: int | None = None
) -> tuple[EvidenceRecord, ...]:
    """The evidence rows of one candidate, optionally given minted ids.

    ``first_id`` exists because an AI contribution must cite the evidence it relied on
    (REQ-AGENT-008, WP-15), and a citation has to name something. The SQL store gets row ids
    from the database; :class:`MemoryFindingStore` mints them here, in capture order, so a
    memory-backed scan can satisfy the same contract as a persisted one. Without an id the
    fact is real evidence but unaddressable, and no AI stage may cite it.
    """
    rows: list[EvidenceRecord] = []
    for offset, item in enumerate(evidence):
        rows.append(
            EvidenceRecord(
                id=None if first_id is None else first_id + offset,
                kind=item.kind,
                payload=dict(item.payload),
                sha256=item.sha256,
                created_at=item.captured_at,
            )
        )
    return tuple(rows)


class MemoryFindingStore:
    """In-memory candidate store (dry runs, unit tests, a scan with no database)."""

    def __init__(self) -> None:
        self._checks: dict[str, int] = {}
        self._candidates: dict[int, list[CandidateRecord]] = {}
        self._next_check = 1
        self._next_candidate = 1
        #: ``check key → version`` so a memory-backed candidate records the same
        #: ``check_version`` a SQL-backed one does (WP-13).
        self._check_versions: dict[int, str] = {}
        self._verifications: dict[int, list[VerificationRecord]] = {}
        self._next_verification = 1
        #: WP-15: evidence ids for a memory-backed scan. A citation must name a row that
        #: exists, so the store that mints candidate ids mints these too.
        self._next_evidence = 1

    def _record_evidence(self, evidence: Iterable[Evidence]) -> tuple[EvidenceRecord, ...]:
        rows = _evidence_rows(evidence, first_id=self._next_evidence)
        self._next_evidence += len(rows)
        return rows

    def record_checks(self, metadata: Iterable[Any]) -> dict[str, int]:
        for item in metadata:
            self._checks.setdefault(item.key, self._next_check)
            if self._checks[item.key] == self._next_check:
                self._next_check += 1
            self._check_versions[self._checks[item.key]] = str(item.version)
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
        identifier = self._next_candidate
        record = CandidateRecord(
            id=identifier,
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
            evidence=self._record_evidence(result.evidence),
        )
        self._next_candidate += 1
        verification = record_for_result(
            result,
            check_version=self._check_versions.get(check_id) if check_id is not None else None,
            verified_at=record.created_at or datetime.now(UTC),
            finding_id=identifier,
            scan_id=scan_id,
        )
        self._verifications[identifier] = [verification]
        self._candidates.setdefault(scan_id, []).append(
            replace(record, verification=verification, verifications=(verification,))
        )
        return self._candidates[scan_id][-1]

    def count_candidates(self, scan_id: int) -> int:
        return len(self._candidates.get(scan_id, ()))

    def list_candidates(self, scan_id: int) -> tuple[CandidateRecord, ...]:
        return tuple(self._candidates.get(scan_id, ()))

    def find_candidate(self, finding_id: int) -> CandidateRecord | None:
        for candidates in self._candidates.values():
            for candidate in candidates:
                if candidate.id == finding_id:
                    return candidate
        return None

    def record_verification(self, record: VerificationRecord) -> VerificationRecord:
        if record.finding_id is None:
            msg = "a verification record must name the finding it belongs to"
            raise ValueError(msg)
        history = self._verifications.setdefault(int(record.finding_id), [])
        if record.parent_id is not None:
            parent = next((item for item in history if item.id == record.parent_id), None)
            if parent is not None and level_rank(record.level) > level_rank(parent.level):
                msg = (
                    f"refusing to persist a re-verification at {record.level} above its "
                    f"parent {parent.level}"
                )
                raise ValueError(msg)
        stored = replace(record, id=self._next_verification)
        self._next_verification += 1
        history.append(stored)
        for candidates in self._candidates.values():
            for index, candidate in enumerate(candidates):
                if candidate.id != stored.finding_id:
                    continue
                candidates[index] = replace(
                    candidate,
                    verification=stored,
                    verifications=tuple(history),
                )
        return stored


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
        auditor: Auditor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signer = signer
        self._region = region
        #: WP-14 (REQ-PROOF-018): the audit trail every evidence blob's content hash is
        #: recorded in at capture. ``None`` means this store writes rows without a chain
        #: (the CLI's read-only paths, a unit test over a bare engine) — the rows are then
        #: verifiable by signature and seal only.
        self._auditor = auditor

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
            # WP-13 (REQ-PROOF-015): every finding persists a verification record, computed
            # here, in the same transaction as the finding it belongs to. The record is
            # derived from the *check's* result — there is no parameter through which an
            # analyzer or an AI contribution could supply one (PD-8).
            verification = _persist_verification(
                session,
                finding=finding,
                result=result,
                check_id=check_id,
                scan_id=scan_id,
            )
            # WP-14 (REQ-PROOF-018): capture the content hash of every blob this finding
            # just stored, from the *stored* payload (the redacted one — the row is the
            # unit of custody, and hashing what arrived before redaction would make the
            # recorded value unmatchable). Emitted after the commit, so the chain append
            # never holds a write transaction open beside this one.
            captures = _capture_lines(rows, scan_id=scan_id)
            session.commit()
            self._record_captures(captures)
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
                verification=verification,
                verifications=(verification,),
            )

    def _record_captures(self, captures: Iterable[Mapping[str, Any]]) -> None:
        """Record one ``evidence.captured`` chain line per stored blob (REQ-PROOF-018).

        One event per blob, not one per batch: an audit line naming a list of ids would make
        "which blob was captured, and when" unanswerable, and the chain is the custody record
        — this is the line ``verify-chain`` walks to find a mismatch.
        """
        if self._auditor is None:
            return
        for capture in captures:
            self._auditor.record(
                AuditAction.EVIDENCE_CAPTURED,
                scan_id=int(capture["scan_id"]),
                target=f"evidence:{capture['evidence_id']}",
                meta={
                    "evidence_id": int(capture["evidence_id"]),
                    "sha256": capture["sha256"],
                    "blob_sha256": capture["blob_sha256"],
                    "kind": capture["kind"],
                    "storage": capture["storage"],
                    "size": int(capture["size"]),
                },
            )

    def record_verification(self, record: VerificationRecord) -> VerificationRecord:
        """Append a verification record and make it the finding's current one (WP-13)."""
        with self._session_factory() as session:
            stored = append_verification(session, record)
            session.commit()
            return stored

    def count_candidates(self, scan_id: int) -> int:
        with self._session_factory() as session:
            total = session.scalar(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
        return int(total or 0)

    def find_candidate(self, finding_id: int) -> CandidateRecord | None:
        with self._session_factory() as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return None
            return _candidates_from_rows(session, [finding])[0]

    def list_candidates(self, scan_id: int) -> tuple[CandidateRecord, ...]:
        """Every candidate of one scan, in a **constant** number of queries (REQ-SCALE-012).

        This sits on the report, analysis, reasoning, posture, fix and benchmark hot paths.
        The pre-WP-17 shape issued one evidence query per finding, opened a *fresh session*
        per finding for the asset identity, and then one query each for the finding's current
        verification record and its whole history — roughly 3N+1 round trips whose count grew
        with the scan. Everything the loop needs is fetched here in a fixed set of batched
        queries and assembled in memory; see :func:`_candidates_from_rows`.
        """
        with self._session_factory() as session:
            findings = session.scalars(
                select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
            ).all()
            return _candidates_from_rows(session, findings)


def _candidates_from_rows(
    session: Session, findings: Sequence[Finding]
) -> tuple[CandidateRecord, ...]:
    """The findings as :class:`CandidateRecord`s, in a constant number of queries.

    Shared by :meth:`SqlFindingStore.list_candidates` and
    :meth:`SqlFindingStore.find_candidate`, so the two cannot describe one row differently.

    Five batched queries, whatever the length of ``findings``: the finding rows themselves
    (already loaded by the caller), their evidence rows, the assets and checks they name, and
    their verification rows. The grouping preserves the previous per-finding ordering
    (evidence and verification rows by id) and the previous field values exactly — a
    :meth:`list_candidates`/``find_candidate`` result is byte-for-byte what it was, which is
    what keeps every golden report unchanged.
    """
    if not findings:
        return ()
    finding_ids = [int(row.id) for row in findings]
    asset_ids = {int(row.asset_id) for row in findings if row.asset_id is not None}
    check_ids = {int(row.check_id) for row in findings if row.check_id is not None}
    # The current record is named by ``findings.verification_id`` and the history by
    # ``finding_verifications.finding_id``; one query covers both shapes.
    verification_ids = {
        int(row.verification_id) for row in findings if row.verification_id is not None
    }

    evidence_by_finding: dict[int, list[EvidenceRow]] = {fid: [] for fid in finding_ids}
    for evidence_row in session.scalars(
        select(EvidenceRow).where(EvidenceRow.finding_id.in_(finding_ids)).order_by(EvidenceRow.id)
    ):
        if evidence_row.finding_id is None:  # pragma: no cover - the column is non-null in a scan
            continue
        evidence_by_finding.setdefault(int(evidence_row.finding_id), []).append(evidence_row)

    assets: dict[int, tuple[str, str]] = {}
    if asset_ids:
        for asset_row in session.scalars(select(AssetRow).where(AssetRow.id.in_(asset_ids))):
            assets[int(asset_row.id)] = (str(asset_row.kind), str(asset_row.value))

    checks: dict[int, Check] = {}
    if check_ids:
        for check_row in session.scalars(select(Check).where(Check.id.in_(check_ids))):
            checks[int(check_row.id)] = check_row

    by_id: dict[int, VerificationRecord] = {}
    verifications_by_finding: dict[int, list[VerificationRecord]] = {fid: [] for fid in finding_ids}
    if finding_ids or verification_ids:
        verification_rows = session.scalars(
            select(FindingVerificationRow)
            .where(
                FindingVerificationRow.finding_id.in_(finding_ids)
                | FindingVerificationRow.id.in_(verification_ids)
            )
            .order_by(FindingVerificationRow.id)
        ).all()
        for verification_row in verification_rows:
            record = _row_to_verification(verification_row)
            by_id[int(verification_row.id)] = record
            verifications_by_finding.setdefault(int(verification_row.finding_id), []).append(record)

    out: list[CandidateRecord] = []
    for finding in findings:
        finding_id = int(finding.id)
        check = checks.get(int(finding.check_id)) if finding.check_id is not None else None
        identity = assets.get(int(finding.asset_id)) if finding.asset_id is not None else None
        current = (
            by_id.get(int(finding.verification_id)) if finding.verification_id is not None else None
        )
        out.append(
            CandidateRecord(
                id=finding_id,
                scan_id=int(finding.scan_id),
                title=str(finding.title),
                status=str(finding.status),
                confidence=finding.confidence,
                severity=finding.severity,
                check_id=finding.check_id,
                asset_id=finding.asset_id,
                asset_kind=identity[0] if identity else None,
                asset_value=identity[1] if identity else None,
                check_key=(
                    f"{check.module}/{check.name}@{check.version}" if check is not None else None
                ),
                module=str(check.module) if check is not None else None,
                research_ref=check.research_ref if check is not None else None,
                created_at=as_utc(finding.created_at),
                evidence=tuple(
                    EvidenceRecord(
                        id=int(evidence_row.id),
                        kind=str(evidence_row.kind),
                        payload=dict(evidence_row.payload_json),
                        sha256=evidence_row.sha256,
                        created_at=as_utc(evidence_row.created_at),
                        size_bytes=evidence_row.size_bytes,
                        storage=evidence_row.storage,
                        storage_key=evidence_row.storage_key,
                    )
                    for evidence_row in evidence_by_finding.get(finding_id, ())
                ),
                verification=current,
                verifications=tuple(verifications_by_finding.get(finding_id, ())),
            )
        )
    return tuple(out)


def _persist_verification(
    session: Session,
    *,
    finding: Finding,
    result: CheckResult,
    check_id: int | None,
    scan_id: int,
) -> VerificationRecord:
    """Write the finding's verification record and point the finding at it (REQ-PROOF-015).

    ``check_version`` comes from the ``checks`` row the candidate's ``check_id`` names, so
    the record says which version of the check established the claim — the question
    "did the check change since?" a re-verification needs.
    """
    version: str | None = None
    if check_id is not None:
        check = session.get(Check, check_id)
        if check is not None:
            version = str(check.version)
    verified_at = (
        result.evidence[0].captured_at if result.evidence else finding.created_at
    ) or datetime.now(UTC)
    record = record_for_result(
        result,
        check_version=version,
        verified_at=verified_at,
        finding_id=int(finding.id),
        scan_id=scan_id,
    )
    row = FindingVerificationRow(
        finding_id=int(finding.id),
        parent_id=None,
        scan_id=scan_id,
        status=record.status,
        level=record.level,
        method=record.method,
        observations_json=[dict(item) for item in record.observations],
        reproducibility_token=record.reproducibility_token,
        verified_at=record.verified_at or datetime.now(UTC),
        check_version=record.check_version,
        outcome=record.outcome,
    )
    session.add(row)
    session.flush()
    finding.verification_id = int(row.id)
    return replace(record, id=int(row.id))


def _row_to_verification(row: FindingVerificationRow) -> VerificationRecord:
    observations = row.observations_json if isinstance(row.observations_json, list) else []
    return VerificationRecord(
        id=int(row.id),
        finding_id=int(row.finding_id),
        parent_id=int(row.parent_id) if row.parent_id is not None else None,
        scan_id=int(row.scan_id) if row.scan_id is not None else None,
        status=str(row.status),
        level=str(row.level),
        method=str(row.method),
        observations=tuple(dict(item) for item in observations if isinstance(item, Mapping)),
        reproducibility_token=(
            str(row.reproducibility_token) if row.reproducibility_token else None
        ),
        verified_at=as_utc(row.verified_at),
        check_version=str(row.check_version) if row.check_version else None,
        outcome=str(row.outcome) if row.outcome else None,
    )


def candidate_summary(records: Iterable[CandidateRecord]) -> Mapping[str, int]:
    """Count candidates by module — the shape a report's summary section wants."""
    counts: dict[str, int] = {}
    for record in records:
        key = record.module or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts
