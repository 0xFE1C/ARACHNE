"""The tamper-evidence store: the audit chain, the seals and the verifier (S25).

This is the data-layer half of REQ-TRUST-005. The arithmetic lives in
:mod:`arachne.core.integrity`; what lives here is everything that needs a database:

* :class:`SqlAuditChain` — appends to the ``audit_log`` hash chain. It is both the
  ``AuditChain`` the :class:`~arachne.core.audit.Auditor` calls and the **durable audit
  sink**: computing a link's digest and writing the row are one transaction, because a
  reserved-but-unwritten sequence number would look exactly like a deleted row to the
  verifier. Two replicas racing for the same ``seq`` are separated by the unique
  constraint on that column — the loser retries and reads the new tail.
* :class:`IntegrityService` — the operator-facing acts: ``seal_scan`` (the signed manifest
  of a completed scan's findings and evidence) and ``anchor`` (a signed checkpoint of the
  chain's head). The scan machine calls ``seal_scan`` on completion; the CLI calls both.
* :class:`IntegrityVerifier` — walks the chain, checks the anchors, re-verifies every row
  signature and recomputes every seal, and returns one
  :class:`~arachne.core.integrity.IntegrityReport`.

The verifier is deliberately *additive* in what it checks and *explicit* about what it
could not: a seal whose scan has been pruned by retention is reported as a note (the rows
were deleted on purpose, under a policy), while a seal whose scan is still present and
whose rows are not is reported as a deletion. Conflating those two would either cry wolf on
every retention run or hide a real deletion behind one.

Every read goes through SQLAlchemy's expression language with bound parameters — the same
discipline the rest of ``arachne.data`` follows (ADR-03). Ordering and range filtering over
the chain are done in Python where a scalar subquery would otherwise be needed, which keeps
the statements identical on SQLite and Postgres.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError as SaIntegrityError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, Auditor
from arachne.core.errors import IntegrityError
from arachne.core.integrity import (
    AUDIT_DOMAIN,
    EVIDENCE_DOMAIN,
    FINDING_DOMAIN,
    GENESIS_HASH,
    Anchor,
    AuditLink,
    EvidenceHashRecord,
    IntegrityIssue,
    IntegrityReport,
    audit_payload,
    chain_digest,
    evidence_hash_records,
    payload_digest,
    reconstruct_audit_payload,
    seal_manifest,
    sign_anchor,
    sign_row,
    sign_seal,
    verify_anchors,
    verify_audit_chain,
    verify_row_signature,
    verify_seal,
)
from arachne.core.logging import get_logger
from arachne.core.signing import Signer
from arachne.data.models import AuditLog, Evidence, Finding, IntegrityAnchor, IntegritySeal, Scan
from arachne.data.scan_store import as_utc

__all__ = [
    "AnchorRecord",
    "IntegrityService",
    "IntegrityVerifier",
    "SealRecord",
    "SqlAuditChain",
]

_logger = get_logger("data.integrity")

#: How many times a chain append retries a lost race for the next ``seq``.
_MAX_CHAIN_ATTEMPTS = 12

#: Default cap on rows re-verified per table by :meth:`IntegrityVerifier.verify`. A
#: verification run is an operator act, not a scan-time hot path, but an unbounded pass over
#: a multi-million-row store would be a denial of service against the operator's own tool.
DEFAULT_ROW_LIMIT = 20_000


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One stored chain checkpoint."""

    id: int | None
    seq: int
    hash: str
    signature: str | None
    reason: str
    created_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seq": self.seq,
            "hash": self.hash,
            "signature": self.signature,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass(frozen=True, slots=True)
class SealRecord:
    """One stored scan seal."""

    id: int | None
    scan_id: int | None
    digest: str
    row_count: int
    signature: str | None
    reason: str
    created_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "digest": self.digest,
            "row_count": self.row_count,
            "signature": self.signature,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def _chained_rows(session: Session, *, limit: int | None = None) -> list[AuditLog]:
    """Every chained audit row, oldest position first.

    Rows written before S25 (and rows an unchained sink wrote) have no ``seq``; they are
    filtered out here rather than in the statement, so the query is the same statement on
    both backends and the caller sees one deterministic order.
    """
    statement = select(AuditLog).order_by(AuditLog.id)
    if limit is not None:
        statement = statement.limit(limit)
    rows = session.scalars(statement).all()
    chained = [row for row in rows if row.seq is not None]
    chained.sort(key=lambda row: int(row.seq or 0))
    return chained


def _newest_chained(session: Session) -> AuditLog | None:
    head = session.scalar(select(func.max(AuditLog.seq)))
    if head is None:
        return None
    return session.scalar(select(AuditLog).where(AuditLog.seq == head))


class SqlAuditChain:
    """The database-backed audit hash chain, and the durable audit sink (S25).

    ``append`` computes the next link from the stored tail and writes the row, in one
    transaction, retrying if another writer claimed the same ``seq`` first. The row's
    ``meta_json`` is the chained payload itself (minus the chain fields), so
    :class:`IntegrityVerifier` recomputes the digest from the stored bytes.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: Signer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signer = signer

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str, str, str | None]:
        """Reserve the next position, persist the row, and return the chain fields."""
        body = audit_payload(payload)
        last_error: Exception | None = None
        for _ in range(_MAX_CHAIN_ATTEMPTS):
            with self._session_factory() as session:
                tail_row = _newest_chained(session)
                seq = int(tail_row.seq) + 1 if tail_row is not None and tail_row.seq else 1
                prev = (
                    str(tail_row.hash) if tail_row is not None and tail_row.hash else GENESIS_HASH
                )
                digest = chain_digest(seq, prev, body)
                signature = (
                    self._signer.sign(AUDIT_DOMAIN, digest.encode("ascii"))
                    if self._signer is not None
                    else None
                )
                session.add(
                    AuditLog(
                        ts=_as_datetime(body.get("ts")),
                        actor=str(body.get("actor") or "system"),
                        action=str(body.get("action") or "unknown"),
                        meta_json=dict(body),
                        seq=seq,
                        prev_hash=prev,
                        hash=digest,
                        signature=signature,
                    )
                )
                try:
                    session.commit()
                except SaIntegrityError as exc:  # another writer took this seq first
                    session.rollback()
                    last_error = exc
                    continue
                return seq, prev, digest, signature
        msg = (
            "could not append to the audit chain after "
            f"{_MAX_CHAIN_ATTEMPTS} attempts (last error: {last_error})"
        )
        raise IntegrityError(msg)

    def tail(self) -> tuple[int, str] | None:
        """``(seq, hash)`` of the newest chained row, or ``None`` for an empty chain."""
        with self._session_factory() as session:
            row = _newest_chained(session)
        if row is None or row.seq is None or not row.hash:
            return None
        return int(row.seq), str(row.hash)


class IntegrityService:
    """The seal/anchor/verify seam (S25, REQ-TRUST-005)."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: Signer | None = None,
        auditor: Auditor | None = None,
        anchor_every: int = 0,
        require_signatures: bool = False,
    ) -> None:
        self._session_factory = session_factory
        self.signer = signer
        self.auditor = auditor
        self.anchor_every = max(0, anchor_every)
        self.require_signatures = require_signatures

    # ------------------------------------------------------------------ acts
    def sign_finding(self, row: Mapping[str, Any]) -> str | None:
        """The signature for a finding row (``None`` without a deployment key)."""
        if self.signer is None:
            return None
        return sign_row(self.signer, FINDING_DOMAIN, row)

    def sign_evidence(self, row: Mapping[str, Any]) -> str | None:
        """The signature for an evidence row (``None`` without a deployment key)."""
        if self.signer is None:
            return None
        return sign_row(self.signer, EVIDENCE_DOMAIN, row)

    def seal_scan(self, scan_id: int, *, reason: str = "finish") -> SealRecord:
        """Sign and store the manifest of ``scan_id``'s findings and evidence.

        Sealing again recomputes the manifest from the rows that are present, so a
        deliberately re-analysed scan can be sealed twice and the newest seal is the one a
        later verification compares against.
        """
        with self._session_factory() as session:
            if session.get(Scan, scan_id) is None:
                # A seal is only meaningful for a scan that exists; refusing here keeps the
                # CLI's error actionable ("scan 42 does not exist") instead of surfacing a
                # foreign-key failure from the insert.
                msg = f"scan {scan_id} does not exist, so it cannot be sealed"
                raise IntegrityError(msg)
            findings = _finding_rows(session, scan_id)
            evidences = _evidence_rows(session, scan_id)
            digest, manifest, count = seal_manifest(findings, evidences)
            signature = sign_seal(self.signer, scan_id, digest, count) if self.signer else None
            existing = session.scalar(select(IntegritySeal).where(IntegritySeal.scan_id == scan_id))
            if existing is None:
                existing = IntegritySeal(
                    scan_id=scan_id,
                    digest=digest,
                    row_count=count,
                    manifest_json=list(manifest),
                    signature=signature,
                    reason=reason,
                    created_at=datetime.now(UTC),
                )
                session.add(existing)
            else:
                existing.digest = digest
                existing.row_count = count
                existing.manifest_json = list(manifest)
                existing.signature = signature
                existing.reason = reason
                existing.created_at = datetime.now(UTC)
            session.commit()
            record = _as_seal(existing)
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.INTEGRITY_SEALED,
                scan_id=scan_id,
                meta={
                    "digest": record.digest,
                    "rows": record.row_count,
                    "signed": record.signature is not None,
                    "reason": reason,
                },
            )
        return record

    def anchor(self, *, reason: str = "manual") -> AnchorRecord | None:
        """Write a signed checkpoint of the chain's current head.

        Returns ``None`` when the chain is empty (nothing to anchor) or when the head is
        already anchored — a second identical anchor adds no evidence and would make the
        anchor table grow without bound on a busy deployment.
        """
        with self._session_factory() as session:
            tail_row = _newest_chained(session)
            if tail_row is None or tail_row.seq is None or not tail_row.hash:
                return None
            seq, digest = int(tail_row.seq), str(tail_row.hash)
            newest = session.scalar(
                select(IntegrityAnchor).order_by(IntegrityAnchor.seq.desc()).limit(1)
            )
            if newest is not None and int(newest.seq) == seq and str(newest.hash) == digest:
                return _as_anchor(newest)
            row = IntegrityAnchor(
                seq=seq,
                hash=digest,
                signature=sign_anchor(self.signer, seq, digest) if self.signer else None,
                reason=reason,
                created_at=datetime.now(UTC),
            )
            session.add(row)
            session.commit()
            record = _as_anchor(row)
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.INTEGRITY_ANCHORED,
                meta={
                    "seq": record.seq,
                    "hash": record.hash,
                    "signed": record.signature is not None,
                    "reason": reason,
                },
            )
        return record

    def anchors(self, *, limit: int = 100) -> tuple[AnchorRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(IntegrityAnchor).order_by(IntegrityAnchor.seq.desc()).limit(limit)
            ).all()
        return tuple(_as_anchor(row) for row in rows)

    def seals(self, *, scan_id: int | None = None, limit: int = 500) -> tuple[SealRecord, ...]:
        with self._session_factory() as session:
            statement = select(IntegritySeal).order_by(IntegritySeal.id.desc()).limit(limit)
            if scan_id is not None:
                statement = statement.where(IntegritySeal.scan_id == scan_id)
            rows = session.scalars(statement).all()
        return tuple(_as_seal(row) for row in rows)

    def maybe_anchor(self, *, head_seq: int | None = None) -> AnchorRecord | None:
        """Anchor when the configured cadence says it is due.

        Called after a chain append, so the caller usually already knows the new ``seq``
        (``head_seq``); a direct call from the CLI omits it and lets the store read the tail.
        """
        if self.anchor_every <= 0:
            return None
        with self._session_factory() as session:
            head = head_seq
            if head is None:
                tail_row = _newest_chained(session)
                head = int(tail_row.seq) if tail_row is not None and tail_row.seq else None
            newest = session.scalar(select(func.max(IntegrityAnchor.seq)))
        if not head:
            return None
        if int(head) - int(newest or 0) >= self.anchor_every:
            return self.anchor(reason="auto")
        return None

    def verifier(self) -> IntegrityVerifier:
        return IntegrityVerifier(
            self._session_factory,
            signer=self.signer,
            require_signatures=self.require_signatures,
        )


class IntegrityVerifier:
    """Verify the chain, the anchors, the row signatures and the seals (S25)."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: Signer | None = None,
        require_signatures: bool = False,
    ) -> None:
        self._session_factory = session_factory
        self.signer = signer
        self.require_signatures = require_signatures

    def verify(
        self,
        *,
        scan_id: int | None = None,
        since_seq: int = 1,
        row_limit: int = DEFAULT_ROW_LIMIT,
    ) -> IntegrityReport:
        """One verification pass over everything the schema holds."""
        links = self.audit_links(since_seq=since_seq)
        reports: list[IntegrityReport] = [
            verify_audit_chain(
                links,
                signer=self.signer,
                require_signature=self.require_signatures,
                start_seq=(links[0].seq if links else 1),
            )
        ]
        if self.signer is not None or self.require_signatures:
            reports.append(self._verify_row_signatures(scan_id=scan_id, limit=row_limit))
        # WP-14 (REQ-PROOF-018): the chain's own record of each blob's content hash. Runs
        # whether or not a signer is configured — the chain detects the edit either way,
        # which is the point of recording the hash there rather than only on the row.
        reports.append(self._verify_evidence_hashes(links=links, scan_id=scan_id))
        reports.append(self._verify_seals(scan_id=scan_id))
        anchors = self.anchors()
        if anchors:
            reports.append(verify_anchors(anchors, links=links, signer=self.signer))
        report = IntegrityReport.combine(*reports)
        if not links:
            report = IntegrityReport(
                checked=report.checked,
                issues=report.issues,
                notes=(*report.notes, "no chained audit rows: nothing to verify"),
            )
        return report

    # ------------------------------------------------------------------ pieces
    def audit_links(self, *, since_seq: int = 1) -> tuple[AuditLink, ...]:
        """The stored chain as verifiable links, oldest first."""
        with self._session_factory() as session:
            rows = _chained_rows(session)
            return tuple(
                AuditLink(
                    seq=int(row.seq or 0),
                    prev_hash=str(row.prev_hash or GENESIS_HASH),
                    hash=str(row.hash or ""),
                    signature=row.signature,
                    payload=reconstruct_audit_payload(str(row.action), dict(row.meta_json or {})),
                )
                for row in rows
                if int(row.seq or 0) >= since_seq
            )

    def anchors(self) -> tuple[Anchor, ...]:
        with self._session_factory() as session:
            rows = session.scalars(select(IntegrityAnchor).order_by(IntegrityAnchor.seq)).all()
        return tuple(
            Anchor(
                id=int(row.id),
                seq=int(row.seq),
                hash=str(row.hash),
                signature=row.signature,
                created_at=row.created_at.isoformat() if row.created_at else None,
                reason=row.reason,
            )
            for row in rows
        )

    def _verify_row_signatures(self, *, scan_id: int | None, limit: int) -> IntegrityReport:
        issues: list[IntegrityIssue] = []
        checked = {"findings": 0, "evidences": 0}
        with self._session_factory() as session:
            findings = list(_finding_rows(session, scan_id, limit=limit))
            evidences = list(_evidence_rows(session, scan_id, limit=limit))
        for row in findings:
            checked["findings"] += 1
            issue = verify_row_signature(
                self.signer,
                FINDING_DOMAIN,
                row,
                _signature_of(row),
                subject=f"finding:{row.get('id')}",
                require_signature=self.require_signatures,
            )
            if issue is not None:
                issues.append(issue)
        for row in evidences:
            checked["evidences"] += 1
            issue = verify_row_signature(
                self.signer,
                EVIDENCE_DOMAIN,
                row,
                _signature_of(row),
                subject=f"evidence:{row.get('id')}",
                require_signature=self.require_signatures,
            )
            if issue is not None:
                issues.append(issue)
        return IntegrityReport(checked=checked, issues=tuple(issues))

    def _verify_evidence_hashes(
        self, *, links: Sequence[AuditLink], scan_id: int | None
    ) -> IntegrityReport:
        """Compare every recorded evidence content hash with the stored payload.

        ``evidence.captured`` records the digest of the stored (redacted) payload, and
        ``pii.remasked`` supersedes it when retention re-masks an older blob, so the map
        this compares against is the chain's latest statement about each blob.

        A missing row is classified before it is an issue. Retention deletes evidence on
        purpose — a pruned scan takes its findings and evidence with it — and a verifier that
        called that tampering would cry wolf on every pruning run (the same distinction
        :meth:`_verify_seals` makes). So a blob whose *scan* is gone is a note; a blob whose
        *finding* is gone while its scan survives is a note too (the findings policy cascaded
        it); a blob whose finding is still there is a deletion, and a blob whose payload
        digest no longer matches the recorded one is ``evidence.mismatch``.
        """
        recorded = evidence_hash_records(links)
        if scan_id is not None:
            recorded = {
                key: value for key, value in recorded.items() if value.scan_id in (None, scan_id)
            }
        if not recorded:
            return IntegrityReport(checked={"evidence_hashes": 0})
        issues: list[IntegrityIssue] = []
        notes: list[str] = []
        checked = 0
        with self._session_factory() as session:
            for evidence_id, record in sorted(recorded.items()):
                row = session.get(Evidence, evidence_id)
                if row is None:
                    note = self._explain_missing_evidence(session, record)
                    if note is not None:
                        notes.append(note)
                        continue
                    issues.append(
                        IntegrityIssue(
                            check="evidence",
                            kind="deleted",
                            subject=f"evidence:{evidence_id}",
                            detail=(
                                f"the chain recorded content hash"
                                f" {record.digest[:16]}... at seq {record.seq} "
                                f"({record.action}) but the row is gone from a scan that "
                                f"still exists"
                            ),
                        )
                    )
                    continue
                checked += 1
                stored = payload_digest(dict(row.payload_json or {}))
                if stored == record.digest:
                    continue
                issues.append(
                    IntegrityIssue(
                        check="evidence",
                        kind="mismatch",
                        subject=f"evidence:{evidence_id}",
                        detail=(
                            f"recorded at seq {record.seq} ({record.action}) as"
                            f" {record.digest[:16]}..., the stored payload now hashes to"
                            f" {stored[:16]}... — the blob was edited after capture"
                        ),
                    )
                )
        return IntegrityReport(
            checked={"evidence_hashes": checked}, issues=tuple(issues), notes=tuple(notes)
        )

    def _explain_missing_evidence(self, session: Session, record: EvidenceHashRecord) -> str | None:
        """Why a recorded blob is absent, when the answer is "retention" (a note, not an issue).

        The only absence a verifier can attribute without guessing is a *pruned scan*: the
        policy removed the parent, and the evidence went with it. A blob missing under a scan
        that still exists is reported as a deletion — the same call :meth:`_verify_seals`
        makes for a sealed row, and deliberately so: the two must not disagree about whether
        an absent row is an event.
        """
        if record.scan_id is None or session.get(Scan, record.scan_id) is None:
            return (
                f"evidence {record.evidence_id} was recorded but its scan was pruned "
                "(retention); its blob is gone by policy, not by tampering"
            )
        return None

    def _verify_seals(self, *, scan_id: int | None) -> IntegrityReport:
        issues: list[IntegrityIssue] = []
        notes: list[str] = []
        checked = {"seals": 0}
        with self._session_factory() as session:
            statement = select(IntegritySeal).order_by(IntegritySeal.id)
            if scan_id is not None:
                statement = statement.where(IntegritySeal.scan_id == scan_id)
            seals = session.scalars(statement).all()
            for seal in seals:
                checked["seals"] += 1
                if seal.scan_id is None:
                    notes.append(
                        f"seal {seal.id} has no scan (its scan was pruned); "
                        "its rows are gone by policy, not by tampering"
                    )
                    continue
                if session.get(Scan, int(seal.scan_id)) is None:
                    notes.append(
                        f"scan {seal.scan_id} was pruned (retention); its seal is kept as "
                        "the record of what was removed"
                    )
                    continue
                findings = list(_finding_rows(session, int(seal.scan_id)))
                evidences = list(_evidence_rows(session, int(seal.scan_id)))
                report = verify_seal(
                    {
                        "scan_id": seal.scan_id,
                        "digest": seal.digest,
                        "row_count": seal.row_count,
                        "manifest_json": list(seal.manifest_json or []),
                        "signature": seal.signature,
                    },
                    findings=findings,
                    evidences=evidences,
                    signer=self.signer,
                    require_signature=self.require_signatures,
                )
                checked["sealed_rows"] = checked.get("sealed_rows", 0) + int(
                    report.checked.get("sealed_rows", 0)
                )
                issues.extend(report.issues)
        return IntegrityReport(checked=checked, issues=tuple(issues), notes=tuple(notes))


# --------------------------------------------------------------------------- projections
def _finding_rows(
    session: Session, scan_id: int | None, *, limit: int | None = None
) -> Sequence[dict[str, Any]]:
    statement = select(Finding).order_by(Finding.id)
    if scan_id is not None:
        statement = statement.where(Finding.scan_id == scan_id)
    if limit is not None:
        statement = statement.limit(limit)
    rows = session.scalars(statement).all()
    return [
        {
            "id": int(row.id),
            "scan_id": int(row.scan_id),
            "check_id": row.check_id,
            "asset_id": row.asset_id,
            "title": row.title,
            "severity": row.severity,
            "confidence": row.confidence,
            "status": row.status,
            # ``as_utc`` matters: SQLite stores a timezone-aware datetime without its
            # offset and reads back a *naive* one, so signing the raw value would differ
            # from the verifier's recomputation and every row would look tampered.
            "created_at": as_utc(row.created_at),
            "signature": row.signature,
        }
        for row in rows
    ]


def _evidence_rows(
    session: Session, scan_id: int | None, *, limit: int | None = None
) -> Sequence[dict[str, Any]]:
    statement = (
        select(Evidence).join(Finding, Evidence.finding_id == Finding.id).order_by(Evidence.id)
    )
    if scan_id is not None:
        statement = statement.where(Finding.scan_id == scan_id)
    if limit is not None:
        statement = statement.limit(limit)
    rows = session.scalars(statement).all()
    return [
        {
            "id": int(row.id),
            "finding_id": row.finding_id,
            "kind": row.kind,
            "payload_json": dict(row.payload_json or {}),
            # ``as_utc`` matters: SQLite stores a timezone-aware datetime without its
            # offset and reads back a *naive* one, so signing the raw value would differ
            # from the verifier's recomputation and every row would look tampered.
            "created_at": as_utc(row.created_at),
            "signature": row.signature,
            "region": row.region,
        }
        for row in rows
    ]


def _signature_of(row: Mapping[str, Any]) -> str | None:
    value = row.get("signature")
    return str(value) if value else None


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:  # pragma: no cover - a hand-edited payload
            return datetime.now(UTC)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _as_anchor(row: IntegrityAnchor) -> AnchorRecord:
    return AnchorRecord(
        id=int(row.id),
        seq=int(row.seq),
        hash=str(row.hash),
        signature=row.signature,
        reason=str(row.reason),
        created_at=row.created_at,
    )


def _as_seal(row: IntegritySeal) -> SealRecord:
    return SealRecord(
        id=int(row.id),
        scan_id=int(row.scan_id) if row.scan_id is not None else None,
        digest=str(row.digest),
        row_count=int(row.row_count),
        signature=row.signature,
        reason=str(row.reason),
        created_at=row.created_at,
    )
