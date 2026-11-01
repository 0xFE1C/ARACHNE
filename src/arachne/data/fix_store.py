"""Persistence for remediation-as-code proposals (S27, area FIX).

One row per proposal, and the store's job is narrow on purpose: create it once, read it
back, and apply a *whitelisted* field update. It does not decide anything — which plan fits
a finding is :mod:`arachne.fix.plans`, what a diff may contain is :mod:`arachne.fix.safety`,
and whether a proposal may advance is :mod:`arachne.fix.proposal`. Keeping the policy out of
the store is what lets the same workflow run against the in-memory twin in tests and against
Postgres in a deployment.

Two properties the store does own:

* **the whitelist.** ``update`` refuses an unknown column, so a caller cannot quietly write
  a status the engine never set or a field the audit trail does not know about;
* **the credential-free diff.** ``diff_text`` is stored exactly as the engine emitted it —
  already masked — and nothing here re-derives or re-renders it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.data import models
from arachne.data.models import utcnow
from arachne.data.scan_store import as_utc

__all__ = [
    "ARTIFACT_FIELDS",
    "UPDATABLE_FIELDS",
    "FixProposalRecord",
    "FixProposalStore",
    "MemoryFixProposalStore",
    "SqlFixProposalStore",
]

#: The columns ``update`` may write. Anything else is refused rather than silently ignored.
UPDATABLE_FIELDS: frozenset[str] = frozenset(
    {
        "status",
        "kind",
        "plan_id",
        "author",
        "parity",
        "summary",
        "rationale",
        "flagged_reason",
        "targets_json",
        "diff_text",
        "verbatim",
        "manual_apply_required",
        "safety_json",
        "self_scan_json",
        "repo_name",
        "repo_path",
        "branch",
        "base_commit",
        "commit",
        "default_branch",
        "pr_artifact",
        "test_command_json",
        "test_outcome",
        "test_output",
        "approved_by",
        "approved_at",
        "rejected_by",
        "applied_by",
        "applied_at",
        "verification_id",
        "verification_outcome",
        "verification_scan_id",
        "meta_json",
    }
)

#: The fields a caller may supply when creating a proposal.
ARTIFACT_FIELDS: frozenset[str] = UPDATABLE_FIELDS | frozenset(
    {"finding_id", "scan_id", "check_key", "asset_value", "requested_by"}
)


@dataclass(frozen=True, slots=True)
class FixProposalRecord:
    """One stored proposal."""

    id: int | None
    status: str
    finding_id: int | None = None
    scan_id: int | None = None
    check_key: str | None = None
    asset_value: str | None = None
    kind: str = "none"
    plan_id: str | None = None
    author: str = "none"
    parity: str = "n/a"
    summary: str = ""
    rationale: str | None = None
    flagged_reason: str | None = None
    targets_json: dict[str, Any] = field(default_factory=dict)
    diff_text: str | None = None
    verbatim: bool = True
    manual_apply_required: bool = False
    safety_json: dict[str, Any] = field(default_factory=dict)
    self_scan_json: dict[str, Any] = field(default_factory=dict)
    repo_name: str | None = None
    repo_path: str | None = None
    branch: str | None = None
    base_commit: str | None = None
    commit: str | None = None
    default_branch: str | None = None
    pr_artifact: str | None = None
    test_command_json: dict[str, Any] = field(default_factory=dict)
    test_outcome: str | None = None
    test_output: str | None = None
    requested_by: str = "system"
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejected_by: str | None = None
    applied_by: str | None = None
    applied_at: datetime | None = None
    verification_id: int | None = None
    verification_outcome: str | None = None
    verification_scan_id: int | None = None
    meta_json: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def targets(self) -> tuple[str, ...]:
        raw = self.targets_json.get("files")
        if isinstance(raw, (list, tuple)):
            return tuple(str(item) for item in raw)
        return ()

    @property
    def skipped(self) -> tuple[str, ...]:
        raw = self.targets_json.get("skipped")
        if isinstance(raw, (list, tuple)):
            return tuple(str(item) for item in raw)
        return ()

    @property
    def has_artifact(self) -> bool:
        return bool(self.diff_text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "check_key": self.check_key,
            "asset_value": self.asset_value,
            "kind": self.kind,
            "plan_id": self.plan_id,
            "author": self.author,
            "parity": self.parity,
            "summary": self.summary,
            "flagged_reason": self.flagged_reason,
            "targets": list(self.targets),
            "branch": self.branch,
            "commit": self.commit,
            "pr_artifact": self.pr_artifact,
            "test_outcome": self.test_outcome,
            "self_scan": dict(self.self_scan_json),
            "safety": dict(self.safety_json),
            "verification_outcome": self.verification_outcome,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "applied_by": self.applied_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FixProposalStore(Protocol):
    """What the engine needs from storage."""

    def add(self, **fields: Any) -> FixProposalRecord: ...

    def proposal(self, proposal_id: int) -> FixProposalRecord | None: ...

    def proposals(
        self,
        *,
        finding_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> tuple[FixProposalRecord, ...]: ...

    def update(self, proposal_id: int, **changes: Any) -> FixProposalRecord | None: ...

    def counts(self) -> dict[str, int]: ...


def _now(moment: datetime | None) -> datetime:
    return (moment or datetime.now(UTC)).astimezone(UTC)


class MemoryFixProposalStore:
    """The in-process twin (same behaviour, so the workflow is testable without Postgres)."""

    def __init__(self) -> None:
        self._rows: dict[int, FixProposalRecord] = {}
        self._next = 1

    def add(self, **fields: Any) -> FixProposalRecord:
        _reject_unknown(fields, ARTIFACT_FIELDS)
        payload: dict[str, Any] = {
            key: value for key, value in fields.items() if key in ARTIFACT_FIELDS
        }
        payload.setdefault("status", "proposed")
        payload["created_at"] = _now(None)
        payload["updated_at"] = payload["created_at"]
        record = FixProposalRecord(id=self._next, **payload)
        self._rows[self._next] = record
        self._next += 1
        return record

    def proposal(self, proposal_id: int) -> FixProposalRecord | None:
        return self._rows.get(proposal_id)

    def proposals(
        self,
        *,
        finding_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> tuple[FixProposalRecord, ...]:
        rows = [
            row
            for row in self._rows.values()
            if (finding_id is None or row.finding_id == finding_id)
            and (status is None or row.status == status)
        ]
        rows.sort(key=lambda item: int(item.id or 0), reverse=True)
        return tuple(rows[: max(1, limit)])

    def update(self, proposal_id: int, **changes: Any) -> FixProposalRecord | None:
        _reject_unknown(changes, UPDATABLE_FIELDS)
        current = self._rows.get(proposal_id)
        if current is None:
            return None
        from dataclasses import replace

        payload = {
            key: value for key, value in changes.items() if key in UPDATABLE_FIELDS
        }
        payload["updated_at"] = _now(None)
        updated = replace(current, **payload)
        self._rows[proposal_id] = updated
        return updated

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for row in self._rows.values():
            out[row.status] = out.get(row.status, 0) + 1
        return out


class SqlFixProposalStore:
    """The SQLAlchemy implementation (SQLite and Postgres identically)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def add(self, **fields: Any) -> FixProposalRecord:
        _reject_unknown(fields, ARTIFACT_FIELDS)
        with self._session_factory() as session:
            row = models.FixProposal(status="proposed")
            for key, value in fields.items():
                if key in ARTIFACT_FIELDS:
                    setattr(row, key, value)
            session.add(row)
            session.commit()
            return _record(row)

    def proposal(self, proposal_id: int) -> FixProposalRecord | None:
        with self._session_factory() as session:
            row = session.get(models.FixProposal, proposal_id)
            return _record(row) if row is not None else None

    def proposals(
        self,
        *,
        finding_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> tuple[FixProposalRecord, ...]:
        with self._session_factory() as session:
            statement = select(models.FixProposal)
            if finding_id is not None:
                statement = statement.where(models.FixProposal.finding_id == finding_id)
            if status is not None:
                statement = statement.where(models.FixProposal.status == status)
            statement = statement.order_by(models.FixProposal.id.desc()).limit(max(1, limit))
            return tuple(_record(row) for row in session.scalars(statement).all())

    def update(self, proposal_id: int, **changes: Any) -> FixProposalRecord | None:
        _reject_unknown(changes, UPDATABLE_FIELDS)
        with self._session_factory() as session:
            row = session.get(models.FixProposal, proposal_id)
            if row is None:
                return None
            for key, value in changes.items():
                if key in UPDATABLE_FIELDS:
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            return _record(row)

    def counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = session.scalars(select(models.FixProposal)).all()
        out: dict[str, int] = {}
        for row in rows:
            key = str(row.status)
            out[key] = out.get(key, 0) + 1
        return out


def _reject_unknown(fields: Mapping[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(fields) - allowed)
    if unknown:
        msg = f"unknown fix-proposal field(s): {', '.join(unknown)}"
        raise ValueError(msg)


def _record(row: models.FixProposal) -> FixProposalRecord:
    return FixProposalRecord(
        id=int(row.id),
        finding_id=int(row.finding_id) if row.finding_id is not None else None,
        scan_id=int(row.scan_id) if row.scan_id is not None else None,
        check_key=row.check_key,
        asset_value=row.asset_value,
        kind=str(row.kind),
        status=str(row.status),
        plan_id=row.plan_id,
        author=str(row.author),
        parity=str(row.parity),
        summary=str(row.summary or ""),
        rationale=row.rationale,
        flagged_reason=row.flagged_reason,
        targets_json=dict(row.targets_json or {}),
        diff_text=row.diff_text,
        verbatim=bool(row.verbatim),
        manual_apply_required=bool(row.manual_apply_required),
        safety_json=dict(row.safety_json or {}),
        self_scan_json=dict(row.self_scan_json or {}),
        repo_name=row.repo_name,
        repo_path=row.repo_path,
        branch=row.branch,
        base_commit=row.base_commit,
        commit=row.commit,
        default_branch=row.default_branch,
        pr_artifact=row.pr_artifact,
        test_command_json=dict(row.test_command_json or {}),
        test_outcome=row.test_outcome,
        test_output=row.test_output,
        requested_by=str(row.requested_by or "system"),
        approved_by=row.approved_by,
        approved_at=as_utc(row.approved_at) if row.approved_at is not None else None,
        rejected_by=row.rejected_by,
        applied_by=row.applied_by,
        applied_at=as_utc(row.applied_at) if row.applied_at is not None else None,
        verification_id=(
            int(row.verification_id) if row.verification_id is not None else None
        ),
        verification_outcome=row.verification_outcome,
        verification_scan_id=(
            int(row.verification_scan_id) if row.verification_scan_id is not None else None
        ),
        meta_json=dict(row.meta_json or {}),
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
    )
