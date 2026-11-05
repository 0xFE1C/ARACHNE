"""Persistence for the quality workflow: suppression rules, risk acceptances, FP history (S21).

Three things live here because they are three views of one dataset — what an operator decided
about the findings a scanner keeps reporting:

* **suppressions** (REQ-QUAL-001/002) — versioned, attributed, commented rules. ``version`` comes
  from ``max(version) + 1`` over the table, which makes "suppressions vN" a real citation and
  keeps the sequence monotonic without a second counter to get out of step;
* **risk acceptances** (REQ-QUAL-003) — real findings, owned and justified, with an expiry, and
  :meth:`QualityStore.reopen_expired` is the method that *applies* the pure decision
  :func:`arachne.quality.acceptance.reopen_expired`: it re-opens the finding, stamps the
  acceptance and writes ``acceptance.expired`` to the audit trail;
* **the feedback history** (REQ-QUAL-004) — the same ``fp_feedback`` rows the tuner aggregates,
  read with their timestamps so a *trend* can be computed where a total cannot.

Both implementations are here, with the same behaviour, because a workflow that only works
against Postgres is a workflow nobody tests: the SQL store is the deployment's, and the memory
store is what the unit and integration tests drive.

The store never invents policy. Whether a suppression is *right*, whether an acceptance should
have been granted, whether a rising FP rate should pause a check — all of that is the
operator's; this module records the decision and applies the one consequence the requirement
does specify (an expiry re-opens its finding).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.analyzer.fp import FeedbackEvent
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.data import models
from arachne.quality.acceptance import ReopenDecision, RiskAcceptance
from arachne.quality.acceptance import reopen_expired as reopen_decisions
from arachne.quality.suppressions import Suppression, SuppressionSet

__all__ = [
    "MemoryQualityStore",
    "QualityStore",
    "SqlQualityStore",
]


class QualityStore(Protocol):
    """The quality workflow's persistence boundary."""

    def suppression_version(self) -> int: ...

    def add_suppression(
        self, suppression: Suppression, *, project_id: int | None = None
    ) -> Suppression: ...

    def list_suppressions(
        self,
        *,
        active_only: bool = True,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[Suppression, ...]: ...

    def revoke_suppression(self, suppression_id: int, *, actor: str) -> Suppression | None: ...

    def suppression_project(self, suppression_id: int) -> tuple[bool, int | None]: ...

    def add_acceptance(
        self, acceptance: RiskAcceptance, *, project_id: int | None = None
    ) -> RiskAcceptance: ...

    def list_acceptances(
        self,
        *,
        finding_id: int | None = None,
        active_only: bool = False,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[RiskAcceptance, ...]: ...

    def revoke_acceptance(self, acceptance_id: int, *, actor: str) -> RiskAcceptance | None: ...

    def acceptance_project(self, acceptance_id: int) -> tuple[bool, int | None]: ...

    def reopen_expired(self, *, now: datetime | None = None) -> tuple[ReopenDecision, ...]: ...

    def feedback_history(
        self, *, keys: Iterable[str] | None = None, since: datetime | None = None
    ) -> tuple[FeedbackEvent, ...]: ...

    def active_suppressions(self) -> SuppressionSet: ...


def _now(moment: datetime | None) -> datetime:
    return (moment or datetime.now(UTC)).astimezone(UTC)


# --------------------------------------------------------------------------- memory


class MemoryQualityStore:
    """An in-process store: the same behaviour without a database (tests, dry runs)."""

    def __init__(self, *, auditor: Auditor | None = None) -> None:
        self.auditor = auditor
        self._suppressions: list[Suppression] = []
        self._acceptances: list[RiskAcceptance] = []
        #: ``rule id → tenant`` parsed separately from the rule document (S26, REQ-ECOS-004):
        #: tenancy is an infrastructure concern, so the frozen domain model does not carry it.
        self._suppression_tenant: dict[int, int | None] = {}
        self._acceptance_tenant: dict[int, int | None] = {}
        #: ``finding_id → status`` overrides applied by an expiry (the memory analogue of the
        #: ``findings.status`` write).
        self.reopened: dict[int, str] = {}
        self._feedback: list[FeedbackEvent] = []
        self._next_suppression = 1
        self._next_acceptance = 1

    # ------------------------------------------------------------------ suppressions
    def suppression_version(self) -> int:
        return max((item.version for item in self._suppressions), default=0)

    def add_suppression(
        self, suppression: Suppression, *, project_id: int | None = None
    ) -> Suppression:
        stored = suppression.model_copy(
            update={"id": self._next_suppression, "version": self.suppression_version() + 1}
        )
        self._suppression_tenant[stored.id or 0] = project_id
        self._next_suppression += 1
        self._suppressions.append(stored)
        self._audit(
            AuditAction.SUPPRESSION_CHANGED,
            target=stored.check_id or f"finding:{stored.finding_id}",
            reason=stored.reason,
            meta={"change": "added", "version": stored.version, "kind": stored.kind},
        )
        return stored

    def list_suppressions(
        self,
        *,
        active_only: bool = True,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[Suppression, ...]:
        rows = [item for item in self._suppressions if item.active or not active_only]
        if project_id is not None:
            rows = [
                item
                for item in rows
                if self._suppression_tenant.get(item.id or 0) == project_id
                or (include_global and self._suppression_tenant.get(item.id or 0) is None)
            ]
        return tuple(reversed(rows))

    def revoke_suppression(self, suppression_id: int, *, actor: str) -> Suppression | None:
        for index, item in enumerate(self._suppressions):
            if item.id != suppression_id:
                continue
            revoked = item.model_copy(update={"active": False, "actor": actor})
            self._suppressions[index] = revoked
            self._audit(
                AuditAction.SUPPRESSION_CHANGED,
                target=revoked.check_id or f"finding:{revoked.finding_id}",
                reason=revoked.reason,
                meta={"change": "revoked", "version": revoked.version},
            )
            return revoked
        return None

    def active_suppressions(self) -> SuppressionSet:
        return SuppressionSet.of(self._suppressions)

    def suppression_project(self, suppression_id: int) -> tuple[bool, int | None]:
        """``(exists, project_id)`` for one rule — the tenant check a revoke route needs."""
        if suppression_id not in self._suppression_tenant:
            return (False, None)
        return (True, self._suppression_tenant[suppression_id])

    # ------------------------------------------------------------------ acceptances
    def add_acceptance(
        self, acceptance: RiskAcceptance, *, project_id: int | None = None
    ) -> RiskAcceptance:
        stored = acceptance.model_copy(update={"id": self._next_acceptance})
        self._acceptance_tenant[stored.id or 0] = project_id
        self._next_acceptance += 1
        self._acceptances.append(stored)
        self._audit(
            AuditAction.ACCEPTANCE_CHANGED,
            target=stored.check_id or f"finding:{stored.finding_id}",
            reason=stored.justification,
            meta={
                "change": "accepted",
                "owner": stored.owner,
                "expires_at": stored.expires_at.isoformat(),
            },
        )
        return stored

    def list_acceptances(
        self,
        *,
        finding_id: int | None = None,
        active_only: bool = False,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[RiskAcceptance, ...]:
        rows = list(self._acceptances)
        if finding_id is not None:
            rows = [item for item in rows if item.finding_id == finding_id]
        if project_id is not None:
            rows = [
                item
                for item in rows
                if self._acceptance_tenant.get(item.id or 0) == project_id
                or (include_global and self._acceptance_tenant.get(item.id or 0) is None)
            ]
        if active_only:
            moment = datetime.now(UTC)
            rows = [item for item in rows if item.active]
            del moment
        return tuple(rows)

    def revoke_acceptance(self, acceptance_id: int, *, actor: str) -> RiskAcceptance | None:
        for index, item in enumerate(self._acceptances):
            if item.id != acceptance_id:
                continue
            revoked = item.model_copy(update={"revoked_at": datetime.now(UTC), "actor": actor})
            self._acceptances[index] = revoked
            self._audit(
                AuditAction.ACCEPTANCE_CHANGED,
                target=revoked.check_id or f"finding:{revoked.finding_id}",
                reason=revoked.justification,
                meta={"change": "revoked"},
            )
            return revoked
        return None

    def acceptance_project(self, acceptance_id: int) -> tuple[bool, int | None]:
        """``(exists, project_id)`` for one acceptance — the tenant check a revoke route needs."""
        if acceptance_id not in self._acceptance_tenant:
            return (False, None)
        return (True, self._acceptance_tenant[acceptance_id])

    def reopen_expired(self, *, now: datetime | None = None) -> tuple[ReopenDecision, ...]:
        moment = _now(now)
        decisions = reopen_decisions(self._acceptances, moment=moment)
        for decision in decisions:
            self.reopened[decision.finding_id] = "open"
            for index, item in enumerate(self._acceptances):
                if item.id == decision.acceptance_id:
                    self._acceptances[index] = item.model_copy(update={"reopened_at": moment})
            self._audit(
                AuditAction.ACCEPTANCE_EXPIRED,
                outcome=AuditOutcome.ALLOWED,
                target=f"finding:{decision.finding_id}",
                reason="the risk acceptance expired; the finding is open again",
                meta=decision.to_dict(),
            )
        return decisions

    # ------------------------------------------------------------------ feedback
    def record_feedback_event(self, event: FeedbackEvent) -> None:
        """Append one decided mark (the memory counterpart of an ``fp_feedback`` row)."""
        self._feedback.append(event)

    def feedback_history(
        self, *, keys: Iterable[str] | None = None, since: datetime | None = None
    ) -> tuple[FeedbackEvent, ...]:
        wanted = set(keys) if keys is not None else None
        return tuple(
            event
            for event in self._feedback
            if (wanted is None or event.key in wanted) and (since is None or event.at >= since)
        )

    def _audit(
        self,
        action: AuditAction,
        *,
        target: str | None = None,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
    ) -> None:
        if self.auditor is not None:
            self.auditor.record(action, outcome=outcome, target=target, reason=reason, meta=meta)


# --------------------------------------------------------------------------- sql


class SqlQualityStore:
    """The deployment's store: two tables plus the existing ``fp_feedback`` history."""

    def __init__(
        self, session_factory: sessionmaker[Session], *, auditor: Auditor | None = None
    ) -> None:
        self._session_factory = session_factory
        self.auditor = auditor

    # ------------------------------------------------------------------ suppressions
    def suppression_version(self) -> int:
        with self._session_factory() as session:
            return self._max_version(session)

    @staticmethod
    def _max_version(session: Session) -> int:
        rows = session.execute(select(models.Suppression.version)).scalars().all()
        return max((int(value) for value in rows), default=0)

    def add_suppression(
        self, suppression: Suppression, *, project_id: int | None = None
    ) -> Suppression:
        with self._session_factory() as session:
            row = models.Suppression(
                project_id=project_id,
                version=self._max_version(session) + 1,
                kind=suppression.kind,
                check_id=suppression.check_id,
                asset_pattern=suppression.asset_pattern,
                finding_id=suppression.finding_id,
                reason=suppression.reason,
                actor=suppression.actor,
                created_at=suppression.created_at,
                expires_at=suppression.expires_at,
                active=True,
            )
            session.add(row)
            session.commit()
            store = _suppression_from_row(row)
        self._audit(
            AuditAction.SUPPRESSION_CHANGED,
            target=store.check_id or f"finding:{store.finding_id}",
            reason=store.reason,
            meta={"change": "added", "version": store.version, "kind": store.kind},
        )
        return store

    def list_suppressions(
        self,
        *,
        active_only: bool = True,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[Suppression, ...]:
        with self._session_factory() as session:
            statement = select(models.Suppression).order_by(models.Suppression.id.desc())
            if active_only:
                statement = statement.where(models.Suppression.active.is_(True))
            if project_id is not None:
                condition = models.Suppression.project_id == project_id
                if include_global:
                    # A deployment-wide rule (project_id IS NULL) applies to every tenant —
                    # which keeps every pre-S26 row in force rather than silently dropping it.
                    condition = condition | models.Suppression.project_id.is_(None)
                statement = statement.where(condition)
            return tuple(_suppression_from_row(row) for row in session.scalars(statement))

    def revoke_suppression(self, suppression_id: int, *, actor: str) -> Suppression | None:
        with self._session_factory() as session:
            row = session.get(models.Suppression, suppression_id)
            if row is None:
                return None
            row.active = False
            row.actor = actor
            session.commit()
            store = _suppression_from_row(row)
        self._audit(
            AuditAction.SUPPRESSION_CHANGED,
            target=store.check_id or f"finding:{store.finding_id}",
            reason=store.reason,
            meta={"change": "revoked", "version": store.version},
        )
        return store

    def active_suppressions(self) -> SuppressionSet:
        return SuppressionSet.of(self.list_suppressions(active_only=True))

    def suppression_project(self, suppression_id: int) -> tuple[bool, int | None]:
        """``(exists, project_id)`` for one rule — the tenant check a revoke route needs."""
        with self._session_factory() as session:
            row = session.get(models.Suppression, suppression_id)
            if row is None:
                return (False, None)
            return (True, row.project_id)

    # ------------------------------------------------------------------ acceptances
    def add_acceptance(
        self, acceptance: RiskAcceptance, *, project_id: int | None = None
    ) -> RiskAcceptance:
        with self._session_factory() as session:
            row = models.RiskAcceptance(
                project_id=project_id,
                finding_id=acceptance.finding_id,
                check_id=acceptance.check_id,
                asset_pattern=acceptance.asset_pattern,
                owner=acceptance.owner,
                justification=acceptance.justification,
                accepted_at=acceptance.accepted_at,
                expires_at=acceptance.expires_at,
                actor=acceptance.actor,
            )
            session.add(row)
            session.commit()
            store = _acceptance_from_row(row)
        self._audit(
            AuditAction.ACCEPTANCE_CHANGED,
            target=store.check_id or f"finding:{store.finding_id}",
            reason=store.justification,
            meta={
                "change": "accepted",
                "owner": store.owner,
                "expires_at": store.expires_at.isoformat(),
            },
        )
        return store

    def list_acceptances(
        self,
        *,
        finding_id: int | None = None,
        active_only: bool = False,
        project_id: int | None = None,
        include_global: bool = True,
    ) -> tuple[RiskAcceptance, ...]:
        with self._session_factory() as session:
            statement = select(models.RiskAcceptance).order_by(models.RiskAcceptance.id.desc())
            if finding_id is not None:
                statement = statement.where(models.RiskAcceptance.finding_id == finding_id)
            if project_id is not None:
                condition = models.RiskAcceptance.project_id == project_id
                if include_global:
                    condition = condition | models.RiskAcceptance.project_id.is_(None)
                statement = statement.where(condition)
            rows = tuple(_acceptance_from_row(row) for row in session.scalars(statement))
        if active_only:
            moment = datetime.now(UTC)
            rows = tuple(item for item in rows if item.active)
            del moment
        return rows

    def revoke_acceptance(self, acceptance_id: int, *, actor: str) -> RiskAcceptance | None:
        with self._session_factory() as session:
            row = session.get(models.RiskAcceptance, acceptance_id)
            if row is None:
                return None
            row.revoked_at = datetime.now(UTC)
            row.actor = actor
            session.commit()
            store = _acceptance_from_row(row)
        self._audit(
            AuditAction.ACCEPTANCE_CHANGED,
            target=store.check_id or f"finding:{store.finding_id}",
            reason=store.justification,
            meta={"change": "revoked"},
        )
        return store

    def acceptance_project(self, acceptance_id: int) -> tuple[bool, int | None]:
        """``(exists, project_id)`` for one acceptance — the tenant check a revoke route needs."""
        with self._session_factory() as session:
            row = session.get(models.RiskAcceptance, acceptance_id)
            if row is None:
                return (False, None)
            return (True, row.project_id)

    def reopen_expired(self, *, now: datetime | None = None) -> tuple[ReopenDecision, ...]:
        moment = _now(now)
        with self._session_factory() as session:
            rows = tuple(
                _acceptance_from_row(row) for row in session.scalars(select(models.RiskAcceptance))
            )
            decisions = reopen_decisions(rows, moment=moment)
            for decision in decisions:
                finding = session.get(models.Finding, decision.finding_id)
                if finding is not None:
                    finding.status = "open"
                if decision.acceptance_id is not None:
                    acceptance = session.get(models.RiskAcceptance, decision.acceptance_id)
                    if acceptance is not None:
                        acceptance.reopened_at = moment
            session.commit()
        for decision in decisions:
            self._audit(
                AuditAction.ACCEPTANCE_EXPIRED,
                target=f"finding:{decision.finding_id}",
                reason="the risk acceptance expired; the finding is open again",
                meta=decision.to_dict(),
            )
        return decisions

    # ------------------------------------------------------------------ feedback
    def feedback_history(
        self, *, keys: Iterable[str] | None = None, since: datetime | None = None
    ) -> tuple[FeedbackEvent, ...]:
        wanted = list(keys) if keys is not None else None
        with self._session_factory() as session:
            statement = select(models.FpFeedback).order_by(models.FpFeedback.created_at)
            if wanted:
                statement = statement.where(models.FpFeedback.key.in_(wanted))
            if since is not None:
                statement = statement.where(models.FpFeedback.created_at >= since)
            return tuple(
                FeedbackEvent(
                    key=row.key,
                    is_fp=bool(row.is_fp),
                    at=_aware(row.created_at),
                )
                for row in session.scalars(statement)
            )

    def _audit(
        self,
        action: AuditAction,
        *,
        target: str | None = None,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
    ) -> None:
        if self.auditor is not None:
            self.auditor.record(action, outcome=outcome, target=target, reason=reason, meta=meta)


# --------------------------------------------------------------------------- adapters


def _suppression_from_row(row: models.Suppression) -> Suppression:
    return Suppression(
        id=int(row.id),
        version=int(row.version),
        kind=row.kind,  # type: ignore[arg-type]
        check_id=row.check_id,
        asset_pattern=row.asset_pattern,
        finding_id=int(row.finding_id) if row.finding_id is not None else None,
        reason=row.reason,
        actor=row.actor,
        created_at=_aware(row.created_at),
        expires_at=_aware(row.expires_at) if row.expires_at is not None else None,
        active=bool(row.active),
    )


def _acceptance_from_row(row: models.RiskAcceptance) -> RiskAcceptance:
    return RiskAcceptance(
        id=int(row.id),
        finding_id=int(row.finding_id) if row.finding_id is not None else None,
        check_id=row.check_id,
        asset_pattern=row.asset_pattern,
        owner=row.owner,
        justification=row.justification,
        accepted_at=_aware(row.accepted_at),
        expires_at=_aware(row.expires_at),
        revoked_at=_aware(row.revoked_at) if row.revoked_at is not None else None,
        reopened_at=_aware(row.reopened_at) if row.reopened_at is not None else None,
        actor=row.actor,
    )


def _aware(value: datetime | None) -> datetime:
    """Re-attach UTC to a naive database timestamp (the stores' shared convention)."""
    if value is None:  # pragma: no cover - callers guard, kept for the type
        return datetime.now(UTC)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def acceptance_is_active(acceptance: RiskAcceptance, *, moment: datetime | None = None) -> bool:
    """Convenience wrapper so a caller never re-implements the clock rule."""
    from arachne.quality.acceptance import active_at

    return active_at(acceptance, _now(moment))


def sequence_of(values: Sequence[int]) -> tuple[int, ...]:
    """Small helper for tests that assert a version sequence is monotonic."""
    return tuple(values)
