"""Persistence for target definitions (F-01-01, F-08-05).

A target definition is what an operator declared and was authorized for, so it is stored
verbatim: ``scope_json`` holds the declared targets and exclusions, ``auth_attestation``
holds who attested what and when (F-08-05). ``upsert`` keys on ``(name, scope_json)`` so
re-running the same fixture reuses the row instead of growing the table.

The read side (:meth:`SqlTargetStore.list_targets` / :meth:`~SqlTargetStore.get_target`)
reconstructs a full :class:`~arachne.core.target.TargetDefinition` from a row: the declared
selectors are in ``scope_json`` and the attestation in ``auth_attestation``, so a stored
target is re-runnable through the API (S12) without a schema change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.target import TargetDefinition
from arachne.data.keyset import PageWindow, with_target_page
from arachne.data.models import Target
from arachne.data.scan_store import as_utc

__all__ = ["SqlTargetStore", "TargetRecord"]


@dataclass(frozen=True, slots=True)
class TargetRecord:
    """One stored target definition, with the parts an interface needs to re-run it."""

    id: int
    name: str
    scope: dict[str, Any] = field(default_factory=dict)
    attestation: dict[str, Any] | None = None
    created_at: datetime | None = None
    #: The tenant/workspace this target belongs to (F-07-06); ``None`` is the default one.
    project_id: int | None = None

    def to_definition(self) -> TargetDefinition:
        """Rebuild the runnable :class:`TargetDefinition` this row was stored from."""
        payload: dict[str, Any] = {
            "name": self.name,
            "targets": list(self.scope.get("targets") or ()),
            "exclusions": list(self.scope.get("exclusions") or ()),
        }
        if self.attestation:
            payload["attestation"] = self.attestation
        return TargetDefinition.model_validate(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "scope": dict(self.scope),
            "attestation": self.attestation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "project_id": self.project_id,
        }


class SqlTargetStore:
    """``TargetStore`` over the ``targets`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, definition: TargetDefinition, *, project_id: int | None = None) -> int:
        """Store ``definition`` and return the ``targets.id`` to attach a scan to.

        A target is identified by ``(name, scope_json, project_id)``: the same fixture run
        by two tenants is two rows, and running it twice inside one tenant reuses the row.
        """
        scope = definition.scope_dict()
        attestation = definition.attestation.to_dict() if definition.attestation else None
        with self._session_factory() as session:
            existing = self._find(session, definition.name, scope, project_id=project_id)
            if existing is not None:
                # The attestation can legitimately be renewed for the same scope.
                existing.auth_attestation = attestation
                session.commit()
                return int(existing.id)
            target = Target(
                name=definition.name,
                scope_json=scope,
                auth_attestation=attestation,
                project_id=project_id,
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            return int(target.id)

    # ------------------------------------------------------------------ reads (S12)
    def list_targets(
        self,
        *,
        limit: int = 100,
        project_id: int | None = None,
        include_unassigned: bool = False,
        window: PageWindow | None = None,
    ) -> tuple[TargetRecord, ...]:
        """Recent targets; ``project_id`` filters, ``include_unassigned`` adds pre-S14 rows.

        ``window`` carries the cursor boundary (targets have one sort field, ``id``); the
        default order is newest first.
        """
        with self._session_factory() as session:
            query = with_target_page(select(Target), window=window, limit=limit)
            if project_id is not None:
                condition = Target.project_id == project_id
                if include_unassigned:
                    condition = condition | Target.project_id.is_(None)
                query = query.where(condition)
            rows = session.scalars(query).all()
            return tuple(_to_record(row) for row in rows)

    def get_target(self, target_id: int) -> TargetRecord | None:
        with self._session_factory() as session:
            row = session.get(Target, target_id)
            return None if row is None else _to_record(row)

    def project_of(self, target_id: int) -> int | None:
        """The tenant a stored target belongs to (``None`` = default/unassigned)."""
        with self._session_factory() as session:
            row = session.get(Target, target_id)
            return None if row is None else row.project_id

    def delete_target(self, target_id: int) -> bool:
        """Delete a target row; its scans cascade. Returns whether a row was removed."""
        with self._session_factory() as session:
            row = session.get(Target, target_id)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    @staticmethod
    def _find(
        session: Session,
        name: str,
        scope: dict[str, object],
        *,
        project_id: int | None = None,
    ) -> Target | None:
        candidates = session.scalars(
            select(Target).where(Target.name == name, Target.project_id == project_id)
        ).all()
        for candidate in candidates:
            if candidate.scope_json == scope:
                return candidate
        return None


def _to_record(row: Target) -> TargetRecord:
    return TargetRecord(
        id=int(row.id),
        name=str(row.name),
        scope=dict(row.scope_json or {}),
        attestation=(dict(row.auth_attestation) if row.auth_attestation else None),
        created_at=as_utc(row.created_at),
        project_id=row.project_id,
    )
