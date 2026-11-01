"""Provenance of the marketplace review pipeline (S26, REQ-ECOS-001).

REQ-ECOS-001 requires that a third-party pack's provenance be *recorded* and that a pack pass
the pipeline *before it is listed*. This store is that record: one row per (name, version,
digest) with the decision and the full gate report.

The digest is part of the identity on purpose. A pack is content-addressed — if its author
rebuilds it with different content, the digest changes and the row no longer matches, so the
pack is re-reviewed rather than inheriting a verdict that was never about these bytes. That is
the property that makes "listed" mean something.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as SaIntegrityError
from sqlalchemy.orm import Session, sessionmaker

from arachne.data.models import PackReview as PackReviewRow
from arachne.plugins.review import DECISION_LISTED, ReviewReport

__all__ = ["PackReviewStore", "ReviewRecord"]


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    """One recorded review."""

    id: int | None
    name: str
    version: str
    digest: str
    key_id: str
    decision: str
    gates: dict[str, Any]
    kind: str | None
    reviewed_by: str | None
    created_at: datetime | None

    @property
    def listed(self) -> bool:
        return self.decision == DECISION_LISTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "key_id": self.key_id,
            "decision": self.decision,
            "listed": self.listed,
            "kind": self.kind,
            "reviewed_by": self.reviewed_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "gates": dict(self.gates),
        }


class PackReviewStore:
    """The ``pack_reviews`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(
        self,
        review: ReviewReport,
        *,
        reviewed_by: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> ReviewRecord:
        """Record ``review``, replacing an earlier verdict for the same digest.

        Re-reviewing the same bytes is idempotent (the newest verdict wins) — which is what a
        re-run of the pipeline should be. A *different* digest for the same name/version is a
        different row, so the history of what was reviewed stays readable.
        """
        payload = review.to_dict()
        gates = {"gates": payload["gates"], "reviewed_at": payload["reviewed_at"]}
        if meta:
            gates["meta"] = dict(meta)
        with self._session_factory() as session:
            existing = session.scalar(
                select(PackReviewRow).where(
                    PackReviewRow.name == review.name,
                    PackReviewRow.version == review.version,
                    PackReviewRow.digest == review.digest,
                )
            )
            if existing is not None:
                existing.decision = review.decision
                existing.key_id = review.key_id or "unsigned"
                existing.gates_json = gates
                existing.kind = review.kind
                existing.reviewed_by = reviewed_by or existing.reviewed_by
                session.commit()
                return _as_record(existing)
            row = PackReviewRow(
                name=review.name,
                version=review.version,
                digest=review.digest,
                key_id=review.key_id or "unsigned",
                decision=review.decision,
                gates_json=gates,
                kind=review.kind,
                reviewed_by=reviewed_by,
                created_at=datetime.now(UTC),
            )
            session.add(row)
            try:
                session.commit()
            except SaIntegrityError:  # a concurrent review of the same digest won
                session.rollback()
                found = session.scalar(
                    select(PackReviewRow).where(
                        PackReviewRow.name == review.name,
                        PackReviewRow.version == review.version,
                        PackReviewRow.digest == review.digest,
                    )
                )
                if found is None:  # pragma: no cover - the row exists if the insert raced
                    raise
                return _as_record(found)
            return _as_record(row)

    def list_reviews(self, *, limit: int = 200) -> tuple[ReviewRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(PackReviewRow).order_by(PackReviewRow.id.desc()).limit(limit)
            ).all()
        return tuple(_as_record(row) for row in rows)

    def find(self, name: str, version: str, digest: str | None = None) -> ReviewRecord | None:
        """The newest review of a pack, optionally pinned to a digest."""
        with self._session_factory() as session:
            query = select(PackReviewRow).where(
                PackReviewRow.name == name, PackReviewRow.version == version
            )
            if digest is not None:
                query = query.where(PackReviewRow.digest == digest)
            row = session.scalar(query.order_by(PackReviewRow.id.desc()))
        return _as_record(row) if row is not None else None

    def is_listed(self, name: str, version: str, digest: str | None = None) -> bool:
        """True when the newest review of these exact bytes says ``listed``."""
        record = self.find(name, version, digest)
        return bool(record is not None and record.listed)

    def listed_index(self) -> dict[tuple[str, str], ReviewRecord]:
        """Every ``(name, version)`` whose newest review is a listing, for the marketplace."""
        index: dict[tuple[str, str], ReviewRecord] = {}
        for record in self.list_reviews(limit=1000):
            key = (record.name, record.version)
            if key not in index:
                index[key] = record
        return {key: value for key, value in index.items() if value.listed}


def _as_record(row: PackReviewRow) -> ReviewRecord:
    return ReviewRecord(
        id=int(row.id),
        name=str(row.name),
        version=str(row.version),
        digest=str(row.digest),
        key_id=str(row.key_id),
        decision=str(row.decision),
        gates=dict(row.gates_json or {}),
        kind=row.kind,
        reviewed_by=row.reviewed_by,
        created_at=row.created_at,
    )
