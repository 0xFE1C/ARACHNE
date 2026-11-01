"""Provenance of imported offline content packs (S25, REQ-RESIL-001).

An air-gapped estate's content arrives by hand, so "what is this deployment running, and
where did it come from?" cannot be answered from a network audit log. This store answers it
from the database: one row per imported pack — name, version, the digest of its signed
manifest, the key that signed it, what it carried and who imported it.

It is also the *idempotence* guard: importing the same pack twice is a no-op rather than a
second row, so the table stays a faithful inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as SaIntegrityError
from sqlalchemy.orm import Session, sessionmaker

from arachne.data.models import ContentPack as ContentPackRow

__all__ = ["ContentPackStore", "PackSourceRecord"]


@dataclass(frozen=True, slots=True)
class PackSourceRecord:
    """One imported pack's provenance."""

    id: int | None
    name: str
    version: str
    digest: str
    key_id: str
    contents: dict[str, Any]
    source: str | None
    imported_by: str | None
    created_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "key_id": self.key_id,
            "contents": self.contents,
            "source": self.source,
            "imported_by": self.imported_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ContentPackStore:
    """The ``content_packs`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(
        self,
        *,
        name: str,
        version: str,
        digest: str,
        key_id: str | None,
        contents: dict[str, Any],
        source: str | None = None,
        imported_by: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> PackSourceRecord:
        """Record an import, or return the existing row when this pack is already known."""
        with self._session_factory() as session:
            existing = session.scalar(
                select(ContentPackRow).where(
                    ContentPackRow.name == name, ContentPackRow.version == version
                )
            )
            if existing is not None:
                if existing.digest == digest:
                    return _as_record(existing)
                # Same name/version, different content: the pack was rebuilt. Replace the
                # digest so the row always names what is actually installed.
                existing.digest = digest
                existing.key_id = key_id or "unknown"
                existing.contents_json = dict(contents)
                existing.source = source or existing.source
                existing.imported_by = imported_by or existing.imported_by
                session.commit()
                return _as_record(existing)
            row = ContentPackRow(
                name=name,
                version=version,
                digest=digest,
                key_id=key_id or "unknown",
                contents_json=dict(contents),
                source=source,
                imported_by=imported_by,
                meta_json=dict(meta or {}),
                created_at=datetime.now(UTC),
            )
            session.add(row)
            try:
                session.commit()
            except SaIntegrityError:  # a concurrent import of the same pack won
                session.rollback()
                found = session.scalar(
                    select(ContentPackRow).where(
                        ContentPackRow.name == name, ContentPackRow.version == version
                    )
                )
                if found is None:  # pragma: no cover - the row must exist if the insert failed
                    raise
                return _as_record(found)
            return _as_record(row)

    def list_packs(self, *, limit: int = 200) -> tuple[PackSourceRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(ContentPackRow).order_by(ContentPackRow.id.desc()).limit(limit)
            ).all()
        return tuple(_as_record(row) for row in rows)

    def find(self, name: str, version: str) -> PackSourceRecord | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(ContentPackRow).where(
                    ContentPackRow.name == name, ContentPackRow.version == version
                )
            )
        return _as_record(row) if row is not None else None


def _as_record(row: ContentPackRow) -> PackSourceRecord:
    return PackSourceRecord(
        id=int(row.id),
        name=str(row.name),
        version=str(row.version),
        digest=str(row.digest),
        key_id=str(row.key_id),
        contents=dict(row.contents_json or {}),
        source=row.source,
        imported_by=row.imported_by,
        created_at=row.created_at,
    )
