"""Reference counting for tenant-scoped, content-addressed evidence blobs (WP-21, REQ-DATA-006).

Content addressing alone is not enough once more than one row can point at the same object:
two findings that captured byte-identical evidence share one blob, and deleting one of them
must not take the object out from under the other. That is what this table and these
functions are for.

**The ledger is a materialised count, written in the caller's transaction.** Every store that
inserts an offloaded evidence row also calls :func:`BlobRegistry.reference` in the *same*
session, and every store that deletes one calls :func:`BlobRegistry.release` in the same
session as the delete. A committed finding therefore always has its reference counted and a
rolled-back one never does — the same discipline ``StorageQuota.add_usage`` uses for bytes.

**A count of zero is the deletion authority, and only it is.** ``refcount`` reaching zero
means no evidence row addresses the blob any more, so the physical object may be unlinked by
:meth:`BlobRegistry.sweep`. Nothing else unlinks an object: the WP-14 retention path used to
unlink every key it had selected regardless of whether another finding still referenced it,
which is exactly the corruption this package removes. A blob at a positive count is never a
sweep candidate, whatever else is true of its rows.

**The tenant is a namespace, not a foreign key.** ``tenant`` is ``"default"`` for the implicit
default workspace (``scans.project_id IS NULL``) and ``"p<id>"`` for a named project —
the same string the backend uses as a path segment. It is deliberately *not* a
``project_id`` column: the default workspace has no ``projects`` row to point at, and a blob
row's whole purpose is to be the refcount for one (tenant, digest) pair. Keeping it a plain
namespace string is also why the tenant-isolation suite (REQ-IDAM-006) does not classify this
table as a resource store: it holds no tenant's content, only the count of references to one
digest within a namespace.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.logging import get_logger
from arachne.data.evidence_backend import DEFAULT_TENANT, EvidenceBackend
from arachne.data.models import Evidence, EvidenceBlob, Finding, Scan

__all__ = [
    "TENANT_PREFIX",
    "BlobRecord",
    "BlobRegistry",
    "tenant_key",
]

_logger = get_logger("data.blobs")

#: The prefix a named project's namespace carries (``p7``), so an object store listing reads
#: as namespaces rather than bare integers.
TENANT_PREFIX: Final = "p"


def tenant_key(project_id: int | None) -> str:
    """The namespace of a tenant: ``default`` for the implicit workspace, ``p<id>`` otherwise.

    The same function derives the key at every layer (the scan that offloads, the store that
    counts the reference, the retention job that releases it, the API that serves it), so a
    blob cannot be written into one namespace and read from another by construction.
    """
    if project_id is None:
        return DEFAULT_TENANT
    return f"{TENANT_PREFIX}{int(project_id)}"


@dataclass(frozen=True, slots=True)
class BlobRecord:
    """One content-addressed blob and how many evidence rows address it."""

    tenant: str
    key: str
    refcount: int
    logical_bytes: int
    physical_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "key": self.key,
            "refcount": self.refcount,
            "logical_bytes": self.logical_bytes,
            "physical_bytes": self.physical_bytes,
        }


class BlobRegistry:
    """Reads and maintains the per-tenant reference ledger.

    The ledger is a plain table read and the two mutators are ``session``-taking statics,
    exactly like ``StorageQuota.add_usage``: the caller owns the transaction, so the reference
    and the evidence row it belongs to commit or roll back together.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ reads
    def record(self, tenant: str, key: str) -> BlobRecord | None:
        """The ledger row for one blob, or ``None`` when nothing references it."""
        with self._session_factory() as session:
            return self._record(session, tenant, key)

    def refcount(self, tenant: str, key: str) -> int:
        with self._session_factory() as session:
            row = self._record(session, tenant, key)
        return row.refcount if row is not None else 0

    def physical_usage(self, tenant: str) -> int:
        """Physical bytes held by ``tenant``: one blob counted once, however many rows cite it.

        This is the number a quota is enforced against (REQ-DATA-006): dedup must not be
        paid for twice, or the ledger would penalise exactly the sharing it exists to reward.
        """
        with self._session_factory() as session:
            return self._physical_usage(session, tenant)

    @staticmethod
    def _physical_usage(session: Session, tenant: str) -> int:
        total = session.scalar(
            select(func.coalesce(func.sum(EvidenceBlob.physical_bytes), 0)).where(
                EvidenceBlob.tenant == tenant
            )
        )
        return int(total or 0)

    @staticmethod
    def count(session: Session, tenant: str, key: str) -> int:
        """The count for one blob **inside a caller's transaction** (0 when absent).

        The store calls this immediately before :meth:`reference` to learn whether the
        reference it is about to add creates the object — the moment a quota should be charged
        its physical bytes.
        """
        value = session.scalar(
            select(EvidenceBlob.refcount).where(
                EvidenceBlob.tenant == tenant, EvidenceBlob.key == key
            )
        )
        return int(value or 0)

    @staticmethod
    def _record(session: Session, tenant: str, key: str) -> BlobRecord | None:
        row = session.scalar(
            select(EvidenceBlob).where(EvidenceBlob.tenant == tenant, EvidenceBlob.key == key)
        )
        if row is None:
            return None
        return BlobRecord(
            tenant=str(row.tenant),
            key=str(row.key),
            refcount=int(row.refcount or 0),
            logical_bytes=int(row.logical_bytes or 0),
            physical_bytes=int(row.physical_bytes or 0),
        )

    # ------------------------------------------------------------------ writes
    @staticmethod
    def reference(
        session: Session,
        tenant: str,
        key: str,
        *,
        logical_bytes: int = 0,
        physical_bytes: int = 0,
    ) -> int:
        """Add one reference and return the new count.

        The row is created at 1 on first sight, so for evidence written through this ledger the
        count is the number of rows that address the blob. A blob that predates the ledger is
        adopted by :meth:`reconcile` on its first delete, which recounts from the rows that
        remain rather than trusting an increment. ``logical_bytes`` records the uncompressed
        payload size and ``physical_bytes`` the size on disk; both are kept at their largest
        observed value so a re-reference cannot shrink the accounting.
        """
        row = session.scalar(
            select(EvidenceBlob).where(EvidenceBlob.tenant == tenant, EvidenceBlob.key == key)
        )
        if row is None:
            row = EvidenceBlob(
                tenant=tenant,
                key=key,
                refcount=1,
                logical_bytes=max(0, int(logical_bytes)),
                physical_bytes=max(0, int(physical_bytes)),
            )
            session.add(row)
            session.flush()
            return 1
        row.refcount = int(row.refcount or 0) + 1
        row.logical_bytes = max(int(row.logical_bytes or 0), int(logical_bytes))
        if physical_bytes:
            row.physical_bytes = max(int(row.physical_bytes or 0), int(physical_bytes))
        session.flush()
        return int(row.refcount)

    @staticmethod
    def release(session: Session, tenant: str, key: str) -> int:
        """Drop one reference and return the new count (0 when nothing references it any more).

        Used by a write path that removes a row without re-reading the ledger. The delete
        paths that must be *exact* — retention, an API delete — call :meth:`reconcile` after
        the rows are gone instead, so the count is derived from what remains and legacy rows
        written before the ledger existed are accounted for.
        """
        row = session.scalar(
            select(EvidenceBlob).where(EvidenceBlob.tenant == tenant, EvidenceBlob.key == key)
        )
        if row is None:
            return 0
        row.refcount = max(0, int(row.refcount or 0) - 1)
        session.flush()
        return int(row.refcount)

    @staticmethod
    def reconcile(session: Session, project_id: int | None, key: str) -> int:
        """Set a blob's count to the number of evidence rows that still address it.

        Called **after** the rows are deleted (and flushed) in the same transaction. Two
        properties follow, and both matter more than the cheaper decrement:

        * the count cannot drift, so "still referenced" is a fact rather than bookkeeping;
        * a blob written before the ledger existed (an offloaded row from a pre-WP-21 release)
          is adopted now: if rows still cite it the count is theirs, and if none do the row is
          created at zero so the sweep can unlink the object that would otherwise be orphaned.

        The physical size of an adopted row is unknown and recorded as zero; the next write of
        the same content re-references the key and fills it in. A quota never overcounts for
        that — undercounting a legacy object is the conservative direction for a *limit*.
        """
        tenant = tenant_key(project_id)
        statement = (
            select(func.count())
            .select_from(Evidence)
            .join(Finding, Finding.id == Evidence.finding_id)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Evidence.storage_key == key)
        )
        statement = (
            statement.where(Scan.project_id.is_(None))
            if project_id is None
            else statement.where(Scan.project_id == project_id)
        )
        remaining = int(session.scalar(statement) or 0)
        row = session.scalar(
            select(EvidenceBlob).where(EvidenceBlob.tenant == tenant, EvidenceBlob.key == key)
        )
        if row is None:
            row = EvidenceBlob(
                tenant=tenant,
                key=key,
                refcount=remaining,
                logical_bytes=0,
                physical_bytes=0,
            )
            session.add(row)
        else:
            row.refcount = remaining
        session.flush()
        return remaining

    @staticmethod
    def unreferenced(session: Session, tenant: str | None = None) -> list[tuple[str, str]]:
        """Every ``(tenant, key)`` whose count is at or below zero."""
        statement = select(EvidenceBlob.tenant, EvidenceBlob.key).where(EvidenceBlob.refcount <= 0)
        if tenant is not None:
            statement = statement.where(EvidenceBlob.tenant == tenant)
        return [(str(row[0]), str(row[1])) for row in session.execute(statement).all()]

    # ------------------------------------------------------------------ collection
    async def sweep(
        self,
        backend: EvidenceBackend,
        *,
        tenant: str | None = None,
        limit: int = 10_000,
    ) -> tuple[tuple[str, str], ...]:
        """Unlink and forget every blob no evidence row references any more.

        Async because the backend's delete is: the retention job already runs on an event
        loop, so the sweep is awaited there rather than driven by a private second loop.

        A blob is unlinked *before* its ledger row is removed: a crash between the two leaves
        a zero-count row whose object is already gone (the sweep simply retries and the
        unlink is idempotent), whereas the reverse would leave an orphaned object nothing
        will ever collect. The count is re-read immediately before the unlink, so a reference
        added since the candidate list was taken wins and the object is left alone; the sweep
        is the retention job's (a single, leader-elected run in a multi-worker deployment),
        which is what keeps that re-check meaningful. Returns the ``(tenant, key)`` pairs it
        removed.
        """
        removed: list[tuple[str, str]] = []
        with self._session_factory() as session:
            candidates = self.unreferenced(session, tenant)[:limit]
        for namespace, key in candidates:
            with self._session_factory() as session:
                row = session.scalar(
                    select(EvidenceBlob).where(
                        EvidenceBlob.tenant == namespace, EvidenceBlob.key == key
                    )
                )
                if row is None or int(row.refcount or 0) > 0:
                    continue  # referenced again since the candidate list was taken
            try:
                await backend.delete(key, tenant=namespace)
            except Exception as exc:  # a store failure must not stop the rest of the sweep
                _logger.warning(
                    "could not unlink an unreferenced evidence object",
                    extra={
                        "event": "evidence.sweep_failed",
                        "tenant": namespace,
                        "key": key,
                        "error": str(exc)[:200],
                    },
                )
                continue
            with self._session_factory() as session:
                row = session.scalar(
                    select(EvidenceBlob).where(
                        EvidenceBlob.tenant == namespace, EvidenceBlob.key == key
                    )
                )
                if row is not None and int(row.refcount or 0) <= 0:
                    session.delete(row)
                session.commit()
            removed.append((namespace, key))
        if removed:
            _logger.info(
                "swept unreferenced evidence objects",
                extra={"event": "evidence.swept", "count": len(removed)},
            )
        return tuple(removed)
