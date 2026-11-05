"""Per-project storage quotas: warn at the soft threshold, hard-stop at the limit (REQ-DATA-003).

A quota is a tenant-contract limit, not a performance guard: an MSSP sells "your evidence is
retained for your retention period", and storage is the line item that makes that promise
cost money. The behaviour the requirement asks for is a *two-stage* refusal:

* above ``warn_ratio`` of the limit the deployment records a warning — once per scan, with
  the usage and the limit — so an operator sees it coming;
* at the limit the write is refused **before it happens**. Nothing is written, the error
  names the project, the limit and the refused payload, and it propagates out of the checks
  step. The scan machine then marks the step and the scan ``failed``, which is exactly the
  state ``arachne scan --resume`` continues from: raise the quota, resume, and the scan
  carries on from the failed step instead of starting over.

**What is counted is physical, not logical (WP-21, REQ-DATA-006).** An offloaded blob is
charged its stored (compressed) size, once, however many evidence rows address it; an inline
payload is charged its own bytes. Charging the logical size per row would make the ledger bill
a tenant twice for one deduplicated object — i.e. it would penalise the behaviour content
addressing exists to produce. The physical figure comes from ``evidence_blobs`` (one row per
tenant-and-digest) plus the inline rows, which is also what ``recompute`` re-derives.

Accounting is a cached running total (``projects.used_bytes``) because it is read on every
evidence write, with a ``SUM`` recomputation used by the pruning job and by
``arachne retention status``. The two agree because every write increments the total in the
same transaction as the rows it accounts for, and every prune recomputes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ConfigurationError, StorageQuotaError
from arachne.data.blob_registry import tenant_key
from arachne.data.models import Evidence, EvidenceBlob, Finding, Project, Scan

__all__ = ["DEFAULT_WARN_RATIO", "QuotaState", "StorageQuota"]

#: Fraction of the limit at which a deployment warns before it refuses.
DEFAULT_WARN_RATIO = 0.8


@dataclass(frozen=True, slots=True)
class QuotaState:
    """Where one project stands against its quota."""

    project_id: int | None
    used_bytes: int
    limit_bytes: int | None
    incoming_bytes: int = 0
    warn_ratio: float = DEFAULT_WARN_RATIO

    @property
    def has_limit(self) -> bool:
        return self.limit_bytes is not None and self.limit_bytes > 0

    @property
    def projected(self) -> int:
        return self.used_bytes + self.incoming_bytes

    @property
    def ratio(self) -> float:
        """Projected usage as a fraction of the limit (0 without a limit)."""
        if not self.has_limit:
            return 0.0
        assert self.limit_bytes is not None
        return self.projected / self.limit_bytes

    @property
    def warning(self) -> bool:
        return self.has_limit and self.ratio >= self.warn_ratio

    @property
    def exceeded(self) -> bool:
        return self.has_limit and self.projected > (self.limit_bytes or 0)

    @property
    def headroom(self) -> int | None:
        """Bytes still available (``None`` when there is no limit; never negative)."""
        if not self.has_limit:
            return None
        assert self.limit_bytes is not None
        return max(0, self.limit_bytes - self.used_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "used_bytes": self.used_bytes,
            "limit_bytes": self.limit_bytes,
            "incoming_bytes": self.incoming_bytes,
            "projected_bytes": self.projected,
            "ratio": round(self.ratio, 4),
            "warning": self.warning,
            "exceeded": self.exceeded,
            "headroom_bytes": self.headroom,
        }


class StorageQuota:
    """Reads and enforces the per-project quota ledger."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        default_limit_bytes: int | None = None,
        warn_ratio: float = DEFAULT_WARN_RATIO,
    ) -> None:
        if not 0.0 < warn_ratio <= 1.0:
            msg = "quota warn_ratio must be in (0, 1]"
            raise ConfigurationError(msg)
        if default_limit_bytes is not None and default_limit_bytes < 0:
            msg = "quota default_limit_bytes must be >= 0"
            raise ConfigurationError(msg)
        self._session_factory = session_factory
        self.default_limit_bytes = default_limit_bytes
        self.warn_ratio = warn_ratio

    # ------------------------------------------------------------------ reads
    def usage(self, project_id: int | None) -> int:
        """The project's stored evidence bytes (cached total, authoritative enough to enforce)."""
        if project_id is None:
            return 0
        with self._session_factory() as session:
            value = session.scalar(select(Project.used_bytes).where(Project.id == project_id))
        return int(value or 0)

    def recompute(self, project_id: int | None) -> int:
        """Recompute a project's usage from the stored bytes and store the result.

        Used after a prune and by the operator-facing status command: the cached total is
        what enforcement reads, and this is what keeps it honest. Two terms, both physical
        (WP-21, REQ-DATA-006): the tenant's content-addressed blobs counted once each, plus
        the payloads small enough to sit inline in ``evidences``.
        """
        if project_id is None:
            return 0
        with self._session_factory() as session:
            blobs = session.scalar(
                select(func.coalesce(func.sum(EvidenceBlob.physical_bytes), 0)).where(
                    EvidenceBlob.tenant == tenant_key(project_id)
                )
            )
            inline = session.scalar(
                select(func.coalesce(func.sum(Evidence.size_bytes), 0))
                .select_from(Evidence)
                .join(Finding, Finding.id == Evidence.finding_id)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(Scan.project_id == project_id)
                .where(Evidence.storage_key.is_(None))
            )
            row = session.get(Project, project_id)
            if row is None:
                return 0
            row.used_bytes = int(blobs or 0) + int(inline or 0)
            session.commit()
            return int(row.used_bytes or 0)

    def limit_for(self, project_id: int | None) -> int | None:
        if project_id is None:
            return self.default_limit_bytes
        with self._session_factory() as session:
            explicit = session.scalar(select(Project.quota_bytes).where(Project.id == project_id))
        if explicit is None:
            return self.default_limit_bytes
        # An explicit 0 is a deliberate "no quota" for this project.
        return int(explicit) if int(explicit) > 0 else None

    def state(self, project_id: int | None, incoming_bytes: int = 0) -> QuotaState:
        return QuotaState(
            project_id=project_id,
            used_bytes=self.usage(project_id),
            limit_bytes=self.limit_for(project_id),
            incoming_bytes=max(0, incoming_bytes),
            warn_ratio=self.warn_ratio,
        )

    def enforce(
        self, project_id: int | None, incoming_bytes: int, *, context: str = ""
    ) -> QuotaState:
        """Return the state, raising :class:`StorageQuotaError` when the write would exceed it."""
        state = self.state(project_id, incoming_bytes)
        if not state.exceeded:
            return state
        limit = state.limit_bytes or 0
        where = f" ({context})" if context else ""
        msg = (
            f"project {project_id} has exceeded its storage quota{where}: "
            f"{state.used_bytes} bytes stored, {incoming_bytes} more requested, "
            f"limit {limit} bytes. Nothing was written. Raise the quota "
            f"(arachne retention quota --project <slug> --bytes <n>) and resume the scan "
            f"with `arachne scan --resume <id>`."
        )
        raise StorageQuotaError(msg)

    def overview(self) -> tuple[dict[str, Any], ...]:
        """Per-project usage for the metrics endpoint and the CLI (bounded by project count)."""
        with self._session_factory() as session:
            rows = session.execute(
                select(Project.id, Project.slug, Project.used_bytes, Project.quota_bytes).order_by(
                    Project.id
                )
            ).all()
        out: list[dict[str, Any]] = []
        for project_id, slug, used, quota in rows:
            limit = int(quota) if quota is not None and int(quota) > 0 else self.default_limit_bytes
            used_bytes = int(used or 0)
            out.append(
                {
                    "project_id": int(project_id),
                    "slug": str(slug),
                    "used_bytes": used_bytes,
                    "limit_bytes": limit,
                    "ratio": (round(used_bytes / limit, 4) if limit else 0.0),
                }
            )
        return tuple(out)

    # ------------------------------------------------------------------ writes
    def set_limit(self, project_id: int, limit_bytes: int | None) -> int | None:
        """Set (or clear) a project's quota; ``None`` clears it back to the deployment default."""
        if limit_bytes is not None and limit_bytes < 0:
            msg = "a quota limit cannot be negative"
            raise ConfigurationError(msg)
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.quota_bytes = limit_bytes
            session.commit()
            return row.quota_bytes

    @staticmethod
    def add_usage(session: Session, project_id: int | None, delta: int) -> int:
        """Increment a project's cached total **inside the caller's transaction**.

        The finding store calls this in the same session that inserts the evidence rows, so a
        committed finding always has its bytes accounted for, and a rolled-back one never
        does. ``delta`` may be negative (a delete).
        """
        if project_id is None or delta == 0:
            return 0
        row = session.get(Project, project_id)
        if row is None:
            return 0
        current = int(row.used_bytes or 0)
        row.used_bytes = max(0, current + delta)
        return int(row.used_bytes)

    @staticmethod
    def project_for_scan(session: Session, scan_id: int) -> int | None:
        """The project a scan belongs to (``None`` for the implicit default workspace)."""
        value = session.scalar(select(Scan.project_id).where(Scan.id == scan_id))
        return None if value is None else int(value)
