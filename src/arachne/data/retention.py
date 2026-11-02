"""Retention policies and the pruning job (REQ-DATA-001).

Continuous scanning at estate scale produces data forever unless something stops it, and
"something" has to be a *policy* — a tenant's contract, a statutory holding period, an
operator's judgement — not a habit of deleting the old. Four rules shape this module:

**Per project, four categories, one direction.** A policy is a set of day counts — findings,
evidence, scans, audit — resolved per project (``projects.retention_json``) over the
deployment defaults (``ARACHNE_RETENTION_*``). ``0`` means "keep forever" for that category:
a tenant with a seven-year audit obligation turns off *audit* retention without turning off
evidence retention. A policy can also be disabled outright (``enabled: false``), which is the
legal-hold state: the job plans nothing for that project and touches nothing.

**Dry run first, and it is the default.** :meth:`RetentionPruner.prune` plans, records the
plan in the audit trail, and returns it without deleting anything unless ``dry_run=False`` is
passed. An operator sees exactly what a run would remove — per project, per category, with
the byte count — before agreeing to it. The applied run records a second audit line.

**The plan is the contract.** A plan carries the exact row ids it selected, and the apply
step deletes those ids. That is what makes "dry run, then apply" trustworthy in the presence
of a clock that keeps moving, and it is what the property test pins: the rows a run removes
are the rows it announced, nothing else.

**Deletion is by age, and the cascade is declared.** Deleting a scan removes its findings and
evidence (the foreign keys cascade). That is not a policy violation, it is the parent's
policy: a finding cannot outlive the scan that produced it. The plan therefore reports the
cascaded rows in the scans category, and ``tests/unit/test_retention_property.py`` asserts
the property directly — every removed row was over its own category's cutoff, or was removed
with a scan that was.

**Audit has no project column, so its cutoff is the strictest one.** ``audit_log`` rows carry
an actor and an action, not a tenant, and an audit line can name any project. Rather than
adding a project column and guessing at attribution, the audit cutoff is the *smallest*
non-zero ``audit_days`` among the configured policies: the tenant with the shortest obligation
wins, which is the only choice that cannot retain one tenant's audit records longer than that
tenant allows.

The job is **bounded**: ``batch_limit`` caps each category per run, so a first prune on a
years-old database is a series of repeatable batches rather than one enormous transaction. A
second run continues where the first stopped, and a run with nothing to do deletes nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, Auditor
from arachne.core.config import Settings, get_settings
from arachne.core.errors import ConfigurationError
from arachne.core.logging import get_logger
from arachne.core.metrics import REGISTRY
from arachne.data.models import AuditLog, Evidence, Finding, Project, Scan
from arachne.data.quota import StorageQuota

__all__ = [
    "CATEGORIES",
    "CategoryPlan",
    "ProjectPrune",
    "PrunePlan",
    "RetentionPolicy",
    "RetentionPruner",
    "policy_for",
]

_logger = get_logger("data.retention")

#: The four retention categories, in deletion order (parents before children).
CATEGORIES: Final[tuple[str, ...]] = ("scans", "findings", "evidence", "audit")

#: Keys a project may put in ``retention_json``.
POLICY_KEYS: Final[frozenset[str]] = frozenset(
    {"enabled", "findings_days", "evidence_days", "scans_days", "audit_days"}
)


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """How long each category of data lives, for one project."""

    findings_days: int = 365
    evidence_days: int = 180
    scans_days: int = 90
    audit_days: int = 730
    enabled: bool = True

    def __post_init__(self) -> None:
        for name in ("findings_days", "evidence_days", "scans_days", "audit_days"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                msg = f"retention.{name} must be a non-negative integer (0 keeps forever)"
                raise ConfigurationError(msg)

    def cutoff(self, category: str, now: datetime) -> datetime | None:
        """The age boundary for ``category``: rows older than this are eligible.

        ``None`` means "keep forever" — either the category's day count is 0 or the whole
        policy is disabled (a legal hold).
        """
        if not self.enabled:
            return None
        days = {
            "findings": self.findings_days,
            "evidence": self.evidence_days,
            "scans": self.scans_days,
            "audit": self.audit_days,
        }.get(category)
        if days is None:
            msg = f"unknown retention category {category!r}"
            raise ConfigurationError(msg)
        return None if days <= 0 else now - timedelta(days=days)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "findings_days": self.findings_days,
            "evidence_days": self.evidence_days,
            "scans_days": self.scans_days,
            "audit_days": self.audit_days,
        }

    @classmethod
    def from_mapping(
        cls,
        defaults: RetentionPolicy,
        override: Mapping[str, Any] | None,
        *,
        source: str = "project",
    ) -> RetentionPolicy:
        """Apply a project's overrides to the deployment defaults (validated strictly).

        Unknown keys are refused: a typo in a retention policy that silently did nothing
        would be discovered by a storage bill or an audit finding, months later.
        """
        if not override:
            return defaults
        unknown = set(override) - POLICY_KEYS
        if unknown:
            msg = f"{source} retention policy has unknown keys: {sorted(unknown)}"
            raise ConfigurationError(msg)
        values: dict[str, Any] = defaults.to_dict()
        values.update(override)
        return cls(
            findings_days=_as_days(values["findings_days"], source, "findings_days"),
            evidence_days=_as_days(values["evidence_days"], source, "evidence_days"),
            scans_days=_as_days(values["scans_days"], source, "scans_days"),
            audit_days=_as_days(values["audit_days"], source, "audit_days"),
            enabled=bool(values["enabled"]),
        )


def _as_days(value: Any, source: str, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{source} retention.{name} must be an integer"
        raise ConfigurationError(msg)
    return value


def policy_for(
    defaults: RetentionPolicy, project_retention: Mapping[str, Any] | None, *, source: str
) -> RetentionPolicy:
    """Resolve one project's effective policy."""
    return RetentionPolicy.from_mapping(defaults, project_retention, source=source)


@dataclass(frozen=True, slots=True)
class CategoryPlan:
    """What one category would remove (or did remove)."""

    category: str
    rows: int = 0
    bytes: int = 0
    #: Rows removed *with* a parent (findings/evidence of an expired scan). Reported so the
    #: plan's totals are honest; they are not separately justified by their own cutoff.
    cascaded_rows: int = 0
    cascaded_bytes: int = 0
    oldest: datetime | None = None
    #: The exact rows this plan selected. The apply step deletes these ids and nothing else,
    #: so "dry run then apply" cannot drift (never serialized).
    ids: tuple[int, ...] = field(default=(), repr=False)
    #: Evidence backend keys to unlink after the rows are gone (never serialized).
    keys: tuple[str, ...] = field(default=(), repr=False)

    def merged(self, other: CategoryPlan) -> CategoryPlan:
        """Fold another plan into this one (the total a report or a caller sees).

        Ids and backend keys are carried through: ``plan.category("scans").ids`` is then the
        complete set of rows one run touches, across every project, which is what makes the
        aggregate as usable as the per-project entry it came from.
        """
        return CategoryPlan(
            category=self.category,
            rows=self.rows + other.rows,
            bytes=self.bytes + other.bytes,
            cascaded_rows=self.cascaded_rows + other.cascaded_rows,
            cascaded_bytes=self.cascaded_bytes + other.cascaded_bytes,
            oldest=_earliest(self.oldest, other.oldest),
            ids=self.ids + other.ids,
            keys=self.keys + other.keys,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rows": self.rows,
            "bytes": self.bytes,
            "cascaded_rows": self.cascaded_rows,
            "cascaded_bytes": self.cascaded_bytes,
            "oldest": self.oldest.isoformat() if self.oldest else None,
        }


@dataclass(frozen=True, slots=True)
class ProjectPrune:
    """One project's share of a pruning run."""

    project_id: int | None
    slug: str
    policy: RetentionPolicy
    categories: Mapping[str, CategoryPlan]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "slug": self.slug,
            "policy": self.policy.to_dict(),
            "categories": {name: plan.to_dict() for name, plan in sorted(self.categories.items())},
        }


@dataclass(frozen=True, slots=True)
class PrunePlan:
    """The complete result of one planning or pruning run."""

    dry_run: bool
    generated_at: datetime
    projects: tuple[ProjectPrune, ...] = ()
    #: Deployment-wide audit retention (see the module docstring on why it is not per project).
    audit: CategoryPlan = field(default_factory=lambda: CategoryPlan("audit"))

    def category(self, name: str) -> CategoryPlan:
        total = CategoryPlan(name)
        for project in self.projects:
            plan = project.categories.get(name)
            if plan is not None:
                total = total.merged(plan)
        if name == "audit":
            total = total.merged(self.audit)
        return total

    @property
    def audit_ids(self) -> tuple[int, ...]:
        return self.audit.ids

    @property
    def total_rows(self) -> int:
        return sum(
            self.category(name).rows + self.category(name).cascaded_rows for name in CATEGORIES
        )

    @property
    def total_bytes(self) -> int:
        return sum(
            self.category(name).bytes + self.category(name).cascaded_bytes for name in CATEGORIES
        )

    @property
    def empty(self) -> bool:
        return self.total_rows == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "generated_at": self.generated_at.isoformat(),
            "totals": {name: self.category(name).to_dict() for name in CATEGORIES},
            "total_rows": self.total_rows,
            "total_bytes": self.total_bytes,
            "audit": self.audit.to_dict(),
            "projects": [project.to_dict() for project in self.projects],
        }


class RetentionPruner:
    """Plans and applies retention pruning across every project."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        settings: Settings | None = None,
        auditor: Auditor | None = None,
        quota: StorageQuota | None = None,
        evidence: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self.settings = settings or get_settings()
        self.auditor = auditor
        self.quota = quota
        #: An object with ``async delete(key) -> bool`` — the evidence backend, when the
        #: deployment offloads payloads. ``None`` means payloads are inline.
        self.evidence = evidence

    # ------------------------------------------------------------------ policies
    @property
    def defaults(self) -> RetentionPolicy:
        retention = self.settings.retention
        return RetentionPolicy(
            findings_days=retention.findings_days,
            evidence_days=retention.evidence_days,
            scans_days=retention.scans_days,
            audit_days=retention.audit_days,
            enabled=retention.enabled,
        )

    def policy_for(self, retention: Mapping[str, Any] | None, *, source: str) -> RetentionPolicy:
        return policy_for(self.defaults, retention, source=source)

    def policies(self) -> tuple[tuple[int | None, str, RetentionPolicy], ...]:
        """Every project's effective policy, plus the implicit default workspace."""
        with self._session_factory() as session:
            rows = self._project_rows(session, None)
        out: list[tuple[int | None, str, RetentionPolicy]] = []
        for pid, slug, retention in rows:
            out.append((pid, slug, self.policy_for(retention, source=f"project {slug}")))
        return tuple(out)

    def _audit_cutoff(self, now: datetime) -> datetime | None:
        """The strictest non-zero audit retention among the configured policies."""
        cutoffs = [
            cutoff
            for _pid, _slug, policy in self.policies()
            if (cutoff := policy.cutoff("audit", now)) is not None
        ]
        # The *largest* cutoff is the strictest policy: it deletes the most.
        return max(cutoffs) if cutoffs else None

    # ------------------------------------------------------------------ planning
    def plan(self, *, now: datetime | None = None, project_id: int | None = None) -> PrunePlan:
        moment = now or datetime.now(UTC)
        batch = max(1, self.settings.retention.batch_limit)
        with self._session_factory() as session:
            entries: list[ProjectPrune] = []
            for pid, slug, retention in self._project_rows(session, project_id):
                policy = self.policy_for(retention, source=f"project {slug}")
                entries.append(
                    ProjectPrune(
                        project_id=pid,
                        slug=slug,
                        policy=policy,
                        categories=self._plan_project(session, pid, policy, moment, batch),
                    )
                )
            cutoff = self._audit_cutoff(moment)
            audit = (
                self._plan_audit(session, cutoff, batch)
                if cutoff is not None
                else CategoryPlan("audit")
            )
        return PrunePlan(dry_run=True, generated_at=moment, projects=tuple(entries), audit=audit)

    def _project_rows(
        self, session: Session, project_id: int | None
    ) -> list[tuple[int | None, str, dict[str, Any] | None]]:
        """Every project plus the implicit default workspace (``project_id IS NULL``)."""
        statement = select(Project.id, Project.slug, Project.retention_json).order_by(Project.id)
        if project_id is not None:
            statement = statement.where(Project.id == project_id)
        rows: list[tuple[int | None, str, dict[str, Any] | None]] = [
            (int(pid), str(slug), dict(retention) if retention else None)
            for pid, slug, retention in session.execute(statement).all()
        ]
        unassigned = session.scalar(
            select(func.count()).select_from(Scan).where(Scan.project_id.is_(None))
        )
        if project_id is None and unassigned:
            rows.insert(0, (None, "(unassigned)", dict(self.settings.retention.defaults)))
        return rows

    def _plan_project(
        self,
        session: Session,
        project_id: int | None,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
    ) -> dict[str, CategoryPlan]:
        empty = {category: CategoryPlan(category) for category in CATEGORIES}
        if not policy.enabled:
            return empty
        scan_cutoff = policy.cutoff("scans", now)
        finding_cutoff = policy.cutoff("findings", now)
        evidence_cutoff = policy.cutoff("evidence", now)

        # --- scans, and everything the foreign keys take with them
        scan_ids = self._select_scan_ids(session, project_id, scan_cutoff, limit)
        cascaded_findings = 0
        cascaded_evidence = 0
        cascaded_bytes = 0
        cascade_keys: list[str] = []
        scan_oldest: datetime | None = None
        if scan_ids:
            scan_oldest = _as_utc(
                session.scalar(select(func.min(Scan.created_at)).where(Scan.id.in_(scan_ids)))
            )
            cascaded_findings = int(
                session.scalar(
                    select(func.count()).select_from(Finding).where(Finding.scan_id.in_(scan_ids))
                )
                or 0
            )
            cascade_stats = session.execute(
                select(func.count(Evidence.id), func.coalesce(func.sum(Evidence.size_bytes), 0))
                .select_from(Evidence)
                .join(Finding, Finding.id == Evidence.finding_id)
                .where(Finding.scan_id.in_(scan_ids))
            ).one()
            cascaded_evidence = int(cascade_stats[0] or 0)
            cascaded_bytes = int(cascade_stats[1] or 0)
            cascade_keys = [
                str(key)
                for key in session.scalars(
                    select(Evidence.storage_key).where(
                        Evidence.finding_id.in_(
                            select(Finding.id).where(Finding.scan_id.in_(scan_ids))
                        ),
                        Evidence.storage_key.is_not(None),
                    )
                ).all()
            ]

        # --- findings whose scan survives
        finding_ids: list[int] = []
        finding_oldest: datetime | None = None
        finding_bytes = 0
        finding_keys: list[str] = []
        if finding_cutoff is not None:
            statement = (
                select(Finding.id, Finding.created_at)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(Finding.created_at < finding_cutoff)
                .order_by(Finding.created_at)
                .limit(limit)
            )
            statement = _scope(statement, project_id)
            rows = session.execute(statement).all()
            finding_ids = [int(row[0]) for row in rows]
            finding_oldest = _as_utc(rows[0][1]) if rows else None
            if finding_ids:
                finding_bytes = int(
                    session.scalar(
                        select(func.coalesce(func.sum(Evidence.size_bytes), 0)).where(
                            Evidence.finding_id.in_(finding_ids)
                        )
                    )
                    or 0
                )
                finding_keys = [
                    str(key)
                    for key in session.scalars(
                        select(Evidence.storage_key).where(
                            Evidence.finding_id.in_(finding_ids),
                            Evidence.storage_key.is_not(None),
                        )
                    ).all()
                ]

        # --- evidence that ages out under its own policy while its finding survives
        evidence_plan = CategoryPlan("evidence")
        if evidence_cutoff is not None:
            evidence_statement: Any = (
                select(Evidence.id, Evidence.created_at, Evidence.size_bytes, Evidence.storage_key)
                .join(Finding, Finding.id == Evidence.finding_id)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(Evidence.created_at < evidence_cutoff)
                .order_by(Evidence.created_at)
                .limit(limit)
            )
            evidence_statement = _scope(evidence_statement, project_id)
            if finding_ids:
                evidence_statement = evidence_statement.where(
                    Evidence.finding_id.notin_(finding_ids)
                )
            if scan_ids:
                evidence_statement = evidence_statement.where(Finding.scan_id.notin_(scan_ids))
            evidence_rows = session.execute(evidence_statement).all()
            evidence_plan = CategoryPlan(
                "evidence",
                rows=len(evidence_rows),
                bytes=sum(int(row[2] or 0) for row in evidence_rows),
                oldest=_as_utc(evidence_rows[0][1]) if evidence_rows else None,
                ids=tuple(int(row[0]) for row in evidence_rows),
                keys=tuple(str(row[3]) for row in evidence_rows if row[3]),
            )

        return {
            "scans": CategoryPlan(
                "scans",
                rows=len(scan_ids),
                bytes=cascaded_bytes,
                cascaded_rows=cascaded_findings + cascaded_evidence,
                cascaded_bytes=cascaded_bytes,
                oldest=scan_oldest,
                ids=tuple(scan_ids),
                keys=tuple(cascade_keys),
            ),
            "findings": CategoryPlan(
                "findings",
                rows=len(finding_ids),
                bytes=finding_bytes,
                cascaded_rows=0,
                cascaded_bytes=finding_bytes,
                oldest=finding_oldest,
                ids=tuple(finding_ids),
                keys=tuple(finding_keys),
            ),
            "evidence": evidence_plan,
            "audit": CategoryPlan("audit"),
        }

    def _select_scan_ids(
        self,
        session: Session,
        project_id: int | None,
        cutoff: datetime | None,
        limit: int,
    ) -> list[int]:
        if cutoff is None:
            return []
        statement = (
            select(Scan.id).where(Scan.created_at < cutoff).order_by(Scan.created_at).limit(limit)
        )
        statement = _scope(statement, project_id)
        return [int(value) for value in session.scalars(statement).all()]

    def _plan_audit(self, session: Session, cutoff: datetime, limit: int) -> CategoryPlan:
        rows = session.execute(
            select(AuditLog.id, AuditLog.ts)
            .where(AuditLog.ts < cutoff)
            .order_by(AuditLog.ts)
            .limit(limit)
        ).all()
        return CategoryPlan(
            "audit",
            rows=len(rows),
            oldest=_as_utc(rows[0][1]) if rows else None,
            ids=tuple(int(row[0]) for row in rows),
        )

    # ------------------------------------------------------------------ pruning
    async def prune(
        self,
        *,
        dry_run: bool = True,
        now: datetime | None = None,
        project_id: int | None = None,
    ) -> PrunePlan:
        """Plan (and, with ``dry_run=False``, apply) one pruning run.

        Dry run is the default *and* the safe default: an accidental call plans and audits
        without deleting. The plan is returned either way, so a caller can render it.
        """
        plan = self.plan(now=now, project_id=project_id)
        if dry_run:
            self._audit(AuditAction.RETENTION_PLANNED, plan, dry_run=True)
            self._count_metrics(plan, deleted=False)
            return plan

        applied = await self._apply(plan)
        self._audit(AuditAction.RETENTION_PRUNED, applied, dry_run=False)
        self._count_metrics(applied, deleted=True)
        return applied

    async def _apply(self, plan: PrunePlan) -> PrunePlan:
        keys: list[str] = []
        applied: list[ProjectPrune] = []
        with self._session_factory() as session:
            for entry in plan.projects:
                categories: dict[str, CategoryPlan] = {}
                for name, model in (
                    ("scans", Scan),
                    ("findings", Finding),
                    ("evidence", Evidence),
                ):
                    category_plan = entry.categories[name]
                    if category_plan.ids:
                        session.execute(delete(model).where(model.id.in_(category_plan.ids)))
                        session.flush()
                    categories[name] = category_plan
                    keys.extend(category_plan.keys)
                categories["audit"] = CategoryPlan("audit")
                applied.append(
                    ProjectPrune(
                        project_id=entry.project_id,
                        slug=entry.slug,
                        policy=entry.policy,
                        categories=categories,
                    )
                )
            if plan.audit.ids:
                session.execute(delete(AuditLog).where(AuditLog.id.in_(plan.audit.ids)))
                session.flush()
            session.commit()

        # Blobs go after the rows: a failure to unlink leaves an orphan (harmless, and
        # visible through the backend's stats) instead of a row pointing at nothing.
        if self.evidence is not None:
            for key in keys:
                try:
                    await self.evidence.delete(key)
                except Exception as exc:
                    _logger.warning(
                        "could not delete an evidence object",
                        extra={"event": "retention.blob_delete_failed", "error": str(exc)[:200]},
                    )
        if self.quota is not None:
            for entry in applied:
                self.quota.recompute(entry.project_id)

        return PrunePlan(
            dry_run=False,
            generated_at=plan.generated_at,
            projects=tuple(applied),
            audit=plan.audit,
        )

    # ------------------------------------------------------------------ audit + metrics
    def _audit(self, action: AuditAction, plan: PrunePlan, *, dry_run: bool) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            action,
            meta={
                "dry_run": dry_run,
                "total_rows": plan.total_rows,
                "total_bytes": plan.total_bytes,
                "categories": {
                    name: {
                        "rows": plan.category(name).rows,
                        "cascaded_rows": plan.category(name).cascaded_rows,
                        "bytes": plan.category(name).bytes,
                    }
                    for name in CATEGORIES
                },
                "projects": [
                    {"project_id": entry.project_id, "slug": entry.slug} for entry in plan.projects
                ],
            },
        )
        _logger.info(
            "retention planned" if dry_run else "retention pruned",
            extra={
                "event": "retention.planned" if dry_run else "retention.pruned",
                "dry_run": dry_run,
                "rows": plan.total_rows,
                "bytes": plan.total_bytes,
            },
        )

    def _count_metrics(self, plan: PrunePlan, *, deleted: bool) -> None:
        metric = "arachne_retention_deleted_total" if deleted else "arachne_retention_planned_total"
        for name in CATEGORIES:
            category = plan.category(name)
            rows = category.rows + category.cascaded_rows
            if rows:
                REGISTRY.increment(metric, {"category": name}, float(rows))


def _scope(statement: Any, project_id: int | None) -> Any:
    """Restrict a statement to one project (``None`` means the implicit default workspace)."""
    if project_id is None:
        return statement.where(Scan.project_id.is_(None))
    return statement.where(Scan.project_id == project_id)


def _earliest(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return left if left <= right else right


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
