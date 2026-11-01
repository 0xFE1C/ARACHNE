"""Projects / workspaces: the tenant boundary of F-07-06.

An MSSP runs one ARACHNE deployment for several customers. Everything a customer can see
must be separated along one axis — the **project** — and the separation has three parts:

* **Scope.** A project declares the addresses its operator may scan. The orchestrator
  refuses a target outside the project's scope even when the deployment allowlist would
  allow it, so a tenant cannot reach a neighbour's estate through a shared API key.
* **Ownership.** Targets and scans carry ``project_id``; every list the API, the CLI and
  the web UI produce is filtered by it.
* **Branding.** A project may carry its own report branding (company name, colours, logo,
  footer, classification), which is what makes a white-labelled report possible.

``project_id IS NULL`` means the implicit default workspace: every row written before S14
reads as that project, so a single-tenant deployment never has to create anything. The
``default`` project row is created on demand by :meth:`SqlProjectStore.ensure_default`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ConfigurationError
from arachne.core.pii import PIIPolicy
from arachne.core.safety import Scope
from arachne.data.models import Project
from arachne.data.scan_store import as_utc

__all__ = [
    "DEFAULT_PROJECT_SLUG",
    "ProjectRecord",
    "SqlProjectStore",
    "scope_from_dict",
    "scope_to_dict",
]

#: Slug of the implicit workspace that owns rows with ``project_id IS NULL``.
DEFAULT_PROJECT_SLUG = "default"

#: ``Scope`` field → the key accepted in ``scope_json``. Both the short and the full name
#: are accepted so a project created from ``ARACHNE_SCOPE_*``-style values and one created
#: from ``Scope.describe()`` round-trip.
_SCOPE_KEYS: dict[str, str] = {
    "allowed_hosts": "hosts",
    "allowed_domains": "domains",
    "allowed_networks": "networks",
    "url_prefixes": "url_prefixes",
    "allowed_refs": "refs",
    "excluded_hosts": "exclude_hosts",
    "excluded_domains": "exclude_domains",
    "excluded_networks": "exclude_networks",
    "excluded_url_prefixes": "exclude_url_prefixes",
    "excluded_refs": "exclude_refs",
}


def scope_from_dict(data: Any) -> Scope:
    """Build a :class:`Scope` from a project's ``scope_json``.

    An empty/missing document is the **full** workspace (``Scope.deny_all()`` is the
    request-time default, but a project with no declared scope means "no project-level
    restriction", exactly like an empty deployment ``ARACHNE_SCOPE_*``). ``is_empty`` on the
    result is what the orchestrator tests to decide whether to apply it.
    """
    if not data:
        return Scope()
    if not isinstance(data, dict):
        msg = "a project scope must be a mapping"
        raise ConfigurationError(msg)
    kwargs: dict[str, tuple[str, ...]] = {}
    for field_name, short in _SCOPE_KEYS.items():
        raw = data.get(short, data.get(field_name))
        if raw is None:
            kwargs[field_name] = ()
        elif isinstance(raw, str):
            kwargs[field_name] = tuple(item.strip() for item in raw.split(",") if item.strip())
        elif isinstance(raw, (list, tuple)):
            kwargs[field_name] = tuple(str(item).strip() for item in raw if str(item).strip())
        else:
            msg = f"project scope field {field_name!r} must be a list or comma-separated string"
            raise ConfigurationError(msg)
    return Scope(**kwargs)


def scope_to_dict(scope: Scope) -> dict[str, Any]:
    """The JSON form of ``scope`` (``Scope.describe()``, minus the derived fields)."""
    described = scope.describe()
    return {short: list(described[field_name]) for field_name, short in _SCOPE_KEYS.items()}


@dataclass(frozen=True, slots=True)
class ProjectRecord:
    """One tenant/workspace row."""

    id: int
    slug: str
    name: str
    description: str | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    branding: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
    #: The tenant's retention policy (S20, REQ-DATA-001); ``None`` inherits the deployment
    #: defaults. See :class:`~arachne.data.retention.RetentionPolicy` for the category keys.
    retention: dict[str, Any] | None = None
    #: The tenant's storage quota in bytes (S20, REQ-DATA-003); ``None`` means no quota.
    quota_bytes: int | None = None
    #: Stored evidence bytes, maintained by the finding store (S20, REQ-DATA-003).
    used_bytes: int | None = None
    #: The tenant's PII policy (S25, REQ-TRUST-006); ``None`` inherits the deployment's
    #: ``ARACHNE_PII_*`` defaults, which are off.
    pii: dict[str, Any] | None = None
    #: The region this tenant's evidence must stay in (S25, REQ-RESIL-004); ``None`` means
    #: no pin.
    residency_region: str | None = None
    #: The language this tenant's reports default to (S26, REQ-ECOS-005); ``None`` inherits
    #: the deployment default (``ARACHNE_REPORT_LOCALE``).
    report_locale: str | None = None

    def to_scope(self) -> Scope:
        """The project's scope guard (empty means "no project-level restriction")."""
        return scope_from_dict(self.scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "scope": dict(self.scope),
            "branding": dict(self.branding),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "retention": dict(self.retention) if self.retention else None,
            "quota_bytes": self.quota_bytes,
            "used_bytes": int(self.used_bytes or 0),
            # The policy is reported through ``PIIPolicy.to_dict`` rather than as stored: the
            # stored document carries the hash salt, which is a secret and must not travel in
            # an API response or a report (`salted: true` says one is configured).
            "pii": PIIPolicy.from_dict(self.pii).to_dict() if self.pii else None,
            "residency_region": self.residency_region,
            "report_locale": self.report_locale,
        }


class SqlProjectStore:
    """``projects`` table access, plus the default-workspace fallback."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ writes
    def create(
        self,
        slug: str,
        name: str | None = None,
        *,
        description: str | None = None,
        scope: dict[str, Any] | None = None,
        branding: dict[str, Any] | None = None,
        report_locale: str | None = None,
    ) -> ProjectRecord:
        """Create a project; ``slug`` is unique and URL-safe. Errors on a duplicate."""
        normalized = _normalize_slug(slug)
        project = Project(
            slug=normalized,
            name=(name or normalized).strip() or normalized,
            description=description,
            scope_json=dict(scope or {}),
            branding_json=dict(branding or {}),
            report_locale=(report_locale or "").strip() or None,
        )
        # Validate before writing, so a bad CIDR fails here rather than at scan time.
        scope_from_dict(project.scope_json)
        with self._session_factory() as session:
            session.add(project)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                msg = f"project {normalized!r} already exists"
                raise ConfigurationError(msg) from exc
            session.refresh(project)
            return _to_record(project)

    def ensure_default(self) -> ProjectRecord:
        """Return the ``default`` project, creating it on first use."""
        existing = self.get_by_slug(DEFAULT_PROJECT_SLUG)
        if existing is not None:
            return existing
        return self.create(DEFAULT_PROJECT_SLUG, "Default workspace")

    def update(
        self,
        project_id: int,
        *,
        name: str | None = None,
        description: str | None = None,
        scope: dict[str, Any] | None = None,
        branding: dict[str, Any] | None = None,
    ) -> ProjectRecord | None:
        """Update the fields supplied; ``None`` leaves a field untouched."""
        if scope is not None:
            scope_from_dict(scope)  # validate before writing
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            if name is not None:
                row.name = name
            if description is not None:
                row.description = description
            if scope is not None:
                row.scope_json = dict(scope)
            if branding is not None:
                row.branding_json = dict(branding)
            session.commit()
            session.refresh(row)
            return _to_record(row)

    def set_retention(
        self, project_id: int, retention: Mapping[str, Any] | None
    ) -> ProjectRecord | None:
        """Set (or clear) a project's retention policy (S20, REQ-DATA-001).

        Validated through :class:`~arachne.data.retention.RetentionPolicy` *before* it is
        stored, so a bad policy fails here rather than at three in the morning when the
        pruning job reads it.
        """
        from arachne.data.retention import RetentionPolicy, policy_for

        if retention is not None:
            policy_for(
                RetentionPolicy(
                    findings_days=int(retention.get("findings_days", 365)),
                    evidence_days=int(retention.get("evidence_days", 180)),
                    scans_days=int(retention.get("scans_days", 90)),
                    audit_days=int(retention.get("audit_days", 730)),
                ),
                retention,
                source=f"project {project_id}",
            )
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.retention_json = dict(retention) if retention else None
            session.commit()
            session.refresh(row)
            return _to_record(row)

    def set_quota(self, project_id: int, limit_bytes: int | None) -> int | None:
        """Set (or clear) a project's storage quota (S20, REQ-DATA-003)."""
        if limit_bytes is not None and limit_bytes < 0:
            msg = "a storage quota cannot be negative"
            raise ConfigurationError(msg)
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.quota_bytes = limit_bytes
            session.commit()
            return row.quota_bytes

    def set_pii(self, project_id: int, policy: Mapping[str, Any] | None) -> ProjectRecord | None:
        """Set (or clear) a project's PII policy (S25, REQ-TRUST-006).

        Validated through :class:`~arachne.core.pii.PIIPolicy` before storage, so an unknown
        category or an unsalted ``hash`` action fails at configuration time rather than
        silently masking nothing during a scan.
        """
        from arachne.core.pii import PIIPolicy

        if policy is not None:
            PIIPolicy.from_dict(policy)
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.pii_json = dict(policy) if policy else None
            session.commit()
            session.refresh(row)
            return _to_record(row)

    def set_residency(self, project_id: int, region: str | None) -> ProjectRecord | None:
        """Pin (or unpin) a project's evidence residency (S25, REQ-RESIL-004)."""
        cleaned = (region or "").strip() or None
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.residency_region = cleaned
            session.commit()
            session.refresh(row)
            return _to_record(row)

    def set_locale(self, project_id: int, locale: str | None) -> ProjectRecord | None:
        """Set (or clear) a project's default report language (S26, REQ-ECOS-005).

        Validated as a primary language subtag (``en``, ``fr``, ``pt-BR``): a typo must fail
        here rather than silently fall back to English, which would look like the setting
        being ignored.
        """
        cleaned = (locale or "").strip() or None
        if cleaned is not None and not re.fullmatch(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*", cleaned):
            msg = f"{locale!r} is not a language tag such as en, fr or pt-BR"
            raise ConfigurationError(msg)
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return None
            row.report_locale = cleaned
            session.commit()
            session.refresh(row)
            return _to_record(row)

    def pii_policy(self, project_id: int | None, *, fallback: Any = None) -> Any:
        """The PII policy in force for ``project_id`` (S25, REQ-TRUST-006).

        A project that declares one wins; a project that declares none inherits
        ``fallback`` (the deployment default, from ``ARACHNE_PII_*``). ``fallback=None``
        means "no policy", i.e. masking off.
        """
        from arachne.core.pii import PIIPolicy

        if project_id is not None:
            record = self.get(project_id)
            if record is not None and record.pii:
                return PIIPolicy.from_dict(record.pii)
        return fallback if fallback is not None else PIIPolicy()

    def residency_for(self, project_id: int | None) -> str | None:
        """The region a project's evidence is pinned to, or ``None`` for no pin."""
        if project_id is None:
            return None
        record = self.get(project_id)
        return record.residency_region if record is not None else None

    def delete(self, project_id: int) -> bool:
        """Delete a project. Its targets/scans survive with ``project_id = NULL``.

        The default workspace cannot be deleted (it is the destination of every pre-S14
        row); refusing is friendlier than a cascade nobody asked for.

        Suppression rules and risk acceptances are tenant-scoped from S26 and are nulled in
        the same transaction (REQ-ECOS-004). They carry no database-level ``ON DELETE SET
        NULL`` — SQLite cannot ALTER a constraint into an existing table (migration 0012) — so
        the store does it explicitly rather than leaving a dangling tenant id behind: a NULL
        reads as "deployment-wide", which is exactly what a decision made in a deleted
        workspace becomes.
        """
        from arachne.data.models import RiskAcceptance
        from arachne.data.models import Suppression as SuppressionRow

        with self._session_factory() as session:
            row = session.get(Project, project_id)
            if row is None:
                return False
            if row.slug == DEFAULT_PROJECT_SLUG:
                msg = "the default project cannot be deleted"
                raise ConfigurationError(msg)
            for table in (SuppressionRow, RiskAcceptance):
                session.query(table).filter(table.project_id == project_id).update(
                    {table.project_id: None}, synchronize_session=False
                )
            session.delete(row)
            session.commit()
            return True

    # ------------------------------------------------------------------ reads
    def list_projects(self) -> tuple[ProjectRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(select(Project).order_by(Project.slug)).all()
            return tuple(_to_record(row) for row in rows)

    def get(self, project_id: int) -> ProjectRecord | None:
        with self._session_factory() as session:
            row = session.get(Project, project_id)
            return None if row is None else _to_record(row)

    def get_by_slug(self, slug: str) -> ProjectRecord | None:
        with self._session_factory() as session:
            row = session.scalar(select(Project).where(Project.slug == _normalize_slug(slug)))
            return None if row is None else _to_record(row)

    def resolve(self, reference: str | int | None, *, create_default: bool = True) -> ProjectRecord:
        """Resolve a slug or numeric id; ``None`` (or ``"default"``) is the workspace."""
        if reference is None or (isinstance(reference, str) and not reference.strip()):
            if create_default:
                return self.ensure_default()
            existing = self.get_by_slug(DEFAULT_PROJECT_SLUG)
            if existing is None:
                msg = "the default project does not exist yet; create it first"
                raise ConfigurationError(msg)
            return existing
        if isinstance(reference, int) or (isinstance(reference, str) and reference.isdigit()):
            found = self.get(int(reference))
        else:
            found = self.get_by_slug(str(reference))
        if found is None:
            msg = f"project {reference!r} does not exist"
            raise ConfigurationError(msg)
        return found


def _normalize_slug(slug: str) -> str:
    normalized = slug.strip().lower()
    if not normalized:
        msg = "a project slug must not be empty"
        raise ConfigurationError(msg)
    if len(normalized) > 64:
        msg = "a project slug must be at most 64 characters"
        raise ConfigurationError(msg)
    if not all(char.isalnum() or char in {"-", "_", "."} for char in normalized):
        msg = f"project slug {slug!r} may only contain letters, digits, '-', '_' and '.'"
        raise ConfigurationError(msg)
    return normalized


def _to_record(row: Project) -> ProjectRecord:
    return ProjectRecord(
        id=int(row.id),
        slug=str(row.slug),
        name=str(row.name),
        description=row.description,
        scope=dict(row.scope_json or {}),
        branding=dict(row.branding_json or {}),
        created_at=as_utc(row.created_at),
        retention=dict(row.retention_json) if row.retention_json else None,
        quota_bytes=row.quota_bytes,
        used_bytes=row.used_bytes,
        pii=dict(row.pii_json) if row.pii_json else None,
        residency_region=row.residency_region,
        report_locale=row.report_locale,
    )
