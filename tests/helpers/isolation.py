"""Cross-tenant isolation cases, derived from the ORM metadata and the live route table.

REQ-IDAM-006 asks for an *adversarial* suite, not a per-endpoint assertion: for every store
and every collection and id-taking endpoint, another tenant's resource must be unreadable,
unchangeable and undeletable, and the attempt must be audited. Two properties keep the suite
from drifting:

* the **store list is computed** — :func:`tenant_tables` walks ``Base.metadata`` outwards
  from the tenant root along real foreign keys, so a table added in a later release fails the
  suite until it is given a case;
* the **endpoint list is computed** — :func:`id_taking_routes` reads the live application's
  route table, so a new ``/{id}`` route fails the suite until it is classified (as a tenant
  resource or as deliberately deployment-wide, with a reason).

So the registry below is the only hand-written part, and it can only become wrong by losing
coverage — which the two computed tests catch.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from arachne.data.models import Base

__all__ = [
    "CASES",
    "CASE_BY_TABLE",
    "GLOBAL_ROUTE_REASONS",
    "TenantCase",
    "classified_routes",
    "id_taking_routes",
    "route_owners",
    "tenant_tables",
]

#: Columns through which a row names its tenant directly. ``project`` is the *slug* the
#: identity tables carry: a key or a session is bound to a tenant rather than partitioned by
#: one, which is why those tables need a different case from the resource tables.
_TENANT_COLUMNS = ("project_id", "project")

#: The tenant root: the table a resource chain has to reach to be tenant-scoped.
_TENANT_ROOT = "projects"


def tenant_tables() -> frozenset[str]:
    """Every tenant-scoped table, computed from the ORM metadata.

    Three constructions, all generational:

    * the tenant root itself (``projects``);
    * a table carrying a ``project_id`` or ``project`` column;
    * a table reachable from one of those along a foreign key (``findings`` → ``scans`` →
      ``projects``), closed to a fixpoint.

    A table that reaches nothing is deployment-wide *by construction* — which is what makes
    the exclusion honest rather than an omission.
    """
    tables = Base.metadata.tables
    tenant: set[str] = {_TENANT_ROOT}
    for name, table in tables.items():
        if any(column in table.columns for column in _TENANT_COLUMNS):
            tenant.add(name)
    changed = True
    while changed:
        changed = False
        for name, table in tables.items():
            if name in tenant:
                continue
            if any(foreign_key.column.table.name in tenant for foreign_key in table.foreign_keys):
                tenant.add(name)
                changed = True
    return frozenset(tenant)


# --------------------------------------------------------------------------- route discovery


def _walk_routes(routes: Any, prefix: str = "") -> Iterator[str]:
    """Every route path in ``routes``, with each included router's prefix folded in.

    FastAPI keeps an ``include_router`` call as a wrapper object holding the original router
    and the include context (which is where the prefix lives), so a plain ``app.routes`` loop
    sees the wrapper and not the routes. Walking the wrappers is what makes the enumeration
    complete instead of silently empty.
    """
    for route in routes:
        context = getattr(route, "include_context", None)
        nested = getattr(route, "original_router", None)
        if context is not None and nested is not None:
            yield from _walk_routes(nested.routes, prefix + (getattr(context, "prefix", "") or ""))
            continue
        children = getattr(route, "routes", None)
        if children:
            yield from _walk_routes(children, prefix)
            continue
        path = getattr(route, "path", "")
        if path:
            yield prefix + path


def id_taking_routes(app: Any) -> frozenset[str]:
    """Every route path that addresses a resource by value, from the live application.

    A path segment in braces is an id (``{scan_id}``, ``{label}``, ``{slug}``, ``{cve}`` …).
    Every one of them has to be classified below: as a tenant resource, or as
    deployment-wide with a stated reason.
    """
    return frozenset(path for path in _walk_routes(getattr(app, "routes", ())) if "{" in path)


# --------------------------------------------------------------------------- seeding


def _project_id(harness: Any, slug: str) -> int:
    record = harness.services.projects.get_by_slug(slug)
    assert record is not None, f"project {slug!r} was not created"
    return int(record.id)


def _seed_project(harness: Any, slug: str) -> str:
    """The fixture already created the tenant; only create one that is genuinely absent."""
    existing = harness.services.projects.get_by_slug(slug)
    if existing is not None:
        return str(existing.slug)
    return str(harness.services.projects.create(slug, f"Isolation {slug}").slug)


def _seed_target(harness: Any, slug: str) -> int:
    from arachne.core.target import TargetDefinition

    definition = TargetDefinition(
        name=f"isolation-{slug}",
        targets=({"kind": "url", "value": f"https://{slug}.example/"},),  # type: ignore[arg-type]
    )
    return int(
        harness.services.target_store.save(definition, project_id=_project_id(harness, slug))
    )


def _seed_scan(harness: Any, slug: str) -> int:
    return int(harness.seed_scan(project=slug))


def _seed_finding(harness: Any, slug: str) -> int:
    return int(harness.seed_finding(scan_id=_seed_scan(harness, slug)))


def _seed_evidence(harness: Any, slug: str) -> int:
    rows = harness.context.queries.evidence_rows(_seed_finding(harness, slug))
    assert rows, "the seeded finding carries no evidence row"
    return int(rows[0]["id"])


def _seed_suppression(harness: Any, slug: str) -> int:
    from arachne.quality.suppressions import Suppression

    rule = Suppression(
        kind="rule",
        check_id="M4/env-file-probe@1.0",
        reason="cross-tenant isolation case",
        actor="pytest",
    )
    stored = harness.services.quality.add_suppression(rule, project_id=_project_id(harness, slug))
    assert stored.id is not None
    return int(stored.id)


def _seed_acceptance(harness: Any, slug: str) -> int:
    from arachne.quality.acceptance import RiskAcceptance

    acceptance = RiskAcceptance(
        check_id="M4/env-file-probe@1.0",
        owner="isolation-owner",
        justification="cross-tenant isolation case: a fixture accepts this risk until it runs",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        actor="pytest",
    )
    stored = harness.services.quality.add_acceptance(
        acceptance, project_id=_project_id(harness, slug)
    )
    assert stored.id is not None
    return int(stored.id)


def _seed_service_account(harness: Any, slug: str) -> str:
    """Create the tenant's probe account, or reuse it.

    ``service_accounts.label`` is unique, so a module-scoped harness would collide on the
    second case that seeds the same tenant. Reusing the row keeps the case about the tenant
    check rather than about how many times the suite has already run.
    """
    label = f"isolation-{slug}"
    if harness.services.service_accounts.get(label) is None:
        harness.services.service_accounts.create(
            label, "viewer", project=slug, owner=f"owner@{slug}"
        )
    return label


# --------------------------------------------------------------------------- the registry


@dataclass(frozen=True)
class _Item:
    """One id-taking route: method, absolute path template, minimum role, request body."""

    method: str
    path: str
    role: str = "viewer"
    body: dict[str, Any] | None = None


@dataclass(frozen=True)
class TenantCase:
    """One tenant-bearing table and how the suite exercises it.

    ``seed`` creates a row belonging to a project and returns the value the routes address it
    by. ``items`` are the id-taking routes that reach it; ``collection`` is its listing
    endpoint. ``bind`` marks the tables whose tenant is a *binding* rather than a partition —
    a key or a session — where the case is that a key bound elsewhere cannot touch it.
    ``via`` names the resource whose routes exercise a table that has no endpoint of its own.
    """

    table: str
    resource: str
    seed: Callable[[Any, str], Any] | None = None
    collection: str | None = None
    items: tuple[_Item, ...] = ()
    via: str | None = None
    bind: bool = False
    note: str = ""


CASES: tuple[TenantCase, ...] = (
    TenantCase(
        table="projects",
        resource="project",
        seed=_seed_project,
        collection="GET /api/v1/projects",
        items=(
            _Item("GET", "/api/v1/projects/{slug}"),
            _Item("GET", "/api/v1/projects/{slug}/retention"),
            _Item("PUT", "/api/v1/projects/{slug}/retention", "admin", {"findings_days": 30}),
            _Item("GET", "/api/v1/projects/{slug}/storage"),
            _Item("PUT", "/api/v1/projects/{slug}/storage", "admin", {"limit_bytes": 1024}),
            _Item("DELETE", "/api/v1/projects/{slug}", "admin"),
        ),
        bind=True,
        note=(
            "addressed by slug and refused for a key bound to another tenant; an unbound admin "
            "key is deployment-wide by design and may name any project"
        ),
    ),
    TenantCase(
        table="targets",
        resource="target",
        seed=_seed_target,
        collection="GET /api/v1/targets",
        items=(
            _Item("GET", "/api/v1/targets/{target_id}"),
            _Item("DELETE", "/api/v1/targets/{target_id}", "admin"),
        ),
    ),
    TenantCase(
        table="scans",
        resource="scan",
        seed=_seed_scan,
        collection="GET /api/v1/scans",
        items=(
            _Item("GET", "/api/v1/scans/{scan_id}"),
            _Item("POST", "/api/v1/scans/{scan_id}/stop", "scanner"),
            _Item("DELETE", "/api/v1/scans/{scan_id}", "admin"),
            _Item("GET", "/api/v1/scans/{scan_id}/report"),
            _Item("POST", "/api/v1/scans/{scan_id}/report", "scanner"),
            _Item("GET", "/api/v1/scans/{scan_id}/hypotheses"),
            _Item(
                "POST",
                "/api/v1/scans/{scan_id}/hypotheses/control",
                "scanner",
                {"directive": "abort"},
            ),
            _Item("GET", "/ui/scans/{scan_id}"),
            _Item("GET", "/ui/scans/{scan_id}/findings"),
            _Item("GET", "/ui/scans/{scan_id}/report"),
            _Item("GET", "/ui/scans/{scan_id}/attack-paths"),
            _Item("POST", "/ui/scans/{scan_id}/stop", "scanner"),
        ),
    ),
    TenantCase(
        table="findings",
        resource="finding",
        seed=_seed_finding,
        collection="GET /api/v1/findings",
        items=(
            _Item("GET", "/api/v1/findings/{finding_id}"),
            _Item("PATCH", "/api/v1/findings/{finding_id}", "scanner", {"status": "open"}),
            _Item("DELETE", "/api/v1/findings/{finding_id}", "admin"),
            _Item("GET", "/ui/findings/{finding_id}"),
            _Item("POST", "/ui/findings/{finding_id}/fp", "scanner", {"note": "isolation"}),
        ),
    ),
    TenantCase(
        table="evidences",
        resource="evidence",
        seed=_seed_evidence,
        items=(_Item("GET", "/api/v1/evidence/{evidence_id}/download"),),
    ),
    TenantCase(
        table="suppressions",
        resource="suppression",
        seed=_seed_suppression,
        collection="GET /api/v1/suppressions",
        items=(
            _Item("DELETE", "/api/v1/suppressions/{suppression_id}", "scanner"),
            _Item("POST", "/ui/quality/suppressions/{suppression_id}/revoke", "scanner"),
        ),
    ),
    TenantCase(
        table="risk_acceptances",
        resource="acceptance",
        seed=_seed_acceptance,
        collection="GET /api/v1/acceptances",
        items=(
            _Item("DELETE", "/api/v1/acceptances/{acceptance_id}", "scanner"),
            _Item("POST", "/ui/quality/acceptances/{acceptance_id}/revoke", "scanner"),
        ),
    ),
    TenantCase(
        table="service_accounts",
        resource="service account",
        seed=_seed_service_account,
        items=(
            _Item("POST", "/api/v1/service-accounts/{label}/rotate", "admin"),
            _Item("POST", "/api/v1/service-accounts/{label}/revoke", "admin"),
        ),
        bind=True,
        note=(
            "a credential is bound to a tenant, not partitioned by one: the case is that a key "
            "bound to another project cannot rotate or revoke it"
        ),
    ),
    TenantCase(
        table="auth_sessions",
        resource="session",
        via="projects",
        bind=True,
        note=(
            "a session carries its tenant and is only ever resolved from the token the caller "
            "presents; no endpoint addresses a session by id, so it has no id-taking surface"
        ),
    ),
    TenantCase(
        table="assets",
        resource="asset",
        via="scans",
        note="reached only through its scan, whose routes the suite exercises",
    ),
    TenantCase(
        table="scan_steps",
        resource="scan step",
        via="scans",
        note="reached only through its scan",
    ),
    TenantCase(
        table="scan_queue",
        resource="queue row",
        via="scans",
        note="derived from scans; the agent plane addresses a scan, which the scan routes cover",
    ),
    TenantCase(
        table="analysis_log",
        resource="analysis row",
        via="findings",
        note="reached only through its finding",
    ),
    TenantCase(
        table="finding_verifications",
        resource="verification",
        via="findings",
        note="reached only through its finding",
    ),
    TenantCase(
        table="fp_feedback",
        resource="feedback row",
        via="findings",
        note="reached only through its finding",
    ),
    TenantCase(
        table="fix_proposals",
        resource="fix proposal",
        via="findings",
        note="reached only through its finding",
    ),
    TenantCase(
        table="integrity_seals",
        resource="integrity seal",
        via="scans",
        note="reached only through its scan",
    ),
    TenantCase(
        table="posture_verifications",
        resource="posture verification",
        via="findings",
        note="reached only through its finding",
    ),
    TenantCase(
        table="purple_runs",
        resource="purple run",
        via="scans",
        note="reached only through its scan (the campaign itself is deployment-wide)",
    ),
    TenantCase(
        table="scans_diff",
        resource="scan diff",
        via="scans",
        note="reached only through the two scans it compares",
    ),
    TenantCase(
        table="simulation_points",
        resource="simulation point",
        via="scans",
        note="reached only through its scan",
    ),
)

CASE_BY_TABLE: dict[str, TenantCase] = {case.table: case for case in CASES}

#: Id-taking routes that are deliberately deployment-wide, each with its reason. Listing them
#: is what lets the exhaustion test tell "classified as global" from "not classified at all".
GLOBAL_ROUTE_REASONS: dict[str, str] = {
    "/api/v1/feeds/lookup/{cve}": "a CVE identifier, not a tenant resource",
    "/api/v1/feeds/{feed_id}": "the feed catalogue is deployment-wide",
    "/api/v1/purple/campaigns/{name}/run": "an ATT&CK campaign is deployment-wide",
    "/api/v1/schedules/{schedule_id}": "schedules are deployment-wide (no tenant column)",
    "/api/v1/schedules/{schedule_id}/run": "schedules are deployment-wide",
    "/ui/feeds/{feed_id}/delete": "the feed catalogue is deployment-wide",
    "/ui/schedules/{schedule_id}/remove": "schedules are deployment-wide",
    "/ui/schedules/{schedule_id}/run": "schedules are deployment-wide",
    "/api/v1/scim/v2/Users/{user_id}": (
        "provisioning is a deployment-wide identity plane: a provisioned principal carries no "
        "tenant (tenancy stays an attribute of the key that acts), and the SCIM routes are "
        "reachable only by a dedicated provisioner credential"
    ),
    "/api/v1/scim/v2/Groups/{group_id}": (
        "the role vocabulary is global, so a provisioned group belongs to no tenant"
    ),
}


def route_owners() -> dict[str, str]:
    """``route template → resource`` for the tenant resources, plus ``""`` for the global ones."""
    owners: dict[str, str] = dict.fromkeys(GLOBAL_ROUTE_REASONS, "")
    for case in CASES:
        for item in case.items:
            owners[item.path] = case.resource
    return owners


def classified_routes() -> frozenset[str]:
    """Every id-taking route template this release classifies, by path."""
    return frozenset(route_owners())
