"""Adversarial cross-tenant isolation, generated from the ORM metadata (REQ-IDAM-006).

Three halves:

* **coverage** — the store list comes from ``Base.metadata`` and the endpoint list from the
  live route table, so a new table or a new ``/{id}`` route fails the suite until it is
  classified. Neither list is written by hand.
* **adversarial** — for every classified tenant resource, a key belonging to tenant A attempts
  to read, mutate and delete tenant B's resource. Every attempt must be refused *and* audited
  as ``api.denied`` with the attempted resource id.
* **self-test** — the collection check is run against a store whose tenant filter has been
  deliberately removed, and it must fail. A suite that cannot fail is not evidence.

A refusal is a 404 (or, for a key bound to another tenant, a 403), so it never confirms that
the row exists; the audit event is what makes the attempt visible.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from tests.helpers.api import ApiHarness, make_api_harness
from tests.helpers.isolation import (
    CASE_BY_TABLE,
    CASES,
    GLOBAL_ROUTE_REASONS,
    TenantCase,
    classified_routes,
    id_taking_routes,
    route_owners,
    tenant_tables,
)

from arachne.core.audit import AuditAction

pytestmark = pytest.mark.integration

#: The two tenants every case runs between. Both are explicit: ``default`` is special-cased
#: (it also owns the pre-multi-tenancy NULL rows) and the case under test is two named tenants.
TENANT_A = "isolation-a"
TENANT_B = "isolation-b"

#: One parameter per route, so a failure names the exact endpoint that leaked.
ID_CASES = [
    pytest.param(case, item, id=f"{case.table}-{item.method.replace('/', '_')}-{item.path}")
    for case in CASES
    for item in case.items
]

COLLECTION_CASES = [
    pytest.param(case, id=case.table) for case in CASES if case.collection is not None
]


@pytest.fixture(scope="module")
def isolated(tmp_path_factory: Any) -> Any:
    """A harness with two tenants and one admin key bound to each of them.

    **Module-scoped on purpose.** Building the app and the database costs 0.28 s (measured),
    and this file needs it 44 times — 12 s of the full suite's budget that asserts nothing.
    The tests share the harness but not their expectations: each seeds the resource it is
    about and asserts on that id, so rows accumulated by an earlier case are invisible to it.
    (The two unique keys a shared harness could collide on — a project's slug and a service
    account's label — are idempotent in the seed helpers for exactly this reason.)
    """
    harness = make_api_harness(tmp_path_factory.mktemp("isolation"))
    harness.services.projects.create(TENANT_A, "Isolation A")
    harness.services.projects.create(TENANT_B, "Isolation B")
    keys: dict[str, str] = {}
    for slug in (TENANT_A, TENANT_B):
        _record, secret = harness.services.service_accounts.create(
            f"probe-{slug}", "admin", project=slug, owner=f"probe@{slug}"
        )
        keys[slug] = str(secret)
    harness.probe_keys = keys  # type: ignore[attr-defined]
    try:
        yield harness
    finally:
        harness.close()


def _bound_key(harness: ApiHarness, slug: str) -> str:
    """The admin service account bound to ``slug`` — the adversary of every case."""
    keys: dict[str, str] = harness.probe_keys  # type: ignore[attr-defined]
    return keys[slug]


def _headers(key: str, method: str) -> dict[str, str]:
    """Auth for one attempt; a UI state change also carries the htmx CSRF marker."""
    headers = {"X-API-Key": key}
    if method != "GET":
        headers["HX-Request"] = "true"
    return headers


def _fill(path: str, target: Any) -> str:
    """Substitute a seeded resource into a route template, whatever the parameter is called."""
    return re.sub(r"\{[a-z_]+\}", str(target), path)


def _call(
    harness: ApiHarness, method: str, path: str, *, headers: dict[str, str], body: Any = None
) -> Any:
    client = harness.client()
    if method == "GET":
        return client.get(path, headers=headers)
    return client.request(method, path, headers=headers, json=body)


def _denials_naming(harness: ApiHarness, resource_id: Any) -> list[Any]:
    return [
        event
        for event in harness.events_of(AuditAction.API_DENIED)
        if str(event.meta.get("resource_id")) == str(resource_id)
    ]


def assert_collection_hides(
    harness: ApiHarness, case: TenantCase, target: Any, *, label: str
) -> None:
    """The collection half of isolation, as one assertion the self-test can also run.

    The owner's listing must contain the row (otherwise the check proves nothing) and the
    neighbour's must not. That differential is what makes an accidental absence — an empty
    page, a filtered-out row — a failure rather than a pass.
    """
    assert case.collection is not None
    method, path = case.collection.split(" ", 1)
    owner = _call(harness, method, path, headers=_headers(_bound_key(harness, TENANT_B), method))
    assert owner.status_code == 200, owner.text
    assert str(target) in owner.text, (
        f"{label}: the owner's own listing does not contain {target!r}, so the check is vacuous"
    )
    neighbour = _call(
        harness, method, path, headers=_headers(_bound_key(harness, TENANT_A), method)
    )
    assert neighbour.status_code == 200, neighbour.text
    assert str(target) not in neighbour.text, (
        f"{label}: {path} listed another tenant's {case.resource} ({target!r})"
    )


# --------------------------------------------------------------------------- coverage


def test_the_registry_covers_exactly_the_tenant_bearing_tables() -> None:
    """A tenant table added without a case fails here; a stale case fails here too."""
    computed = tenant_tables()
    registered = set(CASE_BY_TABLE)
    assert computed - registered == set(), (
        f"these tables reach a tenant but have no isolation case: {sorted(computed - registered)}"
    )
    assert registered - computed == set(), (
        f"these cases name tables that are not tenant-scoped: {sorted(registered - computed)}"
    )
    assert len(computed) >= 20, f"the closure found only {len(computed)} tenant tables"


def test_every_tenant_case_names_a_real_table() -> None:
    from arachne.data.models import Base

    for case in CASES:
        assert case.table in Base.metadata.tables, f"{case.table} is not an ORM table"
        if case.seed is None:
            assert case.via in CASE_BY_TABLE, (
                f"{case.table} has no endpoint of its own and no resource it is reached through"
            )
        else:
            assert case.collection or case.items, f"{case.table} declares no surface at all"


def test_every_id_taking_route_is_classified(isolated: ApiHarness) -> None:
    """A new ``/{id}`` route fails here until it is classified — tenant, or global with a reason."""
    served = id_taking_routes(isolated.app)
    classified = classified_routes()
    assert served - classified == set(), (
        f"these id-taking routes are not classified: {sorted(served - classified)}"
    )
    assert classified - served == set(), (
        f"these classifications name routes the app does not serve: {sorted(classified - served)}"
    )
    for path in GLOBAL_ROUTE_REASONS:
        assert path in served, f"{path} is classified as global but is not served"


def test_every_classified_tenant_route_is_exercised(isolated: ApiHarness) -> None:
    """Every non-global classified route appears in the parametrised adversarial cases."""
    served = id_taking_routes(isolated.app)
    exercised = {item.path for case in CASES for item in case.items}
    for path, resource in route_owners().items():
        if not resource:
            continue
        assert path in served, f"{path} is classified for {resource} but the app does not serve it"
        assert path in exercised, f"{path} is classified for {resource} but no case reaches it"


# --------------------------------------------------------------------------- adversarial


@pytest.mark.parametrize(("case", "item"), ID_CASES)
def test_a_bound_key_cannot_address_another_tenants_resource(
    isolated: ApiHarness, case: TenantCase, item: Any
) -> None:
    """Read, mutate or delete of tenant B's resource by tenant A's key: refused and audited."""
    assert case.seed is not None
    target = case.seed(isolated, TENANT_B)
    key = _bound_key(isolated, TENANT_A)
    path = _fill(str(item.path), target)
    before = len(isolated.events_of(AuditAction.API_DENIED))

    response = _call(
        isolated, item.method, path, headers=_headers(key, item.method), body=item.body
    )

    assert response.status_code in {403, 404}, (
        f"{item.method} {path} answered {response.status_code}: another tenant's "
        f"{case.resource} was reachable"
    )
    assert _denials_naming(isolated, target), (
        f"{item.method} {path} was refused but no api.denied event names {target!r}: "
        f"{[event.meta for event in isolated.events_of(AuditAction.API_DENIED)[before:]]}"
    )


@pytest.mark.parametrize("case", COLLECTION_CASES)
def test_another_tenants_resource_is_absent_from_every_collection(
    isolated: ApiHarness, case: TenantCase
) -> None:
    """The collection endpoints list only the caller's tenant (the read half of isolation)."""
    assert case.seed is not None
    target = case.seed(isolated, TENANT_B)
    assert_collection_hides(isolated, case, target, label=case.table)


def test_the_owners_own_resource_stays_reachable(isolated: ApiHarness) -> None:
    """Negative control: the same key reaching its own tenant's scan is served, not refused."""
    scan_id = isolated.seed_scan(project=TENANT_A)
    key = _bound_key(isolated, TENANT_A)
    response = _call(isolated, "GET", f"/api/v1/scans/{scan_id}", headers=_headers(key, "GET"))
    assert response.status_code == 200, response.text
    assert response.json()["id"] == scan_id


# --------------------------------------------------------------------------- self-test


def test_a_deliberately_broken_query_is_caught(
    isolated: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Remove a store's tenant filter and the collection check must fail.

    The check run here is the same :func:`assert_collection_hides` the suite uses, against a
    store that no longer scopes its listing. If it still passed, the suite's collection half
    would be asserting nothing.
    """
    from arachne.data.scan_store import SqlScanStateStore

    case = CASE_BY_TABLE["scans"]
    target = isolated.seed_scan(project=TENANT_B)

    # The suite's own check passes while the store is honest.
    assert_collection_hides(isolated, case, target, label="before the break")

    original = SqlScanStateStore.list_scans

    def unscoped(self: Any, **kwargs: Any) -> Any:
        kwargs.pop("project_id", None)
        kwargs.pop("include_unassigned", None)
        return original(self, **kwargs)

    monkeypatch.setattr(SqlScanStateStore, "list_scans", unscoped)

    with pytest.raises(AssertionError, match="another tenant"):
        assert_collection_hides(isolated, case, target, label="after the break")
