"""Projects / workspaces: tenant isolation for scopes, scans and reports (F-07-06, S14)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from tests.conftest import build_scan_request

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError, OutOfScopeError
from arachne.core.lifecycle import MemoryScanStateStore
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.target import ScanRequest, TargetDefinition, TargetSelector
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.project_store import (
    DEFAULT_PROJECT_SLUG,
    ProjectRecord,
    SqlProjectStore,
    scope_from_dict,
    scope_to_dict,
)
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.target_store import SqlTargetStore


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    created = create_sqlite_engine(f"sqlite:///{tmp_path / 'projects.db'}")
    create_all(created)
    try:
        yield created
    finally:
        created.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def store(factory: sessionmaker[Session]) -> SqlProjectStore:
    return SqlProjectStore(factory)


# --------------------------------------------------------------------------- store CRUD
def test_create_get_list_and_slug_normalisation(store: SqlProjectStore) -> None:
    created = store.create("Acme", "Acme Corp", description="customer one")
    assert created.slug == "acme"
    assert created.name == "Acme Corp"
    assert store.get(created.id) == created
    assert store.get_by_slug("ACME") == created
    assert [item.slug for item in store.list_projects()] == ["acme"]


def test_a_duplicate_slug_is_refused(store: SqlProjectStore) -> None:
    store.create("acme")
    with pytest.raises(ConfigurationError, match="already exists"):
        store.create("ACME")


@pytest.mark.parametrize("slug", ["", "a b", "a/b", "../etc", "x" * 65])
def test_an_invalid_slug_is_refused(store: SqlProjectStore, slug: str) -> None:
    with pytest.raises(ConfigurationError):
        store.create(slug)


def test_the_default_workspace_is_created_on_demand(store: SqlProjectStore) -> None:
    assert store.get_by_slug(DEFAULT_PROJECT_SLUG) is None
    first = store.ensure_default()
    second = store.ensure_default()
    assert first.id == second.id
    assert first.slug == DEFAULT_PROJECT_SLUG


def test_the_default_workspace_cannot_be_deleted(store: SqlProjectStore) -> None:
    default = store.ensure_default()
    with pytest.raises(ConfigurationError, match="default project"):
        store.delete(default.id)


def test_delete_detaches_scans_rather_than_destroying_them(
    store: SqlProjectStore, factory: sessionmaker[Session]
) -> None:
    project = store.create("acme")
    targets = SqlTargetStore(factory)
    scans = SqlScanStateStore(factory)
    target_id = targets.save(build_scan_request().target, project_id=project.id)
    scan = scans.create_scan(
        target_id=target_id, engine="heuristic", plan={}, project_id=project.id
    )

    assert store.delete(project.id) is True
    assert store.get(project.id) is None
    # ON DELETE SET NULL: the evidence survives, detached from the tenant.
    assert scans.get_scan(scan.id) is not None
    assert scans.get_scan(scan.id).project_id is None


def test_scope_json_round_trips_and_validates(store: SqlProjectStore) -> None:
    scope = {"hosts": ["a.example.com"], "domains": ["example.com"], "networks": ["10.0.0.0/8"]}
    created = store.create("acme", scope=scope)
    parsed = created.to_scope()
    assert parsed.allowed_hosts == ("a.example.com",)
    assert parsed.allowed_domains == ("example.com",)
    assert parsed.allowed_networks == ("10.0.0.0/8",)
    assert scope_to_dict(parsed)["hosts"] == ["a.example.com"]
    # A bad CIDR fails at creation, not at scan time.
    with pytest.raises(ConfigurationError):
        store.create("bad", scope={"networks": ["not-a-cidr"]})


def test_an_empty_scope_means_no_project_restriction() -> None:
    scope = scope_from_dict(None)
    assert isinstance(scope, Scope)
    assert scope.is_empty


def test_resolve_accepts_slug_id_and_none(store: SqlProjectStore) -> None:
    created = store.create("acme")
    assert store.resolve("acme").id == created.id
    assert store.resolve(str(created.id)).id == created.id
    assert store.resolve(None).slug == DEFAULT_PROJECT_SLUG
    with pytest.raises(ConfigurationError, match="does not exist"):
        store.resolve("nope")


# --------------------------------------------------------------------------- ownership
def test_targets_and_scans_are_filtered_by_project(
    store: SqlProjectStore,
    factory: sessionmaker[Session],
) -> None:
    acme = store.create("acme")
    globex = store.create("globex")
    default = store.ensure_default()
    targets = SqlTargetStore(factory)
    scans = SqlScanStateStore(factory)

    definition = build_scan_request().target
    acme_target = targets.save(definition, project_id=acme.id)
    globex_target = targets.save(definition, project_id=globex.id)
    acme_scan = scans.create_scan(
        target_id=acme_target, engine="heuristic", plan={}, project_id=acme.id
    )
    globex_scan = scans.create_scan(
        target_id=globex_target, engine="heuristic", plan={}, project_id=globex.id
    )
    legacy_target = targets.save(definition)
    legacy_scan = scans.create_scan(target_id=legacy_target, engine="heuristic", plan={})

    assert [item.id for item in targets.list_targets(project_id=acme.id)] == [acme_target]
    assert [item.id for item in scans.list_scans(project_id=acme.id)] == [acme_scan.id]
    assert [item.id for item in scans.list_scans(project_id=globex.id)] == [globex_scan.id]
    # Pre-S14 rows (project_id NULL) belong to the default workspace when it asks for them.
    assert [item.id for item in scans.list_scans(project_id=default.id)] == []
    assert [
        item.id for item in scans.list_scans(project_id=default.id, include_unassigned=True)
    ] == [legacy_scan.id]
    assert acme_scan.id not in [
        item.id for item in scans.list_scans(project_id=default.id, include_unassigned=True)
    ]
    assert globex_scan.id not in [
        item.id for item in scans.list_scans(project_id=default.id, include_unassigned=True)
    ]


# --------------------------------------------------------------------------- scope gate
def _request_for(host: str) -> ScanRequest:
    definition = TargetDefinition(
        name=f"target-{host}",
        targets=(TargetSelector(kind="url", value=f"https://{host}/"),),
        attestation={
            "attested_by": "ops@example.com",
            "attested_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "scope_statement": "authorized for the test",
            "allowed_targets": [f"https://{host}/"],
        },
    )
    return ScanRequest(target=definition)


def _orchestrator(project_scope: Scope | None) -> Orchestrator:
    return Orchestrator(
        settings=Settings(),  # empty deployment scope: the definition is the declaration
        store=MemoryScanStateStore(),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        handlers={},
        pipeline=(ScanStep.RECON,),
        project_scope=project_scope,
    )


def test_a_project_scope_refuses_a_neighbour_target() -> None:
    orchestrator = _orchestrator(Scope(allowed_domains=("acme.example",)))
    orchestrator.assert_in_scope(_request_for("app.acme.example"))
    with pytest.raises(OutOfScopeError, match="project scope"):
        orchestrator.assert_in_scope(_request_for("globex.example"))


def test_no_project_scope_adds_no_restriction() -> None:
    orchestrator = _orchestrator(None)
    orchestrator.assert_in_scope(_request_for("anything.example"))


def test_the_refusal_is_audited_with_the_project_origin() -> None:
    sink = MemoryAuditSink()
    orchestrator = Orchestrator(
        settings=Settings(),
        store=MemoryScanStateStore(),
        auditor=Auditor(sink, actor="pytest"),
        handlers={},
        project_scope=Scope(allowed_domains=("acme.example",)),
    )
    with pytest.raises(OutOfScopeError):
        orchestrator.assert_in_scope(_request_for("globex.example"))
    rejected = [event for event in sink.events if event.action == "scope.rejected"]
    assert rejected and rejected[-1].meta.get("origin") == "project scope"


def test_project_record_exposes_branding_for_reports() -> None:
    record = ProjectRecord(
        id=1,
        slug="acme",
        name="Acme",
        branding={"company_name": "Acme Security"},
    )
    assert record.to_dict()["branding"] == {"company_name": "Acme Security"}
