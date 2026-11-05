"""The pruning invariant, as a property over generated estates (REQ-DATA-001).

The requirement is precise — *a property test MUST prove pruning removes only what policy
allows* — so this file generates estates (projects with their own policies, scans of many
ages, findings and evidence beneath them, audit rows) and asserts the property directly on the
real database, over many seeds:

1. **Nothing is removed that a policy does not allow.** Every deleted row is over its own
   category's cutoff, or was removed together with a scan that was — the cascade, which is the
   parent's policy rather than a leak. A project under legal hold loses nothing; a category set
   to ``0`` days keeps everything for ever.
2. **Everything a policy does allow is removed.** A row inside its retention survives; a row
   outside it does not (the batch limit is set high so one run is complete). This is the other
   half of the property, and without it "delete nothing" would pass.
3. **The plan is the contract.** The rows a run removes are exactly the rows it announced, and
   a dry run removes nothing at all — including no evidence objects.
4. **Running twice is a no-op.** The second run finds nothing, because the first did what it
   said.
5. **The ledger stays true.** After a run, each project's cached usage equals the sum of its
   remaining evidence sizes.

The estate is generated from a fixed seed, so a failure is reproducible from the seed in the
assertion message.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select

from arachne.core.config import RetentionSettings, Settings
from arachne.core.errors import ConfigurationError
from arachne.data.blob_registry import tenant_key
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import (
    AuditLog,
    Evidence,
    EvidenceBlob,
    Finding,
    Project,
    Scan,
    Target,
)
from arachne.data.quota import StorageQuota
from arachne.data.retention import CATEGORIES, RetentionPolicy, RetentionPruner
from arachne.data.scan_store import SqlScanStateStore

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)

CATEGORY_MODELS: dict[str, Any] = {
    "scans": Scan,
    "findings": Finding,
    "evidence": Evidence,
    "audit": AuditLog,
}


class RecordingBackend:
    """Stands in for the evidence backend: records the keys it was asked to delete.

    ``tenant`` is part of the backend protocol since WP-21 (REQ-DATA-006): an object lives in
    a tenant namespace, so the sweep names the namespace it is unlinking from.
    """

    def __init__(self) -> None:
        self.deleted: list[str] = []
        self.tenants: list[str | None] = []

    async def delete(self, key: str, *, tenant: str | None = None) -> bool:
        self.deleted.append(key)
        self.tenants.append(tenant)
        return True


def _days(rng: random.Random) -> int:
    """A day count, weighted towards real policies: mostly positive, sometimes "for ever"."""
    choice = rng.random()
    if choice < 0.15:
        return 0
    if choice < 0.85:
        return rng.choice([1, 7, 30, 90, 180, 365, 730])
    return rng.randint(1, 1000)


def _policy(rng: random.Random) -> dict[str, Any]:
    return {
        "enabled": rng.random() > 0.12,
        "findings_days": _days(rng),
        "evidence_days": _days(rng),
        "scans_days": _days(rng),
        "audit_days": _days(rng),
    }


def _add_target(session: Any, project_id: int | None) -> int:
    """A scan requires a declared target (``scans.target_id`` is NOT NULL)."""
    _counter["value"] += 1
    target = Target(
        project_id=project_id,
        name=f"host-{_counter['value']:04d}",
        scope_json={},
        auth_attestation={"attested_by": "property-test", "authorized": True},
    )
    session.add(target)
    session.flush()
    return int(target.id)


_counter = {"value": 0}


def _seed_estate(services: Any, rng: random.Random) -> dict[str, Any]:
    """Generate a random but plausible estate; return the ids written, by category."""
    written: dict[str, list[int]] = {name: [] for name in CATEGORIES}
    #: The parent link of every generated finding/evidence row, so the test can say which rows
    #: a scan's deletion legitimately takes with it (the cascade is part of the property).
    parents: dict[str, dict[int, int]] = {"findings": {}, "evidence": {}}
    policies: dict[int | None, dict[str, Any]] = {}
    with services.session_factory() as session:
        for index in range(rng.randint(1, 4)):
            policy = _policy(rng)
            project = Project(
                slug=f"tenant-{index}",
                name=f"Tenant {index}",
                scope_json={},
                branding_json={},
                retention_json=policy,
                quota_bytes=rng.choice([None, 10_000_000]),
                used_bytes=0,
            )
            session.add(project)
            session.flush()
            policies[int(project.id)] = policy
        # Some scans predate projects (S14): they belong to the implicit default workspace.
        project_ids: list[int | None] = [*policies, None]
        for _ in range(rng.randint(4, 12)):
            project_id = rng.choice(project_ids)
            age_days = rng.uniform(0, 900)
            created = NOW - timedelta(days=age_days)
            scan = Scan(
                target_id=_add_target(session, project_id),
                project_id=project_id,
                status="completed",
                plan_json={},
                engine="heuristic",
                stats_json={},
                created_at=created,
            )
            session.add(scan)
            session.flush()
            written["scans"].append(int(scan.id))
            for _ in range(rng.randint(0, 3)):
                finding = Finding(
                    scan_id=scan.id,
                    check_id=None,
                    asset_id=None,
                    title="generated finding",
                    severity=None,
                    confidence=50.0,
                    status="open",
                    evidence_refs_json=[],
                    created_at=created + timedelta(hours=rng.randint(0, 12)),
                )
                session.add(finding)
                session.flush()
                written["findings"].append(int(finding.id))
                parents["findings"][int(finding.id)] = int(scan.id)
                for _ in range(rng.randint(1, 3)):
                    key = None
                    storage = "inline"
                    if rng.random() > 0.5:
                        key = f"{rng.getrandbits(256):064x}"
                        storage = "local"
                    row = Evidence(
                        finding_id=finding.id,
                        kind="http_response",
                        payload_json={"body": "x" * rng.randint(10, 200)},
                        sha256=f"{rng.getrandbits(256):064x}",
                        size_bytes=rng.randint(50, 5000),
                        storage=storage,
                        storage_key=key,
                        created_at=created + timedelta(hours=rng.randint(0, 36)),
                    )
                    session.add(row)
                    session.flush()
                    written["evidence"].append(int(row.id))
                    parents["evidence"][int(row.id)] = int(finding.id)
        for _ in range(rng.randint(3, 10)):
            row = AuditLog(
                ts=NOW - timedelta(days=rng.uniform(0, 1200)),
                actor="cli",
                action="scan.finished",
                meta_json={},
            )
            session.add(row)
            session.flush()
            written["audit"].append(int(row.id))
        session.commit()
    # The cached usage must describe the seeded rows, as a real write path would leave it.
    quota = StorageQuota(services.session_factory)
    for project_id in policies:
        quota.recompute(project_id)
    return {"written": written, "policies": policies, "parents": parents}


def _ids(session: Any, model: Any) -> set[int]:
    return {int(value) for value in session.scalars(select(model.id)).all()}


def strictest_of(policy_of: Any) -> datetime | None:
    """The deployment-wide audit cutoff: the strictest non-zero policy wins."""
    candidates = [
        cutoff
        for project_id in (*_policies_seen, None)
        if (cutoff := policy_of(project_id).cutoff("audit", NOW)) is not None
    ]
    return max(candidates) if candidates else None


_policies_seen: tuple[int | None, ...] = ()


def _created_at(session: Any, model: Any, row_id: int) -> datetime:
    column = AuditLog.ts if model is AuditLog else model.created_at
    value = session.scalar(select(column).where(model.id == row_id))
    assert value is not None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _project_of(session: Any, model: Any, row_id: int) -> int | None:
    """The project a row belongs to (``findings``/``evidence`` reach it through the scan)."""
    if model is AuditLog:
        return None
    if model is Scan:
        return session.scalar(select(Scan.project_id).where(Scan.id == row_id))
    if model is Finding:
        return session.scalar(
            select(Scan.project_id)
            .join(Finding, Finding.scan_id == Scan.id)
            .where(Finding.id == row_id)
        )
    return session.scalar(
        select(Scan.project_id)
        .join(Finding, Finding.scan_id == Scan.id)
        .join(Evidence, Evidence.finding_id == Finding.id)
        .where(Evidence.id == row_id)
    )


def _cutoffs(
    policies: dict[int | None, dict[str, Any]], defaults: RetentionPolicy
) -> dict[str, Any]:
    """Per-project cutoffs, resolved through the *same* public policy type the job uses."""

    def policy_of(project_id: int | None) -> RetentionPolicy:
        override = policies.get(project_id) if project_id is not None else None
        return RetentionPolicy.from_mapping(defaults, override, source="property test")

    return policy_of


@pytest.fixture
def services(tmp_path: Any) -> Any:
    from arachne.data.services import ScanServices

    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'property.db'}",
        retention=RetentionSettings(batch_limit=100_000),
    )
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    factory = create_session_factory(engine)
    yield ScanServices(
        settings=settings,
        engine=engine,
        session_factory=factory,
        store=SqlScanStateStore(factory),
        target_store=None,  # type: ignore[arg-type]
        findings=None,  # type: ignore[arg-type]
        analyses=None,  # type: ignore[arg-type]
        projects=None,  # type: ignore[arg-type]
        feeds=None,  # type: ignore[arg-type]
        registry=None,  # type: ignore[arg-type]
        auditor=None,  # type: ignore[arg-type]
        bus=None,  # type: ignore[arg-type]
        quota=StorageQuota(factory),
    )
    engine.dispose()


@pytest.mark.parametrize("seed", range(25))
async def test_pruning_removes_only_what_the_policies_allow(services: Any, seed: int) -> None:
    rng = random.Random(seed)
    estate = _seed_estate(services, rng)
    policies: dict[int | None, dict[str, Any]] = estate["policies"]
    global _policies_seen
    _policies_seen = (*policies, None)
    parents: dict[str, dict[int, int]] = estate["parents"]
    backend = RecordingBackend()
    pruner = RetentionPruner(
        services.session_factory,
        settings=services.settings,
        quota=services.quota,
        evidence=backend,
    )

    with services.session_factory() as session:
        before = {name: _ids(session, model) for name, model in CATEGORY_MODELS.items()}
        # Ages and owners are captured up front: after the prune a removed row cannot be read
        # back, and the property is about the rows that were there.
        meta: dict[str, dict[int, tuple[datetime, int | None]]] = {
            name: {
                row_id: (_created_at(session, model, row_id), _project_of(session, model, row_id))
                for row_id in before[name]
            }
            for name, model in CATEGORY_MODELS.items()
        }

    def created_of(name: str, row_id: int) -> datetime:
        return meta[name][row_id][0]

    def owner_of(name: str, row_id: int) -> int | None:
        return meta[name][row_id][1]

    plan = pruner.plan(now=NOW)

    # ---- 3a: a plan changes nothing at all.
    with services.session_factory() as session:
        after_plan = {name: _ids(session, model) for name, model in CATEGORY_MODELS.items()}
    assert after_plan == before, f"seed {seed}: planning modified the estate"
    assert backend.deleted == []

    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.dry_run is False

    with services.session_factory() as session:
        after = {name: _ids(session, model) for name, model in CATEGORY_MODELS.items()}
        removed = {name: before[name] - after[name] for name in CATEGORIES}

        # ---- 3b: the run removed exactly what the plan announced, plus the rows the
        # announced scans take with them (the foreign-key cascade, which the plan reports as
        # ``cascaded_rows`` under ``scans`` rather than as separate victims).
        removed_scans_planned = set(plan.category("scans").ids) | set(applied.category("scans").ids)
        removed_findings_planned = set(plan.category("findings").ids) | set(
            applied.category("findings").ids
        )
        cascaded_findings = {
            finding_id
            for finding_id, scan_id in parents["findings"].items()
            if scan_id in removed_scans_planned
        }
        cascaded_evidence = {
            evidence_id
            for evidence_id, finding_id in parents["evidence"].items()
            if finding_id in cascaded_findings or finding_id in removed_findings_planned
        }
        expected = {
            "scans": removed_scans_planned,
            "findings": removed_findings_planned | cascaded_findings,
            "evidence": set(plan.category("evidence").ids)
            | set(applied.category("evidence").ids)
            | cascaded_evidence,
            "audit": set(plan.audit.ids) | set(applied.audit.ids),
        }
        for name in CATEGORIES:
            assert removed[name] == expected[name], f"seed {seed}: {name} removal != plan"
        assert set(backend.deleted) == set(plan.category("scans").keys) | set(
            plan.category("findings").keys
        ) | set(plan.category("evidence").keys), f"seed {seed}: blob deletion != plan"
        del removed_findings_planned

        policy_of = _cutoffs(policies, pruner.defaults)
        removed_scans = removed["scans"]
        removed_findings = removed["findings"]
        removed_evidence = removed["evidence"]

        # ---- 1: nothing was removed that a policy does not allow. A row removed with its
        # parent (the cascade) is justified by the *parent's* cutoff, which is checked here.
        for scan_id in removed_scans:
            policy = policy_of(owner_of("scans", scan_id))
            cutoff = policy.cutoff("scans", NOW)
            assert cutoff is not None, f"seed {seed}: a scan was pruned under a hold"
            assert created_of("scans", scan_id) < cutoff, f"seed {seed}: scan within retention"
        for finding_id in removed_findings:
            if finding_id in cascaded_findings:
                continue  # went with its scan, which was over its own cutoff
            policy = policy_of(owner_of("findings", finding_id))
            cutoff = policy.cutoff("findings", NOW)
            assert cutoff is not None, f"seed {seed}: a finding was pruned under a hold"
            assert created_of("findings", finding_id) < cutoff, f"seed {seed}: finding in retention"
        for evidence_id in removed_evidence:
            if evidence_id in cascaded_evidence:
                continue  # went with its finding or its scan
            policy = policy_of(owner_of("evidence", evidence_id))
            cutoff = policy.cutoff("evidence", NOW)
            assert cutoff is not None, f"seed {seed}: evidence was pruned under a hold"
            assert created_of("evidence", evidence_id) < cutoff, (
                f"seed {seed}: evidence in retention"
            )
        strictest = strictest_of(policy_of)
        for audit_id in removed["audit"]:
            # Audit is deployment-wide: the strictest non-zero policy decides, so every
            # removed row is older than the smallest audit retention that was configured.
            assert strictest is not None
            assert created_of("audit", audit_id) < strictest

        # ---- 2: everything a policy does allow was removed. Survivors are all in retention
        # (or their project is under a hold / the category is "keep for ever").
        for scan_id in before["scans"] - removed_scans:
            policy = policy_of(owner_of("scans", scan_id))
            cutoff = policy.cutoff("scans", NOW)
            assert cutoff is None or created_of("scans", scan_id) >= cutoff, (
                f"seed {seed}: a scan past its retention survived"
            )
        for finding_id in before["findings"] - removed_findings:
            policy = policy_of(owner_of("findings", finding_id))
            cutoff = policy.cutoff("findings", NOW)
            assert cutoff is None or created_of("findings", finding_id) >= cutoff, (
                f"seed {seed}: a finding past its retention survived"
            )
        for evidence_id in before["evidence"] - removed_evidence:
            policy = policy_of(owner_of("evidence", evidence_id))
            cutoff = policy.cutoff("evidence", NOW)
            assert cutoff is None or created_of("evidence", evidence_id) >= cutoff, (
                f"seed {seed}: evidence past its retention survived"
            )
        for audit_id in before["audit"] - removed["audit"]:
            assert created_of("audit", audit_id) >= strictest_of(policy_of), (
                f"seed {seed}: an audit row past the strictest policy survived"
            )

        # ---- 5: the usage ledger still describes the surviving rows, in physical bytes.
        # WP-21 (REQ-DATA-006): a deduplicated object is charged once (from
        # ``evidence_blobs``), and a payload small enough to stay inline is charged its own
        # bytes. Charging the logical size of every offloaded row would bill a tenant twice
        # for one object, so the old single SUM is no longer the ledger's definition.
        for project_id in policies:
            inline = session.scalar(
                select(func.coalesce(func.sum(Evidence.size_bytes), 0))
                .select_from(Evidence)
                .join(Finding, Finding.id == Evidence.finding_id)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(Scan.project_id == project_id)
                .where(Evidence.storage_key.is_(None))
            )
            physical = session.scalar(
                select(func.coalesce(func.sum(EvidenceBlob.physical_bytes), 0)).where(
                    EvidenceBlob.tenant == tenant_key(project_id)
                )
            )
            cached = session.scalar(select(Project.used_bytes).where(Project.id == project_id))
            assert int(cached or 0) == int(inline or 0) + int(physical or 0), (
                f"seed {seed}: usage ledger drifted"
            )

    # ---- 4: the second run is a no-op.
    second = await pruner.prune(dry_run=False, now=NOW)
    assert second.total_rows == 0, f"seed {seed}: pruning is not idempotent"


async def test_a_legal_hold_stops_the_job_for_that_project(tmp_path: Any) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'hold.db'}")
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    factory = create_session_factory(engine)
    try:
        ancient = NOW - timedelta(days=5_000)
        with factory() as session:
            session.add(
                Project(
                    slug="held",
                    name="Held",
                    scope_json={},
                    branding_json={},
                    retention_json={"enabled": False},
                )
            )
            session.add(
                Project(
                    slug="exposed",
                    name="Exposed",
                    scope_json={},
                    branding_json={},
                    retention_json={"scans_days": 1, "findings_days": 1, "evidence_days": 1},
                )
            )
            session.commit()
            held = session.scalar(select(Project.id).where(Project.slug == "held"))
            exposed = session.scalar(select(Project.id).where(Project.slug == "exposed"))
            for project_id in (held, exposed):
                session.add(
                    Scan(
                        target_id=_add_target(session, project_id),
                        project_id=project_id,
                        status="completed",
                        plan_json={},
                        engine="heuristic",
                        stats_json={},
                        created_at=ancient,
                    )
                )
            session.commit()

        pruner = RetentionPruner(factory, settings=settings)
        plan = pruner.plan(now=NOW)
        held_entry = next(entry for entry in plan.projects if entry.slug == "held")
        exposed_entry = next(entry for entry in plan.projects if entry.slug == "exposed")
        assert held_entry.categories["scans"].rows == 0
        assert exposed_entry.categories["scans"].rows == 1
        removed = await pruner.prune(dry_run=False, now=NOW)
        assert removed.category("scans").rows == 1
    finally:
        engine.dispose()


async def test_a_category_at_zero_days_keeps_its_data_for_ever(tmp_path: Any) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'zero.db'}")
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            project = Project(
                slug="archive",
                name="Archive",
                scope_json={},
                branding_json={},
                retention_json={
                    "scans_days": 0,
                    "findings_days": 0,
                    "evidence_days": 0,
                    "audit_days": 0,
                },
            )
            session.add(project)
            session.commit()
            session.add(
                Scan(
                    target_id=_add_target(session, int(project.id)),
                    project_id=int(project.id),
                    status="completed",
                    plan_json={},
                    engine="heuristic",
                    stats_json={},
                    created_at=NOW - timedelta(days=9_000),
                )
            )
            session.commit()
        pruner = RetentionPruner(factory, settings=settings)
        plan = pruner.plan(now=NOW)
        assert plan.empty
        applied = await pruner.prune(dry_run=False, now=NOW)
        assert applied.total_rows == 0
    finally:
        engine.dispose()


def test_an_unknown_policy_key_is_refused() -> None:
    defaults = RetentionPolicy()
    with pytest.raises(ConfigurationError):
        RetentionPolicy.from_mapping(defaults, {"finding_days": 30}, source="typo")
    with pytest.raises(ConfigurationError):
        RetentionPolicy.from_mapping(defaults, {"scans_days": -1}, source="negative")
    with pytest.raises(ConfigurationError):
        RetentionPolicy.from_mapping(defaults, {"scans_days": "lots"}, source="not-a-number")
