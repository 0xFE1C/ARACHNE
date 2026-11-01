"""Resilience end-to-end: tamper detection, air-gapped runs, HA, DR, residency (S25).

Each test drives the real stack (the CLI and the composition root, a migrated database, the
bundled demo fixtures replayed with no socket) and asserts the property the requirement
states — not a unit's return value:

* **REQ-TRUST-005** — a scan produces a verifiable chain and a seal; *editing* an audit row,
  *deleting* a finding row and *truncating* the chain's tail are each detected, with the
  failure kind distinguishing them.
* **REQ-RESIL-001** — an air-gapped deployment runs the full heuristic pipeline from an
  imported signed content pack with zero sockets opened, and refuses an external host.
* **REQ-RESIL-002** — a worker killed mid-lease loses no scan (the lease is reclaimed and the
  scan completes exactly once), and the release migration applies to a populated database.
* **REQ-RESIL-004** — evidence pinned to another region is refused, in both directions.

The tamper cases edit rows through the ORM and then commit: that is exactly what a
database-level attacker with write access does, and it is what the verifier must catch. No
test here writes a SQL string — the ORM's bound parameters are the house discipline.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.errors import ResidencyError
from arachne.core.signing import DeploymentSigner
from arachne.data.models import AuditLog, Evidence, Finding, Scan, Target
from arachne.data.schema import LATEST_SCHEMA_REVISION
from arachne.data.services import build_integrity_verifier, build_services
from arachne.resil.packs import build_pack, read_pack_file, write_pack

CODE_ROOT = Path(__file__).resolve().parents[2]
DEMO = CODE_ROOT / "docker" / "demo"
TARGET = DEMO / "target.yaml"
TEMPLATES = CODE_ROOT / "src" / "arachne" / "templates" / "plan"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"
INTEGRITY_KEY = "s25-integration-integrity-key-0001"

runner = CliRunner()


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Nothing in this file may open a socket: every scan here is a replay."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


def _env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    airgapped: bool = False,
    region: str | None = None,
) -> Path:
    """The demo scan's environment plus S25's switches, and a migrated database."""
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'resilience.db'}")
    monkeypatch.setenv("ARACHNE_HTTP_FIXTURES", str(DEMO / "http"))
    monkeypatch.setenv("ARACHNE_OSINT_ENABLED", "true")
    monkeypatch.setenv("ARACHNE_OSINT_FIXTURES", str(DEMO / "osint"))
    monkeypatch.setenv("ARACHNE_OSINT_PROVIDERS", "crtsh,circl,wayback,commoncrawl,internetdb")
    monkeypatch.setenv("ARACHNE_OSINT_SEARCH_URL", SEARCH_URL)
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_INTEGRITY_KEY", INTEGRITY_KEY)
    monkeypatch.setenv("ARACHNE_CONTENT_DIR", str(tmp_path / "content"))
    if airgapped:
        # An air-gapped deployment declares its estate in the *deployment* scope: that
        # allowlist is what the mode keeps reachable, so "targets only" is a configuration
        # statement rather than an implicit one.
        monkeypatch.setenv("ARACHNE_AIRGAPPED", "true")
        monkeypatch.setenv("ARACHNE_SCOPE_HOSTS", "example.com,93.184.216.34,93.184.216.35")
        monkeypatch.setenv("ARACHNE_SCOPE_DOMAINS", "example.com")
    if region is not None:
        monkeypatch.setenv("ARACHNE_REGION", region)
    reset_settings_cache()
    upgraded = runner.invoke(app, ["db", "upgrade"])
    assert upgraded.exit_code == 0, upgraded.output
    return tmp_path / "content"


def _run_scan() -> int:
    result = runner.invoke(app, ["scan", "--target", str(TARGET), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("{") :])
    return int(payload["scan_id"])


def _alembic_config(database_url: str) -> Config:
    config = Config(str(CODE_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(CODE_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _audit_actions(services: Any) -> list[str]:
    factory = services.session_factory
    with factory() as session:
        return [str(row.action) for row in session.scalars(select(AuditLog).order_by(AuditLog.id))]


# --------------------------------------------------------------- REQ-TRUST-005
def test_a_scan_produces_a_verifiable_chain_and_a_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    scan_id = _run_scan()
    services = build_services(get_settings())
    try:
        report = build_integrity_verifier(services).verify()
        assert report.ok, report.to_dict()
        assert report.checked["audit_rows"] > 0
        seals = services.integrity.seals(scan_id=scan_id) if services.integrity else ()
        assert seals and seals[0].signature is not None
        assert seals[0].row_count > 0
    finally:
        services.close()


def test_an_edited_audit_row_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    _run_scan()
    services = build_services(get_settings())
    try:
        # Edit a stored audit row the way a database-level attacker would: change a field,
        # leaving the chain columns alone.
        with services.session_factory() as session:
            row = session.scalars(
                select(AuditLog).where(AuditLog.seq.is_not(None)).order_by(AuditLog.seq).limit(1)
            ).first()
            assert row is not None
            # The *chained* content is ``meta_json`` (the serialized event minus its action),
            # so that is what an edit has to touch to be dishonest.
            row.meta_json = {**dict(row.meta_json or {}), "actor": "somebody-else"}
            session.commit()
        report = build_integrity_verifier(services).verify()
        assert not report.ok
        assert report.modified
        assert any("does not match the recomputed" in issue.detail for issue in report.issues)
    finally:
        services.close()


def test_a_deleted_finding_row_is_detected_by_the_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    scan_id = _run_scan()
    services = build_services(get_settings())
    try:
        candidates = services.findings.list_candidates(scan_id)
        assert candidates, "the demo scan must produce at least one finding"
        with services.session_factory() as session:
            row = session.get(Finding, candidates[-1].id)
            assert row is not None
            session.delete(row)
            session.commit()
        report = build_integrity_verifier(services).verify(scan_id=scan_id)
        assert not report.ok
        assert report.deleted, report.to_dict()
        assert any("is gone" in issue.detail for issue in report.deleted)
    finally:
        services.close()


def test_a_truncated_chain_tail_is_detected_by_an_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    _run_scan()
    services = build_services(get_settings())
    try:
        anchor = services.integrity.anchor(reason="test") if services.integrity else None
        assert anchor is not None
        # Delete the anchored row and everything after it. The remaining log is still a
        # *contiguous* chain (no gap for the chain check to find), which is exactly the case
        # only an anchor can catch: the checkpoint says the log reached inside the deleted
        # region, and it no longer does.
        with services.session_factory() as session:
            rows = session.scalars(select(AuditLog).order_by(AuditLog.seq.desc())).all()
            doomed = [row for row in rows if row.seq is not None and int(row.seq) >= anchor.seq]
            assert doomed, "the anchor's own row (and the act that wrote it) is the tail"
            for row in doomed:
                session.delete(row)
            session.commit()
        report = build_integrity_verifier(services).verify()
        assert not report.ok
        assert any("trailing row(s) were deleted" in issue.detail for issue in report.issues)
    finally:
        services.close()


def test_verify_chain_exits_nonzero_on_a_planted_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The accept criterion, through the operator's own command."""
    _env(tmp_path, monkeypatch)
    _run_scan()
    clean = runner.invoke(app, ["verify-chain", "--json"])
    assert clean.exit_code == 0, clean.output
    assert json.loads(clean.output[clean.output.index("{") :])["ok"] is True

    services = build_services(get_settings())
    try:
        with services.session_factory() as session:
            row = session.scalars(
                select(AuditLog).where(AuditLog.seq.is_not(None)).order_by(AuditLog.seq).limit(1)
            ).first()
            assert row is not None
            row.meta_json = {**dict(row.meta_json or {}), "actor": "tampered"}
            session.commit()
    finally:
        services.close()

    tampered = runner.invoke(app, ["verify-chain", "--json"])
    assert tampered.exit_code == 1, tampered.output
    payload = json.loads(tampered.output[tampered.output.index("{") :])
    assert payload["ok"] is False
    assert payload["issues"]


def test_require_signatures_needs_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'nokey.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.delenv("ARACHNE_INTEGRITY_KEY", raising=False)
    monkeypatch.delenv("ARACHNE_INTEGRITY_KEY_FILE", raising=False)
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    result = runner.invoke(app, ["verify-chain", "--require-signatures"])
    assert result.exit_code == 2
    assert "ARACHNE_INTEGRITY_KEY" in result.output


def test_the_audit_chain_records_the_release_work_as_it_happens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chain is not a separate trail: the resilience acts land in the same one."""
    _env(tmp_path, monkeypatch)
    _run_scan()
    services = build_services(get_settings())
    try:
        assert services.integrity is not None
        services.integrity.anchor(reason="test")
        actions = _audit_actions(services)
        assert "integrity.sealed" in actions
        assert "integrity.anchored" in actions
    finally:
        services.close()


# --------------------------------------------------------------- REQ-RESIL-001
def test_an_air_gapped_scan_runs_from_an_imported_signed_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The G6 acceptance criterion: a no-network full scan from a signed offline pack.

    Review is waived here on purpose (S26). This test is the air-gap *transport* criterion —
    build a pack, carry it in, verify it, scan from it with no socket open — and the pack is the
    deployment's own signed content. The review pipeline is a separate gate with its own
    coverage: `tests/test_pack_review_safety.py` proves a pack cannot be listed without passing
    it, that a refused pack cannot be imported, and that review itself opens no socket.
    """
    monkeypatch.setenv("ARACHNE_PLUGIN_REQUIRE_REVIEW", "false")
    reset_settings_cache()
    content_dir = _env(tmp_path, monkeypatch, airgapped=True)
    signer = DeploymentSigner(INTEGRITY_KEY)
    pack_path = tmp_path / "baseline.tar.gz"
    write_pack(
        pack_path,
        {"checks": TEMPLATES},
        name="offline-baseline",
        version="1.0.0",
        signer=signer,
    )

    imported = runner.invoke(app, ["packs", "import", str(pack_path), "--json"])
    assert imported.exit_code == 0, imported.output
    payload = json.loads(imported.output[imported.output.index("{") :])
    assert payload["key_id"] == signer.key_id
    assert (content_dir / "offline-baseline" / "1.0.0").is_dir()

    services = build_services(get_settings())
    try:
        records = services.content_packs.list_packs() if services.content_packs else ()
        assert [record.name for record in records] == ["offline-baseline"]
    finally:
        services.close()

    # The full pipeline still runs, with no socket opened (the fixture above asserts that).
    scan_id = _run_scan()
    services = build_services(get_settings())
    try:
        assert services.findings.count_candidates(scan_id) > 0
        assert build_integrity_verifier(services).verify().ok
        assert services.settings.airgap.enabled is True
        assert "pack.imported" in _audit_actions(services)
    finally:
        services.close()


def test_an_air_gapped_deployment_refuses_an_external_host_at_the_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch, airgapped=True)
    services = build_services(get_settings())
    try:
        settings = services.settings
        assert settings.airgap.enabled
        from arachne.core.airgap import build_airgap_policy

        policy = build_airgap_policy(settings)
        scope_hosts = tuple(settings.safety.scope.allowed_hosts) + tuple(
            settings.safety.scope.allowed_domains
        )
        # The scan targets stay reachable (they are in the deployment scope), the outside does
        # not: that is the second, stricter allowlist the mode adds.
        assert policy.refusal("feeds.nvd.nist.gov", scope_hosts=scope_hosts) is not None
        assert policy.refusal("updates.vendor.example", scope_hosts=scope_hosts) is not None
    finally:
        services.close()


def test_a_pack_signed_elsewhere_is_refused_by_the_import_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch, airgapped=True)
    pack_path = tmp_path / "foreign.tar.gz"
    write_pack(
        pack_path,
        {"checks": TEMPLATES},
        name="foreign",
        version="1.0.0",
        signer=DeploymentSigner("a-completely-different-key-0001"),
    )
    result = runner.invoke(app, ["packs", "import", str(pack_path)])
    assert result.exit_code == 1
    assert "REFUSED" in result.output
    assert not (tmp_path / "content" / "foreign").exists()
    services = build_services(get_settings())
    try:
        # A refused import is a security event, so it is in the trail.
        assert "pack.rejected" in _audit_actions(services)
        records = services.content_packs.list_packs() if services.content_packs else ()
        assert records == ()
    finally:
        services.close()


def test_an_unsigned_pack_import_is_refused_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch, airgapped=True)
    pack_path = tmp_path / "unsigned.tar.gz"
    pack_bytes, _manifest, _signature = build_pack(
        {"checks": TEMPLATES}, name="unsigned", version="1.0.0"
    )
    pack_path.write_bytes(pack_bytes)
    result = runner.invoke(app, ["packs", "import", str(pack_path)])
    assert result.exit_code == 1
    assert not (tmp_path / "content" / "unsigned").exists()
    # The explicit exception is what a lab uses, and it is recorded as such.
    pack = read_pack_file(
        pack_path, signer=DeploymentSigner(INTEGRITY_KEY), require_signature=False
    )
    assert pack.signature is None


# --------------------------------------------------------------- REQ-RESIL-002
def test_a_killed_worker_loses_no_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A replica killed mid-lease: the work is reclaimed and each scan finishes exactly once."""
    _env(tmp_path, monkeypatch)
    services = build_services(get_settings())
    try:
        assert services.queue is not None and services.agents is not None
        agent_a = services.agents.register("replica-a")
        agent_b = services.agents.register("replica-b")
        assert agent_a.id is not None and agent_b.id is not None
        scan_ids: list[int] = []
        with services.session_factory() as session:
            target = Target(name="ha-lab", scope_json={"hosts": ["lab.example"]})
            session.add(target)
            session.flush()
            for _ in range(5):
                scan = Scan(
                    target_id=target.id,
                    status="pending",
                    plan_json={},
                    stats_json={},
                    created_at=datetime.now(UTC),
                )
                session.add(scan)
                session.flush()
                scan_ids.append(int(scan.id))
            session.commit()
        for scan_id in scan_ids:
            services.queue.enqueue(scan_id, project_id=None, requested_by="pytest")

        # Replica A leases three and finishes two, then is killed while holding the third.
        leased = services.queue.lease_next(
            "replica-a", agent_id=int(agent_a.id), cap=3, ttl_s=1
        )
        assert len(leased) == 3
        held = [entry.scan_id for entry in leased]
        for scan_id in held[:2]:
            assert services.queue.complete("replica-a", scan_id)
        killed_hold = held[2]

        # B picks up the two scans A never touched (that is the farm working), but the scan A
        # is still nominally holding is not available: it is marked out-of-service by the
        # *auditor*, not by the row's owner.
        while True:
            batch = services.queue.lease_next("replica-b", agent_id=int(agent_b.id), ttl_s=60)
            assert killed_hold not in [entry.scan_id for entry in batch]
            if not batch:
                break
            for entry in batch:
                assert services.queue.complete("replica-b", entry.scan_id)
        # Nothing is queued and the killed hold is still leased, so B gets nothing.
        assert services.queue.lease_next("replica-b", agent_id=int(agent_b.id), ttl_s=60) == ()
        # Once the lease expires it is re-leasable — no cleanup step, exactly as a SIGKILL
        # leaves things.
        expired = services.queue.reclaim_expired(now=datetime.now(UTC) + timedelta(seconds=5))
        assert killed_hold in [item.scan_id for item in expired]
        reclaimed = services.queue.lease_next("replica-b", agent_id=int(agent_b.id), ttl_s=60)
        assert [entry.scan_id for entry in reclaimed] == [killed_hold]
        assert reclaimed[0].attempts >= 2  # re-leased, not re-enqueued
        assert services.queue.complete("replica-b", killed_hold)

        # Drain the rest on B: every scan completed, none twice.
        while True:
            batch = services.queue.lease_next("replica-b", agent_id=int(agent_b.id), ttl_s=60)
            if not batch:
                break
            for entry in batch:
                assert services.queue.complete("replica-b", entry.scan_id)
        stats = services.queue.stats()
        assert stats.get("done") == len(scan_ids)
        assert stats.get("queued", 0) == 0 and stats.get("leased", 0) == 0
    finally:
        services.close()


def test_the_release_migration_applies_to_a_populated_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The zero-downtime upgrade path: expand on a database that already holds data.

    The estate is populated the honest way — by running a scan at the *current* release — then
    rolled back to the previous schema and upgraded again, which is exactly the shape of a
    release rollout: rows in place, a code upgrade, no rewrite of what is there.
    """
    _env(tmp_path, monkeypatch)
    scan_id = _run_scan()
    database_url = get_settings().database_url
    config = _alembic_config(database_url)

    # Back to the previous release's schema (the S25 tables/columns are contracted away).
    command.downgrade(config, "0010")
    engine = create_engine(database_url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("audit_log")}
        assert "seq" not in columns
    finally:
        engine.dispose()

    # The rollout: expand on top of the existing rows.
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar()
            targets = connection.exec_driver_sql("SELECT COUNT(*) FROM targets").scalar()
            findings = connection.exec_driver_sql("SELECT COUNT(*) FROM findings").scalar()
        assert version == LATEST_SCHEMA_REVISION
        assert int(targets or 0) >= 1
        assert int(findings or 0) >= 1
        audit_columns = {column["name"] for column in inspect(engine).get_columns("audit_log")}
        assert {"seq", "prev_hash", "hash", "signature"} <= audit_columns
        project_columns = {column["name"] for column in inspect(engine).get_columns("projects")}
        assert {"pii_json", "residency_region"} <= project_columns
    finally:
        engine.dispose()

    # The old rows are still readable through the new model (expand, not contract) and the
    # scan's data is intact.
    services = build_services(get_settings())
    try:
        assert services.target_store.list_targets()
        assert services.findings.count_candidates(scan_id) > 0
    finally:
        services.close()


def test_a_rolling_replica_sees_the_new_schema_while_the_old_one_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An old-style (unchained) audit row does not break a verifier on the new schema.

    That is what makes the rollout safe: during the window one replica writes rows the new
    code would have chained. The verifier starts at the first chained row rather than
    reporting a gap that never existed.
    """
    _env(tmp_path, monkeypatch)
    _run_scan()
    services = build_services(get_settings())
    try:
        with services.session_factory() as session:
            session.add(
                AuditLog(
                    ts=datetime.now(UTC),
                    actor="legacy-replica",
                    action="scan.started",
                    meta_json={"schema_version": "1.1", "actor": "legacy-replica"},
                )
            )
            session.commit()
        report = build_integrity_verifier(services).verify()
        assert report.ok, report.to_dict()
    finally:
        services.close()


def test_the_leader_lease_is_visible_through_the_ha_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    services = build_services(get_settings())
    try:
        assert services.leader is not None
        assert services.leader.state().holder is None  # free until a tick acquires it
        assert services.leader.try_acquire(reason="test")
        state = services.leader.state()
        assert state.holder == services.leader.holder
        assert "leader.acquired" in _audit_actions(services)
    finally:
        services.close()


# --------------------------------------------------------------- REQ-RESIL-004
def test_evidence_pinned_to_another_region_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch, region="eu-west-1")
    _run_scan()
    services = build_services(get_settings())
    try:
        assert services.evidence is not None
        with services.session_factory() as session:
            row = session.scalars(select(Evidence)).first()
            assert row is not None
            row.region = "us-east-1"  # written by the other region's deployment
            session.commit()
            key = str(row.storage_key or "deadbeef" * 8)
        assert services.settings.resilience.region == "eu-west-1"
        with pytest.raises(ResidencyError):
            asyncio.run(services.evidence.download(key, region="us-east-1"))
        # A same-region read, and an unpinned row, are both served.
        services.evidence.require_region("eu-west-1")
        services.evidence.require_region(None)
        assert "residency.rejected" in _audit_actions(services)
    finally:
        services.close()


def test_a_deployment_with_no_region_does_not_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(tmp_path, monkeypatch)
    services = build_services(get_settings())
    try:
        assert services.evidence is not None
        assert services.settings.resilience.region is None
        services.evidence.require_region("us-east-1")  # no pin, no refusal
    finally:
        services.close()


def test_pii_masking_is_applied_to_the_scans_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQ-TRUST-006 through the real path: policy in force, nothing seeded survives."""
    _env(tmp_path, monkeypatch)
    monkeypatch.setenv("ARACHNE_PII_ENABLED", "true")
    monkeypatch.setenv("ARACHNE_PII_CATEGORIES", "email,ipv4")
    reset_settings_cache()
    scan_id = _run_scan()
    services = build_services(get_settings())
    try:
        assert services.evidence is not None
        policy = services.evidence.policy_for(None)
        assert policy.active and "email" in policy.categories
        # Enforce it on a payload the way the checks step does, then assert the audit line.
        from arachne.core.results import CheckResult
        from arachne.core.results import Evidence as EvidenceItem

        result = CheckResult(
            check="unit.seeded",
            module="m1",
            title="seeded",
            status="info",
            detail="seeded PII",
            confidence=0.5,
            evidence=(
                EvidenceItem.of("note", {"contact": "jane.operator@example.com"}),
            ),
        )
        staged = asyncio.run(services.evidence.stage(result, scan_id=scan_id, project_id=None))
        assert "jane.operator@example.com" not in json.dumps(staged.evidence[0].payload)
        assert "pii.masked" in _audit_actions(services)
    finally:
        services.close()


def test_the_api_serves_the_shipped_security_txt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQ-TRUST-007: the disclosure policy is reachable where a researcher looks for it."""
    _env(tmp_path, monkeypatch)
    from fastapi.testclient import TestClient

    from arachne.api.app import create_app

    services = build_services(get_settings())
    try:
        with TestClient(create_app(services)) as client:
            response = client.get("/.well-known/security.txt")
        assert response.status_code == 200
        # RFC 9116 admits either a mailbox or a URL as the Contact; this project's
        # working channel is the private advisory form, so assert the shape, not a
        # mailbox the project does not operate.
        contact = next(
            line for line in response.text.splitlines() if line.startswith("Contact:")
        )
        assert contact.startswith(("Contact: mailto:", "Contact: https:")), contact
        assert "Expires:" in response.text
    finally:
        services.close()
