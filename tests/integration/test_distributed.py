"""Distributed scan execution (S16, area SCALE) — the gate-G2 integration evidence.

Every acceptance criterion of the area runs here, against real machinery over a shared
SQLite file standing in for the Postgres queue:

* **Two agents drain a 20-scan queue without duplicate execution** (REQ-SCALE-002) —
  the agents are real ``AgentLoop``s talking HTTP to the real app (API-key
  authentication included) over an ASGI transport.
* **Agent-kill mid-scan re-leases and completes** (REQ-SCALE-003) — a *child process*
  leases a scan and SIGKILLs itself mid-step (no ack, no unwinding); after the lease
  expires, another agent reclaims it, records the interruption note, and resumes from
  the persisted lifecycle state.
* **Audit continuity** (REQ-SCALE-004) — agent control-plane calls are authenticated
  with existing API keys and every trail line names the agent.
* **Streaming** (REQ-SCALE-005) — findings and evidence are readable from a second
  connection while the scan is still running.
* **Deterministic plans** (REQ-SCALE-006) — node B executes the plan node A stored.
* **Scheduler as producer** (REQ-SCALE-007) — a due schedule enqueues; the diff is
  computed when the agent completes the scan.
* **Gates on the executing node** (REQ-SCALE-008) — the refusal side lives in the
  safety suite (``tests/test_safety.py``); this file adds the stop/cancel path.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from tests.helpers.api import SCANNER_KEY, VIEWER_KEY, auth, make_api_harness
from tests.helpers.distributed import DistributedStack, build_stack, distributed_settings
from tests.helpers.scan_harness import make_handlers

from arachne.agent.control import DirectControlPlane, HttpControlPlane
from arachne.agent.runner import AgentLoop, build_executor, rebuild_request
from arachne.agent.service import AgentService
from arachne.core.audit import AuditAction
from arachne.core.config import Settings
from arachne.core.lifecycle import StepContext, StepOutcome
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import load_scan_request
from arachne.data.models import Finding, Scan, ScanDiff
from arachne.data.services import build_orchestrator

pytestmark = pytest.mark.integration

CODE_ROOT = Path(__file__).resolve().parents[2]
LAB_FIXTURE = CODE_ROOT / "examples" / "targets" / "lab-fixture.yaml"

TARGET: dict[str, object] = {
    "name": "fleet-target",
    "targets": [{"kind": "url", "value": "https://example.com/"}],
    "attestation": {
        "attested_by": "fleet test",
        "attested_at": "2026-10-01T00:00:00Z",
        "scope_statement": "distributed-test authorization covering example.com",
        "allowed_targets": ["example.com"],
    },
}


def asgi_client(app: Any) -> httpx.AsyncClient:
    """An HTTP client that speaks to the in-process app (sockets stay closed)."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://testserver",
    )


def agent_loop(harness: Any, name: str, *, pipeline: tuple[ScanStep, ...]) -> AgentLoop:
    """A real agent over the HTTP control plane, executing on the harness's services."""
    from arachne.core.config import RateLimitSettings
    from arachne.core.safety import StaticResolver, UrlSafetyPolicy

    control = HttpControlPlane(
        "https://testserver",
        SCANNER_KEY,
        settings=Settings(
            database_url=str(harness.settings.database_url),
            rate_limit=RateLimitSettings(
                per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
            ),
        ),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver(("127.0.0.1",)),
        transport=httpx.ASGITransport(app=harness.app),
    )
    return AgentLoop(
        control,
        name=name,
        executor=build_executor(harness.services, name=name, pipeline=pipeline),
        lease_ttl_s=5.0,
        heartbeat_interval_s=0.02,
        poll_interval_s=0.01,
    )


def direct_agent_loop(
    stack: DistributedStack, name: str, *, pipeline: tuple[ScanStep, ...]
) -> AgentLoop:
    """A real agent over the in-process control plane (no API server in the loop)."""
    return AgentLoop(
        DirectControlPlane(AgentService(stack.services, settings=stack.settings)),
        name=name,
        executor=build_executor(stack.services, name=name, pipeline=pipeline),
        lease_ttl_s=30.0,
        heartbeat_interval_s=0.02,
        poll_interval_s=0.01,
    )


# ---------------------------------------------------------------------------
# REQ-SCALE-001/002/004: the queue, the agent role, and the audit trail
# ---------------------------------------------------------------------------
async def test_two_agents_drain_a_twenty_scan_queue_without_duplicate_execution(
    tmp_path: Path,
) -> None:
    harness = make_api_harness(
        tmp_path, settings=distributed_settings(tmp_path / "fleet.db"), pipeline=(ScanStep.RECON,)
    )
    try:
        async with asgi_client(harness.app) as http:
            # Admit 20 scans through the API: in distributed mode the runner is an
            # enqueue-and-track front-end (REQ-SCALE-007), so each 202 is a queued row.
            scan_ids: list[int] = []
            for _ in range(20):
                response = await http.post(
                    "/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET}
                )
                assert response.status_code == 202, response.text
                scan_ids.append(response.json()["scan_id"])
            overview = (await http.get("/api/v1/agent/queue", headers=auth(VIEWER_KEY))).json()
            assert overview["stats"]["queued"] == 20

            agents = [
                agent_loop(harness, f"agent-{i}", pipeline=(ScanStep.RECON,)) for i in (1, 2)
            ]
            executed = await asyncio.gather(*(loop.run_until_drained() for loop in agents))
            assert sum(executed) == 20
            for loop in agents:
                await loop.close()

            # Every scan completed exactly once: the lifecycle never re-ran a step.
            for scan_id in scan_ids:
                record = harness.services.store.get_scan(scan_id)
                assert record is not None and record.status.value == "completed"
                recon = record.step_state(ScanStep.RECON)
                assert recon is not None and recon.attempts == 1
            assert harness.services.queue.stats() == {"done": 20}

            # Audit continuity (REQ-SCALE-004): 20 leases, one per scan, each naming
            # the agent and the API key that leased it.
            leased = harness.events_of(AuditAction.SCAN_LEASED)
            assert len(leased) == 20
            assert len({event.scan_id for event in leased}) == 20
            assert {event.meta["agent"] for event in leased} == {"agent-1", "agent-2"}
            assert all(event.meta["key"] == "scanner" for event in leased)
            registered = harness.events_of(AuditAction.AGENT_REGISTERED)
            assert {event.target for event in registered} == {"agent-1", "agent-2"}
            # The execution's own trail lines carry the agent identity as the actor.
            started = harness.events_of(AuditAction.SCAN_STARTED)
            assert {event.actor for event in started} <= {"agent:agent-1", "agent:agent-2"}
    finally:
        harness.close()


async def test_the_agent_control_plane_requires_a_scanner_key(tmp_path: Path) -> None:
    harness = make_api_harness(tmp_path, settings=distributed_settings(tmp_path / "auth.db"))
    try:
        async with asgi_client(harness.app) as http:
            assert (
                await http.post("/api/v1/agent/register", json={"name": "ghost"})
            ).status_code == 401
            assert (
                await http.post(
                    "/api/v1/agent/register", headers=auth(VIEWER_KEY), json={"name": "ghost"}
                )
            ).status_code == 403
            ok = await http.post(
                "/api/v1/agent/register", headers=auth(SCANNER_KEY), json={"name": "agent-1"}
            )
            assert ok.status_code == 200 and ok.json()["agent"]["name"] == "agent-1"
            # An unregistered agent cannot lease; a registered one gets an empty lease.
            assert (
                await http.post(
                    "/api/v1/agent/lease", headers=auth(SCANNER_KEY), json={"name": "x"}
                )
            ).status_code == 409
            empty = await http.post(
                "/api/v1/agent/lease",
                headers=auth(SCANNER_KEY),
                json={"name": "agent-1", "cap": 1, "ttl_s": 5},
            )
            assert empty.status_code == 200 and empty.json()["leases"] == []
    finally:
        harness.close()


# ---------------------------------------------------------------------------
# REQ-SCALE-003: agent-kill mid-scan re-leases and completes
# ---------------------------------------------------------------------------
def test_an_agent_killed_mid_scan_is_re_leased_and_completes_on_another_node(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "fleet.db"
    marker = tmp_path / "marker.txt"
    stack = build_stack(db_path)

    # Node A (the producer): admit the scan through the real orchestrator and enqueue it.
    orchestrator = build_orchestrator(stack.services)
    request = load_scan_request(LAB_FIXTURE)
    session = asyncio.run(orchestrator.launch(request))
    scan_id = session.scan_id
    assert scan_id is not None
    stack.services.queue.enqueue(scan_id, requested_by="producer")
    stack.close()

    # The doomed agent: a real child process that leases and SIGKILLs itself mid-step.
    environment = {
        "ARACHNE_AGENT_DB": str(db_path),
        "ARACHNE_AGENT_MARKER": str(marker),
        "ARACHNE_AGENT_STEP": ScanStep.DISCOVERY.value,
        "ARACHNE_AGENT_NAME": "agent-doomed",
        "PATH": "/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "tests.helpers.agent_child"],
        cwd=CODE_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == -9, (  # SIGKILL: no unwinding, no ack
        f"expected the killed agent, got {completed.returncode}: "
        f"{completed.stdout}{completed.stderr}"
    )
    assert marker.read_text().split() == ["recon", "discovery"]

    # What the kill left behind: the row is still leased, the scan still running.
    survivor = build_stack(db_path)
    try:
        row = survivor.services.queue.entry_for(scan_id)
        assert row is not None and row.status == "leased" and row.agent_name == "agent-doomed"
        record = survivor.services.store.get_scan(scan_id)
        assert record is not None and record.status.value == "running"

        # Wait out the TTL (the parent never reclaims by hand: reclaiming is the
        # *claiming* agent's beat, and that is where the interruption gets recorded).
        deadline = time.monotonic() + 10
        while True:
            current = survivor.services.queue.entry_for(scan_id)
            assert current is not None and current.lease_expires_at is not None
            if current.lease_expires_at <= datetime.now(UTC):
                break
            assert time.monotonic() < deadline, "the lease never expired"
            time.sleep(0.2)

        loop = AgentLoop(
            DirectControlPlane(AgentService(survivor.services, settings=survivor.settings)),
            name="agent-b",
            executor=build_executor(
                survivor.services,
                name="agent-b",
                handlers=make_handlers(marker),
            ),
            lease_ttl_s=5.0,
            heartbeat_interval_s=0.02,
            poll_interval_s=0.01,
        )
        assert asyncio.run(loop.run_until_drained()) == 1
        asyncio.run(loop.close())

        finished = survivor.services.store.get_scan(scan_id)
        assert finished is not None and finished.status.value == "completed"
        interruptions = finished.stats.get("interruptions")
        assert interruptions and interruptions[0]["agent"] == "agent-doomed"
        recon = finished.step_state(ScanStep.RECON)
        discovery = finished.step_state(ScanStep.DISCOVERY)
        assert recon is not None and recon.attempts == 1  # the completed step never re-ran
        assert discovery is not None and discovery.attempts == 2  # resumed where it died

        lines = marker.read_text().split()
        assert lines.count("recon") == 1
        assert lines.count("discovery") == 2
        assert lines[:3] == ["recon", "discovery", "discovery"]

        # The interruption is on the trail, and the resuming agent signs its work.
        interrupted = survivor.events_of(AuditAction.SCAN_INTERRUPTED)
        assert len(interrupted) == 1
        assert interrupted[0].meta["agent"] == "agent-doomed"
        resumed = survivor.events_of(AuditAction.SCAN_RESUMED)
        assert any(event.actor == "agent:agent-b" for event in resumed)
        assert survivor.services.queue.stats() == {"done": 1}
    finally:
        survivor.close()


# ---------------------------------------------------------------------------
# REQ-SCALE-005: findings and evidence stream to the central store as produced
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Metadata:
    """Minimal check metadata for ``record_checks`` (duck-typed by the store)."""

    module: str
    name: str
    version: str
    title: str
    description: str | None = None
    cwe: str | None = None
    research_ref: str | None = None

    @property
    def key(self) -> str:
        return f"{self.module}/{self.name}@{self.version}"


async def test_findings_stream_to_the_central_store_while_the_scan_runs(tmp_path: Path) -> None:
    stack = build_stack(tmp_path / "stream.db")
    mid_scan = asyncio.Event()
    pipeline = (ScanStep.RECON, ScanStep.CHECKS, ScanStep.ANALYSIS)

    def streaming_handlers() -> dict[ScanStep, Any]:
        async def recon(context: StepContext) -> StepOutcome:
            return StepOutcome(stats={"step": "recon"})

        async def checks(context: StepContext) -> StepOutcome:
            # The candidate + its evidence are committed *here*, mid-scan.
            check_ids = stack.services.findings.record_checks(
                [_Metadata(module="M4", name="env-file-probe", version="1.0", title="planted")]
            )
            asset = stack.services.store.add_asset(
                context.scan_id, kind="url", value="https://example.com/"
            )
            stack.services.findings.record_candidate(
                context.scan_id,
                result=CheckResult(
                    module="M4",
                    check="m4.env-file-probe",
                    title="planted mid-scan",
                    status="vulnerable",
                    detail="streaming test",
                    confidence=0.7,
                    evidence=(Evidence(kind="http_response", payload={"status": 200}),),
                ),
                check_id=check_ids.get("M4/env-file-probe@1.0"),
                asset_id=asset.id,
            )
            return StepOutcome(stats={"step": "checks"})

        async def analysis(context: StepContext) -> StepOutcome:
            mid_scan.set()  # the scan is still running; the test now reads the store
            await asyncio.sleep(0.2)
            return StepOutcome(stats={"step": "analysis"})

        return {ScanStep.RECON: recon, ScanStep.CHECKS: checks, ScanStep.ANALYSIS: analysis}

    orchestrator = build_orchestrator(
        stack.services, handlers=streaming_handlers(), pipeline=pipeline
    )
    request = load_scan_request(LAB_FIXTURE)
    session = await orchestrator.launch(request)
    scan_id = session.scan_id
    assert scan_id is not None
    stack.services.queue.enqueue(scan_id)

    loop = AgentLoop(
        DirectControlPlane(AgentService(stack.services, settings=stack.settings)),
        name="agent-stream",
        executor=build_executor(
            stack.services,
            name="agent-stream",
            handlers=streaming_handlers(),
            pipeline=pipeline,
        ),
        lease_ttl_s=30.0,
        heartbeat_interval_s=0.05,
        poll_interval_s=0.01,
    )
    run_task = asyncio.ensure_future(loop.run_until_drained())
    await asyncio.wait_for(mid_scan.wait(), timeout=10)

    # A second, independent connection reads what the agent produced so far — the
    # finding is in the central store *before* the scan completes (REQ-SCALE-005).
    from arachne.data.db import create_session_factory

    second = create_session_factory(stack.services.engine)
    with second() as reader:
        findings = reader.scalars(select(Finding)).all()
        assert len(findings) == 1 and findings[0].scan_id == scan_id
        scan_row = reader.get(Scan, scan_id)
        assert scan_row is not None and scan_row.status == "running"

    assert await run_task
    await loop.close()
    record = stack.services.store.get_scan(scan_id)
    assert record is not None and record.status.value == "completed"
    assert len(record.steps) == 3
    stack.close()


# ---------------------------------------------------------------------------
# REQ-SCALE-006: deterministic plans across nodes
# ---------------------------------------------------------------------------
def test_the_same_scan_id_yields_the_same_plan_on_any_node(tmp_path: Path) -> None:
    node_a = build_stack(tmp_path / "plan.db")
    node_b = build_stack(tmp_path / "plan.db", settings=node_a.settings)
    try:
        orchestrator_a = build_orchestrator(node_a.services, pipeline=(ScanStep.RECON,))
        request = load_scan_request(LAB_FIXTURE)
        session = asyncio.run(orchestrator_a.launch(request))
        scan_id = session.scan_id
        assert scan_id is not None
        plan_a = session.plan

        # Node B rebuilds the admitted request and executes the stored plan — it does
        # not re-plan, so "the same scan id" cannot mean a different plan anywhere.
        record_b = node_b.services.store.get_scan(scan_id)
        assert record_b is not None
        request_b = rebuild_request(node_b.services, record_b)
        assert request_b.target == request.target
        assert request_b.options == request.options

        session_b = asyncio.run(
            build_orchestrator(node_b.services, pipeline=(ScanStep.RECON,)).execute(
                scan_id, request_b
            )
        )
        assert session_b.plan == plan_a

        # And re-planning from scratch on node B is deterministic in content: every
        # field except the planning timestamp is identical (same pipeline, so the same
        # handled steps).
        fresh = Orchestrator(
            settings=node_b.settings,
            store=node_b.services.store,
            registry=node_b.services.registry,
            pipeline=(ScanStep.RECON,),
        ).plan(request, dry_run=False)
        left, right = plan_a.to_dict(), fresh.to_dict()
        left.pop("created_at")
        right.pop("created_at")
        assert left == right
    finally:
        node_a.close()
        node_b.close()


# ---------------------------------------------------------------------------
# REQ-SCALE-007: the scheduler is a producer; the diff is computed on completion
# ---------------------------------------------------------------------------
def test_the_scheduler_enqueues_and_the_completion_computes_the_diff(tmp_path: Path) -> None:
    from arachne.scheduler.model import ScheduleSpec
    from arachne.scheduler.runner import Scheduler
    from arachne.scheduler.store import ScheduleStore

    db_path = tmp_path / "sched.db"
    settings = distributed_settings(db_path)
    stack = build_stack(db_path, settings=settings)
    try:
        scheduler = Scheduler(settings, services=stack.services)
        spec = ScheduleSpec(id="nightly", target=str(LAB_FIXTURE), cron="* * * * *")

        first = asyncio.run(scheduler.run_one(spec))
        assert first.status == "queued" and first.scan_id is not None
        row = stack.services.queue.entry_for(first.scan_id)
        assert row is not None
        assert row.schedule_id == "nightly" and row.status == "queued"
        assert row.requested_by == "schedule:nightly"
        assert row.previous_scan_id is None

        # The agent executes the produced scan and acks: no diff yet (first run).
        loop = direct_agent_loop(stack, "agent-sched", pipeline=(ScanStep.RECON,))
        assert asyncio.run(loop.run_until_drained()) == 1
        assert stack.services.queue.stats() == {"done": 1}

        # Second run: enqueued with the previous scan id; completion computes the diff.
        second = asyncio.run(scheduler.run_one(spec))
        assert second.scan_id is not None and second.scan_id != first.scan_id
        assert asyncio.run(loop.run_until_drained()) == 1

        with stack.services.session_factory() as db_session:
            diffs = db_session.scalars(select(ScanDiff)).all()
        assert len(diffs) == 1
        assert {diffs[0].scan_id_a, diffs[0].scan_id_b} == {first.scan_id, second.scan_id}

        stored = ScheduleStore(settings.scheduler.state_path).get("nightly")
        assert stored is not None
        assert stored.state.last_status == "queued"
        assert stored.state.last_scan_id == second.scan_id
    finally:
        stack.close()


# ---------------------------------------------------------------------------
# REQ-SCALE-008 companion: a stopped scan is cancelled fleet-wide
# ---------------------------------------------------------------------------
async def test_stopping_a_queued_scan_cancels_the_row_and_aborts_the_scan(tmp_path: Path) -> None:
    harness = make_api_harness(tmp_path, settings=distributed_settings(tmp_path / "stop.db"))
    try:
        async with asgi_client(harness.app) as http:
            started = await http.post(
                "/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET}
            )
            scan_id = started.json()["scan_id"]
            assert harness.services.queue.entry_for(scan_id).status == "queued"

            stopped = await http.post(f"/api/v1/scans/{scan_id}/stop", headers=auth(SCANNER_KEY))
            assert stopped.status_code == 200
            assert harness.services.queue.entry_for(scan_id).status == "cancelled"
            record = harness.services.store.get_scan(scan_id)
            assert record is not None and record.status.value == "aborted"
            assert harness.events_of(AuditAction.SCAN_ABORTED)
            assert (
                await http.post(f"/api/v1/scans/{scan_id}/stop", headers=auth(SCANNER_KEY))
            ).status_code == 409
    finally:
        harness.close()
