"""The Orchestrator: gates, wiring, plan/run/resume (F-01-02/03/04/09/10).

The three properties worth pinning here:

* **No gate, no scan.** An out-of-scope target, a missing attestation or an unauthorized
  active-check request all refuse *before* anything is persisted, and each refusal is in
  the audit log with its reason (F-01-08).
* **Dry run is inert.** It plans, audits the plan, and touches neither a database nor a
  client.
* **Resume is honest.** A stored scan can only be continued with the definition it was
  created from.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.conftest import build_scan_request

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import SafetySettings, Settings
from arachne.core.errors import AuthorizationError, OutOfScopeError, ScanStateError
from arachne.core.events import EventBus, EventType
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus, StepStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.steps import default_handlers

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def _offline_client_factory(scope: Scope) -> object:
    """A scoped client over a recorded ``example.com`` page (no socket, no internet).

    These tests exercise the orchestrator, not the network; a live scan through every
    module's probes would be slow and non-deterministic. The recording is one HTML page, so
    the crawl has a surface and every other path answers 501 immediately (the replay
    transport's documented behaviour).
    """
    from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
    from arachne.core.safety import StaticResolver

    responses = [
        RecordedResponse(
            method="GET",
            url="https://example.com/",
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8", "Server": "example"},
            body="<html><body><h1>Example</h1><a href='/about'>About</a></body></html>",
        )
    ]
    from arachne.core.config import RateLimitSettings

    return ScopedHttpClient(
        settings=Settings(
            database_url="sqlite:///:memory:",
            rate_limit=RateLimitSettings(
                per_host_rate=1_000_000.0,
                per_host_burst=1_000_000,
                global_rate=1_000_000.0,
                global_burst=1_000_000,
            ),
        ),
        scope=scope,
        resolver=StaticResolver(("93.184.216.34",)),
        transport=fixture_transport(responses),
    )


def build_orchestrator(**kwargs: object) -> tuple[Orchestrator, MemoryAuditSink]:
    kwargs.setdefault("client_factory", _offline_client_factory)
    sink = MemoryAuditSink()
    # A live scan runs every module's probes; the recorded transport answers instantly, so
    # rate limiting is what would make the test slow. Bounds are kept small for the same
    # reason — these tests exercise orchestration, not a module's probe count (which the
    # module suites own).
    from arachne.core.config import M4Settings, M5Settings, RateLimitSettings, WebSettings

    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(),
        log_level="WARNING",
        actor="pytest",
        rate_limit=RateLimitSettings(
            per_host_rate=100_000.0,
            per_host_burst=100_000,
            global_rate=100_000.0,
            global_burst=100_000,
        ),
        web=WebSettings(max_pages=4, max_depth=0, max_params_per_check=2),
        m4=M4Settings(max_paths=4, max_findings_per_check=2),
        m5=M5Settings(max_paths=4, max_findings_per_check=2),
    )
    orchestrator = Orchestrator(
        settings=kwargs.pop("settings", settings),  # type: ignore[arg-type]
        auditor=Auditor(sink, actor="pytest"),
        bus=EventBus(),
        store=MemoryScanStateStore(),
        **kwargs,  # type: ignore[arg-type]
    )
    return orchestrator, sink


# --------------------------------------------------------------------- scope gate
def test_scan_of_an_out_of_scope_target_is_blocked_and_audited() -> None:
    """F-01-02: the deployment allowlist refuses targets it does not cover."""
    deployment = Scope(allowed_hosts=("in-scope.example",))
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(scope=deployment),
        log_level="WARNING",
    )
    orchestrator, sink = build_orchestrator(settings=settings)

    with pytest.raises(OutOfScopeError) as excinfo:
        orchestrator.plan(build_scan_request(), dry_run=True)

    assert "deployment scope" in excinfo.value.reason
    rejected = sink.of_action(AuditAction.SCOPE_REJECTED)
    assert rejected, "a refusal must be recorded in the audit log (F-01-08)"
    assert rejected[0].outcome.value == "blocked"
    assert rejected[0].target == "https://example.com/"
    # Nothing was created: the gate runs before any state is written.
    assert orchestrator.store.list_scans() == ()


def test_a_target_fully_excluded_by_its_own_definition_is_blocked() -> None:
    request = build_scan_request(
        targets=[{"kind": "domain", "value": "example.com"}],
        exclusions=[{"kind": "domain", "value": "example.com"}],
    )
    orchestrator, sink = build_orchestrator()
    with pytest.raises(OutOfScopeError, match="excluded"):
        orchestrator.plan(request, dry_run=True)
    assert sink.of_action(AuditAction.SCOPE_REJECTED)


def test_a_fully_covered_deployment_scope_lets_the_scan_through() -> None:
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(scope=Scope(allowed_domains=("example.com",))),
        log_level="WARNING",
    )
    orchestrator, _ = build_orchestrator(settings=settings)
    plan = orchestrator.plan(build_scan_request(), dry_run=True)
    assert plan.deployment_scope is not None
    assert plan.totals.included_checks > 0


def test_effective_scope_is_the_definition_scope_plus_the_allowlist() -> None:
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(scope=Scope(allowed_domains=("example.com",))),
        log_level="WARNING",
    )
    orchestrator, _ = build_orchestrator(settings=settings)
    request = build_scan_request()
    request_scope, deployment = orchestrator.effective_scope(request.target)
    assert request_scope.url_prefixes == ("https://example.com/",)
    assert deployment is not None and deployment.allowed_domains == ("example.com",)


def test_without_a_deployment_scope_the_definition_is_the_declaration() -> None:
    orchestrator, _ = build_orchestrator()
    _, deployment = orchestrator.effective_scope(build_scan_request().target)
    assert deployment is None


# --------------------------------------------------------------- authorization gate
def test_a_live_scan_without_attestation_is_refused_and_audited() -> None:
    orchestrator, sink = build_orchestrator()
    with pytest.raises(AuthorizationError):
        orchestrator.plan(build_scan_request(attestation=None), dry_run=False)

    rejected = sink.of_action(AuditAction.AUTH_REJECTED)
    assert rejected and rejected[0].outcome.value == "blocked"
    assert "no authorization attestation" in (rejected[0].reason or "")


def test_a_dry_run_needs_no_attestation_but_reports_it() -> None:
    orchestrator, _ = build_orchestrator()
    plan = orchestrator.plan(build_scan_request(attestation=None), dry_run=True)
    assert plan.attestation is None
    assert not plan.live_ready


def test_an_authorized_live_scan_records_the_attestation() -> None:
    """F-08-05: the attestation (who/scope/when) is recorded in the audit log."""
    orchestrator, sink = build_orchestrator()
    orchestrator.plan(build_scan_request(), dry_run=False)

    recorded = sink.of_action(AuditAction.ATTESTATION_RECORDED)
    assert recorded
    meta = recorded[0].meta
    assert meta["attested_by"].startswith("Jane Operator")
    assert meta["attested_at"].startswith("2026-10-01")
    assert meta["authorization_ref"] == "TEST-1"


def test_unauthorized_active_checks_refuse_a_live_scan() -> None:
    orchestrator, sink = build_orchestrator()
    with pytest.raises(AuthorizationError, match="active checks"):
        orchestrator.plan(build_scan_request(options={"active_checks": True}), dry_run=False)
    assert sink.of_action(AuditAction.AUTH_REJECTED)


# ------------------------------------------------------------------------- planning
def test_planning_audits_what_was_loaded_and_planned() -> None:
    orchestrator, sink = build_orchestrator()
    plan = orchestrator.plan(build_scan_request(), dry_run=True)

    loaded = sink.of_action(AuditAction.TARGET_LOADED)
    assert loaded and loaded[0].meta["dry_run"] is True
    planned = sink.of_action(AuditAction.SCAN_PLANNED)
    assert planned
    assert planned[0].meta["estimated_requests"] == plan.totals.estimated_requests
    assert planned[0].meta["included_checks"] == plan.totals.included_checks


def test_dry_run_creates_no_scan_and_no_asset_state() -> None:
    orchestrator, _ = build_orchestrator()
    session = orchestrator.plan(build_scan_request(), dry_run=True)
    assert session.totals.estimated_requests > 0
    assert orchestrator.store.list_scans() == ()


# -------------------------------------------------------------------------- running
async def test_a_live_scan_runs_the_pipeline_and_persists_state() -> None:
    orchestrator, sink = build_orchestrator()
    session = await orchestrator.scan(build_scan_request())

    assert session.scan_id is not None
    assert session.status is ScanStatus.COMPLETED
    assert session.outcome is not None
    # The built-in handlers seed the asset inventory (recon) and derive endpoints.
    assert session.outcome.assets > 0
    assert session.record is not None
    assert session.record.step_state(ScanStep.RECON).status is StepStatus.COMPLETED  # type: ignore[union-attr]

    actions = sink.actions()
    assert AuditAction.SCAN_CREATED.value in actions
    assert AuditAction.SCAN_FINISHED.value in actions


async def test_a_live_scan_publishes_plan_and_lifecycle_events() -> None:
    orchestrator, _ = build_orchestrator()
    await orchestrator.scan(build_scan_request())

    types = orchestrator.bus.types()
    assert EventType.SCAN_PLANNED in types
    assert EventType.HOST_DISCOVERED in types
    assert EventType.SCAN_FINISHED in types


async def test_a_live_scan_only_contacts_declared_in_scope_urls() -> None:
    """S3 registers the M1 checks: a live scan works, and every request stays in scope.

    The unit-level companion of the CLI replay test. The scope is built from the target
    definition, so the assertion is the F-01-02 property itself rather than "nothing
    happened": every URL the scan reached for was one the operator declared.
    """
    calls: list[tuple[str, str]] = []

    def counting_client(scope: Scope) -> object:

        client = _offline_client_factory(scope)
        assert hasattr(client, "request")
        original = client.request  # type: ignore[union-attr]

        async def wrapped(method: str, url: str, **kwargs: object) -> object:
            calls.append((method, url))
            return await original(method, url, **kwargs)  # type: ignore[arg-type]

        client.request = wrapped  # type: ignore[method-assign,union-attr]
        return client

    request = build_scan_request()
    scope = request.target.compile_scope()
    orchestrator, _ = build_orchestrator(client_factory=counting_client)
    await orchestrator.scan(request)

    assert calls, "the js-asset-scan check should have read the declared web asset"
    for method, url in calls:
        assert method == "GET", "a default scan only performs read-only requests"
        assert scope.check_url(url).allowed, f"{url} is outside the declared scope"


async def test_the_plan_is_stored_with_the_scan() -> None:
    orchestrator, _ = build_orchestrator()
    session = await orchestrator.scan(build_scan_request())
    assert session.record is not None
    assert session.record.plan["target_name"] == "unit-fixture"
    assert session.record.plan["totals"]["included_checks"] == session.plan.totals.included_checks


async def test_handler_step_skips_are_recorded_in_the_scan_stats() -> None:
    orchestrator, _ = build_orchestrator()
    session = await orchestrator.scan(build_scan_request())
    assert session.record is not None
    # S5 gives analysis and correlation real handlers, so they run (over zero candidates in
    # this scan). The checks step has no implemented check here, and reporting has no handler.
    assert "analysis" in session.record.stats["steps_executed"]
    assert "correlation" in session.record.stats["steps_executed"]
    assert "reporting" in session.record.stats["steps_skipped"]


async def test_handlers_can_be_replaced_entirely() -> None:
    seen: list[str] = []

    async def handler(context: object) -> object:
        from arachne.core.lifecycle import StepOutcome

        seen.append("custom")
        return StepOutcome(stats={"custom": True})

    orchestrator, _ = build_orchestrator(handlers={ScanStep.RECON: handler})
    session = await orchestrator.scan(build_scan_request())
    assert seen == ["custom"]
    assert session.outcome is not None
    assert session.outcome.executed == (ScanStep.RECON,)
    assert set(session.outcome.skipped) == {
        ScanStep.DISCOVERY,
        ScanStep.CHECKS,
        ScanStep.ANALYSIS,
        ScanStep.CORRELATION,
        ScanStep.REPORTING,
    }


async def test_resume_continues_a_stored_scan() -> None:
    calls: list[str] = []
    fail = {"on": True}

    async def flaky(context: object) -> object:
        from arachne.core.errors import ScanStateError
        from arachne.core.lifecycle import StepOutcome

        step = getattr(context, "step", None)
        calls.append(str(step))
        if step is ScanStep.DISCOVERY and fail["on"]:
            msg = "interrupted"
            raise ScanStateError(msg)
        return StepOutcome()

    orchestrator, _ = build_orchestrator(
        handlers={ScanStep.RECON: flaky, ScanStep.DISCOVERY: flaky}
    )
    request = build_scan_request()
    with pytest.raises(ScanStateError):
        await orchestrator.scan(request)

    assert calls == ["recon", "discovery"]
    scan_id = orchestrator.store.list_scans()[0].id
    fail["on"] = False

    session = await orchestrator.resume(scan_id, request)

    assert calls == ["recon", "discovery", "discovery"]  # recon was not repeated
    assert session.status is ScanStatus.COMPLETED
    assert session.outcome is not None and session.outcome.resumed is True


async def test_resuming_an_unknown_scan_is_refused() -> None:
    orchestrator, _ = build_orchestrator()
    with pytest.raises(ScanStateError, match="does not exist"):
        await orchestrator.resume(4242, build_scan_request())


async def test_resuming_with_a_different_definition_is_refused() -> None:
    orchestrator, _ = build_orchestrator()
    session = await orchestrator.scan(build_scan_request())
    assert session.scan_id is not None

    other = build_scan_request(name="another-target")
    with pytest.raises(ScanStateError, match="refusing to resume"):
        await orchestrator.resume(session.scan_id, other)


async def test_resuming_an_interrupted_scan_requires_authorization() -> None:
    """A resume re-runs steps, so it must pass the same gate as the original scan."""
    orchestrator, _ = build_orchestrator(handlers={ScanStep.CHECKS: _always_fails})
    request = build_scan_request()
    with pytest.raises(ScanStateError):
        await orchestrator.scan(request)
    interrupted = orchestrator.store.list_scans()[0].id

    with pytest.raises(AuthorizationError):
        await orchestrator.resume(interrupted, build_scan_request(attestation=None))


async def test_resuming_a_completed_scan_needs_no_attestation() -> None:
    """Nothing left to execute means nothing can leave the process."""
    orchestrator, _ = build_orchestrator()
    session = await orchestrator.scan(build_scan_request())
    assert session.scan_id is not None

    resumed = await orchestrator.resume(session.scan_id, build_scan_request(attestation=None))
    assert resumed.status is ScanStatus.COMPLETED


async def _always_fails(context: object) -> object:
    msg = "boom"
    raise ScanStateError(msg)


async def test_resume_re_reads_the_plan_from_the_store() -> None:
    orchestrator, _ = build_orchestrator(handlers={})
    request = build_scan_request()
    session = await orchestrator.scan(request)
    assert session.scan_id is not None

    resumed = await orchestrator.resume(session.scan_id, request)
    assert resumed.plan.target_name == "unit-fixture"
    assert resumed.plan.totals.estimated_requests == session.plan.totals.estimated_requests


def test_target_store_persists_the_definition_when_one_is_configured() -> None:
    class FakeTargetStore:
        def __init__(self) -> None:
            self.saved: list[str] = []

        def save(self, definition: object) -> int:
            self.saved.append(str(definition.name))
            return 7

    store = FakeTargetStore()
    orchestrator, _ = build_orchestrator(target_store=store)
    orchestrator.plan(build_scan_request(), dry_run=True)
    assert store.saved == []  # planning does not persist anything


async def test_a_live_scan_persists_its_target_row() -> None:
    class FakeTargetStore:
        def __init__(self) -> None:
            self.saved: list[str] = []

        def save(self, definition: object) -> int:
            self.saved.append(str(definition.name))
            return 7

    store = FakeTargetStore()
    orchestrator, _ = build_orchestrator(target_store=store)
    session = await orchestrator.scan(build_scan_request())
    assert store.saved == ["unit-fixture"]
    assert session.record is not None and session.record.target_id == 7


def test_default_handlers_cover_recon_and_discovery_only() -> None:
    assert set(default_handlers()) == {ScanStep.RECON, ScanStep.DISCOVERY}


def test_module_of_step_maps_the_pipeline_to_modules() -> None:
    from arachne.core.orchestrator import module_of_step

    assert module_of_step(ScanStep.RECON) == ("M1",)
    assert module_of_step(ScanStep.DISCOVERY) == ("M2",)
    assert module_of_step(ScanStep.CHECKS) == ("M3", "M4", "M5", "M6")
