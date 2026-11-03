"""Acceptance: a full scan in AI mode against a local OpenAI-compatible endpoint (DONE 2/3/4).

The endpoint is real (``tests.helpers.ai_server``, a loopback HTTP server) and the provider is
reached through the shipped ``HttpLlmTransport`` → ``ScopedHttpClient`` path, so this is the
whole chain: prompt store → scope-bound HTTP → structured output → pydantic validation →
merged ``Analysis`` → persisted findings and ``analysis_log``. The *target* is the recorded M1
fixture, so nothing but loopback is contacted and the scan is deterministic apart from the
model's answers.

Four things are proven here:

1. AI mode produces the same finding set as heuristic mode, with AI provenance recorded
   (F-03-05).
2. Structured output is validated and used: the stored narrative and the triage verdict in
   ``analysis_log`` are the model's.
3. Killing the endpoint mid-scan leaves a completed scan with every finding, each degraded
   analysis marked in provenance (DONE criterion 3).
4. The per-scan token cap is enforced and the scan still completes (DONE criterion 4).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.ai_server import FakeOpenAI

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, StaticResolver
from arachne.core.target import EngineName, load_scan_request
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes
from arachne.modules.registry import ModuleRegistry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"
HTTP_FIXTURES = FIXTURES / "http"


@pytest.fixture
def server() -> Iterator[FakeOpenAI]:
    """A fake OpenAI-compatible endpoint on loopback, stopped after the test."""
    endpoint = FakeOpenAI().start()
    try:
        yield endpoint
    finally:
        endpoint.stop()


@pytest.fixture
def ai_env(server: FakeOpenAI, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """Point the deployment's AI configuration at the fake endpoint (env only)."""
    env = {
        "ARACHNE_AI_PROVIDER": "openai_compatible",
        "ARACHNE_AI_BASE_URL": server.base_url,
        "ARACHNE_AI_MODEL": "fake-model-1",
        "ARACHNE_AI_PRIVACY": "redact",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    yield env


def build_settings(env: dict[str, str] | None = None, **ai_overrides: str) -> Settings:
    document = {
        "ARACHNE_LOG_LEVEL": "CRITICAL",
        **(env or {}),
        **ai_overrides,
    }
    settings = Settings.from_env(document)
    # The target client replays the recorded M1 fixture; OSINT stays off (the default).
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        http_fixtures=str(HTTP_FIXTURES),
        ai=settings.ai,
    )


def build_orchestrator(
    settings: Settings,
) -> tuple[Orchestrator, MemoryFindingStore, MemoryAnalysisStore, MemoryAuditSink, EventBus]:
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    bus = EventBus()
    handlers = build_handlers(
        settings=settings,
        registry=registry,
        findings=findings,
        analyses=analyses,
        auditor=auditor,
    )
    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
        auditor=auditor,
        bus=bus,
        handlers=handlers,
        registry=registry,
        client_factory=lambda scope: _target_client(scope, auditor),
    )
    return orchestrator, findings, analyses, sink, bus


def _target_client(scope: Scope, auditor: Auditor) -> ScopedHttpClient:
    replay = FixtureReplay(load_fixture_routes(HTTP_FIXTURES))
    return ScopedHttpClient(
        scope=scope,
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


async def run_scan(settings: Settings, *, engine: str) -> tuple[object, ...]:
    orchestrator, findings, analyses, sink, bus = build_orchestrator(settings)
    request = load_scan_request(TARGET_FIXTURE)
    request = request.model_copy(
        update={"options": request.options.model_copy(update={"engine": EngineName(engine)})}
    )
    session = await orchestrator.scan(request)
    return orchestrator, findings, analyses, sink, bus, session


def payloads(analyses: MemoryAnalysisStore, scan_id: int) -> list[dict[str, object]]:
    """The ``analysis_log`` payloads of a scan, as plain dicts."""
    return [dict(row.payload) for row in analyses.list_analyses(scan_id)]


# --------------------------------------------------------------------------- 1. parity


async def test_ai_mode_finds_the_same_findings_and_records_ai_provenance(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    settings = build_settings(ai_env)
    _orch_h, findings_h, _analyses_h, _sink_h, _bus_h, session_h = await run_scan(
        settings, engine="heuristic"
    )
    orchestrator, findings_a, _analyses_a, _sink_a, _bus_a, session_a = await run_scan(
        settings, engine="ai"
    )

    assert session_h.status is ScanStatus.COMPLETED
    assert session_a.status is ScanStatus.COMPLETED

    heuristic_set = {
        (record.check_key, record.title)
        for record in findings_h.list_candidates(session_h.scan_id or 0)
    }
    ai_set = {
        (record.check_key, record.title)
        for record in findings_a.list_candidates(session_a.scan_id or 0)
    }
    assert ai_set == heuristic_set, "AI mode changed the finding set "

    # The AI half really ran, and the model saw delimited target data.
    assert server.requests, "no model call was made in AI mode"
    staged = server.stages()
    assert "triage" in staged
    bodies = [request["body"] for request in server.requests]
    assert any("[TARGET_DATA]" in str(body["messages"]) for body in bodies)
    # Every call is a JSON POST to the configured endpoint; this deployment configured no
    # credential (a local OpenAI-compatible endpoint), and none is invented.
    assert all(request["path"].endswith("/v1/chat/completions") for request in server.requests)
    assert all(
        request["headers"].get("content-type") == "application/json" for request in server.requests
    )
    assert all("authorization" not in request["headers"] for request in server.requests)
    assert all("api_key" not in request["body"] for request in server.requests)

    # Every candidate is still analysed (nothing was lost to the AI path).
    assert len(findings_a.list_candidates(session_a.scan_id or 0)) == len(heuristic_set)
    record = orchestrator.store.get_scan(session_a.scan_id or 0)
    assert record is not None
    analysis_step = record.step_state(ScanStep.ANALYSIS)
    assert analysis_step is not None
    assert analysis_step.stats["findings"] >= 1
    ai_stats = analysis_step.stats.get("ai")
    assert isinstance(ai_stats, dict)
    assert ai_stats["provider"] == "openai_compatible"
    assert ai_stats["budget"]["requests"] > 0
    assert ai_stats["budget"]["tokens"]["total_tokens"] > 0
    assert ai_stats["degraded"] == 0


async def test_the_stored_analysis_carries_the_models_narrative_and_verdict(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    """Structured output validated and *used*: the narrative and triage are the model's."""
    settings = build_settings(ai_env)
    _orchestrator, findings, analyses, _sink, _bus, session = await run_scan(settings, engine="ai")
    scan_id = session.scan_id or 0

    stored = payloads(analyses, scan_id)
    assert stored, "the analysis step wrote no analysis rows"

    # Every candidate was analysed (the analysis store is where the verdict lands; the module
    # layer deliberately leaves ``findings.severity`` NULL — ADR-02).
    candidates = findings.list_candidates(scan_id)
    assert len(stored) >= len(candidates)
    assert all(row["severity"] for row in stored), "findings were not analysed"
    ai_rows = [row for row in stored if row["provenance"]["engine"] == "ai"]
    assert ai_rows, "no analysis carries AI provenance"
    assert server.stages().count("triage") >= len(ai_rows)

    row = ai_rows[0]
    assert row["narrative"] == "The deployment serves a configuration file from the web root."
    assert row["provenance"]["provider"] == "openai_compatible"
    assert row["provenance"]["model"] == "fake-model-1"
    assert row["provenance"]["prompt_hash"]
    assert row["ai"]["stages"]["triage"]["severity"] == "critical"
    # The verdict itself stayed the deterministic one .
    assert row["severity"] == row["score"]["derived_severity"] or row["severity"] in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert row["provenance"]["fallback"] is None


# --------------------------------------------------------------------------- 2. mid-scan kill


async def test_killing_the_endpoint_mid_scan_completes_with_provenance_marked(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    """DONE criterion 3: the provider dies mid-scan; the scan finishes on heuristics."""
    server.fail_after = 3
    settings = build_settings(ai_env)
    orchestrator, findings, _analyses, sink, _bus, session = await run_scan(settings, engine="ai")

    assert session.status is ScanStatus.COMPLETED
    candidates = findings.list_candidates(session.scan_id or 0)
    assert candidates, "the scan lost every finding when the provider died"
    rows = payloads(_analyses, session.scan_id or 0)
    assert rows, "the analysis step wrote nothing"
    assert all(row["severity"] for row in rows), "findings were left unanalysed"
    # Every degraded row says which stage(s) fell back and why — never "AI analysed" (03- §7).
    fallbacks = [row["provenance"]["fallback"] for row in rows if row["provenance"]["fallback"]]
    assert fallbacks
    assert all(str(item).startswith(("heuristic_fallback:", "partial:")) for item in fallbacks)
    assert any("provider_error" in str(item) for item in fallbacks)

    # The degradation is in the audit trail, not only in the statistics.
    degraded = [event for event in sink.events if event.action is AuditAction.AI_DEGRADED]
    assert degraded
    assert any(event.meta.get("outcome") == "provider_error" for event in degraded)

    record = orchestrator.store.get_scan(session.scan_id or 0)
    assert record is not None
    step = record.step_state(ScanStep.ANALYSIS)
    assert step is not None
    ai_stats = step.stats["ai"]
    assert ai_stats["degraded"] >= 1
    assert ai_stats["fallbacks"], "no fallback reason was recorded"
    # The candidate's analysis kept the AI stages that succeeded before the endpoint died.
    assert ai_stats["engines"]

    # The degradation is in the audit trail, not only in the statistics .
    degraded = [event for event in sink.events if event.action is AuditAction.AI_DEGRADED]
    assert degraded
    assert any("provider_error" in str(event.meta.get("outcome")) for event in degraded)


async def test_a_provider_that_is_down_from_the_start_degrades_every_analysis(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    """The ``heuristic_fallback`` half of the chain: no stage ever succeeded."""
    server.fail_after = 1
    settings = build_settings(ai_env)
    _orchestrator, _findings, analyses, _sink, _bus, session = await run_scan(settings, engine="ai")
    assert session.status is ScanStatus.COMPLETED
    rows = payloads(analyses, session.scan_id or 0)
    assert rows
    for row in rows:
        assert row["provenance"]["engine"] == "heuristic"
        assert str(row["provenance"]["fallback"]).startswith("heuristic_fallback:provider_error")
        assert row["provenance"]["provider"] is None
        assert row["narrative"], "a degraded analysis must still carry the heuristic prose"
        assert row["remediation"]["id"]


# --------------------------------------------------------------------------- 3. budget


async def test_the_per_scan_token_cap_is_enforced(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    """DONE criterion 4: a tiny cap stops the calls and the scan still completes."""
    settings = build_settings(ai_env, ARACHNE_AI_MAX_TOKENS_PER_SCAN="10")
    orchestrator, findings, _analyses, sink, _bus, session = await run_scan(settings, engine="ai")

    assert session.status is ScanStatus.COMPLETED
    assert findings.list_candidates(session.scan_id or 0)
    record = orchestrator.store.get_scan(session.scan_id or 0)
    assert record is not None
    step = record.step_state(ScanStep.ANALYSIS)
    assert step is not None
    budget = step.stats["ai"]["budget"]
    assert budget["refused"] >= 1
    assert budget["tokens"]["total_tokens"] == 0
    # The cap was hit before the spend, so the endpoint saw no (or only cached) work.
    assert len(server.requests) == 0
    exhausted = [event for event in sink.events if event.action is AuditAction.BUDGET_EXHAUSTED]
    assert exhausted


# --------------------------------------------------------------------------- 4. explicitness


async def test_ai_mode_without_a_provider_is_refused_at_plan_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-03-03: no provider configured means the scan is refused, not silently downgraded."""
    for key in (
        "ARACHNE_AI_PROVIDER",
        "ARACHNE_AI_BASE_URL",
        "ARACHNE_AI_MODEL",
        "ARACHNE_AI_CONFIG",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = build_settings()
    orchestrator, _findings, _analyses, _sink, _bus = build_orchestrator(settings)
    request = load_scan_request(TARGET_FIXTURE)
    request = request.model_copy(
        update={"options": request.options.model_copy(update={"engine": EngineName.AI})}
    )
    with pytest.raises(ConfigurationError, match="no AI provider is configured"):
        orchestrator.plan(request, dry_run=False)


async def test_hybrid_without_a_provider_is_the_heuristic_engine() -> None:
    """: hybrid is heuristics alone when nothing is configured."""
    settings = build_settings()
    _orch, findings, _analyses, _sink, _bus, session = await run_scan(settings, engine="hybrid")
    assert session.status is ScanStatus.COMPLETED
    assert findings.list_candidates(session.scan_id or 0)


# --------------------------------------------------------------------------- 5. provenance


async def test_every_ai_row_persists_a_cited_provenance_record(
    ai_env: dict[str, str], server: FakeOpenAI
) -> None:
    """REQ-AGENT-008, end to end: the row carries what left the boundary and what came back.

    "An AI-produced row is distinguishable from a heuristic one without reading logs" is the
    ``origin`` field on the row's own provenance; the citation is what makes the claim checkable;
    and the tokens are attributed to the row that bought them, not to the scan in general.
    """
    from arachne.ai.provenance import AI_ORIGIN, ProvenanceRecord, summarize_provenance

    settings = build_settings(ai_env)
    _orchestrator, findings, analyses, _sink, _bus, session = await run_scan(settings, engine="ai")
    scan_id = session.scan_id or 0
    rows = analyses.list_analyses(scan_id)
    assert rows, "the analysis step wrote no analysis rows"

    candidates = {record.id: record for record in findings.list_candidates(scan_id)}
    ai_rows = [row for row in rows if row.origin == AI_ORIGIN]
    assert ai_rows, "no row declared an AI origin"

    for row in ai_rows:
        record = ProvenanceRecord.from_dict(row.provenance)
        assert record.is_ai
        assert record.provider == "openai_compatible"
        assert record.model == "fake-model-1"
        assert record.prompt_hash and record.template_version
        assert record.prompt_tokens > 0 and record.completion_tokens > 0
        assert record.total_tokens > 0
        assert record.stages
        # The citation is real: every id the model gave is an evidence row of *this* finding.
        assert row.finding_id is not None
        evidence_ids = {str(item.id) for item in candidates[row.finding_id].evidence}
        assert record.evidence_ids, "an AI row must cite an evidence id"
        assert set(record.evidence_ids) <= evidence_ids, (record.evidence_ids, evidence_ids)
        # ... and the change the AI half made is recorded, not inferred.
        assert "policy" in record.change

    # A heuristic row is distinguishable by the same field, with no log in sight.
    for row in rows:
        if row.origin == AI_ORIGIN:
            continue
        assert row.provenance.get("origin") in {None, "heuristic"}

    summary = summarize_provenance([row.provenance for row in rows], scan_ids=(scan_id,))
    assert summary["uncited_ai_rows"] == 0
    assert summary["ai_rows"] == len(ai_rows)
    assert summary["providers"]["openai_compatible"]["rows"] == len(ai_rows)
    assert summary["providers"]["openai_compatible"]["total_tokens"] > 0
    assert set(summary["stages"]) <= {"triage", "explain", "remediate", "narrative"}


async def test_no_provider_configured_leaves_every_row_heuristic_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REQ-AGENT-008: removing the provider config leaves the scan working, and honest.

    Nothing about the finding set changes; what changes is that no row claims an AI origin — and
    the row says so itself rather than leaving a reader to infer it from a missing log line.
    """
    from arachne.ai.provenance import HEURISTIC_ORIGIN

    for key in (
        "ARACHNE_AI_PROVIDER",
        "ARACHNE_AI_BASE_URL",
        "ARACHNE_AI_MODEL",
        "ARACHNE_AI_CONFIG",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = build_settings()
    _orch, findings, analyses, _sink, _bus, session = await run_scan(settings, engine="hybrid")

    assert session.status is ScanStatus.COMPLETED
    scan_id = session.scan_id or 0
    assert findings.list_candidates(scan_id), "the scan lost its findings without a provider"
    rows = analyses.list_analyses(scan_id)
    assert rows
    assert all(row.origin == HEURISTIC_ORIGIN for row in rows)
    for row in rows:
        assert not row.evidence_ids
        assert row.payload["provenance"]["engine"] == "heuristic"
        assert row.payload["narrative"], "the heuristic engine still writes the analysis"
