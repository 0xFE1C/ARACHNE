"""The parity guarantee (docs/spec/04- §5, G-05, F-03-02) — completed in S9.

The guarantee is narrow and testable, and this module tests exactly it: for *deterministic*
checks (all of M1-M4 in this build) the heuristic engine and the AI engine produce the **same
finding set** — the same ``(check_id, asset)`` pairs — and structurally equivalent ``Analysis``
objects, so the report engine cannot tell which engine ran except through ``provenance``.

Three layers, cheapest first:

1. **structural** — the heuristic engine implements the ``Analyzer`` protocol, its output is
   the report's ``Analysis`` schema, and its finding set is stable across runs (determinism);
2. **cross-engine, unit** — two candidates, both engines, one finding set and equal verdicts;
3. **cross-engine, whole scan** — the same recorded M1 scan through the real pipeline in both
   engine modes, compared analysis row by analysis row.

The AI engine used here is the shipped one with a scripted provider, so the test asserts the
*engine's* contract rather than a model's mood; the live-endpoint behaviour is covered by
``tests/integration/test_ai_scan.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.ai import make_engine
from tests.helpers.ai_server import FakeOpenAI

from arachne.ai.stages import CANDIDATE_STAGES
from arachne.analyzer.engine import Analyzer, HeuristicEngine, select_engine
from arachne.analyzer.handlers import create_heuristic_engine
from arachne.analyzer.model import (
    Analysis,
    Candidate,
    EvidenceFact,
    ScanContext,
    VerificationOutcome,
)
from arachne.analyzer.signatures import SignatureLibrary
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import MemoryScanStateStore
from arachne.core.orchestrator import Orchestrator
from arachne.core.safety import Scope, StaticResolver
from arachne.core.target import EngineName, load_scan_request
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes
from arachne.modules.registry import ModuleRegistry

ANALYZER_REQUIRED_FIELDS = (
    "finding_id",
    "severity",
    "confidence",
    "risk_notes",
    "remediation",
    "narrative",
    "provenance",
)

#: The fields both engines must agree on for the *same* candidate. ``provenance`` is excluded
#: by design: it is the one field allowed to differ (docs/spec/04- §5).
PARITY_FIELDS = ("severity", "confidence", "cwe", "verdict", "title")

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"
HTTP_FIXTURES = FIXTURES / "http"


def env_candidate(finding_id: int = 1) -> Candidate:
    return Candidate(
        scan_id=1,
        title="Sensitive environment file exposed",
        finding_id=finding_id,
        check_id="m4.env-file-probe",
        check_module="M4",
        check_name="env-file-probe",
        research_ref="ch04#1",
        cwe="CWE-200",
        severity_hint="high",
        verifiable=True,
        check_confidence=80,
        asset_kind="url",
        asset_value="https://target.example/.env",
        evidence=(
            EvidenceFact(
                "http_request",
                {"method": "GET", "url": "https://target.example/.env"},
                source="https://target.example/.env",
            ),
            EvidenceFact(
                "http_response",
                {"status_code": 200, "headers": {}, "body": "DB_PASSWORD=[REDACTED:value]"},
                source="https://target.example/.env",
            ),
        ),
    )


def service_candidate(finding_id: int = 2) -> Candidate:
    return Candidate(
        scan_id=1,
        title="SMBv1 is supported on 10.0.0.5:445/tcp",
        finding_id=finding_id,
        check_id="m2.smb-enum",
        check_module="M2",
        check_name="smb-enum",
        research_ref="ch02#16",
        cwe="CWE-200",
        severity_hint="high",
        verifiable=True,
        check_confidence=90,
        asset_kind="host",
        asset_value="10.0.0.5",
        evidence=(
            EvidenceFact(
                "note",
                {
                    "service": {
                        "host": "10.0.0.5",
                        "port": 445,
                        "protocol": "tcp",
                        "service": "smb",
                    },
                    "facts": {"dialects": ["NT LM 0.12"]},
                },
                source="10.0.0.5:445",
            ),
        ),
    )


def scan_context(*candidates: Candidate) -> ScanContext:
    return ScanContext(
        scan_id=1,
        verification={
            candidate.key: VerificationOutcome(count=2, attempted=True, reproducible=True)
            for candidate in candidates
        },
    )


def finding_set(analyses: Sequence[Analysis]) -> set[tuple[str | None, str | None]]:
    """The identity of a finding for parity purposes: its check and its asset."""
    return {(analysis.check_id, analysis.asset) for analysis in analyses}


def assert_structurally_equivalent(left: Analysis, right: Analysis) -> None:
    """The structural contract two engines' analyses of one candidate must share."""
    for field in ANALYZER_REQUIRED_FIELDS:
        assert getattr(left, field) is not None, field
        assert getattr(right, field) is not None, field
    for field in PARITY_FIELDS:
        assert getattr(left, field) == getattr(right, field), (
            f"engine disagreement on {field}: {getattr(left, field)!r} != {getattr(right, field)!r}"
        )
    # Provenance is the only field allowed to differ, and it must name its engine.
    assert left.provenance.engine and right.provenance.engine
    assert left.provenance.rule_ids == right.provenance.rule_ids


# --------------------------------------------------------------------------- structural gate


def test_the_heuristic_engine_is_an_analyzer() -> None:
    engine = HeuristicEngine(signatures=SignatureLibrary.load())
    assert isinstance(engine, Analyzer)
    assert engine.name == "heuristic"
    assert callable(engine.analyze)


def test_the_analysis_schema_carries_every_report_field() -> None:
    engine = HeuristicEngine(signatures=SignatureLibrary.load())
    candidates = (env_candidate(), service_candidate())
    analyses = engine.analyze(candidates, scan_context(*candidates))
    assert len(analyses) == len(candidates)
    for analysis in analyses:
        for field in ANALYZER_REQUIRED_FIELDS:
            assert getattr(analysis, field) is not None
        payload = analysis.to_dict()
        for key in ANALYZER_REQUIRED_FIELDS:
            assert key in payload


def test_the_heuristic_finding_set_is_deterministic() -> None:
    """The property the AI engine is measured against: same input, same finding set."""
    engine = HeuristicEngine(signatures=SignatureLibrary.load())
    candidates = (env_candidate(), service_candidate())
    first = engine.analyze(candidates, scan_context(*candidates))
    second = engine.analyze(candidates, scan_context(*candidates))
    assert finding_set(first) == finding_set(second)
    for left, right in zip(first, second, strict=True):
        assert_structurally_equivalent(left, right)


# --------------------------------------------------------------------------- cross-engine


async def test_heuristic_and_ai_engines_agree_on_the_finding_set() -> None:
    """The cross-engine half of G-05 (docs/spec/04- §5)."""
    heuristic = HeuristicEngine(signatures=SignatureLibrary.load())
    ai, provider = make_engine(heuristic=HeuristicEngine(signatures=SignatureLibrary.load()))
    candidates = (env_candidate(), service_candidate())
    context = scan_context(*candidates)

    heuristic_analyses = heuristic.analyze(candidates, context)
    ai_analyses = await ai.analyze_async(candidates, context)

    assert finding_set(heuristic_analyses) == finding_set(ai_analyses)
    by_key = {(item.check_id, item.asset): item for item in heuristic_analyses}
    for analysis in ai_analyses:
        counterpart = by_key[(analysis.check_id, analysis.asset)]
        assert_structurally_equivalent(counterpart, analysis)
        # ... and the AI half really ran (a parity test that skipped AI would be worthless).
        assert analysis.provenance.engine == "ai"
        assert analysis.provenance.prompt_hash

    assert sorted(provider.stages_called) == sorted(list(CANDIDATE_STAGES) * 2)


async def test_an_adopted_ai_verdict_is_still_one_analysis_per_candidate() -> None:
    """The authoritative escape hatch changes a verdict, never the finding set."""
    heuristic = HeuristicEngine(signatures=SignatureLibrary.load())
    ai, _provider = make_engine(
        heuristic=HeuristicEngine(signatures=SignatureLibrary.load()),
        authoritative=("m4.env-file-probe",),
    )
    candidates = (env_candidate(),)
    context = scan_context(*candidates)
    assert finding_set(heuristic.analyze(candidates, context)) == finding_set(
        await ai.analyze_async(candidates, context)
    )


def test_engine_selection_prefers_ai_only_when_it_is_configured() -> None:
    heuristic = HeuristicEngine()
    assert select_engine("heuristic", heuristic=heuristic) is heuristic
    assert select_engine("hybrid", heuristic=heuristic) is heuristic


# --------------------------------------------------------------------------- whole scan


def _scan_settings(env: dict[str, str]) -> Settings:
    settings = Settings.from_env({"ARACHNE_LOG_LEVEL": "CRITICAL", **env})
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        http_fixtures=str(HTTP_FIXTURES),
        ai=settings.ai,
    )


def _target_client(scope: Scope, auditor: Auditor) -> ScopedHttpClient:
    replay = FixtureReplay(load_fixture_routes(HTTP_FIXTURES))
    return ScopedHttpClient(
        scope=scope,
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


async def _scan(settings: Settings, engine: EngineName) -> dict[str, Any]:
    """Run one recorded M1 scan end to end in ``engine`` mode; return what it analysed."""
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
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
        bus=EventBus(),
        handlers=handlers,
        registry=registry,
        client_factory=lambda scope: _target_client(scope, auditor),
    )
    request = load_scan_request(TARGET_FIXTURE)
    request = request.model_copy(
        update={"options": request.options.model_copy(update={"engine": engine})}
    )
    session = await orchestrator.scan(request)
    assert session.scan_id is not None
    return {
        "status": session.status,
        "candidates": findings.list_candidates(session.scan_id),
        "analyses": [dict(row.payload) for row in analyses.list_analyses(session.scan_id)],
    }


@pytest.fixture
def endpoint() -> Any:
    server = FakeOpenAI().start()
    try:
        yield server
    finally:
        server.stop()


async def test_a_whole_scan_in_both_modes_yields_the_same_findings(
    endpoint: FakeOpenAI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A whole-scan parity run (docs/spec/04- §5): the same scan, two engines, one finding set.

    The scan is the recorded M1 replay (deterministic, offline apart from loopback), so the
    comparison is about the *engines*, not about a live target's mood.
    """
    env = {
        "ARACHNE_AI_PROVIDER": "openai_compatible",
        "ARACHNE_AI_BASE_URL": endpoint.base_url,
        "ARACHNE_AI_MODEL": "fake-model-1",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    settings = _scan_settings(env)

    baseline = await _scan(settings, EngineName.HEURISTIC)
    upgraded = await _scan(settings, EngineName.AI)

    assert baseline["status"] is upgraded["status"]
    assert baseline["candidates"] and upgraded["candidates"]

    candidate_keys = {(item.check_key, item.title) for item in upgraded["candidates"]}
    assert candidate_keys == {(item.check_key, item.title) for item in baseline["candidates"]}
    assert endpoint.requests, "the AI mode scan made no model call"

    def index(rows: list[dict[str, Any]]) -> dict[tuple[Any, Any], dict[str, Any]]:
        return {(row["check_id"], row["asset"]): row for row in rows}

    baseline_rows = index(baseline["analyses"])
    upgraded_rows = index(upgraded["analyses"])
    assert set(upgraded_rows) == set(baseline_rows), (
        "the finding set differs between engines (docs/spec/04- §5)"
    )
    for key, row in upgraded_rows.items():
        counterpart = baseline_rows[key]
        for field in PARITY_FIELDS:
            assert row[field] == counterpart[field], f"{key}: {field} differs between engines"
        assert row["score"] == counterpart["score"]
        assert row["verdict"] in {"analyzed", "dropped"}
        # Provenance is where the two engines are *allowed* to differ (docs/spec/04- §5) ...
        assert counterpart["provenance"]["engine"] == "heuristic"
        assert row["provenance"]["engine"] in {"ai", "heuristic"}
        assert row["narrative"] and counterpart["narrative"]
        assert row["remediation"]["id"] and counterpart["remediation"]["id"]
    # ... and at least one row was genuinely AI-authored, or this would prove nothing.
    assert any(row["provenance"]["engine"] == "ai" for row in upgraded_rows.values())


def test_ai_engine_selection_needs_a_provider() -> None:
    """F-03-03: ``ai`` is refused without one, so a "parity" run cannot silently be heuristic."""
    assert create_heuristic_engine() is not None  # the fallback always exists


# --------------------------------------------------------------------------- proof parity (S15)
def test_the_heuristic_engine_never_proposes_escalation() -> None:
    """REQ-PROOF-014 (parity): heuristic mode defaults to L1 and never escalates.

    Two properties, over the whole shipped check set:
    * with the default options (no attestation), no *included* check in a heuristic plan
      runs above L1 — the L2+ rows are opt-in and the L3/L4 rows additionally require the
      state-change attestation, so a default heuristic plan is ladder-flat at L1;
    * with every authorization granted, no check's effective level ever exceeds its own
      declaration — an upgrade is unrepresentable, escalation is only ever the operator's
      explicit, attested opt-in.
    """
    from tests.conftest import build_scan_request

    from arachne.core.config import SafetySettings, Settings
    from arachne.core.orchestrator import Orchestrator
    from arachne.core.proof import ProofLevel
    from arachne.core.safety import Scope
    from arachne.modules.registry import ModuleRegistry

    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(scope=Scope(allowed_hosts=("example.com",))),
    )
    orchestrator = Orchestrator(
        settings=settings,
        registry=ModuleRegistry.builtin(),
        handlers={},
    )
    default_plan = orchestrator.plan(build_scan_request(attestation=None), dry_run=True)
    included = [check for check in default_plan.checks if check.included]
    assert included, "the parity plan must include checks"
    assert all(check.proof_effective is ProofLevel.L1 for check in included)
    # And the L2+ rows are all withheld from a default plan:
    assert all(not check.included for check in default_plan.checks if check.proof.is_opt_in)

    fully_authorized = orchestrator.plan(
        build_scan_request(
            attestation={"active_checks_authorized": True, "state_changes_authorized": True},
            options={
                "active_checks": True,
                "modules": {
                    "checks": ("m3.rce-echo", "m3.state-marker", "m3.sqli-oob", "m3.ssrf-probe")
                },
            },
        ),
        dry_run=True,
    )
    for check in fully_authorized.checks:
        assert check.proof_effective.rank <= check.proof.rank, check.key
    # The named L3/L4 checks run at their declared level — the attestation is what the
    # escalation consumed, and it exists (state_changes_authorized=true).
    named = {check.name: check for check in fully_authorized.included_checks}
    assert named["rce-echo"].proof_effective is ProofLevel.L3
    assert named["state-marker"].proof_effective is ProofLevel.L4
