"""The analysis and correlation step handlers (docs/spec/02- §3 steps 5-6).

These are the seam tests: a stored candidate row must become exactly the analyzer input the
engine expects (dot-form check id, asset identity, check metadata, evidence), and the two
handlers must persist what they decide — including the DONE criterion that a scan's
candidates are analysed end to end.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from arachne.analyzer.engine import HeuristicEngine
from arachne.analyzer.handlers import (
    CandidateMetadata,
    build_analysis_handlers,
    candidate_from_record,
    create_correlation_engine,
    create_heuristic_engine,
    make_analysis_handler,
    make_correlation_handler,
    metadata_map,
)
from arachne.analyzer.model import Candidate, VerificationOutcome
from arachne.analyzer.signatures import SignatureLibrary
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import AnalysisSettings, Settings
from arachne.core.events import EventBus, EventType
from arachne.core.lifecycle import MemoryScanStateStore, StepContext, StepOutcome
from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import load_scan_request
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.db import create_session_factory, create_sqlite_engine
from arachne.data.finding_store import (
    CandidateRecord,
    EvidenceRecord,
    MemoryFindingStore,
    SqlFindingStore,
)


class FakeMetadata:
    """The subset of ``CheckMetadata`` the adapter reads."""

    def __init__(
        self,
        *,
        key: str = "M4/env-file-probe@1.0",
        research_ref: str = "ch04#1",
        cwe: str | None = "CWE-200",
        cve: str | None = None,
        severity_hint: str = "high",
        verifiable: bool = True,
    ) -> None:
        self.key = key
        self.research_ref = research_ref
        self.cwe = cwe
        self.cve = cve
        self.severity_hint = severity_hint
        self.verifiable = verifiable


class FakeRegistry:
    def __init__(self, *metadata: FakeMetadata) -> None:
        self._metadata = metadata or (FakeMetadata(),)

    def metadata(self) -> tuple[FakeMetadata, ...]:
        return self._metadata


class RecordingVerifier:
    """A verifier that reports a reproduction without any I/O."""

    def __init__(self, *, contradicted: bool = False, attempted: bool = True) -> None:
        self.contradicted = contradicted
        self.attempted = attempted
        self.seen: list[Candidate] = []

    async def verify(self, candidate: Candidate) -> VerificationOutcome:
        self.seen.append(candidate)
        return VerificationOutcome(
            count=1 if self.contradicted else 2,
            attempted=self.attempted,
            reproducible=not self.contradicted and self.attempted,
            contradicted=self.contradicted,
            detail="contradicted" if self.contradicted else "reproduced",
        )


def record(
    *,
    finding_id: int = 1,
    check_key: str | None = "M4/env-file-probe@1.0",
    module: str | None = "M4",
    title: str = "Sensitive environment file exposed",
    asset_kind: str | None = "url",
    asset_value: str | None = "https://example.com/.env",
    evidence: tuple[EvidenceRecord, ...] = (),
) -> CandidateRecord:
    return CandidateRecord(
        id=finding_id,
        scan_id=1,
        title=title,
        status="open",
        confidence=80.0,
        check_id=1,
        asset_id=2,
        asset_kind=asset_kind,
        asset_value=asset_value,
        check_key=check_key,
        module=module,
        research_ref="ch04#1",
        evidence=evidence,
    )


def response_evidence(
    *, body: str = "DB_PASSWORD=x", status: int = 200
) -> tuple[EvidenceRecord, ...]:
    return (
        EvidenceRecord(
            id=1,
            kind="http_request",
            payload={"method": "GET", "url": "https://example.com/.env"},
            sha256="req",
        ),
        EvidenceRecord(
            id=2,
            kind="http_response",
            payload={"status_code": status, "headers": {}, "body": body},
            sha256="resp",
        ),
    )


def env_artifact_evidence() -> EvidenceRecord:
    """The artifact an M4 check attaches; ``exposure.env-file`` reads it as facts."""
    return EvidenceRecord(
        id=3,
        kind="artifact",
        payload={
            "signal": "exposed-env-file",
            "family": "env",
            "path": "/.env",
            "status": 200,
            "bytes": 13,
            "marker": False,
            "assignment_count": 1,
            "assignment_keys": ["DB_PASSWORD"],
            "detectors": ["generic-password"],
        },
        sha256="artifact",
    )


# --------------------------------------------------------------------------- adapter


def test_the_adapter_maps_a_row_onto_the_engine_input() -> None:
    metadata = CandidateMetadata(
        key="M4/env-file-probe@1.0",
        research_ref="ch04#1",
        cwe="CWE-200",
        severity_hint="high",
        verifiable=True,
    )
    candidate = candidate_from_record(record(evidence=response_evidence()), metadata)
    assert candidate.check_id == "m4.env-file-probe"
    assert candidate.check_module == "M4"
    assert candidate.check_name == "env-file-probe"
    assert candidate.check_version == "1.0"
    assert candidate.asset_kind == "url"
    assert candidate.asset_value == "https://example.com/.env"
    assert candidate.cwe == "CWE-200"
    assert candidate.severity_hint == "high"
    assert candidate.verifiable is True
    assert candidate.check_confidence == 80.0
    assert [item.kind for item in candidate.evidence] == ["http_request", "http_response"]
    assert candidate.evidence[1].id == 2


def test_the_adapter_tolerates_a_row_without_metadata() -> None:
    candidate = candidate_from_record(record(evidence=response_evidence()))
    assert candidate.check_id == "m4.env-file-probe"
    assert candidate.cwe is None
    assert candidate.verifiable is False
    assert candidate.asset_value == "https://example.com/.env"


def test_skipped_results_are_not_analysis_input() -> None:
    skipped_note = EvidenceRecord(
        id=3, kind="note", payload={"skipped": True, "reason": "no OSINT"}, sha256=None
    )
    candidate = candidate_from_record(record(evidence=(*response_evidence(), skipped_note)))
    assert [item.kind for item in candidate.evidence] == ["http_request", "http_response"]


def test_metadata_map_reads_the_registry() -> None:
    from arachne.modules.registry import ModuleRegistry

    mapped = metadata_map(ModuleRegistry.builtin())
    assert "M1/ct-lookup@1.0" in mapped
    assert mapped["M1/ct-lookup@1.0"].research_ref
    assert metadata_map(None) == {}


# --------------------------------------------------------------------------- engine factory


def test_the_factory_honours_data_overrides(tmp_path: Any) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        """
version: "override"
rules:
  - id: override.rule
    title: "Override rule"
    check_ref: ["*"]
    default_severity: low
""",
        encoding="utf-8",
    )
    settings = Settings.from_env({"ARACHNE_ANALYSIS_RULES": str(rules)})
    engine = create_heuristic_engine(settings)
    assert engine.rules.version == "override"
    assert isinstance(engine, HeuristicEngine)


def test_the_correlation_factory_builds_from_settings() -> None:
    engine = create_correlation_engine(Settings.from_env({}))
    assert engine.rules.rules


# --------------------------------------------------------------------------- step context


@pytest.fixture
def step_context() -> Iterator[StepContext]:
    request = load_scan_request("tests/fixtures/targets/m1-fixture.yaml")
    sink = MemoryAuditSink()
    store = MemoryScanStateStore()
    scan = store.create_scan(target_id=None, engine="heuristic", plan={})
    yield StepContext(
        scan_id=scan.id,
        step=ScanStep.ANALYSIS,
        definition=request.target,
        options=request.options,
        scope=request.target.compile_scope(),
        store=store,
        bus=EventBus(),
        auditor=Auditor(sink, actor="pytest"),
    )


@pytest.mark.asyncio
async def test_the_analysis_handler_analyses_and_persists(
    step_context: StepContext,
) -> None:
    findings = MemoryFindingStore()
    findings._candidates[1] = [  # type: ignore[attr-defined]
        record(evidence=(*response_evidence(), env_artifact_evidence()))
    ]
    analyses = MemoryAnalysisStore()
    verifier = RecordingVerifier()
    handler = make_analysis_handler(
        engine=HeuristicEngine(signatures=SignatureLibrary.load()),
        findings=findings,
        analyses=analyses,
        verifier=verifier,
        registry=FakeRegistry(),
        settings=Settings.from_env({}),
    )
    outcome = await handler(step_context)
    assert isinstance(outcome, StepOutcome)
    assert outcome.stats["candidates_analyzed"] == 1
    assert outcome.stats["findings"] == 1
    assert outcome.stats["severities"]["high"] == 1
    assert "exposure.env-file" in outcome.stats["rules_fired"]
    assert outcome.stats["verified"] == 1
    assert verifier.seen and verifier.seen[0].check_id == "m4.env-file-probe"
    stored = analyses.list_analyses(1)
    assert len(stored) == 1
    assert stored[0].severity == "high"
    assert stored[0].status == "verified"
    # The step audit trail records what the analyzer decided.
    assert AuditAction.ANALYSIS_COMPLETED in [
        event.action
        for event in step_context.auditor._sink.events  # type: ignore[attr-defined]
    ]


@pytest.mark.asyncio
async def test_the_analysis_handler_emits_an_event_and_drops_on_contradiction(
    step_context: StepContext,
) -> None:
    findings = MemoryFindingStore()
    findings._candidates[1] = [record(evidence=response_evidence())]  # type: ignore[attr-defined]
    analyses = MemoryAnalysisStore()
    events: list[Any] = []

    async def subscriber(event: Any) -> None:
        events.append(event)

    step_context.bus.subscribe(None, subscriber)
    handler = make_analysis_handler(
        engine=HeuristicEngine(signatures=SignatureLibrary.load()),
        findings=findings,
        analyses=analyses,
        verifier=RecordingVerifier(contradicted=True),
        registry=FakeRegistry(),
        settings=Settings.from_env({}),
    )
    outcome = await handler(step_context)
    assert outcome.stats["dropped"] == 1
    assert outcome.stats["findings"] == 0
    assert any(event.type is EventType.ANALYSIS_DONE for event in events)
    assert analyses.list_analyses(1)[0].status == "fp"


@pytest.mark.asyncio
async def test_the_analysis_handler_with_no_candidates(step_context: StepContext) -> None:
    handler = make_analysis_handler(
        engine=HeuristicEngine(),
        findings=MemoryFindingStore(),
        analyses=MemoryAnalysisStore(),
        settings=Settings.from_env({}),
    )
    outcome = await handler(step_context)
    assert outcome.stats == {"candidates_analyzed": 0, "findings": 0}


@pytest.mark.asyncio
async def test_verification_is_skipped_when_the_configuration_disables_it(
    step_context: StepContext,
) -> None:
    findings = MemoryFindingStore()
    findings._candidates[1] = [record(evidence=response_evidence())]  # type: ignore[attr-defined]
    verifier = RecordingVerifier()
    handler = make_analysis_handler(
        engine=HeuristicEngine(),
        findings=findings,
        analyses=MemoryAnalysisStore(),
        verifier=verifier,
        registry=FakeRegistry(),
        settings=Settings(analysis=AnalysisSettings(verify=False)),
    )
    outcome = await handler(step_context)
    assert verifier.seen == []
    assert outcome.stats["verified"] == 0


@pytest.mark.asyncio
async def test_the_correlation_handler_emits_compounds(
    step_context: StepContext,
) -> None:
    findings = MemoryFindingStore()
    findings._candidates[1] = [record(evidence=response_evidence())]  # type: ignore[attr-defined]
    analyses = MemoryAnalysisStore()
    engine = HeuristicEngine(signatures=SignatureLibrary.load())
    analysis_handler = make_analysis_handler(
        engine=engine,
        findings=findings,
        analyses=analyses,
        registry=FakeRegistry(),
        settings=Settings.from_env({}),
    )
    await analysis_handler(step_context)

    correlation_handler = make_correlation_handler(
        engine=create_correlation_engine(Settings.from_env({})),
        findings=findings,
        analyses=analyses,
        store=step_context.store,
    )
    outcome = await correlation_handler(step_context)
    assert outcome.stats["candidates_considered"] == 1
    assert outcome.stats["compounds"] == 0  # one finding cannot satisfy a two-signal rule
    assert outcome.skipped is False


@pytest.mark.asyncio
async def test_the_correlation_handler_reports_a_disabled_configuration(
    step_context: StepContext,
) -> None:
    handler = make_correlation_handler(
        engine=create_correlation_engine(),
        findings=MemoryFindingStore(),
        analyses=MemoryAnalysisStore(),
        enabled=False,
    )
    outcome = await handler(step_context)
    assert outcome.skipped is True
    assert "disabled" in (outcome.note or "")


@pytest.mark.asyncio
async def test_build_analysis_handlers_covers_both_steps(step_context: StepContext) -> None:
    handlers = build_analysis_handlers(
        settings=Settings.from_env({}),
        findings=MemoryFindingStore(),
        analyses=MemoryAnalysisStore(),
    )
    assert set(handlers) == {ScanStep.ANALYSIS, ScanStep.CORRELATION}
    outcome = await handlers[ScanStep.CORRELATION](step_context)
    assert outcome.stats["compounds"] == 0


# --------------------------------------------------------------------------- SQL store


def test_candidates_carry_their_asset_identity_from_the_store(tmp_path: Any) -> None:
    """The checks step records the asset with the candidate, so the analyzer sees it."""
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'cand.db'}")
    from arachne.data.db import create_all

    create_all(engine)
    try:
        factory: sessionmaker[Session] = create_session_factory(engine)
        from arachne.data.models import Asset, Check, Scan, Target

        with factory() as session:
            target = Target(name="t", scope_json={})
            session.add(target)
            session.flush()
            scan = Scan(target_id=target.id, plan_json={})
            session.add(scan)
            session.flush()
            asset = Asset(
                scan_id=scan.id, kind="url", value="https://example.com/.env", meta_json={}
            )
            session.add(asset)
            check = Check(module="M4", name="env-file-probe", version="1.0")
            session.add(check)
            session.commit()
            scan_id = int(scan.id)
            asset_id = int(asset.id)

        store = SqlFindingStore(factory)
        result = CheckResult(
            status="vulnerable",
            title="Sensitive environment file exposed",
            evidence=(Evidence.of("http_response", {"status_code": 200, "body": "x"}),),
            confidence=0.9,
            check="M4/env-file-probe@1.0",
            module="M4",
        )
        record_ = store.record_candidate(scan_id, result=result, check_id=None, asset_id=asset_id)
        assert record_.asset_kind == "url"
        assert record_.asset_value == "https://example.com/.env"
        listed = SqlFindingStore(factory).list_candidates(scan_id)
        assert listed[0].asset_value == "https://example.com/.env"
        assert listed[0].confidence == 90
    finally:
        engine.dispose()
