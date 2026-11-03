"""AI provenance: the record, the citation invariant, the column, the export (REQ-AGENT-008).

Four claims are asserted here, one per acceptance criterion of the requirement:

* an AI-produced row is distinguishable from a heuristic one **without reading logs** — the
  ``provenance.origin`` field on the analysis row says which it is;
* an AI row **cannot exist without a cited evidence id** — the invariant is structural
  (:class:`ProvenanceRecord` refuses to be constructed without one), the engine refuses an answer
  that cites nothing, and the store refuses to *persist* a payload that claims AI without a
  citation;
* the provenance is **exportable per scan and per project**, with the provider and the token
  counts an auditor asks for;
* with no provider configured the scan is unaffected and every row is heuristic-origin (that half
  lives in ``tests/integration/test_ai_scan.py``, where a whole scan runs).

The engine-level behaviour is exercised through the shipped engine with the scripted provider;
the store-level behaviour through a real SQLite database, because the column is the deliverable.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select
from tests.helpers.ai import env_candidate, make_engine
from typer.testing import CliRunner

from arachne.ai.provenance import (
    AI_ORIGIN,
    HEURISTIC_ORIGIN,
    ProvenanceError,
    ProvenanceRecord,
    summarize_provenance,
)
from arachne.analyzer.model import Analysis, Provenance, Remediation, ScoreBreakdown
from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.results import CheckResult, Evidence
from arachne.data.analysis_store import MemoryAnalysisStore, SqlAnalysisStore, provenance_of
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Project, Target
from arachne.data.scan_store import SqlScanStateStore
from arachne.modules.registry import ModuleRegistry

runner = CliRunner()


def analysis(**overrides: object) -> Analysis:
    """A minimal, valid analysis (the shape both engines produce)."""
    base = Analysis(
        title="Sensitive environment file exposed",
        severity="high",
        confidence=80,
        narrative="The deployment serves a configuration file from the web root.",
        remediation=Remediation(id="rotate-credentials", summary="Rotate the exposed credentials."),
        finding_id=1,
        check_id="m4.env-file-probe",
        asset="url:https://target.example/.env",
        cwe="CWE-200",
        score=ScoreBreakdown(derived_severity="high", confidence=80),
    )
    return replace(base, **overrides)


# ------------------------------------------------------------------ the record


def test_an_ai_record_must_cite_evidence() -> None:
    """The invariant, on the type itself: no citation, no AI origin."""
    with pytest.raises(ProvenanceError) as raised:
        ProvenanceRecord.ai(
            provider="ollama",
            model="qwen3:32b",
            prompt_hash="a" * 64,
            stages=("triage",),
            evidence_ids=(),
        )
    assert "cite at least one evidence id" in str(raised.value)


def test_an_ai_record_must_name_its_provider_model_and_prompt() -> None:
    with pytest.raises(ProvenanceError) as raised:
        ProvenanceRecord.ai(
            provider="",
            model="",
            prompt_hash="",
            stages=("triage",),
            evidence_ids=("12",),
        )
    assert "provider, model, prompt_hash" in str(raised.value)


def test_a_heuristic_record_needs_no_citation() -> None:
    record = ProvenanceRecord.heuristic(fallback="heuristic_fallback:provider_error")
    assert record.origin == HEURISTIC_ORIGIN
    assert not record.is_ai
    assert record.evidence_ids == ()


def test_an_unknown_origin_is_refused() -> None:
    with pytest.raises(ProvenanceError):
        ProvenanceRecord(origin="model-ish")


def test_a_stored_record_round_trips_and_a_bad_one_is_refused() -> None:
    record = ProvenanceRecord.ai(
        provider="openai_compatible",
        model="Qwen/Qwen3-32B",
        prompt_hash="b" * 64,
        template_version="corpus-1",
        stages=("triage", "narrative"),
        evidence_ids=("12", "13"),
        prompt_tokens=120,
        completion_tokens=40,
        change={"severity": ["high", "critical"]},
    )
    payload = json.loads(json.dumps(record.to_dict()))
    assert ProvenanceRecord.from_dict(payload) == record
    assert record.total_tokens == 160
    # A row whose stored record claims AI without a citation cannot be read back as an AI row.
    payload["evidence_ids"] = []
    with pytest.raises(ProvenanceError):
        ProvenanceRecord.from_dict(payload)


def test_the_summary_answers_which_provider_received_how_many_tokens() -> None:
    records = (
        ProvenanceRecord.ai(
            provider="openai",
            model="gpt-4o-mini",
            prompt_hash="c" * 64,
            stages=("triage",),
            evidence_ids=("12",),
            prompt_tokens=100,
            completion_tokens=20,
        ),
        ProvenanceRecord.ai(
            provider="openai",
            model="gpt-4o-mini",
            prompt_hash="d" * 64,
            stages=("narrative",),
            evidence_ids=("13",),
            prompt_tokens=200,
            completion_tokens=50,
            cached=True,
        ),
        ProvenanceRecord.heuristic(),
    )
    summary = summarize_provenance(records, scan_ids=(7,))
    assert summary["rows"] == 3
    assert summary["ai_rows"] == 2
    assert summary["heuristic_rows"] == 1
    assert summary["scan_ids"] == [7]
    assert summary["uncited_ai_rows"] == 0
    assert summary["providers"]["openai"] == {
        "rows": 2,
        "prompt_tokens": 300,
        "completion_tokens": 70,
        "total_tokens": 370,
        "cached_rows": 1,
    }
    assert summary["models"]["gpt-4o-mini"]["total_tokens"] == 370
    assert summary["stages"] == {"narrative": 1, "triage": 1}


# ------------------------------------------------------------------ the engine


def test_the_engine_records_provenance_with_the_cited_evidence() -> None:
    engine, _provider = make_engine()
    candidate = env_candidate()
    analysis_obj = engine.analyze([candidate], _context(candidate))[0]
    record = ProvenanceRecord.from_dict(analysis_obj.ai["provenance"])
    assert record.is_ai
    assert record.provider == "ollama"
    assert record.model == "fake-model-1"
    assert record.prompt_hash
    assert record.template_version
    assert set(record.evidence_ids) <= {"101", "102"}
    assert record.evidence_ids, "an AI row must cite at least one evidence id"
    assert record.prompt_tokens > 0 and record.completion_tokens > 0
    assert record.stages
    assert record.change["policy"] == "preserve"
    # The analyzer's own provenance agrees: this is an AI row.
    assert analysis_obj.provenance.engine == "ai"


def test_an_answer_that_cites_nothing_is_refused_and_the_row_stays_heuristic() -> None:
    """The engine's half of the invariant: an uncited answer is a failed stage, not a weak one."""
    from tests.helpers.ai import FakeProvider

    # ``raw_text`` bypasses the helper's citation injection, so the answer really does cite an
    # id this finding does not have — the case the engine must refuse.
    provider = FakeProvider(
        raw_text=json.dumps(
            {
                "severity": "critical",
                "confidence": 99,
                "fp_likely": False,
                "reason": "no citation this finding can back",
                "categories": [],
                "evidence_ids": ["999"],
            }
        )
    )
    engine, _ = make_engine(provider=provider, stages=("triage",))
    candidate = env_candidate()
    result = engine.analyze([candidate], _context(candidate))[0]
    assert result.provenance.engine == "heuristic"
    record = ProvenanceRecord.from_dict(result.ai["provenance"])
    assert not record.is_ai
    assert any("evidence_not_cited" in item for item in result.ai["fallback"])
    assert "999" in result.risk_notes


def test_a_candidate_with_no_addressable_evidence_gets_no_ai_origin() -> None:
    engine, _ = make_engine()
    candidate = replace(env_candidate(), evidence=())
    result = engine.analyze([candidate], _context(candidate))[0]
    assert result.provenance.engine == "heuristic"
    assert not result.ai["stages"], "no stage may contribute without an id to cite"


def _context(candidate: object) -> object:
    from arachne.analyzer.model import ScanContext

    return ScanContext(scan_id=1)


# ------------------------------------------------------------------ the store


def test_the_store_writes_the_provenance_column_and_reads_it_back() -> None:
    analysis_obj = _ai_analysis()
    store = MemoryAnalysisStore()
    stored = store.apply(1, [analysis_obj], engine="ai")[0]
    assert stored.provenance["origin"] == AI_ORIGIN
    assert stored.origin == "ai"
    assert stored.evidence_ids == ("12", "13")
    assert stored.provenance["provider"] == "ollama"


def test_the_store_refuses_to_persist_an_uncited_ai_claim() -> None:
    """A payload claiming ``ai`` with no citation is written as heuristic, and marked."""
    payload = _ai_analysis()
    broken = replace(
        payload,
        ai={"provenance": {"origin": AI_ORIGIN, "provider": "ollama", "evidence_ids": []}},
    )
    record = provenance_of(broken)
    assert record.origin == HEURISTIC_ORIGIN
    assert record.fallback == "provenance_invalid"
    stored = MemoryAnalysisStore().apply(1, [broken], engine="ai")[0]
    assert stored.origin == "heuristic"


def test_an_analysis_without_a_record_is_heuristic_origin() -> None:
    """A third-party ``Analyzer`` produces no record; the row must say so, not claim AI."""
    record = provenance_of(analysis(ai={}))
    assert record.origin == HEURISTIC_ORIGIN
    assert not record.is_ai


def _ai_analysis() -> Analysis:
    record = ProvenanceRecord.ai(
        provider="ollama",
        model="qwen3:32b",
        prompt_hash="e" * 64,
        template_version="corpus",
        stages=("triage", "narrative"),
        evidence_ids=("12", "13"),
        prompt_tokens=120,
        completion_tokens=40,
    ).to_dict()
    return analysis(
        provenance=Provenance(
            engine="ai",
            model="qwen3:32b",
            provider="ollama",
            prompt_hash="e" * 64,
            prompt_template="narrative,triage",
        ),
        ai={"policy": "preserve", "stages": {"triage": {}}, "provenance": record},
    )


# ------------------------------------------------------------------ the column, over SQLite


@pytest.fixture
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A migrated SQLite database, so the provenance column is the real one."""
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'ai-provenance.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    try:
        upgraded = runner.invoke(app, ["db", "upgrade"])
        assert upgraded.exit_code == 0, upgraded.output
        yield get_settings().database_url
    finally:
        reset_settings_cache()


def _seed_scan(*, project_id: int | None = None) -> tuple[int, int]:
    """One finished scan with one analysed finding; returns ``(scan_id, finding_id)``."""
    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            target = Target(name="target.example", scope_json={"allowed_hosts": ["target.example"]})
            session.add(target)
            if project_id is not None:
                # The scan's project is a real foreign key: the export joins through it.
                session.add(Project(id=project_id, slug=f"tenant-{project_id}", name="Tenant"))
            session.commit()
            target_id = int(target.id)
        scans = SqlScanStateStore(factory)
        scan = scans.create_scan(
            target_id=target_id,
            engine="ai",
            project_id=project_id,
            plan={
                "target_name": "target.example",
                "engine": "ai",
                "checks": [
                    {
                        "module": "M4",
                        "name": "env-file-probe",
                        "version": "1.0",
                        "title": "Exposed environment file",
                        "included": True,
                    }
                ],
            },
        )
        scans.update_scan(scan.id, status=None, mark_started=True)
        asset = scans.add_asset(scan.id, kind="url", value="https://target.example/.env", meta={})
        findings = SqlFindingStore(factory)
        ids = findings.record_checks(
            [
                metadata
                for group in ModuleRegistry.discover().groups
                for metadata in group.metadata()
                if metadata.id == "m4.env-file-probe"
            ]
        )
        candidate = findings.record_candidate(
            scan.id,
            result=CheckResult(
                status="vulnerable",
                title="Sensitive environment file exposed",
                detail="returned 200",
                cwe="CWE-200",
                confidence=0.9,
                check="m4.env-file-probe",
                module="M4",
                evidence=(
                    Evidence.of("http_response", {"status_code": 200, "body": "DB_PASSWORD=[R]"}),
                ),
            ),
            check_id=ids["M4/env-file-probe@1.0"],
            asset_id=asset.id,
            asset=("url", "https://target.example/.env"),
        )
        SqlAnalysisStore(factory).apply(
            scan.id, [replace(_ai_analysis(), finding_id=candidate.id)], engine="ai"
        )
        scans.update_scan(scan.id, status=None, mark_finished=True)
        return int(scan.id), int(candidate.id)
    finally:
        engine.dispose()


def test_the_sql_column_persists_and_the_export_reads_it(cli_db: str) -> None:
    """End to end through the real column: write an AI row, read it back per scan and project."""
    from arachne.data.models import AnalysisLog

    scan_id, _finding_id = _seed_scan(project_id=None)
    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    store = SqlAnalysisStore(factory)
    try:
        per_scan = store.provenance_for_scan(scan_id)
        assert len(per_scan) == 1
        assert per_scan[0]["origin"] == AI_ORIGIN
        assert per_scan[0]["evidence_ids"] == ["12", "13"]
        assert summarize_provenance(per_scan)["providers"]["ollama"]["total_tokens"] == 160

        with factory() as session:
            row = session.scalars(select(AnalysisLog)).one()
            assert row.provenance is not None
            assert row.provenance["origin"] == AI_ORIGIN
            # The token column now carries what the *row* cost, not a hard zero.
            assert row.tokens_used == 160

        # The implicit default project owns a scan with no project_id; another project does not.
        assert len(store.provenance_for_project(None)) == 1
        assert store.provenance_for_project(4242) == ()
    finally:
        engine.dispose()


def test_a_row_that_claims_ai_without_a_citation_is_persisted_as_heuristic(cli_db: str) -> None:
    """The boundary that keeps a foreign payload from smuggling in an unverifiable claim."""
    from arachne.data.models import AnalysisLog

    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    try:
        scan_id, finding_id = _seed_scan()
        broken = replace(
            _ai_analysis(),
            finding_id=finding_id,
            ai={"provenance": {"origin": AI_ORIGIN, "provider": "ollama", "evidence_ids": []}},
        )
        SqlAnalysisStore(factory).apply(scan_id, [broken], engine="ai")
        with factory() as session:
            rows = session.scalars(select(AnalysisLog).order_by(AnalysisLog.id)).all()
            assert rows[-1].provenance is not None
            assert rows[-1].provenance["origin"] == HEURISTIC_ORIGIN
            assert rows[-1].provenance["fallback"] == "provenance_invalid"
            assert rows[-1].engine == "heuristic"
    finally:
        engine.dispose()


def test_the_cli_exports_provenance_per_scan_and_per_project(cli_db: str) -> None:
    scan_id, _finding_id = _seed_scan(project_id=1)
    result = runner.invoke(app, ["ai", "provenance", "--scan", str(scan_id)])
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["document"] == "arachne-ai-provenance"
    assert document["scope"] == {"kind": "scan", "scan_id": scan_id}
    assert document["providers"]["ollama"]["total_tokens"] == 160
    assert document["uncited_ai_rows"] == 0
    assert document["origins"] == {AI_ORIGIN: 1}

    per_project = runner.invoke(app, ["ai", "provenance", "--project", "1"])
    assert per_project.exit_code == 0, per_project.output
    project_document = json.loads(per_project.output)
    assert project_document["scope"] == {"kind": "project", "project_id": 1}
    assert project_document["rows"] == 1

    table = runner.invoke(app, ["ai", "provenance", "--scan", str(scan_id), "--table"])
    assert table.exit_code == 0
    assert "ollama" in table.output and "160" in table.output


def test_the_cli_refuses_both_or_neither_scope(cli_db: str) -> None:
    neither = runner.invoke(app, ["ai", "provenance"])
    assert neither.exit_code != 0
    both = runner.invoke(app, ["ai", "provenance", "--scan", "1", "--project", "1"])
    assert both.exit_code != 0
    missing = runner.invoke(app, ["ai", "provenance", "--scan", "9999"])
    assert missing.exit_code != 0


def test_the_compliance_export_carries_the_ai_token_attribution(cli_db: str) -> None:
    """REQ-AGENT-008's export clause: ``arachne compliance export`` answers the governance
    question — which provider received how many tokens for this scan — inside the document an
    auditor already reads."""
    scan_id, _finding_id = _seed_scan(project_id=None)
    result = runner.invoke(
        app, ["compliance", "export", "--scan", str(scan_id), "--framework", "iso27001"]
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["document"] == "arachne-control-evidence"
    block = document["ai"]
    assert block is not None, "the export must carry the AI-governance block"
    assert block["scope"] == {"kind": "scan", "scan_id": scan_id}
    assert block["providers"]["ollama"]["total_tokens"] == 160
    assert block["providers"]["ollama"]["rows"] == 1
    assert block["uncited_ai_rows"] == 0
    # The block carries ids, hashes and counts only — never a payload the report did not have.
    assert "payload" not in json.dumps(block)
