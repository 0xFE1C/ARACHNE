"""Analysis persistence and FP feedback (F-03-05, F-05-07).

What must hold: an analysis updates the finding row (severity, confidence, remediation,
status), the whole analysis lands in ``analysis_log.output_json``, a compound finding gets
its own row, and the feedback table aggregates per key.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.analyzer.fp import FeedbackRecord, feedback_key
from arachne.analyzer.model import Analysis, Candidate, FpStats, Remediation, ScoreBreakdown
from arachne.data.analysis_store import (
    MemoryAnalysisStore,
    SqlAnalysisStore,
    analysis_from_log,
)
from arachne.data.db import create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import AnalysisLog, Asset, Check, Finding, FpFeedback, Scan, Target
from arachne.data.scan_store import as_utc


def analysis(
    *,
    finding_id: int | None,
    severity: str = "high",
    confidence: int = 88,
    verdict: str = "analyzed",
    verified: bool = False,
    contributors: tuple[int, ...] = (),
    merged_evidence: tuple[int, ...] = (),
) -> Analysis:
    return Analysis(
        title="Sensitive environment file exposed",
        severity=severity,
        confidence=confidence,
        narrative="The file returned HTTP 200 and held credentials.",
        remediation=Remediation(id="env-file-exposure", summary="Block it.", steps=("1. deny",)),
        finding_id=finding_id,
        check_id="m4.env-file-probe",
        asset="url:https://example.com/.env",
        cwe="CWE-200",
        verdict=verdict,  # type: ignore[arg-type]
        verified=verified,
        score=ScoreBreakdown(cvss_base=7.5, owasp_risk="high", confidence=confidence),
        contributors=contributors,
        merged_evidence_refs=merged_evidence,
        correlated=bool(contributors),
    )


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine: Engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'analysis.db'}")
    from arachne.data.db import create_all

    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scan_id(factory: sessionmaker[Session]) -> int:
    with factory() as session:
        target = Target(name="t", scope_json={})
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, plan_json={})
        session.add(scan)
        session.flush()
        asset = Asset(scan_id=scan.id, kind="url", value="https://example.com/.env", meta_json={})
        session.add(asset)
        session.flush()
        check = Check(module="M4", name="env-file-probe", version="1.0")
        session.add(check)
        session.flush()
        finding = Finding(
            scan_id=scan.id,
            check_id=check.id,
            asset_id=asset.id,
            title="Sensitive environment file exposed",
            severity=None,
            confidence=80.0,
            status="open",
            evidence_refs_json=[1, 2],
        )
        session.add(finding)
        session.commit()
        return int(scan.id)


def test_applying_an_analysis_updates_the_finding_and_logs_it(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlAnalysisStore(factory)
    with factory() as session:
        finding_id = int(session.scalars(select(Finding)).one().id)

    stored = store.apply(
        scan_id, [analysis(finding_id=finding_id, verified=True)], engine="heuristic"
    )
    assert len(stored) == 1
    assert stored[0].finding_id == finding_id
    assert stored[0].status == "verified"
    assert stored[0].severity == "high"

    with factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        assert finding.severity == "high"
        assert finding.confidence == 88.0
        assert finding.status == "verified"
        assert finding.remediation_id == "env-file-exposure"
        log = session.scalars(select(AnalysisLog)).one()
        assert log.engine == "heuristic"
        assert log.output_json["narrative"].startswith("The file returned")
        assert log.output_json["score"]["cvss_base"] == 7.5


def test_a_dropped_analysis_marks_the_finding_false_positive(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlAnalysisStore(factory)
    with factory() as session:
        finding_id = int(session.scalars(select(Finding)).one().id)
    store.apply(
        scan_id,
        [analysis(finding_id=finding_id, verdict="dropped", confidence=20)],
        engine="heuristic",
    )
    with factory() as session:
        assert session.get(Finding, finding_id).status == "fp"  # type: ignore[union-attr]


def test_a_compound_finding_gets_its_own_row(factory: sessionmaker[Session], scan_id: int) -> None:
    store = SqlAnalysisStore(factory)
    compound = analysis(finding_id=None, contributors=(1,), merged_evidence=(11, 12))
    stored = store.create_compound(scan_id, compound, engine="heuristic")
    assert stored.finding_id is not None
    with factory() as session:
        finding = session.get(Finding, stored.finding_id)
        assert finding is not None
        assert finding.check_id is None
        assert finding.severity == "high"
        assert finding.evidence_refs_json == [11, 12]
        log = session.scalars(
            select(AnalysisLog).where(AnalysisLog.finding_id == stored.finding_id)
        ).one()
        assert log.output_json["correlated"] is True


def test_analyses_round_trip_through_the_log(factory: sessionmaker[Session], scan_id: int) -> None:
    store = SqlAnalysisStore(factory)
    with factory() as session:
        finding_id = int(session.scalars(select(Finding)).one().id)
    original = analysis(finding_id=finding_id, verified=True)
    store.apply(scan_id, [original], engine="heuristic")

    rows = store.list_analyses(scan_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.severity == "high"
    assert row.check_id == "m4.env-file-probe"
    assert row.narrative == original.narrative
    rebuilt = analysis_from_log(row)
    assert rebuilt is not None
    assert rebuilt.severity == original.severity
    assert rebuilt.confidence == original.confidence
    assert rebuilt.cwe == "CWE-200"
    assert rebuilt.remediation.id == "env-file-exposure"
    assert rebuilt.verdict == "analyzed"
    assert rebuilt.verified is True
    assert store.count_analyses(scan_id) == 1


def test_an_analysis_without_a_finding_is_logged_but_not_linked(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlAnalysisStore(factory)
    stored = store.apply(scan_id, [analysis(finding_id=None)], engine="heuristic")
    assert stored[0].finding_id is None
    with factory() as session:
        log = session.scalars(select(AnalysisLog)).one()
        assert log.finding_id is None


def test_feedback_is_aggregated_per_key(factory: sessionmaker[Session]) -> None:
    store = SqlAnalysisStore(factory)
    candidate = Candidate(scan_id=1, title="t", check_id="m4.env-file-probe", asset_kind="url")
    key = feedback_key(candidate)
    for is_fp in (True, True, False):
        store.record_feedback(FeedbackRecord(key=key, is_fp=is_fp), actor="pytest")
    store.record_feedback(FeedbackRecord(key="other|url|none", is_fp=True))
    stats = store.feedback_stats([key])
    assert stats == {key: FpStats(total=3, false_positives=2)}
    assert len(store.feedback_stats()) == 2
    with factory() as session:
        assert session.scalars(select(FpFeedback)).all()


def test_the_memory_store_mirrors_the_sql_behaviour() -> None:
    store = MemoryAnalysisStore()
    stored = store.apply(
        1, [analysis(finding_id=5), analysis(finding_id=6, verdict="dropped")], engine="heuristic"
    )
    assert [item.status for item in stored] == ["open", "fp"]
    assert len(store.list_analyses(1)) == 2
    compound = store.create_compound(
        1, analysis(finding_id=None, contributors=(5,)), engine="heuristic"
    )
    assert compound.finding_id is not None
    store.record_feedback(FeedbackRecord(key="k", is_fp=True))
    assert store.feedback_stats(["k"])["k"] == FpStats(total=1, false_positives=1)


def test_an_empty_log_row_does_not_rebuild(factory: sessionmaker[Session], scan_id: int) -> None:
    store = SqlAnalysisStore(factory)
    rows = store.list_analyses(scan_id)
    assert rows == ()
    _ = as_utc
    _ = SqlFindingStore
