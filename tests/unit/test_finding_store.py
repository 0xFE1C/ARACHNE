"""Candidate persistence: the ``checks``/``findings``/``evidences`` tables (F-02-08, F-09-02).

The store is where the "checks emit candidates, not severities" rule (ADR-02) becomes
observable: a persisted candidate has a title, confidence and evidence, and its ``severity``
is NULL until the analyzer runs. These tests also pin the two properties the report engine
(S8) will rely on: every candidate has at least one evidence row, and the check that produced
it is versioned in the ``checks`` table.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.results import CheckResult, Evidence
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import (
    MemoryFindingStore,
    SqlFindingStore,
    candidate_summary,
)
from arachne.data.models import Check, Finding, Scan, Target
from arachne.data.models import Evidence as EvidenceRow
from arachne.modules.registry import ModuleRegistry


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine: Engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'findings.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scan_id(factory: sessionmaker[Session]) -> int:
    """A scan row, because every finding references one."""
    with factory() as session:
        target = Target(name="fixture", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, status="running", plan_json={}, engine="heuristic")
        session.add(scan)
        session.commit()
        return int(scan.id)


def candidate(title: str = "exposed .env", **overrides: object) -> CheckResult:
    payload: dict[str, object] = {
        "status": "vulnerable",
        "title": title,
        "detail": "GET /.env returned 200 with 3 secret-looking pairs",
        "cwe": "CWE-200",
        "confidence": 0.7,
        "evidence": (
            Evidence.of("http_request", {"method": "GET", "url": "https://example.com/.env"}),
            Evidence.of("http_response", {"status_code": 200, "body": "AWS_KEY=[REDACTED]"}),
        ),
        "check": "M1/ct-lookup@1.0",
        "module": "M1",
    }
    payload.update(overrides)
    return CheckResult(**payload)  # type: ignore[arg-type]


# ------------------------------------------------------------------ memory store
def test_memory_store_versions_checks_and_counts_candidates() -> None:
    store = MemoryFindingStore()
    metadata = ModuleRegistry.builtin().metadata()
    ids = store.record_checks(metadata)
    assert len(ids) == len(metadata)
    assert len(set(ids.values())) == len(metadata), "every check gets its own row id"

    store.record_candidate(1, result=candidate(), check_id=1, asset_id=None)
    assert store.count_candidates(1) == 1
    assert store.count_candidates(2) == 0
    record = store.list_candidates(1)[0]
    assert record.severity is None and record.is_candidate
    assert record.evidence and record.evidence[0].kind == "http_request"


# ------------------------------------------------------------------ SQL store
def test_sql_store_persists_a_candidate_with_its_evidence(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlFindingStore(factory)
    ids = store.record_checks(ModuleRegistry.builtin().metadata())
    check_id = ids["M1/ct-lookup@1.0"]

    record = store.record_candidate(scan_id, result=candidate(), check_id=check_id, asset_id=None)
    assert record.id is not None
    assert record.severity is None, "the module layer must not score (ADR-02)"
    assert record.status == "open"
    # The check's 0-1 confidence is stored on the report's 0-100 scale (docs/spec/06- §2), so
    # the column means one thing whether or not the analyzer has run yet.
    assert record.confidence == 70
    # Two captured exchanges plus the provenance note: a candidate always carries evidence.
    kinds = [item.kind for item in record.evidence]
    assert kinds == ["http_request", "http_response", "note"]
    assert all(item.sha256 for item in record.evidence[:2])
    assert record.evidence[2].payload["detail"].startswith("GET /.env")

    with factory() as session:
        finding = session.scalars(select(Finding)).one()
        assert finding.severity is None
        assert finding.status == "open"
        assert finding.evidence_refs_json == [item.id for item in record.evidence]
        assert session.scalars(select(EvidenceRow)).all()


def test_sql_store_reports_the_check_that_produced_a_candidate(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlFindingStore(factory)
    ids = store.record_checks(ModuleRegistry.builtin().metadata())
    store.record_candidate(
        scan_id,
        result=candidate(),
        check_id=ids["M1/ct-lookup@1.0"],
        asset_id=None,
    )
    listed = store.list_candidates(scan_id)
    assert listed[0].check_key == "M1/ct-lookup@1.0"
    assert listed[0].module == "M1"
    assert listed[0].research_ref == "ch01#8"
    assert candidate_summary(listed) == {"M1": 1}


def test_sql_store_is_idempotent_about_check_rows(
    factory: sessionmaker[Session],
) -> None:
    """Re-running a scan must not duplicate the check catalogue (F-02-10)."""
    store = SqlFindingStore(factory)
    first = store.record_checks(ModuleRegistry.builtin().metadata())
    second = store.record_checks(ModuleRegistry.builtin().metadata())
    assert first == second
    with factory() as session:
        rows = session.scalars(select(Check)).all()
    assert len(rows) == len(first)
    assert {row.research_ref for row in rows} >= {"ch01#1", "ch01#8"}


def test_sql_store_keeps_candidates_of_different_scans_apart(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlFindingStore(factory)
    ids = store.record_checks(ModuleRegistry.builtin().metadata())
    with factory() as session:
        target = Target(name="second", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        other = Scan(target_id=target.id, status="running", plan_json={}, engine="heuristic")
        session.add(other)
        session.commit()
        other_id = int(other.id)

    store.record_candidate(
        scan_id, result=candidate("a"), check_id=ids["M1/ct-lookup@1.0"], asset_id=None
    )
    store.record_candidate(other_id, result=candidate("b"), check_id=None, asset_id=None)
    assert [r.title for r in store.list_candidates(scan_id)] == ["a"]
    assert [r.title for r in store.list_candidates(other_id)] == ["b"]
    assert store.count_candidates(scan_id) == 1


def test_sql_store_records_a_candidate_without_a_check_row(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    """A plugin check that is not in the registry must not break persistence."""
    store = SqlFindingStore(factory)
    record = store.record_candidate(scan_id, result=candidate(), check_id=None, asset_id=None)
    assert record.check_id is None
    listed = store.list_candidates(scan_id)[0]
    assert listed.check_key is None
    assert listed.evidence  # the note alone is still evidence


def test_candidate_titles_are_truncated_to_the_column_width(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    store = SqlFindingStore(factory)
    record = store.record_candidate(
        scan_id, result=candidate("x" * 900), check_id=None, asset_id=None
    )
    assert record.title is not None and len(record.title) == 512


def test_evidence_records_round_trip_as_dicts(factory: sessionmaker[Session], scan_id: int) -> None:
    store = SqlFindingStore(factory)
    record = store.record_candidate(scan_id, result=candidate(), check_id=None, asset_id=None)
    payload = record.to_dict()
    assert payload["status"] == "open"
    assert payload["severity"] is None
    first = payload["evidence"][0]
    assert isinstance(first["created_at"], str)
    datetime.fromisoformat(first["created_at"])  # timezone-aware ISO text (ADR-060.4)
