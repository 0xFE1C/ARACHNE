"""The hot-path query budget (REQ-SCALE-012, G6 clause 2).

The report, analysis, reasoning, posture, fix and benchmark paths all read a scan's
candidates and analyses. Before WP-17 that read was **3N+1**: one evidence query per
finding, a *fresh session* per finding for its asset identity, one query for its current
verification record and one for its history — plus one ``Finding`` lookup per analysis row.
Growing the scan grew the round-trip count linearly, which is why the report degraded
visibly on large scans.

Two things are pinned here, and both are facts about SQL that actually reached the database
rather than about this module's shape:

* the count is **constant** — a 100-finding scan issues exactly the same number of queries
  as a 10-finding scan; and
* that constant is at most :data:`HOT_PATH_QUERY_BUDGET`.

The counter is a SQLAlchemy ``before_cursor_execute`` listener on the engine, so a future
change that reintroduces an N+1 (a lazy relationship, a ``session.get`` in a loop, a second
session per row) fails here even if it looks clean.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session, sessionmaker

from arachne.analyzer.model import Analysis, Remediation, ScoreBreakdown
from arachne.core.results import CheckResult, Evidence
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Asset, Check, Scan, Target

#: The documented ceiling for one reading of a scan's findings **and** analyses, including
#: the finding rows, the analysis log rows and the ``IN`` lookups each needs. Five batched
#: queries for the candidates (findings, evidence, assets, checks, verifications), three for
#: the analyses (log rows, the findings they name, nothing else) — measured below at 8 for
#: both 10 and 100 findings, so the budget leaves exactly zero slack by design: raising it
#: means raising it in the operator guide as well (``docs/performance.md``).
HOT_PATH_QUERY_BUDGET = 8

#: The two sizes G6 names. The count must not move between them.
SMALL = 10
LARGE = 100


@contextmanager
def _count_queries(engine: Engine) -> Iterator[dict[str, int]]:
    """Count every statement the engine executes inside the block."""
    counter = {"queries": 0}

    def _before(
        _conn: object,
        _cursor: object,
        _statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        counter["queries"] += 1

    event.listen(engine, "before_cursor_execute", _before)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", _before)


def _candidate(number: int) -> CheckResult:
    return CheckResult(
        status="vulnerable",
        title=f"exposed endpoint {number}",
        detail=f"GET /path-{number} returned 200",
        cwe="CWE-200",
        confidence=0.7,
        evidence=(
            Evidence.of("http_request", {"method": "GET", "url": f"https://example.com/{number}"}),
            Evidence.of("http_response", {"status_code": 200, "body": "ok"}),
        ),
        check="M3/xss-oracle@1.0",
        module="M3",
    )


def _seed(tmp_path: Path, count: int) -> tuple[Engine, sessionmaker[Session], int]:
    """A scan with ``count`` findings, each with evidence, a record and an analysis."""
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / f'scan-{count}.db'}")
    create_all(engine)
    factory = create_session_factory(engine)
    store = SqlFindingStore(factory)

    with factory() as session:
        target = Target(name="perf", scope_json={})
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, status="completed", plan_json={}, engine="heuristic")
        session.add(scan)
        session.flush()
        scan_id = int(scan.id)
        check = Check(module="M3", name="xss-oracle", version="1.0")
        session.add(check)
        session.flush()
        check_id = int(check.id)
        asset_ids: list[int] = []
        for number in range(count):
            asset = Asset(
                scan_id=scan_id,
                kind="url",
                value=f"https://example.com/path-{number}",
                meta_json={},
            )
            session.add(asset)
            session.flush()
            asset_ids.append(int(asset.id))
        session.commit()

    finding_ids: list[int] = []
    for number in range(count):
        record = store.record_candidate(
            scan_id, result=_candidate(number), check_id=check_id, asset_id=asset_ids[number]
        )
        finding_ids.append(record.id)

    analyses = [
        Analysis(
            title=f"finding {number}",
            severity="high",
            confidence=88,
            narrative="confirmed",
            remediation=Remediation(id="env", summary="fix it", steps=("1. fix",)),
            finding_id=finding_id,
            check_id="m3.xss-oracle",
            asset=f"url:https://example.com/path-{number}",
            cwe="CWE-200",
            verdict="analyzed",
            score=ScoreBreakdown(cvss_base=7.5, owasp_risk="high", confidence=88),
        )
        for number, finding_id in enumerate(finding_ids)
    ]
    SqlAnalysisStore(factory).apply(scan_id, analyses, engine="heuristic")
    return engine, factory, scan_id


def _measure(tmp_path: Path, count: int) -> tuple[int, int]:
    """``(candidate queries, analysis queries)`` for one scan of ``count`` findings."""
    engine, factory, scan_id = _seed(tmp_path, count)
    try:
        findings = SqlFindingStore(factory)
        analyses = SqlAnalysisStore(factory)
        with _count_queries(engine) as counter:
            records = findings.list_candidates(scan_id)
        assert len(records) == count, "the fixture must really contain the findings it claims"
        candidate_queries = counter["queries"]
        with _count_queries(engine) as counter:
            rows = analyses.list_analyses(scan_id)
        assert len(rows) == count
        return candidate_queries, counter["queries"]
    finally:
        engine.dispose()


def test_the_candidate_and_analysis_query_count_does_not_grow_with_the_scan(
    tmp_path: Path,
) -> None:
    small = _measure(tmp_path, SMALL)
    large = _measure(tmp_path, LARGE)

    assert large == small, (
        "the hot-path query count grew with the finding count "
        f"({SMALL}: {small}, {LARGE}: {large}) — an N+1 is back"
    )
    assert sum(large) <= HOT_PATH_QUERY_BUDGET, (
        f"a {LARGE}-finding report+analysis read needs {sum(large)} queries, over the "
        f"documented budget of {HOT_PATH_QUERY_BUDGET}"
    )


def test_the_query_budget_is_really_independent_of_findings(tmp_path: Path) -> None:
    """A single-finding scan costs the same as a large one (the batch is fixed-size)."""
    one = _measure(tmp_path, 1)
    large = _measure(tmp_path, LARGE)
    assert one == large


@pytest.mark.parametrize("count", [SMALL, LARGE])
def test_an_empty_scan_is_cheaper_but_bounded(tmp_path: Path, count: int) -> None:
    """No findings means no batched ``IN`` queries — and still never more than the budget."""
    engine, factory, scan_id = _seed(tmp_path, count)
    try:
        with _count_queries(engine) as counter:
            assert SqlFindingStore(factory).list_candidates(scan_id + 1) == ()
        assert counter["queries"] <= HOT_PATH_QUERY_BUDGET
    finally:
        engine.dispose()
