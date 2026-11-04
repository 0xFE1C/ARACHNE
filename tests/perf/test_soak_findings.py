"""The finding/evidence soak (REQ-SCALE-010, G6 clause 4).

**What is being proven.** The scan path writes one finding at a time — a check produces its
results, they are persisted, and the next check runs — so the process never has to hold a
whole scan's findings in memory. What makes that true is that
:meth:`SqlFindingStore.record_candidate` opens its own session and transaction per finding:
the SQLAlchemy identity map is discarded with the session, so nothing accumulates. This test
drives the real store through 1,000, 10,000 and 100,000 findings and asserts

* every size completes with the store holding exactly that many findings (nothing is lost),
* the resident set never rises more than :data:`WRITE_PATH_CEILING` above its pre-loop
  baseline at any size, and
* growing the finding count 100-fold adds less than :data:`SUB_LINEAR_SLACK` of resident
  memory — a constant, not a curve.

The last assertion is the one that matters. If the store ever batched a scan's findings in
memory before writing (or kept references across calls), the largest size would move RSS in
proportion to the finding count and both bounds would fail.

**Why RSS and not ``tracemalloc``.** The question is "does the process hold the findings?",
and resident set is the honest answer for that — it includes the ORM's and the driver's own
C-level buffers, which allocation tracing cannot see. It is also cheap enough to sample
during a 100k loop, where per-allocation tracing tripled the run and made the test unusable.

**Cost.** The store's write path is deliberately durable (per-finding transaction, plus the
verification record): about 2.5 ms per finding in this fixture, which is ~280 s for the three
sizes together (the 100k pass alone is ~252 s). The whole module is therefore marked ``perf``
and excluded from the default suite, the database for a measured size is deleted before the
next one is written (they are hundreds of megabytes each, and ``tmp_path`` is memory-backed
here), and the run prints its numbers rather than only asserting them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.results import CheckResult, Evidence
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Asset, Check, Finding, Scan, Target

#: The three sizes the growth assertion is made over.
SIZES = (1_000, 10_000, 100_000)

#: The documented ceiling for the streaming write path: peak resident memory may exceed the
#: pre-loop baseline by at most this, at any finding count. The store holds one finding's
#: evidence and one identity map at a time; everything else it allocates is fixed.
WRITE_PATH_CEILING = 64 * 1024 * 1024

#: Growing the finding count 100-fold may add at most this much resident memory. A path that
#: accumulated findings would add hundreds of megabytes at 100k.
SUB_LINEAR_SLACK = 32 * 1024 * 1024

#: How often to sample RSS during the loop. Every 500 findings is 200 samples at the largest
#: size — enough to catch a ramp, cheap enough to be invisible against 2 ms writes.
SAMPLE_EVERY = 500


def _result(number: int) -> CheckResult:
    return CheckResult(
        status="vulnerable",
        title=f"soak finding {number}",
        detail=f"GET /soak/{number} returned 200",
        cwe="CWE-200",
        confidence=0.7,
        evidence=(
            Evidence.of("http_request", {"method": "GET", "url": f"https://example.com/{number}"}),
            Evidence.of("http_response", {"status_code": 200, "body": "ok"}),
            Evidence.of("note", {"detail": f"soak {number}"}),
        ),
        check="M3/xss-oracle@1.0",
        module="M3",
    )


def rss_kb() -> int:
    """Resident set size of this process, in KiB (``0`` where ``/proc`` is unavailable)."""
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:  # pragma: no cover - non-Linux
        return 0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0  # pragma: no cover - /proc without VmRSS


def _fixture(tmp_path: Path, name: str) -> tuple[Engine, sessionmaker[Session], int, int, int]:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / name}")
    create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        target = Target(name="soak", scope_json={})
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, status="completed", plan_json={}, engine="heuristic")
        session.add(scan)
        session.flush()
        check = Check(module="M3", name="xss-oracle", version="1.0")
        asset = Asset(scan_id=scan.id, kind="url", value="https://example.com/soak", meta_json={})
        session.add_all([check, asset])
        session.commit()
        return engine, factory, int(scan.id), int(check.id), int(asset.id)


def _remove_database(path: Path) -> None:
    """Drop one size's database and its WAL sidecars as soon as it has been measured.

    The 100k database is hundreds of megabytes, and ``tmp_path`` is on ``/tmp`` — a
    memory-backed filesystem on the reference machine. Leaving all three databases behind
    while the largest one is written is what turns a 250 s soak into a writeback stall; the
    peak-memory number is already taken, so the file is no longer needed.
    """
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


def _soak(tmp_path: Path, count: int) -> tuple[int, int, int]:
    """Write ``count`` findings through the store.

    Returns ``(baseline_rss_kb, peak_rss_kb, rows_stored)``. The baseline is sampled after
    the fixture is built and before the first write, so it captures the cost of everything
    the test set up rather than of the write path under test. The database is removed before
    returning: only the measurement is kept.
    """
    database = tmp_path / f"soak-{count}.db"
    engine, factory, scan_id, check_id, asset_id = _fixture(tmp_path, database.name)
    store = SqlFindingStore(factory)
    baseline = rss_kb()
    peak = baseline
    try:
        for number in range(count):
            store.record_candidate(
                scan_id, result=_result(number), check_id=check_id, asset_id=asset_id
            )
            if number % SAMPLE_EVERY == 0:
                peak = max(peak, rss_kb())
        peak = max(peak, rss_kb())
        stored = store.count_candidates(scan_id)
    finally:
        engine.dispose()
        _remove_database(database)
    return baseline, peak, stored


@pytest.mark.perf
# 1,500 s: the measured run is about 280 s (1,000 findings ~2 s, 10,000 ~24 s, 100,000
# ~252 s), but this is the one test whose cost scales with a fixture rather than with code,
# and a ``/tmp`` that is already full made it exceed 900 s once. It is the explicit,
# reviewed timeout REQ-QUAL-012 allows for a genuinely slower test.
@pytest.mark.timeout(1500)
def test_a_100k_finding_soak_stays_within_the_ceiling_and_grows_sub_linearly(
    tmp_path: Path,
) -> None:
    if rss_kb() == 0:  # pragma: no cover - non-Linux runners
        pytest.skip("resident-set measurement needs /proc/self/status")

    peaks: dict[int, int] = {}
    for size in SIZES:
        baseline, peak, stored = _soak(tmp_path, size)
        assert stored == size, f"the store kept {stored} of {size} findings"
        growth = peak - baseline
        assert growth < WRITE_PATH_CEILING, (
            f"{size} findings grew RSS by {growth / 1024 / 1024:.1f} MiB over the "
            f"{WRITE_PATH_CEILING // 1024 // 1024} MiB ceiling"
        )
        peaks[size] = peak

    smallest, largest = SIZES[0], SIZES[-1]
    extra = peaks[largest] - peaks[smallest]
    print(
        "\nPERF soak: "
        + ", ".join(f"{size} findings -> peak RSS {peaks[size] / 1024:.0f} MiB" for size in SIZES)
        + f"; 100x the findings added {extra / 1024 / 1024:.1f} MiB"
    )
    assert extra < SUB_LINEAR_SLACK, (
        f"{largest} findings used {extra / 1024 / 1024:.1f} MiB more resident memory than "
        f"{smallest}: the write path is holding findings in memory"
    )


@pytest.mark.perf
@pytest.mark.timeout(120)
def test_a_failure_mid_stream_leaves_a_resumable_store(tmp_path: Path) -> None:
    """A finding that cannot be persisted rolls back alone; the earlier ones stay readable.

    ``record_candidate`` commits each finding in its own transaction, so a failure part-way
    through a scan leaves every completed finding committed and the store immediately usable
    again — a resumable state, not a half-written one. The failing finding here is a result
    whose evidence payload is not JSON-serializable, which fails at the column's serializer
    and propagates out of the store's session block.
    """
    engine, factory, scan_id, check_id, asset_id = _fixture(tmp_path, "resumable.db")
    try:
        store = SqlFindingStore(factory)
        for number in range(3):
            store.record_candidate(
                scan_id, result=_result(number), check_id=check_id, asset_id=asset_id
            )
        with factory() as session:
            assert len(session.scalars(select(Finding)).all()) == 3

        broken = _result(99)
        broken.evidence[1].payload["captured_at"] = datetime.now(UTC)  # not JSON-serializable
        # SQLAlchemy wraps the serializer's TypeError in a StatementError at flush time.
        with pytest.raises(StatementError):
            store.record_candidate(scan_id, result=broken, check_id=check_id, asset_id=asset_id)

        # The three committed findings survive, the failed one is absent, and the store is
        # still writable: the next finding persists normally.
        assert store.count_candidates(scan_id) == 3
        store.record_candidate(scan_id, result=_result(4), check_id=check_id, asset_id=asset_id)
        assert store.count_candidates(scan_id) == 4
        records = store.list_candidates(scan_id)
        assert [record.title for record in records] == [f"soak finding {n}" for n in (0, 1, 2, 4)]
    finally:
        engine.dispose()
