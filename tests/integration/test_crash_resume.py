"""Acceptance: a crashed scan resumes from its last completed step (F-01-04).

Three levels, each stricter than the last:

1. **In-process**: a handler raises; the failure is recorded as data, and a resume
   re-runs only the failed step.
2. **Restart from disk**: every in-memory object is discarded and rebuilt over the same
   SQLite file — which is all a process restart preserves.
3. **Hard kill**: a *child process* runs a scan and ``SIGKILL``s itself mid-step. The
   parent then inspects the database (the step is still ``running``), rebuilds the stack,
   and resumes: the completed step is not repeated and the scan finishes.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text
from tests.helpers.scan_harness import Harness

from arachne.core.errors import ScanStateError
from arachne.core.lifecycle import ScanStatus, StepStatus
from arachne.core.planner import ScanStep
from arachne.data.db import create_all, create_sqlite_engine

CODE_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    """A fresh, migrated SQLite file plus its marker file."""
    db_path = tmp_path / "crash.db"
    engine = create_sqlite_engine(f"sqlite:///{db_path}")
    create_all(engine)
    engine.dispose()
    return Harness(db_path, tmp_path / "marker.txt")


# ------------------------------------------------------------------ 1. in-process
async def test_a_failing_step_is_recorded_and_resuming_continues_after_it(
    harness: Harness,
) -> None:
    orchestrator = harness.orchestrator()
    request = harness.load_request()

    # The harness handlers never fail; replace the discovery one with a raising handler
    # so the scan dies in the middle of the pipeline.
    async def failing(context: object) -> object:
        msg = "simulated interruption"
        raise ScanStateError(msg)

    orchestrator.handlers = {**orchestrator.handlers, ScanStep.DISCOVERY: failing}  # type: ignore[arg-type]
    with pytest.raises(ScanStateError):
        await orchestrator.scan(request)

    record = orchestrator.store.list_scans()[0]
    assert record.status is ScanStatus.FAILED
    discovery = record.step_state(ScanStep.DISCOVERY)
    assert discovery is not None and discovery.status is StepStatus.FAILED
    assert "simulated interruption" in (discovery.error or "")
    assert record.next_step() is ScanStep.DISCOVERY
    assert harness.marker_lines() == ["recon"]  # the failing step never got to run

    # Resume with the healthy handler set: recon is skipped, everything from discovery on
    # runs. The completed step is not repeated — that is the whole point of F-01-04.
    resumed = harness.orchestrator()
    session = await resumed.resume(record.id, request)

    assert session.status is ScanStatus.COMPLETED
    assert session.outcome is not None
    assert session.outcome.already_completed == (ScanStep.RECON,)
    assert session.outcome.resumed is True
    lines = harness.marker_lines()
    assert lines == [
        "recon",
        "discovery",
        "checks",
        "analysis",
        "correlation",
        "reporting",
    ]
    assert lines.count("recon") == 1


# ------------------------------------------------------------ 2. restart from disk
async def test_a_restart_rebuilds_state_from_the_database(harness: Harness) -> None:
    request = harness.load_request()
    orchestrator = harness.orchestrator()
    session = await orchestrator.scan(request)
    assert session.scan_id is not None
    harness.close()  # everything in memory is gone

    restarted = Harness(harness.db_path, harness.marker)
    try:
        loaded = restarted.store.get_scan(session.scan_id)
        assert loaded is not None
        assert loaded.status is ScanStatus.COMPLETED
        assert loaded.next_step() is None
        assert [state.step for state in loaded.steps] == [
            ScanStep.RECON,
            ScanStep.DISCOVERY,
            ScanStep.CHECKS,
            ScanStep.ANALYSIS,
            ScanStep.CORRELATION,
            ScanStep.REPORTING,
        ]
        before = restarted.marker_lines()

        resumed = await restarted.orchestrator().resume(session.scan_id, request)

        assert resumed.status is ScanStatus.COMPLETED
        assert restarted.marker_lines() == before, "a completed scan re-ran a step on resume"
    finally:
        restarted.close()


# ----------------------------------------------------------------------- 3. hard kill
def test_hard_kill_mid_scan_then_resume_continues_from_the_last_completed_step(
    harness: Harness, tmp_path: Path
) -> None:
    environment = {
        "ARACHNE_CRASH_DB": str(harness.db_path),
        "ARACHNE_CRASH_MARKER": str(harness.marker),
        "ARACHNE_CRASH_STEP": ScanStep.DISCOVERY.value,
        "PATH": "/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "tests.helpers.crash_child"],
        cwd=CODE_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == -9, (  # SIGKILL
        f"expected the child to be killed, got {completed.returncode}: "
        f"{completed.stdout}{completed.stderr}"
    )
    assert harness.marker_lines() == ["recon", "discovery"]

    # What the crash left in the database: recon finished, discovery was in flight.
    restarted = Harness(harness.db_path, harness.marker)
    try:
        record = restarted.store.list_scans()[0]
        assert record.status is ScanStatus.RUNNING

        recon = record.step_state(ScanStep.RECON)
        discovery = record.step_state(ScanStep.DISCOVERY)
        assert recon is not None and recon.status is StepStatus.COMPLETED
        assert discovery is not None and discovery.status is StepStatus.RUNNING
        assert discovery.attempts == 1
        assert discovery.finished_at is None
        assert record.next_step() is ScanStep.DISCOVERY

        session = asyncio.run(restarted.orchestrator().resume(record.id, restarted.load_request()))

        assert session.status is ScanStatus.COMPLETED
        assert session.outcome is not None
        assert session.outcome.resumed is True
        assert session.outcome.already_completed == (ScanStep.RECON,)
    finally:
        restarted.close()

    # recon ran exactly once; discovery ran once before the kill and once on the resume.
    lines = harness.marker_lines()
    assert lines.count("recon") == 1
    assert lines.count("discovery") == 2
    assert lines[:3] == ["recon", "discovery", "discovery"]

    # The resumed run finished the whole pipeline exactly once after the crash.
    engine = create_sqlite_engine(f"sqlite:///{harness.db_path}")
    try:
        with engine.connect() as connection:
            steps = connection.execute(
                text("SELECT step, status, attempts FROM scan_steps ORDER BY id")
            ).all()
            status = connection.execute(text("SELECT status FROM scans")).one()[0]
    finally:
        engine.dispose()
    assert status == "completed"
    attempts = {row[0]: row[2] for row in steps}
    assert attempts["recon"] == 1
    assert attempts["discovery"] == 2
    assert all(row[1] == "completed" for row in steps)
