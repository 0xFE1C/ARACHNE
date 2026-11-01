"""A scanner wired for the crash/resume test, with a handler that can hard-kill itself.

Shared by the parent test and the child process it kills, so both sides run *identical*
code: only the handlers' ``crash_after`` setting differs. Nothing here is pytest-specific
— the child is a plain script (``crash_child.py``) so the kill is a real ``SIGKILL`` to a
real process, not a simulated exception.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import Auditor
from arachne.core.config import Settings
from arachne.core.events import EventBus
from arachne.core.lifecycle import StepContext, StepHandler, StepOutcome
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.target import ScanRequest, load_scan_request
from arachne.data.audit_sink import SqlAuditSink
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.target_store import SqlTargetStore

#: Steps this harness gives a handler to, so the crash test can reach *any* step. The
#: production handler set is much smaller (``arachne.core.steps.default_handlers``).
CRASH_TEST_STEPS: tuple[ScanStep, ...] = (
    ScanStep.RECON,
    ScanStep.DISCOVERY,
    ScanStep.CHECKS,
    ScanStep.ANALYSIS,
    ScanStep.CORRELATION,
    ScanStep.REPORTING,
)

DEFAULT_FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "targets" / "lab-fixture.yaml"


def append_marker(path: Path, line: str) -> None:
    """Append ``line`` and force it to disk, so a kill cannot lose it."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")
        handle.flush()
        os.fsync(handle.fileno())


def make_handlers(
    marker: Path,
    *,
    crash_after: ScanStep | None = None,
    steps: Iterable[ScanStep] = CRASH_TEST_STEPS,
) -> dict[ScanStep, StepHandler]:
    """Handlers that record which step ran, and SIGKILL the process at ``crash_after``."""

    def build(step: ScanStep) -> StepHandler:
        async def handler(context: StepContext) -> StepOutcome:
            append_marker(marker, step.value)
            if crash_after is step:
                # A genuine hard kill: no unwinding, no finally blocks, no flush by the
                # interpreter. Whatever is in the database is what a real crash would leave.
                os.kill(os.getpid(), signal.SIGKILL)
            return StepOutcome(stats={"step": step.value})

        return handler

    return {step: build(step) for step in steps}


class Harness:
    """A scan stack over one SQLite file, rebuildable from scratch to model a restart."""

    def __init__(self, db_path: Path, marker: Path) -> None:
        self.db_path = db_path
        self.marker = marker
        self.settings = Settings(
            database_url=f"sqlite:///{db_path}",
            log_level="CRITICAL",
            log_json=False,
            actor="crash-test",
        )
        self.engine: Engine = create_db_engine(settings=self.settings)
        self.session_factory: sessionmaker[Session] = create_session_factory(self.engine)
        self.store = SqlScanStateStore(self.session_factory)
        self.target_store = SqlTargetStore(self.session_factory)
        self.bus = EventBus()
        self.auditor = Auditor(SqlAuditSink(self.session_factory), actor="crash-test")

    def orchestrator(self, *, crash_after: ScanStep | None = None) -> Orchestrator:
        return Orchestrator(
            settings=self.settings,
            store=self.store,
            target_store=self.target_store,
            auditor=self.auditor,
            bus=self.bus,
            handlers=make_handlers(self.marker, crash_after=crash_after),
        )

    def close(self) -> None:
        self.engine.dispose()

    def load_request(self, fixture: Path = DEFAULT_FIXTURE) -> ScanRequest:
        return load_scan_request(fixture)

    def marker_lines(self) -> list[str]:
        if not self.marker.exists():
            return []
        return self.marker.read_text(encoding="utf-8").split()
