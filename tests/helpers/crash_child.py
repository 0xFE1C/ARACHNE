"""Child process for the hard-kill test: start a scan, then SIGKILL ourselves mid-step.

Run as ``python -m tests.helpers.crash_child`` from ``code/``. Reads three environment
variables:

``ARACHNE_CRASH_DB``
    SQLite file to use (already migrated by the parent).
``ARACHNE_CRASH_MARKER``
    File the handlers append to, so the parent can tell which steps ran.
``ARACHNE_CRASH_STEP``
    Step to kill inside (default ``discovery``, the second step).

Exits with the SIGKILL status (137) — the parent asserts on that.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from arachne.core.planner import ScanStep
from tests.helpers.scan_harness import Harness


def main() -> int:
    db_path = Path(os.environ["ARACHNE_CRASH_DB"])
    marker = Path(os.environ["ARACHNE_CRASH_MARKER"])
    crash_step = ScanStep(os.environ.get("ARACHNE_CRASH_STEP", ScanStep.DISCOVERY.value))

    harness = Harness(db_path, marker)
    try:
        orchestrator = harness.orchestrator(crash_after=crash_step)
        asyncio.run(orchestrator.scan(harness.load_request()))
    finally:
        harness.close()
    return 0  # pragma: no cover - the process is killed before this is reached


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
