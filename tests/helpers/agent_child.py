"""Child process for the agent-kill test (S16): lease a scan, then SIGKILL mid-step.

Run as ``python -m tests.helpers.agent_child`` from ``code/``. Reads four environment
variables (``tests/integration/test_distributed.py`` is the parent):

``ARACHNE_AGENT_DB``
    SQLite file the fleet shares (already created by the parent, scan enqueued).
``ARACHNE_AGENT_MARKER``
    File the step handlers append to, so the parent can tell which steps ran.
``ARACHNE_AGENT_STEP``
    Step to kill inside (default ``discovery``).
``ARACHNE_AGENT_NAME``
    The agent's fleet name (the lease and the audit trail carry it).

The child registers against the *in-process* control plane (a direct
:class:`~arachne.agent.service.AgentService` over the shared store — a remote agent uses
the same loop over HTTP), leases with a short TTL, and executes the scan through the real
orchestrator. The SIGKILL is a genuine hard kill: no unwinding, no ack, no cleanup —
whatever is in the database is what a killed agent leaves behind. The abandoned lease
expires and the scan becomes re-leasable (REQ-SCALE-003).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from arachne.agent.control import DirectControlPlane
from arachne.agent.runner import AgentLoop, build_executor
from arachne.agent.service import AgentService
from arachne.core.planner import ScanStep
from tests.helpers.scan_harness import make_handlers


def main() -> int:
    from tests.helpers.distributed import build_stack, distributed_settings

    db_path = Path(os.environ["ARACHNE_AGENT_DB"])
    marker = Path(os.environ["ARACHNE_AGENT_MARKER"])
    crash_step = ScanStep(os.environ.get("ARACHNE_AGENT_STEP", ScanStep.DISCOVERY.value))
    name = os.environ.get("ARACHNE_AGENT_NAME", "agent-doomed")

    settings = distributed_settings(db_path)
    stack = build_stack(db_path, settings=settings)
    try:
        service = AgentService(stack.services, settings=settings)
        loop = AgentLoop(
            DirectControlPlane(service, principal="child"),
            name=name,
            executor=build_executor(
                stack.services,
                name=name,
                handlers=make_handlers(marker, crash_after=crash_step),
            ),
            concurrency=1,
            lease_ttl_s=1.0,
        )
        asyncio.run(loop.run_until_drained())
    finally:
        stack.services.close()
    return 0  # pragma: no cover - the process is killed before this is reached


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
