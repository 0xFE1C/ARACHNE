"""``arachne agent`` — run one worker of the scan fleet (S16, area SCALE).

The agent is the distributed counterpart of ``arachne serve``'s in-process runner: it
registers with the deployment, leases queued scans (one at a time by default,
``--concurrency`` at most), executes them through the real orchestrator — every safety
gate evaluated on this node — heartbeats the lease while a scan runs, and acks
completion. An agent authenticates with an existing API key (a scanner-role key) when it
talks to a remote deployment; against a local store it uses the in-process control plane
directly. Either way its identity lands in the audit trail.

    arachne agent --name fleet-1 --api-url https://arachne.internal --api-key <key>
    arachne agent --once            # drain the queue and exit (cron/systemd friendly)
"""

from __future__ import annotations

import asyncio
import socket
from typing import Annotated

import typer

from arachne import __version__
from arachne.core.config import get_settings
from arachne.core.logging import get_logger

__all__ = ["agent_command"]

_logger = get_logger("cli.agent")


def agent_command(
    name: Annotated[
        str | None,
        typer.Option("--name", help="The agent's fleet name (default ARACHNE_AGENT_NAME)."),
    ] = None,
    api_url: Annotated[
        str | None,
        typer.Option("--api-url", help="The deployment's base URL (default ARACHNE_API_URL)."),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key", help="API key for --api-url (default ARACHNE_API_KEY); scanner role."
        ),
    ] = None,
    concurrency: Annotated[
        int | None,
        typer.Option("--concurrency", help="Per-agent scan cap (default 1 — one at a time)."),
    ] = None,
    once: Annotated[
        bool, typer.Option("--once", help="Drain the queue and exit instead of looping.")
    ] = False,
    max_scans: Annotated[
        int | None, typer.Option("--max-scans", help="With --once: leave after N scans.")
    ] = None,
) -> None:
    """Run an ``arachne agent`` worker: register, lease, execute, heartbeat, ack."""
    settings = get_settings()
    distributed = settings.distributed
    agent_name = name or distributed.agent_name or f"agent-{socket.gethostname()}"
    effective_url = api_url or distributed.api_url
    import os

    from arachne.agent.control import ControlPlane, DirectControlPlane, HttpControlPlane
    from arachne.agent.runner import AgentLoop, build_executor
    from arachne.agent.service import AgentService
    from arachne.data.services import build_services

    effective_key = api_key or os.environ.get("ARACHNE_API_KEY") or None
    if effective_url and not effective_key:
        raise typer.BadParameter(
            "an agent talking to a remote deployment needs an API key "
            "(--api-key or ARACHNE_API_KEY)"
        )
    if not effective_url and not settings.distributed.enabled:
        typer.echo(
            "note: ARACHNE_DISTRIBUTED is not enabled — producers (API, scheduler) will "
            "keep running scans in-process until it is set",
            err=True,
        )

    services = build_services(settings)
    control: ControlPlane
    try:
        if effective_url and effective_key:
            control = HttpControlPlane(effective_url, effective_key, settings=settings)
            typer.echo(f"agent {agent_name} -> {effective_url}")
        else:
            from arachne.core.errors import ScanStateError

            try:
                control = DirectControlPlane(
                    AgentService(services, settings=settings), principal="cli"
                )
            except ScanStateError as exc:
                # The store predates S16 (no queue tables): tell the operator what to do.
                raise typer.BadParameter(str(exc)) from exc
        loop = AgentLoop(
            control,
            name=agent_name,
            executor=build_executor(services, name=agent_name),
            concurrency=concurrency if concurrency is not None else distributed.concurrency,
            lease_ttl_s=float(distributed.lease_ttl_s),
            heartbeat_interval_s=distributed.heartbeat_interval_s,
            poll_interval_s=distributed.poll_interval_s,
        )
        if once:
            executed = asyncio.run(loop.run_until_drained(max_scans=max_scans))
            typer.echo(f"agent {agent_name}: drained {executed} scan(s); queue is empty")
        else:
            typer.echo(f"ARACHNE {__version__} agent {agent_name} starting (Ctrl-C to stop)")
            asyncio.run(loop.run_forever())
    except KeyboardInterrupt:
        typer.echo(f"agent {agent_name}: stopped; unacked leases will expire and re-queue")
    finally:
        services.close()


if __name__ == "__main__":  # pragma: no cover - manual invocation
    agent_command()
