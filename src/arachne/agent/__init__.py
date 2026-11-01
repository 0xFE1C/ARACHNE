"""Distributed scan execution (S16, area SCALE).

Three pieces, deliberately kept apart:

* :mod:`arachne.agent.service` — the *control plane* the deployment exposes: register,
  heartbeat, lease, complete. The REST API mounts it under ``/api/v1/agent`` (every call
  authenticated by an existing API key as a scanner); the in-process control plane uses
  the same service directly.
* :mod:`arachne.agent.control` — the client side: a :class:`ControlPlane` protocol and
  its two implementations (HTTP for a remote agent, direct for an embedded one).
* :mod:`arachne.agent.runner` — the :class:`~arachne.agent.runner.AgentLoop`: lease
  within the concurrency cap, execute on the lifecycle state, heartbeat the lease,
  ack — and the default executor that rebuilds the admitted request and runs it through
  the orchestrator, with every safety gate re-evaluated on the executing node.
"""

from __future__ import annotations

from arachne.agent.control import AgentLease, ControlPlane, DirectControlPlane, HttpControlPlane
from arachne.agent.runner import AgentLoop, ExecutionResult, build_executor

__all__ = [
    "AgentLease",
    "AgentLoop",
    "ControlPlane",
    "DirectControlPlane",
    "ExecutionResult",
    "HttpControlPlane",
    "build_executor",
]
