"""The agent control-plane routes (S16, REQ-SCALE-002/003/004).

The four verbs an ``arachne agent`` needs, mounted at ``/api/v1/agent``. Every route
requires an existing API key with at least the scanner role
(:class:`~arachne.api.deps.ScannerPrincipal`) — an agent is a scanner, not a new
credential type — and the API middleware already records the key label of every call;
the service adds the agent name, so the audit trail answers "which node, which key?"
for the whole fleet.

``GET /agent/queue`` is the operator's fleet view (queue counts + registered agents) and
needs only a viewer.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from arachne.agent.control import lease_payload
from arachne.agent.service import AgentService
from arachne.api.deps import ContextDep, ScannerPrincipal, ViewerPrincipal
from arachne.api.schemas import (
    AgentCompleteIn,
    AgentHeartbeatIn,
    AgentLeaseIn,
    AgentRegisterIn,
)

__all__ = ["agent_router"]

agent_router = APIRouter()


def _service(context: ContextDep) -> AgentService:
    return AgentService(context.services, settings=context.settings)


@agent_router.post("/agent/register", tags=["agent"])
def register_agent(
    payload: AgentRegisterIn, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Register (or refresh) an agent; idempotent, so restarts are cheap."""
    record = _service(context).register(
        payload.name,
        principal=principal.label,
        node=payload.node,
        version=payload.version,
        concurrency=payload.concurrency,
    )
    return JSONResponse({"agent": record.to_dict()})


@agent_router.post("/agent/heartbeat", tags=["agent"])
def heartbeat_agent(
    payload: AgentHeartbeatIn, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Liveness + lease renewal. ``renewals[scan_id] == false`` means "abort that scan"."""
    renewals = _service(context).heartbeat(payload.name, principal=principal.label)
    return JSONResponse(
        {
            "agent": payload.name,
            "renewals": {str(scan_id): ok for scan_id, ok in renewals.items()},
        }
    )


@agent_router.post("/agent/lease", tags=["agent"])
def lease_agent(
    payload: AgentLeaseIn, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Claim up to ``cap`` queued scans; expired leases are reclaimed (and noted) first."""
    entries = _service(context).lease(
        payload.name,
        principal=principal.label,
        cap=payload.cap,
        ttl_s=payload.ttl_s,
    )
    return JSONResponse(
        {"agent": payload.name, "leases": [lease_payload(entry) for entry in entries]}
    )


@agent_router.post("/agent/complete", tags=["agent"])
def complete_agent(
    payload: AgentCompleteIn, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Ack a finished (or failed) leased scan. A lost lease is a 409, not an error path."""
    released = _service(context).complete(payload.name, payload.scan_id, principal=principal.label)
    if not released:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"scan {payload.scan_id} is not leased to agent {payload.name!r}",
        )
    return JSONResponse({"agent": payload.name, "scan_id": payload.scan_id, "released": True})


@agent_router.get("/agent/queue", tags=["agent"])
def queue_overview(principal: ViewerPrincipal, context: ContextDep) -> JSONResponse:
    """Queue counts and the registered fleet (the operator's fleet dashboard)."""
    return JSONResponse(_service(context).queue_overview())
