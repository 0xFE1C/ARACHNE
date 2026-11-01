"""Resilience routes: integrity status/verification and the HA view (S25, areas RESIL/TRUST).

Three read-only routes, all ``viewer`` like every other read, so an operator's dashboard can
show the platform's resilience posture without handing out a scanner key:

``GET /api/v1/integrity/status``
    the deployment key, the audit chain's head, the anchors and the seals (REQ-TRUST-005).
    Aggregate only: no audit content, no evidence.
``GET /api/v1/integrity/verify``
    run the verifier and return its verdict — the same report ``arachne verify-chain``
    prints, so a monitoring system can alert on it. ``?scan_id=`` narrows it to one scan.
``GET /api/v1/resilience/status``
    the leader leases, the queue depth and the replica count the autoscaler's arithmetic
    wants (REQ-RESIL-002/003), plus the region and air-gapped state (REQ-RESIL-001/004).

The routes never mutate: an anchor or a seal is an operator act through the CLI (or a scan's
own completion), never something a web caller can trigger.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from arachne.api.deps import ContextDep, ViewerPrincipal
from arachne.data.leader_store import LeaderElector
from arachne.data.services import build_integrity_verifier
from arachne.resil.autoscale import ScaleToZeroPolicy, queue_depth_source
from arachne.resil.migrations import check_expand_only

__all__ = ["resilience_router"]

resilience_router = APIRouter()

#: The singleton leases this build runs. Named here so the HA view lists a job that has not
#: been acquired yet (a fresh deployment) as free rather than as missing.
SINGLETON_JOBS = ("scheduler", "retention", "integrity-anchor")

#: An API verification is bounded more tightly than the CLI's: an unbounded pass over a huge
#: store behind a web request would be a self-inflicted denial of service.
API_ROW_LIMIT = 2000


@resilience_router.get("/integrity/status", tags=["integrity"])
def integrity_status(principal: ViewerPrincipal, context: ContextDep) -> dict[str, Any]:
    """The tamper-evidence posture: key, chain head, anchors and seals."""
    service = context.services.integrity
    settings = context.settings
    from arachne.core.signing import build_signer

    signer = build_signer(settings)
    chain_head: str | None = None
    if service is not None:
        from arachne.data.integrity_store import SqlAuditChain

        tail = SqlAuditChain(context.services.session_factory).tail()
        if tail is not None:
            chain_head = f"seq {tail[0]} hash {tail[1][:16]}…"
    anchors = service.anchors(limit=5) if service is not None else ()
    seals = service.seals(limit=5) if service is not None else ()
    return {
        "integrity_key": (
            {"configured": True, "key_id": signer.key_id} if signer else {"configured": False}
        ),
        "require_signatures": settings.integrity.require_signatures,
        "seal_on_finish": settings.integrity.seal_on_finish,
        "chain_head": chain_head,
        "anchors": [record.to_dict() for record in anchors],
        "seals": [record.to_dict() for record in seals],
        "airgapped": settings.airgap.enabled,
        "region": settings.resilience.region,
    }


@resilience_router.get("/integrity/verify", tags=["integrity"])
def integrity_verify(
    principal: ViewerPrincipal,
    context: ContextDep,
    scan_id: Annotated[int | None, Query(ge=1, description="Verify one scan only.")] = None,
) -> dict[str, Any]:
    """Run the verifier and return its verdict (never raises on a tamper finding)."""
    del principal
    verifier = build_integrity_verifier(context.services)
    report = verifier.verify(scan_id=scan_id, row_limit=API_ROW_LIMIT)
    return report.to_dict()


@resilience_router.get("/resilience/status", tags=["resilience"])
def resilience_status(principal: ViewerPrincipal, context: ContextDep) -> dict[str, Any]:
    """The HA view: leases, queue depth, the scaling decision and the air-gap state."""
    del principal
    settings = context.settings
    services = context.services
    leases = [
        LeaderElector(services.session_factory, name=name).state().to_dict()
        for name in SINGLETON_JOBS
    ]
    depth = queue_depth_source(services).depth()
    decision = ScaleToZeroPolicy().decide(
        depth,
        per_replica=settings.resilience.queue_depth_per_replica,
        min_replicas=settings.resilience.min_replicas,
        max_replicas=settings.resilience.max_replicas,
    )
    return {
        "region": settings.resilience.region,
        "airgapped": settings.airgap.enabled,
        "leader_ttl_s": settings.resilience.leader_ttl_s,
        "leases": leases,
        "queue_depth": depth,
        "scaling": decision.to_dict(),
        "head_migration": check_expand_only(_migrations_dir()).to_dict(),
    }


def _migrations_dir() -> Any:
    from pathlib import Path

    from arachne.cli.main import PROJECT_ROOT

    candidate = PROJECT_ROOT / "migrations" / "versions"
    return candidate if candidate.is_dir() else Path("migrations") / "versions"
