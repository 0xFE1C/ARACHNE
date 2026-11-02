"""The purple-team SIEM ingest and campaign routes (S24, area VALID).

Three routes, all authenticated like every other write:

``POST /api/v1/purple/alerts``
    the **webhook ingest** (REQ-VALID-002): a SIEM's forwarder posts alerts here — one
    alert, ``{"alerts": [...]}`` or newline-delimited JSON (the content type ARACHNE's own
    SIEM webhook destination emits, so an existing forwarder needs no rewriting). Every
    ingest is audited (``purple.alert_ingested``) with the technique and the nonce, and
    deduplicated on ``(source, alert_id)`` so a re-delivery cannot inflate coverage.

``GET /api/v1/purple/campaigns``
    the campaigns and their latest run, for an operator or a dashboard.

``POST /api/v1/purple/campaigns/{name}/run``
    run one campaign now. It goes through exactly the same window gate as the scheduler:
    refused (audited) outside the coordinated interval, never forced.

Nothing here can widen a purple run: the routes ingest and trigger, and the scan the trigger
starts is admitted by the orchestrator's gates like any other.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from arachne.api.deps import AdminPrincipal, ContextDep, ScannerPrincipal
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.purple.alerts import parse_alert_document, parse_alert_text
from arachne.purple.campaign import PurpleCampaignService

__all__ = ["purple_router"]

purple_router = APIRouter()


def _service(context: ContextDep) -> PurpleCampaignService:
    """The campaign service over this request's services stack."""
    try:
        return PurpleCampaignService(context.services)
    except ArachneError as exc:  # no purple store wired
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc


@purple_router.post("/purple/alerts", tags=["purple"])
def ingest_alerts(
    payload: dict[str, Any] | list[dict[str, Any]],
    principal: ScannerPrincipal,
    context: ContextDep,
) -> dict[str, Any]:
    """Ingest defender alerts (the SIEM webhook). Returns how many were new."""
    service = _service(context)
    source = f"webhook:{principal.label}"
    try:
        alerts = parse_alert_document(payload, source=source)
    except ConfigurationError as exc:
        context.auditor.record(
            AuditAction.PURPLE_ALERT_INGESTED,
            outcome=AuditOutcome.ERROR,
            target=source,
            reason=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    added = service.ingest(alerts, source=source)
    return {
        "accepted": len(alerts),
        "new": added,
        "duplicates": len(alerts) - added,
        "source": source,
    }


@purple_router.post("/purple/alerts/text", tags=["purple"])
def ingest_alerts_text(
    body: str,
    principal: ScannerPrincipal,
    context: ContextDep,
) -> dict[str, Any]:
    """Ingest a newline-delimited or JSON export posted as text (content type agnostic)."""
    service = _service(context)
    source = f"webhook:{principal.label}"
    try:
        alerts = parse_alert_text(body, source=source)
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    added = service.ingest(alerts, source=source)
    return {"accepted": len(alerts), "new": added, "duplicates": len(alerts) - added}


@purple_router.get("/purple/campaigns", tags=["purple"])
def list_campaigns(principal: AdminPrincipal, context: ContextDep) -> dict[str, Any]:
    """Every campaign with its latest run's coverage."""
    service = _service(context)
    items: list[dict[str, Any]] = []
    for campaign in service.list_campaigns():
        runs = service.store.runs(campaign.name, limit=1)
        latest = runs[-1] if runs else None
        items.append(
            campaign.to_dict()
            | {
                "latest_run": latest.to_dict() if latest is not None else None,
                "trend": [point.to_dict() for point in service.trend(campaign.name, limit=10)],
            }
        )
    return {"campaigns": items}


@purple_router.post("/purple/campaigns/{name}/run", tags=["purple"])
async def run_campaign(name: str, principal: AdminPrincipal, context: ContextDep) -> dict[str, Any]:
    """Run one campaign inside its coordinated window (refused outside it, audited)."""
    service = _service(context)
    try:
        result = await service.run_campaign(name)
    except ArachneError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return result.to_dict()
