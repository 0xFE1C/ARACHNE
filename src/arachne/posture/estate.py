"""Assemble an estate's posture from stored data — one implementation, three surfaces (S26).

``arachne posture report`` (CLI), ``GET /ui/posture`` (the executive dashboard) and any future
API route all need the same thing: the newest scans' severity trend, the drift between
consecutive scans, the fix-verification loop's counters and the baseline inventory, joined from
what is already stored. Doing that assembly in each surface is how three answers to "what is our
posture?" start disagreeing.

:func:`assemble_estate` is that join. It performs **no scan, no network call and no re-analysis**
— every input is a row an earlier scan wrote — which is what lets a dashboard page render in
one request.
"""

from __future__ import annotations

from typing import Any

from arachne.posture.trend import EstatePosture, ScanPoint, build_estate_posture

__all__ = ["assemble_estate"]

#: Default trend depth for a dashboard. The CLI passes its own ``--limit``.
DEFAULT_ESTATE_LIMIT: int = 20


def assemble_estate(
    services: Any, *, project_id: int | None, name: str, limit: int = DEFAULT_ESTATE_LIMIT
) -> EstatePosture:
    """Build the estate posture for one tenant from stored rows.

    ``project_id=None`` means "the whole deployment" (every project's scans), which is what the
    default workspace shows. A ``project_id`` scopes the trend to that tenant, and
    ``include_unassigned`` is set for the default workspace so pre-S14 rows — which belong to no
    project — are still counted rather than silently invisible.
    """
    from arachne.data.api_store import ApiQueryStore

    queries = ApiQueryStore(services.session_factory)
    trend = queries.scan_trend(
        project_id=project_id, include_unassigned=project_id is None, limit=limit
    )
    points: list[ScanPoint] = []
    finding_sets: list[dict[str, Any]] = []
    for row in trend:
        record = services.store.get_scan(row.scan_id)
        target_name = (
            str(record.plan.get("target_name") or f"scan-{row.scan_id}")
            if record
            else f"scan-{row.scan_id}"
        )
        points.append(
            ScanPoint(
                scan_id=row.scan_id,
                target_name=target_name,
                created_at=row.created_at,
                counts=dict(row.counts),
            )
        )
        identity: dict[str, Any] = {}
        for candidate in services.findings.list_candidates(row.scan_id):
            if candidate.status != "vulnerable" or candidate.severity is None:
                continue
            key = f"{candidate.check_key}|{candidate.asset_value or ''}"
            identity.setdefault(key, candidate)
        finding_sets.append(identity)

    posture = getattr(services, "posture", None)
    verifications = (
        posture.verification_counts()
        if posture is not None
        else {"verified": 0, "reopened": 0, "still-open": 0}
    )
    inventory = (
        posture.baseline_inventory() if posture is not None else {"scopes": (), "by_service": {}}
    )
    return build_estate_posture(
        project=name,
        points=points,
        finding_sets=finding_sets,
        open_counts=dict(trend[-1].counts) if trend else {},
        closed_by_verification=int(verifications.get("verified", 0)),
        reopened_regressions=int(verifications.get("reopened", 0)),
        still_open_verifications=int(verifications.get("still-open", 0)),
        inventory=dict(inventory.get("by_service") or {}),
        watched_scopes=tuple(inventory.get("scopes") or ()),
    )
