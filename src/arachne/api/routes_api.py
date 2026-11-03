"""The REST API (F-07-02, S12) — resources over the evidence store.

Mounted at ``/api/v1``. Every route is authenticated (API key + role) and the whole app is
rate-limited; the OpenAPI document is served at ``/openapi.json`` and the interactive docs
at ``/docs`` unless a deployment turns them off (``ARACHNE_API_DOCS=false``).

Resource map and the role each needs:

======================  =========================  ============
Resource                Verbs                      Minimum role
======================  =========================  ============
``/health``             GET                        (none)
``/scans``              GET, POST                  viewer / scanner
``/scans/{id}``         GET, DELETE                viewer / admin
``/scans/{id}/stop``    POST                       scanner
``/scans/{id}/report``  GET, POST                  viewer / scanner
``/findings``           GET                        viewer
``/findings/{id}``      GET, PATCH, DELETE         viewer / scanner / admin
``/targets``            GET, POST                  viewer / admin
``/targets/{id}``       GET, DELETE                viewer / admin
``/modules``            GET                        viewer
``/schedules``          GET, POST, DELETE, /run    viewer / scanner
``/webhooks``           GET                        admin
======================  =========================  ============

The API never scans inline: ``POST /scans`` admits a scan and runs it in the background (see
:mod:`arachne.api.runner`), so a slow scan cannot hold an HTTP connection open.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from arachne import __version__
from arachne.api.deps import (
    AdminPrincipal,
    AppContext,
    ContextDep,
    ProjectDep,
    ScannerPrincipal,
    ViewerPrincipal,
)
from arachne.api.filters import (
    FINDING_FILTER_FIELDS,
    FINDING_SORT_VALUES,
    SCAN_FILTER_FIELDS,
    SCAN_SORT_VALUES,
    STATUS_FILTER_FIELDS,
    FindingStatusValue,
    ScanStatusValue,
    SeverityValue,
    SortOrder,
)
from arachne.api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Cursor,
    apply_page,
    build_page,
    clamp_limit,
    cursor_or_400,
    paginate_sequence,
    reject_unknown_query_params,
    resolve_sort_field,
)
from arachne.api.schemas import (
    AcceptanceIn,
    AcceptanceOut,
    FeedImport,
    FindingOut,
    FindingReview,
    HealthOut,
    HypothesisControlIn,
    ModuleOut,
    PackReviewRequest,
    PluginInstallRequest,
    ProjectIn,
    ProjectOut,
    QuotaIn,
    RetentionIn,
    ScanDetail,
    ScanSummary,
    ScheduleIn,
    ScheduleOut,
    ServiceAccountIn,
    StartScanRequest,
    StepOut,
    SuppressionIn,
    SuppressionOut,
    TargetIn,
    TargetOut,
)
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.core.lifecycle import ScanRecord
from arachne.core.target import ScanRequest, TargetDefinition
from arachne.data.keyset import PageWindow
from arachne.data.project_store import DEFAULT_PROJECT_SLUG, ProjectRecord
from arachne.report import module_versions_for

__all__ = ["api_router"]

api_router = APIRouter()


# --------------------------------------------------------------------------- health
@api_router.get("/health", response_model=HealthOut, tags=["system"])
def health(context: ContextDep) -> HealthOut:
    """Liveness and a one-line build summary (no authentication)."""
    return HealthOut(
        version=__version__,
        database=_database_label(context.settings.database_url),
        api_keys=len(context.key_store),
        docs=context.settings.api.docs_enabled,
    )


def _database_label(url: str) -> str:
    return "sqlite" if url.startswith("sqlite") else url.split(":", 1)[0]


# --------------------------------------------------------------------------- scans
@api_router.get("/scans", response_model=list[ScanSummary], tags=["scans"])
def list_scans(
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    request: Request,
    response: Response,
    status_filter: Annotated[
        ScanStatusValue | None,
        Query(alias="status", description="Only scans in this lifecycle state."),
    ] = None,
    target_id: Annotated[
        int | None, Query(ge=1, description="Only scans of this stored target.")
    ] = None,
    sort: Annotated[
        Literal["id", "status"] | None,
        Query(description="Sort field. `id` is indexed; `status` is not (documented as slow)."),
    ] = None,
    order: Annotated[
        SortOrder | None, Query(description="Sort direction (default `desc`).")
    ] = None,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[ScanSummary]:
    """List this project's scans, newest first, with cursor pagination and validated filters."""
    reject_unknown_query_params(request, SCAN_FILTER_FIELDS)
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    sort_field = resolve_sort_field(sort, SCAN_SORT_VALUES, default="id")
    descending = order != "asc"
    window = _page_window(page_cursor, sort_field, descending)
    records = context.services.store.list_scans(
        limit=size + 1,
        project_id=project.id,
        include_unassigned=_include_unassigned(project),
        status=status_filter,
        target_id=target_id,
        window=window,
    )
    ordered = _forward_order(records, page_cursor)
    page = build_page(
        ordered,
        limit=size,
        key_of=_scan_sort_key(sort_field),
        id_of=lambda record: record.id,
        cursor=page_cursor,
        backward=bool(page_cursor and page_cursor.backward),
    )
    apply_page(response, request, page)
    counts = context.queries.severity_counts_for([record.id for record in page.items])
    return [
        _scan_summary(record, counts.get(record.id, {}), context.runner.is_running(record.id))
        for record in page.items
    ]


@api_router.post("/scans", status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
async def start_scan(
    payload: StartScanRequest,
    principal: ScannerPrincipal,
    context: ContextDep,
    project: ProjectDep,
) -> JSONResponse:
    """Admit a scan in this project and run it in the background (or plan it, with ``dry_run``)."""
    request = _scan_request(payload, context, project=project)
    if payload.dry_run:
        from arachne.core.orchestrator import Orchestrator

        plan = Orchestrator(
            settings=context.settings,
            auditor=context.auditor,
            project_id=project.id,
            project_scope=project.to_scope(),
        ).plan(request, dry_run=True)
        return JSONResponse({"dry_run": True, "plan": plan.to_dict()})
    started = await context.runner.start(
        request,
        project_id=project.id,
        project_scope=project.to_scope(),
        requested_by=principal.actor,
    )
    return JSONResponse(
        started.to_dict(),
        status_code=status.HTTP_202_ACCEPTED,
        headers={"Location": f"/api/v1/scans/{started.scan_id}"},
    )


@api_router.get("/scans/{scan_id}", response_model=ScanDetail, tags=["scans"])
def get_scan(
    scan_id: int, principal: ViewerPrincipal, context: ContextDep, project: ProjectDep
) -> ScanDetail:
    """One scan's summary, per-step progress and its discovered assets."""
    record = _require_scan(context, scan_id, project)
    counts = context.queries.severity_counts(scan_id)
    assets = [
        {"id": item.id, "kind": item.kind, "value": item.value, "meta": dict(item.meta)}
        for item in context.services.store.list_assets(scan_id)
    ]
    summary = _scan_summary(record, counts, context.runner.is_running(scan_id))
    return ScanDetail(
        **summary.model_dump(),
        plan=dict(record.plan),
        stats=dict(record.stats),
        residue_attestation=(
            dict(record.residue_attestation) if record.residue_attestation else None
        ),
        steps=[
            StepOut(
                step=state.step.value,
                status=state.status.value,
                attempts=state.attempts,
                error=state.error,
                stats=dict(state.stats),
            )
            for state in record.steps
        ],
        assets=assets,
    )


@api_router.post("/scans/{scan_id}/stop", tags=["scans"])
async def stop_scan(
    scan_id: int, principal: ScannerPrincipal, context: ContextDep, project: ProjectDep
) -> JSONResponse:
    """Cancel a background scan this process is running (F-07-02 "stop")."""
    _require_scan(context, scan_id, project)
    if not await context.runner.stop(scan_id):
        raise _conflict(f"scan {scan_id} is not running in this process")
    record = _require_scan(context, scan_id, project)
    return JSONResponse({"scan_id": scan_id, "status": record.status.value})


@api_router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["scans"])
def delete_scan(
    scan_id: int, principal: AdminPrincipal, context: ContextDep, project: ProjectDep
) -> Response:
    """Delete a scan and everything that cascades from it."""
    record = _require_scan(context, scan_id, project)
    if context.runner.is_running(record.id):
        raise _conflict(f"scan {scan_id} is running; stop it first")
    if not context.queries.delete_scan(scan_id):
        raise _not_found(f"scan {scan_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- reports
@api_router.get("/scans/{scan_id}/report", tags=["reports"])
def get_report(
    scan_id: int,
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    fmt: Annotated[str, Query(alias="format")] = "md",
    diff_with: Annotated[int | None, Query()] = None,
    locale: Annotated[
        str | None,
        Query(description="Report language (e.g. en, fr); defaults to the project's."),
    ] = None,
) -> Response:
    """Render a stored scan's report (built-in formats and installed plugins, F-06-02).

    ``locale`` selects the report language (S26, REQ-ECOS-005): the same scan can be delivered
    to a French-speaking client and to an English-speaking auditor without a second scan. The
    label vocabulary is the shipped catalogue (``templates/i18n/``); an unknown locale falls
    back to English rather than failing the request.
    """
    _require_scan(context, scan_id, project)
    from arachne.report import default_registry, media_type, report_bytes

    if default_registry().get(fmt) is None:
        known = ", ".join(default_registry().names())
        raise HTTPException(
            status_code=400, detail=f"unknown report format {fmt!r}; this build ships {known}"
        )
    report = context.reports.build(scan_id, diff_with=diff_with, locale=locale)
    context.auditor.with_actor(principal.actor).record(
        AuditAction.REPORT_GENERATED,
        scan_id=scan_id,
        meta={
            "format": fmt,
            "findings": len(report.findings),
            "locale": report.locale or "default",
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return Response(content=report_bytes(report, fmt), media_type=media_type(fmt))


@api_router.post("/scans/{scan_id}/report", tags=["reports"])
async def push_report(
    scan_id: int, principal: ScannerPrincipal, context: ContextDep, project: ProjectDep
) -> JSONResponse:
    """Render a report and push it to the configured webhooks (F-06-06)."""
    _require_scan(context, scan_id, project)
    results = await context.reports.notify(scan_id)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "delivered": [item.to_dict() for item in results],
            "enabled": bool(context.notifier and context.notifier.enabled),
        }
    )


# --------------------------------------------------------------------------- findings
@api_router.get("/findings", response_model=list[FindingOut], tags=["findings"])
def list_findings(
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    request: Request,
    response: Response,
    scan_id: Annotated[int | None, Query(ge=1, description="Only findings of this scan.")] = None,
    module: Annotated[
        str | None, Query(max_length=64, description="Only findings from this module.")
    ] = None,
    severity: Annotated[
        SeverityValue | None,
        Query(description="Only findings of this severity (`unanalysed` matches a NULL severity)."),
    ] = None,
    cwe: Annotated[
        str | None, Query(max_length=32, description="Only findings with this CWE id.")
    ] = None,
    status_filter: Annotated[
        FindingStatusValue | None, Query(alias="status", description="Only findings in this state.")
    ] = None,
    asset: Annotated[
        str | None, Query(max_length=2048, description="Substring match on the asset value.")
    ] = None,
    q: Annotated[
        str | None, Query(max_length=512, description="Substring match on the finding title.")
    ] = None,
    sort: Annotated[
        Literal["id", "severity", "status", "title"] | None,
        Query(description="Sort field. `id` is indexed; the others are a full scan (slow)."),
    ] = None,
    order: Annotated[SortOrder | None, Query(description="Sort direction (default `asc`).")] = None,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(
            ge=0, deprecated=True, description="Deprecated: use `cursor`. Ignored with a cursor."
        ),
    ] = 0,
) -> list[FindingOut]:
    """List/filter this project's findings, with cursor pagination and a validated vocabulary.

    Every filter above is validated: an unknown query field is a ``400`` naming it, and a
    value outside the documented enum is refused rather than silently matching nothing.
    """
    reject_unknown_query_params(request, FINDING_FILTER_FIELDS)
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    sort_field = resolve_sort_field(sort, FINDING_SORT_VALUES, default="id")
    descending = order == "desc"
    window = _page_window(page_cursor, sort_field, descending)
    rows = context.queries.finding_rows(
        scan_id=scan_id,
        module=module,
        severity=severity,
        cwe=cwe,
        status=status_filter,
        asset=asset,
        query=q,
        limit=size + 1,
        offset=0 if page_cursor is not None else offset,
        project_id=project.id,
        include_unassigned=_include_unassigned(project),
        window=window,
    )
    ordered = _forward_order(rows, page_cursor)
    page = build_page(
        ordered,
        limit=size,
        key_of=_finding_sort_key(sort_field),
        id_of=lambda row: row.id,
        cursor=page_cursor,
        backward=bool(page_cursor and page_cursor.backward),
    )
    apply_page(response, request, page)
    return [FindingOut.model_validate(row.to_dict()) for row in page.items]


@api_router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(
    finding_id: int, principal: ViewerPrincipal, context: ContextDep, project: ProjectDep
) -> JSONResponse:
    """One finding with its evidence and remediation (the expanded view)."""
    _require_finding(context, finding_id, project)
    row = context.queries.finding_row(finding_id)
    if row is None:
        raise _not_found(f"finding {finding_id} does not exist")
    payload = row.to_dict()
    payload["evidence"] = list(context.queries.evidence_rows(finding_id))
    return JSONResponse(payload)


@api_router.patch("/findings/{finding_id}", response_model=FindingOut, tags=["findings"])
def review_finding(
    finding_id: int,
    payload: FindingReview,
    principal: ScannerPrincipal,
    context: ContextDep,
    project: ProjectDep,
) -> FindingOut:
    """Set a finding's status and, optionally, record F-05-07 false-positive feedback."""
    _require_finding(context, finding_id, project)
    row = context.queries.finding_row(finding_id)
    if row is None:
        raise _not_found(f"finding {finding_id} does not exist")
    if payload.is_false_positive is not None:
        is_fp = payload.is_false_positive
    else:
        is_fp = payload.status == "fp"
    updated = context.queries.set_finding_status(finding_id, payload.status)
    assert updated is not None  # checked above
    if payload.status == "fp" or payload.is_false_positive is not None:
        _record_feedback(context, row, is_fp=is_fp, note=payload.note, actor=principal.label)
    context.auditor.with_actor(principal.actor).record(
        AuditAction.FINDING_REVIEWED,
        scan_id=updated.scan_id,
        target=f"finding:{finding_id}",
        meta={
            "status": payload.status,
            "is_fp": is_fp,
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return FindingOut.model_validate(updated.to_dict())


@api_router.delete(
    "/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["findings"]
)
def delete_finding(
    finding_id: int, principal: AdminPrincipal, context: ContextDep, project: ProjectDep
) -> Response:
    _require_finding(context, finding_id, project)
    if not context.queries.delete_finding(finding_id):
        raise _not_found(f"finding {finding_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _record_feedback(
    context: AppContext, row: Any, *, is_fp: bool, note: str | None, actor: str
) -> None:
    """Write the F-05-07 feedback row the tuner aggregates on (ADR-02: one place).

    The key matches :func:`arachne.analyzer.fp.feedback_key`: ``check|asset-kind|signature``
    with the *dot* check id, so a decision taken here adjusts the same threshold a decision
    taken during a scan would.
    """
    from arachne.analyzer.fp import FeedbackRecord, feedback_key_for

    key = feedback_key_for(row.check_id, row.asset_kind)
    context.services.analyses.record_feedback(
        FeedbackRecord(key=key, is_fp=is_fp, finding_id=row.id, note=note), actor=actor
    )


# --------------------------------------------------------------------------- targets
@api_router.get("/targets", response_model=list[TargetOut], tags=["targets"])
def list_targets(
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    request: Request,
    response: Response,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[TargetOut]:
    """List this project's stored targets, newest first, with cursor pagination."""
    reject_unknown_query_params(request, frozenset())
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    window = _page_window(page_cursor, "id", True)
    records = context.services.target_store.list_targets(
        limit=size + 1,
        project_id=project.id,
        include_unassigned=_include_unassigned(project),
        window=window,
    )
    ordered = _forward_order(records, page_cursor)
    page = build_page(
        ordered,
        limit=size,
        key_of=lambda record: record.id,
        id_of=lambda record: record.id,
        cursor=page_cursor,
        backward=bool(page_cursor and page_cursor.backward),
    )
    apply_page(response, request, page)
    return [TargetOut.model_validate(record.to_dict()) for record in page.items]


@api_router.post(
    "/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED, tags=["targets"]
)
def create_target(
    payload: TargetIn, principal: AdminPrincipal, context: ContextDep, project: ProjectDep
) -> TargetOut:
    """Store a target definition in this project (F-01-01)."""
    definition = _definition_from_payload(payload.model_dump())
    target_id = context.services.target_store.save(definition, project_id=project.id)
    record = context.services.target_store.get_target(target_id)
    assert record is not None
    return TargetOut.model_validate(record.to_dict())


@api_router.get("/targets/{target_id}", response_model=TargetOut, tags=["targets"])
def get_target(
    target_id: int, principal: ViewerPrincipal, context: ContextDep, project: ProjectDep
) -> TargetOut:
    record = context.services.target_store.get_target(target_id)
    if record is None or not _visible(record.project_id, project):
        raise _not_found(f"target {target_id} does not exist")
    return TargetOut.model_validate(record.to_dict())


@api_router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["targets"])
def delete_target(
    target_id: int, principal: AdminPrincipal, context: ContextDep, project: ProjectDep
) -> Response:
    record = context.services.target_store.get_target(target_id)
    if record is None or not _visible(record.project_id, project):
        raise _not_found(f"target {target_id} does not exist")
    if not context.services.target_store.delete_target(target_id):
        raise _not_found(f"target {target_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- modules
@api_router.get("/modules", response_model=list[ModuleOut], tags=["modules"])
def list_modules(
    principal: ViewerPrincipal,
    context: ContextDep,
    request: Request,
    response: Response,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[ModuleOut]:
    """The installed modules and their checks, plus this deployment's effective config.

    Module configuration is environment-driven (F-08-01) and therefore read-only here: the
    response describes what *is* configured, so an operator can confirm it without ``shell``
    access, but no endpoint mutates deployment settings.
    """
    registry = context.services.registry
    stored = {row.key: row for row in context.queries.list_checks()}
    out: list[ModuleOut] = []
    for group in registry.groups:
        checks: list[dict[str, Any]] = []
        for metadata in group.metadata():
            row = stored.get(metadata.key)
            checks.append(
                {
                    "id": metadata.id,
                    "name": metadata.name,
                    "version": metadata.version,
                    "title": metadata.title,
                    "research_ref": metadata.research_ref,
                    "cwe": metadata.cwe,
                    "active": metadata.requires_active_checks,
                    "enabled_by_default": metadata.enabled_by_default,
                    "estimated_requests": metadata.estimated_requests,
                    "ran": row is not None,
                }
            )
        out.append(
            ModuleOut(
                id=group.id,
                title=getattr(group, "title", None),
                version=group.version,
                step=group.step.value,
                checks=checks,
            )
        )
    reject_unknown_query_params(request, frozenset())
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    positions = {module.id: index for index, module in enumerate(out)}
    page = paginate_sequence(
        out,
        limit=size,
        key_of=lambda module: module.id,
        id_of=lambda module: positions[module.id],
        cursor=page_cursor,
    )
    apply_page(response, request, page)
    return page.items


@api_router.get("/config", tags=["modules"])
def effective_config(principal: AdminPrincipal, context: ContextDep) -> JSONResponse:
    """The effective, redacted deployment configuration (F-07-02 "module config")."""
    settings = context.settings
    return JSONResponse(
        {
            "database": _database_label(settings.database_url),
            "rate_limits": {
                "per_host_per_second": settings.rate_limit.per_host_rate,
                "per_host_burst": settings.rate_limit.per_host_burst,
                "global_per_second": settings.rate_limit.global_rate,
                "global_burst": settings.rate_limit.global_burst,
                "api_per_minute": settings.api.rate_limit_per_minute,
                "api_burst": settings.api.rate_limit_burst,
            },
            "scope": {
                "hosts": list(settings.safety.scope.allowed_hosts),
                "domains": list(settings.safety.scope.allowed_domains),
                "excluded_hosts": list(settings.safety.scope.excluded_hosts),
            },
            "url_safety": {
                "allow_private_ips": settings.safety.policy.allow_private_ips,
                "allow_loopback": settings.safety.policy.allow_loopback,
            },
            "modules": module_versions_for(context.services.registry),
            "webhooks": list(settings.webhooks.configured_targets()),
            "engine": settings.ai.engine or "heuristic",
            "tls_required": settings.api.require_tls,
        }
    )


# --------------------------------------------------------------------------- projects
@api_router.get("/projects", response_model=list[ProjectOut], tags=["projects"])
def list_projects(
    principal: ViewerPrincipal,
    context: ContextDep,
    request: Request,
    response: Response,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[ProjectOut]:
    """Every tenant/workspace (F-07-06). The default workspace is created on demand.

    Ordered by slug, with cursor pagination.
    """
    context.services.projects.ensure_default()
    records = [
        ProjectOut.model_validate(record.to_dict())
        for record in context.services.projects.list_projects()
    ]
    reject_unknown_query_params(request, frozenset())
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    page = paginate_sequence(
        records,
        limit=size,
        key_of=lambda project: project.slug,
        id_of=lambda project: project.id,
        cursor=page_cursor,
    )
    apply_page(response, request, page)
    return page.items


@api_router.post(
    "/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED, tags=["projects"]
)
def create_project(
    payload: ProjectIn, principal: AdminPrincipal, context: ContextDep
) -> ProjectOut:
    """Create a tenant with its scope and optional white-label branding."""
    record = context.services.projects.create(
        payload.slug,
        payload.name,
        description=payload.description,
        scope=payload.scope,
        branding=payload.branding.model_dump() if payload.branding else {},
        report_locale=payload.report_locale,
    )
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PROJECT_CHANGED,
        target=record.slug,
        meta={
            "action": "created",
            "scope": record.scope,
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return ProjectOut.model_validate(record.to_dict())


@api_router.get("/projects/{slug}", response_model=ProjectOut, tags=["projects"])
def get_project(slug: str, principal: ViewerPrincipal, context: ContextDep) -> ProjectOut:
    from arachne.core.errors import ConfigurationError as _ConfigurationError

    try:
        record = context.services.projects.resolve(slug)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    return ProjectOut.model_validate(record.to_dict())


@api_router.get("/projects/{slug}/retention", tags=["projects"])
def get_retention(slug: str, principal: ViewerPrincipal, context: ContextDep) -> dict[str, Any]:
    """A tenant's effective retention policy (S20, REQ-DATA-001).

    The *effective* policy is what the pruning job will act on: the project's own overrides on
    top of the deployment defaults, with the deployment values shown for anything the project
    does not declare.
    """
    from arachne.core.errors import ConfigurationError as _ConfigurationError
    from arachne.data.retention import RetentionPolicy

    try:
        record = context.services.projects.resolve(slug)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    defaults = RetentionPolicy(
        findings_days=context.settings.retention.findings_days,
        evidence_days=context.settings.retention.evidence_days,
        scans_days=context.settings.retention.scans_days,
        audit_days=context.settings.retention.audit_days,
        enabled=context.settings.retention.enabled,
    )
    effective = RetentionPolicy.from_mapping(
        defaults, record.retention, source=f"project {record.slug}"
    )
    return {
        "project": record.slug,
        "declared": dict(record.retention) if record.retention else None,
        "defaults": defaults.to_dict(),
        "effective": effective.to_dict(),
    }


@api_router.put("/projects/{slug}/retention", tags=["projects"])
def set_retention(
    slug: str, payload: RetentionIn, principal: AdminPrincipal, context: ContextDep
) -> dict[str, Any]:
    """Set a tenant's retention policy (admin). ``0`` days keeps a category for ever."""
    from arachne.core.errors import ConfigurationError as _ConfigurationError

    try:
        record = context.services.projects.resolve(slug, create_default=False)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    declared = payload.model_dump()
    try:
        updated = context.services.projects.set_retention(record.id, declared)
    except _ConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PROJECT_CHANGED,
        target=record.slug,
        meta={"action": "retention", "retention": declared, "identity": principal.actor},
    )
    return {
        "project": record.slug,
        "declared": dict(updated.retention) if updated and updated.retention else None,
    }


@api_router.get("/projects/{slug}/storage", tags=["projects"])
def get_storage(slug: str, principal: ViewerPrincipal, context: ContextDep) -> dict[str, Any]:
    """A tenant's storage usage against its quota (S20, REQ-DATA-003)."""
    from arachne.core.errors import ConfigurationError as _ConfigurationError

    try:
        record = context.services.projects.resolve(slug)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    quota = context.services.quota
    state = quota.state(record.id) if quota is not None else None
    return {
        "project": record.slug,
        "used_bytes": state.used_bytes if state else int(record.used_bytes or 0),
        "limit_bytes": state.limit_bytes if state else record.quota_bytes,
        "ratio": round(state.ratio, 4) if state else 0.0,
        "warning": bool(state.warning) if state else False,
        "exceeded": bool(state.exceeded) if state else False,
    }


@api_router.put("/projects/{slug}/storage", tags=["projects"])
def set_quota(
    slug: str, payload: QuotaIn, principal: AdminPrincipal, context: ContextDep
) -> dict[str, Any]:
    """Set (or clear) a tenant's storage quota (admin); ``null`` removes the limit."""
    from arachne.core.errors import ConfigurationError as _ConfigurationError

    try:
        record = context.services.projects.resolve(slug, create_default=False)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    try:
        context.services.projects.set_quota(record.id, payload.limit_bytes)
    except _ConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PROJECT_CHANGED,
        target=record.slug,
        meta={"action": "quota", "limit_bytes": payload.limit_bytes, "identity": principal.actor},
    )
    return {"project": record.slug, "limit_bytes": payload.limit_bytes}


@api_router.delete("/projects/{slug}", status_code=status.HTTP_204_NO_CONTENT, tags=["projects"])
def delete_project(slug: str, principal: AdminPrincipal, context: ContextDep) -> Response:
    """Delete a tenant; its scans survive with no project. The default one is protected."""
    from arachne.core.errors import ConfigurationError as _ConfigurationError

    try:
        record = context.services.projects.resolve(slug, create_default=False)
        context.services.projects.delete(record.id)
    except _ConfigurationError as exc:
        raise _not_found(str(exc)) from exc
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PROJECT_CHANGED,
        target=record.slug,
        meta={"action": "deleted", "actor": principal.label, "identity": principal.actor},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- evidence
@api_router.get("/evidence/{evidence_id}/download", tags=["evidence"])
async def download_evidence(
    evidence_id: int,
    principal: ViewerPrincipal,
    context: ContextDep,
    redirect: Annotated[bool, Query()] = True,
) -> Response:
    """Fetch one evidence payload (S20, REQ-DATA-002).

    Three cases, one route:

    * **Offloaded to an object store** — with ``redirect=true`` (the default) the caller gets a
      ``302`` to a presigned URL, so the browser fetches straight from the store and ARACHNE
      never proxies the bytes. ``redirect=false`` streams them through the API for a client
      that cannot follow a redirect.
    * **Offloaded to the local backend** — streamed from disk.
    * **Inline** — the stored payload, returned as JSON.

    Viewer role, like every other read: an evidence payload is the thing the operator's
    findings are justified by.

    Residency (S25, REQ-RESIL-004) is checked *before* anything is served: a payload pinned
    to another region is refused with the same 403-family error a scope refusal uses, whether
    it would have been streamed from an object store or returned inline. Refusing only the
    offloaded case would leave a cross-region read of the small payloads, which is not a
    boundary at all.
    """
    row = context.queries.evidence_row(evidence_id)
    if row is None:
        raise _not_found(f"evidence {evidence_id} does not exist")
    service = getattr(context.services, "evidence", None)
    if service is not None:
        service.require_region(row.get("region"))
    filename = f"evidence-{evidence_id}-{row['kind']}.json"
    key = row.get("storage_key")
    stored = row.get("storage") not in (None, "inline")
    if stored and key and service is not None:
        if redirect:
            url = service.presign(str(key), filename=filename)
            if url:
                return RedirectResponse(url, status_code=status.HTTP_302_FOUND)
        try:
            data = await service.download(str(key))
        except ArachneError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    payload = json.dumps(row["payload"], default=str, ensure_ascii=False, sort_keys=True)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------- feeds
@api_router.get("/feeds", tags=["feeds"])
def list_feeds(
    principal: ViewerPrincipal,
    context: ContextDep,
    kind: Annotated[str | None, Query()] = None,
) -> JSONResponse:
    """Imported CVE/EPSS feeds, newest first (F-09-03)."""
    records = [record.to_dict() for record in context.services.feeds.list_feeds(kind=kind)]
    return JSONResponse({"feeds": records, "stats": context.services.feeds.stats()})


@api_router.post("/feeds", status_code=status.HTTP_201_CREATED, tags=["feeds"])
def import_feed(
    payload: FeedImport, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Ingest an uploaded EPSS/KEV/CVE document (validated and normalised, F-09-03)."""
    record = context.services.feeds.import_text(
        payload.content,
        kind=payload.kind,
        name=payload.name,
        source=payload.source or f"api:{principal.label}",
        imported_by=principal.label,
        max_entries=context.settings.feeds.max_entries,
    )
    context.auditor.with_actor(principal.actor).record(
        AuditAction.FEED_IMPORTED,
        target=record.name,
        meta={
            "kind": record.kind,
            "entries": record.record_count,
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return JSONResponse(record.to_dict(), status_code=status.HTTP_201_CREATED)


@api_router.get("/feeds/stats", tags=["feeds"])
def feed_stats(principal: ViewerPrincipal, context: ContextDep) -> JSONResponse:
    return JSONResponse(context.services.feeds.stats())


@api_router.get("/feeds/lookup/{cve}", tags=["feeds"])
def feed_lookup(cve: str, principal: ViewerPrincipal, context: ContextDep) -> JSONResponse:
    """The merged EPSS/KEV row for one CVE across the active feeds."""
    found = context.services.feeds.lookup(cve)
    if found is None:
        raise _not_found(f"{cve.upper()} is not in the active ingested feeds")
    return JSONResponse(found)


@api_router.get("/feeds/{feed_id}", tags=["feeds"])
def show_feed(
    feed_id: int,
    principal: ViewerPrincipal,
    context: ContextDep,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> JSONResponse:
    record = context.services.feeds.get(feed_id)
    if record is None:
        raise _not_found(f"feed {feed_id} does not exist")
    return JSONResponse(
        {**record.to_dict(), "entries": list(context.services.feeds.entries(feed_id, limit=limit))}
    )


@api_router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["feeds"])
def delete_feed(feed_id: int, principal: AdminPrincipal, context: ContextDep) -> Response:
    if not context.services.feeds.delete(feed_id):
        raise _not_found(f"feed {feed_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- plugins
@api_router.get("/plugins", tags=["plugins"])
def list_plugins(principal: ViewerPrincipal, context: ContextDep) -> JSONResponse:
    """Installed check and report-format plugins (F-09-01)."""
    from arachne.plugins import installed_plugins

    return JSONResponse(
        {
            **installed_plugins(),
            "install_enabled": context.settings.plugins.allow_install,
        }
    )


@api_router.get("/plugins/formats", tags=["plugins"])
def list_formats(principal: ViewerPrincipal, context: ContextDep) -> JSONResponse:
    """Every report format this build can render, built-in and installed."""
    from arachne.report import default_registry

    return JSONResponse({"formats": default_registry().summary()})


@api_router.get("/plugins/marketplace", tags=["plugins"])
def plugin_marketplace(
    principal: ViewerPrincipal,
    context: ContextDep,
    search: Annotated[str | None, Query()] = None,
) -> JSONResponse:
    """The plugin catalogue, annotated with installed state and the recorded review verdict.

    ``review`` is computed from the provenance store (S26, REQ-ECOS-001): ``listed`` when the
    newest recorded review of those exact bytes passed every gate, ``rejected`` when it did
    not, and ``unreviewed`` when nothing has been reviewed.
    """
    from arachne.plugins.marketplace import load_marketplace
    from arachne.plugins.review import DECISION_LISTED

    catalogue = load_marketplace(context.settings.plugins.marketplace)
    rows = catalogue.listing(term=search)
    store = getattr(context.services, "pack_reviews", None)
    decisions: dict[tuple[str, str], str] = {}
    if store is not None:
        for record in store.list_reviews(limit=1000):
            decisions.setdefault((record.name, record.version), record.decision)
    for row in rows:
        decision = decisions.get((str(row["name"]), str(row["version"])))
        row["review"] = decision or "unreviewed"
        row["reviewed"] = decision == DECISION_LISTED
    return JSONResponse({**catalogue.to_dict(), "entries": rows})


@api_router.get("/plugins/reviews", tags=["plugins"])
def list_pack_reviews(
    principal: ViewerPrincipal,
    context: ContextDep,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> JSONResponse:
    """The recorded marketplace review provenance (S26, REQ-ECOS-001)."""
    store = getattr(context.services, "pack_reviews", None)
    rows = [record.to_dict() for record in store.list_reviews(limit=limit)] if store else []
    return JSONResponse(
        {
            "reviews": rows,
            "require_review": context.settings.plugins.require_review,
            "allow_unsigned": context.settings.plugins.allow_unsigned_packs,
        }
    )


@api_router.post("/plugins/review", tags=["plugins"])
def review_plugin(
    payload: PackReviewRequest, principal: AdminPrincipal, context: ContextDep
) -> JSONResponse:
    """Run the review pipeline over a content pack on this host (S26, REQ-ECOS-001).

    The pack is read from a **local path** the ARACHNE process can reach — the same
    post-verification position ``POST /plugins/install`` takes for a git URL, and deliberately
    not a file upload: a multi-hundred-megabyte pack through a JSON body would be a resource
    exhaustion vector, and an operator who can put a file on the host is already the actor this
    endpoint authorizes. A rejection is a 200 with ``listed: false`` and the reasons, because
    "this pack is hostile" is an *outcome* the caller asked for, not a request error.
    """
    from arachne.core.signing import build_signer
    from arachne.plugins.review import review_pack_bytes

    path = Path(payload.pack).expanduser()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"cannot read pack: {exc}") from exc
    report = review_pack_bytes(
        data,
        signer=build_signer(context.settings),
        allow_unsigned=payload.allow_unsigned or context.settings.plugins.allow_unsigned_packs,
        source=str(path),
    )
    store = getattr(context.services, "pack_reviews", None)
    if payload.publish and store is not None:
        store.record(report, reviewed_by=principal.actor)
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PACK_REVIEWED,
        outcome=AuditOutcome.ALLOWED if report.listed else AuditOutcome.BLOCKED,
        target=report.name,
        reason=None if report.listed else "; ".join(item.message for item in report.blockers),
        meta={
            "version": report.version,
            "digest": report.digest,
            "decision": report.decision,
            "published": payload.publish,
        },
    )
    return JSONResponse({**report.to_dict(), "published": payload.publish and store is not None})


@api_router.post("/plugins/install", tags=["plugins"])
def install_plugin(
    payload: PluginInstallRequest, principal: AdminPrincipal, context: ContextDep
) -> JSONResponse:
    """Install a plugin from a path or git URL (F-09-01).

    **Off by default** (``ARACHNE_PLUGIN_INSTALL=true`` enables it): installing runs pip and
    mutates the running environment, which is an operator action. The CLI always works.
    """
    from arachne.plugins.installer import PluginInstallError, install_and_verify

    if not context.settings.plugins.allow_install:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "plugin installation over the API is disabled; set "
                "ARACHNE_PLUGIN_INSTALL=true or use `arachne plugin install`"
            ),
        )
    extra: list[str] = []
    if payload.no_deps:
        extra.append("--no-deps")
    if payload.no_build_isolation:
        extra.append("--no-build-isolation")
    try:
        result, appeared = install_and_verify(
            payload.source,
            target=payload.target,
            dry_run=payload.dry_run,
            timeout_s=context.settings.plugins.install_timeout_s,
            extra_args=tuple(extra),
        )
    except PluginInstallError as exc:
        raise ConfigurationError(str(exc)) from exc
    context.auditor.with_actor(principal.actor).record(
        AuditAction.PLUGIN_INSTALLED,
        target=payload.source,
        meta={
            "actor": principal.label,
            "identity": principal.actor,
            "dry_run": payload.dry_run,
            "checks": len(appeared["checks"]),
            "formats": len(appeared["report_formats"]),
        },
    )
    return JSONResponse({"install": result.to_dict(), "appeared": appeared})


# --------------------------------------------------------------------------- quality (S21)


def _quality(context: AppContext) -> Any:
    """The quality store, or a 503 when the deployment has none wired (S21)."""
    store = getattr(context.services, "quality", None)
    if store is None:
        raise HTTPException(
            status_code=503, detail="this deployment has no quality store configured"
        )
    return store


def _quality_error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@api_router.get("/suppressions", response_model=list[SuppressionOut], tags=["quality"])
def list_suppressions(
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    request: Request,
    response: Response,
    include_revoked: Annotated[bool, Query()] = False,
    all_projects: Annotated[
        bool,
        Query(description="Return every tenant's rules (S26); the project header is ignored."),
    ] = False,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[SuppressionOut]:
    """The suppression rules in force for the requesting tenant, newest first.

    S26 scopes this to the request's project (``x-project`` / ``?project=``), including the
    deployment-wide rules (``project_id IS NULL``) that apply to every tenant. ``all_projects``
    returns the whole estate's rules, which is what an MSSP operator auditing across customers
    needs — and it is a *read*, so it is available to any viewer rather than gated further.
    """
    del principal
    reject_unknown_query_params(request, STATUS_FILTER_FIELDS)
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    rows = _quality(context).list_suppressions(
        active_only=not include_revoked,
        project_id=None if all_projects else project.id,
    )
    page = paginate_sequence(
        rows,
        limit=size,
        key_of=lambda rule: rule.id,
        id_of=lambda rule: rule.id or 0,
        descending=True,
        cursor=page_cursor,
    )
    apply_page(response, request, page)
    return [SuppressionOut.model_validate(row.to_dict()) for row in page.items]


@api_router.post(
    "/suppressions",
    response_model=SuppressionOut,
    status_code=status.HTTP_201_CREATED,
    tags=["quality"],
)
def create_suppression(
    payload: SuppressionIn, principal: ScannerPrincipal, context: ContextDep, project: ProjectDep
) -> SuppressionOut:
    """Record a suppression rule (a reason is required, and the actor is attributed)."""
    from arachne.quality.suppressions import Suppression

    if payload.finding_id is not None and context.queries.finding_row(payload.finding_id) is None:
        raise _not_found(f"finding {payload.finding_id} does not exist")
    try:
        rule = Suppression(
            kind=payload.kind,
            check_id=payload.check_id,
            asset_pattern=payload.asset_pattern,
            finding_id=payload.finding_id,
            reason=payload.reason,
            actor=principal.label,
            expires_at=payload.expires_at,
        )
    except (ValueError, ArachneError) as exc:
        raise _quality_error(exc) from exc
    stored = _quality(context).add_suppression(rule, project_id=project.id)
    return SuppressionOut.model_validate(stored.to_dict())


@api_router.delete(
    "/suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["quality"]
)
def revoke_suppression(
    suppression_id: int, principal: ScannerPrincipal, context: ContextDep
) -> Response:
    """Revoke a rule. The row stays (a report from before the revocation still reads)."""
    if _quality(context).revoke_suppression(suppression_id, actor=principal.label) is None:
        raise _not_found(f"suppression {suppression_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@api_router.get("/acceptances", response_model=list[AcceptanceOut], tags=["quality"])
def list_acceptances(
    principal: ViewerPrincipal,
    context: ContextDep,
    project: ProjectDep,
    request: Request,
    response: Response,
    finding_id: Annotated[int | None, Query(ge=1)] = None,
    active_only: Annotated[bool, Query()] = True,
    all_projects: Annotated[bool, Query(description="Return every tenant's (S26).")] = False,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[AcceptanceOut]:
    """The risk acceptances recorded for this tenant, and the deployment-wide ones (S26)."""
    del principal
    reject_unknown_query_params(request, frozenset({"finding_id", "active_only", "all_projects"}))
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    rows = _quality(context).list_acceptances(
        finding_id=finding_id,
        active_only=active_only,
        project_id=None if all_projects else project.id,
    )
    page = paginate_sequence(
        rows,
        limit=size,
        key_of=lambda acceptance: acceptance.id,
        id_of=lambda acceptance: acceptance.id or 0,
        descending=True,
        cursor=page_cursor,
    )
    apply_page(response, request, page)
    return [AcceptanceOut.model_validate(row.to_dict()) for row in page.items]


@api_router.post(
    "/acceptances",
    response_model=AcceptanceOut,
    status_code=status.HTTP_201_CREATED,
    tags=["quality"],
)
def create_acceptance(
    payload: AcceptanceIn, principal: ScannerPrincipal, context: ContextDep, project: ProjectDep
) -> AcceptanceOut:
    """Accept a risk until a date: owner, justification and expiry are all mandatory."""
    from datetime import timedelta

    from arachne.quality.acceptance import RiskAcceptance

    if payload.finding_id is not None and context.queries.finding_row(payload.finding_id) is None:
        raise _not_found(f"finding {payload.finding_id} does not exist")
    expires = (
        payload.expires_at.astimezone(UTC)
        if payload.expires_at is not None
        else datetime.now(UTC) + timedelta(days=payload.ttl_days or 30)
    )
    try:
        acceptance = RiskAcceptance(
            finding_id=payload.finding_id,
            check_id=payload.check_id,
            asset_pattern=payload.asset_pattern,
            owner=payload.owner,
            justification=payload.justification,
            expires_at=expires,
            actor=principal.label,
        )
    except (ValueError, ArachneError) as exc:
        raise _quality_error(exc) from exc
    stored = _quality(context).add_acceptance(acceptance, project_id=project.id)
    return AcceptanceOut.model_validate(stored.to_dict())


@api_router.delete(
    "/acceptances/{acceptance_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["quality"]
)
def revoke_acceptance(
    acceptance_id: int, principal: ScannerPrincipal, context: ContextDep
) -> Response:
    """Withdraw an acceptance before its expiry."""
    if _quality(context).revoke_acceptance(acceptance_id, actor=principal.label) is None:
        raise _not_found(f"acceptance {acceptance_id} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@api_router.post("/acceptances/expire", tags=["quality"])
def expire_acceptances(principal: ScannerPrincipal, context: ContextDep) -> dict[str, Any]:
    """Re-open every finding whose acceptance has expired (REQ-QUAL-003).

    Explicit rather than a background daemon: the caller decides *when* the clock is checked,
    and the same call is what a cron job, a scan's admission or an operator uses.
    """
    decisions = _quality(context).reopen_expired()
    for decision in decisions:
        context.auditor.with_actor(principal.actor).record(
            AuditAction.ACCEPTANCE_EXPIRED,
            target=f"finding:{decision.finding_id}",
            reason="the risk acceptance expired; the finding is open again",
            meta=decision.to_dict(),
        )
    return {"reopened": [decision.to_dict() for decision in decisions]}


@api_router.get("/scans/{scan_id}/hypotheses", tags=["quality"])
def scan_hypotheses(
    scan_id: int, principal: ViewerPrincipal, context: ContextDep, project: ProjectDep
) -> JSONResponse:
    """The agentic journal of one scan (S21, REQ-AGENT-002): proposals, decisions, budget."""
    del principal
    record = context.services.store.get_scan(scan_id)
    if record is None or (project.id is not None and record.project_id not in (None, project.id)):
        raise _not_found(f"scan {scan_id} does not exist")
    journal = (record.stats or {}).get("hypotheses")
    if not journal:
        raise _not_found(f"scan {scan_id} ran no agentic reasoning")
    return JSONResponse(journal)


@api_router.post("/scans/{scan_id}/hypotheses/control", tags=["quality"])
def control_hypotheses(
    scan_id: int,
    payload: HypothesisControlIn,
    principal: ScannerPrincipal,
    context: ContextDep,
    project: ProjectDep,
) -> dict[str, Any]:
    """The operator kill switch (S21, REQ-AGENT-007): pause, abort or clear.

    The directive is written where a running scan can read it (a file both processes reach),
    so a scan on another node stops between two hypotheses and leaves a resumable journal.
    """
    from arachne.reasoning.control import build_hypothesis_control

    del principal, project
    control = build_hypothesis_control(context.settings.hypotheses.control_path)
    control.set(scan_id, payload.directive)
    return {"scan_id": scan_id, "directive": payload.directive}


# --------------------------------------------------------------------------- schedules
@api_router.get("/schedules", response_model=list[ScheduleOut], tags=["schedules"])
def list_schedules(
    principal: ViewerPrincipal,
    context: ContextDep,
    request: Request,
    response: Response,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a `next`/`prev` Link header.")
    ] = None,
    limit: Annotated[
        int,
        Query(description=f"Page size, clamped to {MAX_LIMIT}. Values above are not honoured."),
    ] = DEFAULT_LIMIT,
) -> list[ScheduleOut]:
    from arachne.scheduler.store import ScheduleStore

    store = ScheduleStore(context.settings.scheduler.state_path)
    records = [
        ScheduleOut(spec=row.spec.to_dict(), state=row.state.to_dict()) for row in store.load()
    ]
    reject_unknown_query_params(request, frozenset())
    page_cursor = cursor_or_400(cursor)
    size = clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)
    positions = {str(schedule.spec.get("id", "")): index for index, schedule in enumerate(records)}
    page = paginate_sequence(
        records,
        limit=size,
        key_of=lambda schedule: str(schedule.spec.get("id", "")),
        id_of=lambda schedule: positions[str(schedule.spec.get("id", ""))],
        cursor=page_cursor,
    )
    apply_page(response, request, page)
    return page.items


@api_router.post(
    "/schedules",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
    tags=["schedules"],
)
def create_schedule(
    payload: ScheduleIn, principal: ScannerPrincipal, context: ContextDep
) -> ScheduleOut:
    from arachne.scheduler.model import ScheduleSpec, ScheduleState
    from arachne.scheduler.store import ScheduleStore

    spec = ScheduleSpec(
        id=payload.id,
        target=payload.target,
        cron=payload.cron,
        engine=payload.engine,
        active_checks=payload.active_checks,
        modules=tuple(payload.modules),
        checks=tuple(payload.checks),
        enabled=payload.enabled,
    )
    next_run = spec.expression.next_after(datetime.now(UTC).astimezone())
    store = ScheduleStore(context.settings.scheduler.state_path)
    store.upsert(spec, state=ScheduleState(next_run_at=next_run))
    row = store.get(payload.id)
    assert row is not None
    return ScheduleOut(spec=row.spec.to_dict(), state=row.state.to_dict())


@api_router.delete(
    "/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["schedules"]
)
def delete_schedule(schedule_id: str, principal: ScannerPrincipal, context: ContextDep) -> Response:
    from arachne.scheduler.store import ScheduleStore

    if not ScheduleStore(context.settings.scheduler.state_path).remove(schedule_id):
        raise _not_found(f"schedule {schedule_id!r} does not exist")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@api_router.post("/schedules/{schedule_id}/run", tags=["schedules"])
async def run_schedule(
    schedule_id: str, principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Run one schedule now (the same path ``arachne schedule run --id`` uses)."""
    from arachne.scheduler.runner import Scheduler
    from arachne.scheduler.store import ScheduleStore

    store = ScheduleStore(context.settings.scheduler.state_path)
    row = store.get(schedule_id)
    if row is None:
        raise _not_found(f"schedule {schedule_id!r} does not exist")
    scheduler = Scheduler(context.settings, services=context.services)
    run = await scheduler.run_one(row.spec)
    return JSONResponse(run.to_dict())


# --------------------------------------------------------------------------- webhooks
@api_router.get("/webhooks", tags=["webhooks"])
def webhook_status(principal: AdminPrincipal, context: ContextDep) -> JSONResponse:
    """Which integrations are configured (names and threshold, never URLs or tokens)."""
    hooks = context.settings.webhooks
    return JSONResponse(
        {
            "enabled": hooks.enabled,
            "integrations": list(hooks.configured_targets()),
            "min_severity": hooks.min_severity,
            "max_findings": hooks.max_findings,
            "base_url_configured": bool(context.settings.api.base_url),
        }
    )


# --------------------------------------------------------------------------- service accounts
@api_router.get("/service-accounts", tags=["identity"])
def list_service_accounts(principal: AdminPrincipal, context: ContextDep) -> JSONResponse:
    """Every service-account key, newest metadata only — never a secret (REQ-IDAM-003)."""
    store = _service_accounts(context)
    return JSONResponse({"accounts": [record.to_dict() for record in store.list_accounts()]})


@api_router.post("/service-accounts", status_code=status.HTTP_201_CREATED, tags=["identity"])
def create_service_account(
    payload: ServiceAccountIn, principal: AdminPrincipal, context: ContextDep
) -> JSONResponse:
    """Mint a service-account key; the secret is returned **once** and never stored in clear."""
    store = _service_accounts(context)
    if store.get(payload.label) is not None:
        raise _conflict(f"service account {payload.label!r} already exists")
    if payload.project is not None:
        try:
            context.services.projects.resolve(payload.project, create_default=False)
        except ConfigurationError as exc:
            raise _not_found(str(exc)) from exc
    owner = payload.owner or principal.user
    record, secret = store.create(
        payload.label,
        payload.role,
        project=payload.project,
        owner=owner,
        created_by=principal.actor,
        expires_in_s=payload.expires_in_s,
    )
    context.auditor.with_actor(principal.actor).record(
        AuditAction.SERVICE_ACCOUNT_CHANGED,
        target=record.label,
        meta={
            "action": "created",
            "role": record.role,
            "project": record.project,
            "owner": record.owner,
            "expires_at": record.to_dict()["expires_at"],
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return JSONResponse(
        {"account": record.to_dict(), "secret": secret},
        status_code=status.HTTP_201_CREATED,
    )


@api_router.post("/service-accounts/{label}/rotate", tags=["identity"])
def rotate_service_account(
    label: str, principal: AdminPrincipal, context: ContextDep
) -> JSONResponse:
    """Rotate a key: the old secret stops working immediately, the new one is returned once."""
    store = _service_accounts(context)
    rotated = store.rotate(label, actor=principal.actor)
    if rotated is None:
        raise _not_found(f"service account {label!r} does not exist")
    record, secret = rotated
    context.auditor.with_actor(principal.actor).record(
        AuditAction.SERVICE_ACCOUNT_CHANGED,
        target=record.label,
        meta={
            "action": "rotated",
            "actor": principal.label,
            "identity": principal.actor,
        },
    )
    return JSONResponse({"account": record.to_dict(), "secret": secret})


@api_router.post("/service-accounts/{label}/revoke", tags=["identity"])
def revoke_service_account(
    label: str, principal: AdminPrincipal, context: ContextDep
) -> JSONResponse:
    """Revoke a key (it never authenticates again; the row is kept for audit lineage)."""
    store = _service_accounts(context)
    record = store.revoke(label, actor=principal.actor)
    if record is None:
        raise _not_found(f"service account {label!r} does not exist")
    context.auditor.with_actor(principal.actor).record(
        AuditAction.SERVICE_ACCOUNT_CHANGED,
        target=record.label,
        meta={"action": "revoked", "actor": principal.label, "identity": principal.actor},
    )
    return JSONResponse({"account": record.to_dict()})


def _service_accounts(context: AppContext) -> Any:
    store = context.services.service_accounts
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="the identity store is unavailable",
        )
    return store


# --------------------------------------------------------------------------- helpers
def _page_window(cursor: Cursor | None, sort_field: str, descending: bool) -> PageWindow:
    """Turn a decoded cursor (or its absence) into the store's typed page window."""
    if cursor is None:
        return PageWindow(sort_key=sort_field, descending=descending)
    return PageWindow(
        sort_key=sort_field,
        descending=descending,
        boundary=(cursor.key, cursor.item_id),
        backward=cursor.backward,
    )


def _forward_order(rows: Any, cursor: Cursor | None) -> tuple[Any, ...]:
    """Restore the endpoint's forward order after a ``prev`` fetch (which reverses it)."""
    ordered = tuple(rows)
    return tuple(reversed(ordered)) if cursor is not None and cursor.backward else ordered


def _scan_sort_key(sort_field: str) -> Any:
    """The cursor key for a scan row: it must equal the SQL column the ordering uses."""
    if sort_field == "status":
        return lambda record: getattr(record.status, "value", record.status)
    return lambda record: record.id


def _finding_sort_key(sort_field: str) -> Any:
    """The cursor key for a finding row, matching the column ``keyset`` orders by."""
    if sort_field == "severity":
        return lambda row: row.severity or ""
    if sort_field == "status":
        return lambda row: row.status
    if sort_field == "title":
        return lambda row: row.title
    return lambda row: row.id


def _include_unassigned(project: ProjectRecord) -> bool:
    """The default workspace also owns rows written before multi-tenancy (``project_id`` NULL)."""
    return project.slug == DEFAULT_PROJECT_SLUG


def _visible(project_id: int | None, project: ProjectRecord) -> bool:
    """Whether a row belongs to ``project`` (pre-S14 NULL rows belong to the default one)."""
    if project_id is None:
        return _include_unassigned(project)
    return project_id == project.id


def _scan_request(
    payload: StartScanRequest, context: AppContext, *, project: ProjectRecord
) -> ScanRequest:
    """Turn a ``StartScanRequest`` into a validated :class:`ScanRequest`."""
    if payload.target_id is not None:
        record = context.services.target_store.get_target(payload.target_id)
        if record is None or not _visible(record.project_id, project):
            raise _not_found(f"target {payload.target_id} does not exist")
        definition = record.to_definition()
    elif payload.target is not None:
        definition = _definition_from_payload(payload.target)
    else:  # pragma: no cover - the model validator makes this unreachable
        raise ConfigurationError("a scan request needs a target definition or a target id")
    document: dict[str, Any] = {"target": definition.model_dump(mode="json")}
    if payload.options:
        document["options"] = payload.options
    try:
        return ScanRequest.model_validate(document)
    except ArachneError:
        raise
    except Exception as exc:  # pydantic ValidationError → 400 with the reason
        raise ConfigurationError(f"invalid scan request: {exc}") from exc


def _definition_from_payload(payload: dict[str, Any]) -> TargetDefinition:
    try:
        return TargetDefinition.model_validate(payload)
    except Exception as exc:
        raise ConfigurationError(f"invalid target definition: {exc}") from exc


def _scan_summary(record: ScanRecord, counts: dict[str, int], running: bool) -> ScanSummary:
    target_name = record.stats.get("target_name") or record.plan.get("target_name")
    return ScanSummary(
        id=record.id,
        target_id=record.target_id,
        target_name=str(target_name) if target_name else None,
        status=record.status.value,
        engine=record.engine,
        created_at=_iso(record.created_at),
        started_at=_iso(record.started_at),
        finished_at=_iso(record.finished_at),
        counts=dict(counts),
        total_findings=sum(counts.values()),
        running=running,
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _require_scan(context: AppContext, scan_id: int, project: ProjectRecord) -> ScanRecord:
    record = context.services.store.get_scan(scan_id)
    if record is None or not _visible(record.project_id, project):
        raise _not_found(f"scan {scan_id} does not exist")
    return record


def _require_finding(context: AppContext, finding_id: int, project: ProjectRecord) -> int:
    """Ensure the finding's scan belongs to ``project``; returns the scan id."""
    scan_id = context.queries.finding_scan_id(finding_id)
    if scan_id is None:
        raise _not_found(f"finding {finding_id} does not exist")
    _require_scan(context, scan_id, project)
    return scan_id


def _not_found(message: str) -> HTTPException:
    return HTTPException(status_code=404, detail=message)


def _conflict(message: str) -> HTTPException:
    return HTTPException(status_code=409, detail=message)
