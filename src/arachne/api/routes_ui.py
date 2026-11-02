"""The web UI: read-mostly HTML over the same services as the API (F-07-03, S12).

Jinja + a tiny htmx-style runtime, no build step, one process. The pages are:

``/ui/``                 dashboard — recent scans, status, severity counts, severity trend
``/ui/scans``            scan list + controls (start, stop, schedule)
``/ui/scans/{id}``       report viewer — findings by severity, expandable evidence and
                         remediation, filtered by module / asset / CWE
``/ui/modules``          module config — the installed modules and their effective settings
``/ui/schedules``        recurring scans (F-01-05)
``/ui/login``            the API key login that sets the session cookie

Three rules keep the UI a *view* and never a dependency of the scanner:

* It reads through :class:`~arachne.data.api_store.ApiQueryStore` and renders; no page runs
  a check, touches a target or opens a socket.
* State changes go through the same orchestration entry points the CLI/API use (the runner's
  ``start``/``stop``, the scheduler store), so a button press and a ``curl`` do the same
  thing.
* It is authenticated by the same API keys and roles. A browser session is a cookie holding
  the operator's key; state-changing posts additionally require the ``HX-Request`` header
  htmx sends (a cross-site form post cannot forge it), which is the CSRF defense here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from arachne.api.auth import API_KEY_COOKIE, Principal, Role, identify
from arachne.api.deps import ContextDep
from arachne.api.routes_api import _definition_from_payload, _scan_request, _visible
from arachne.api.schemas import StartScanRequest
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import SEVERITY_LEVELS
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.data.project_store import DEFAULT_PROJECT_SLUG, ProjectRecord

__all__ = ["ui_router"]

ui_router = APIRouter(include_in_schema=False)

#: Display order and colours of the severity ladder (most severe first).
_SEVERITY_ORDER = tuple(reversed(SEVERITY_LEVELS))

#: The detail shape a finding gets when the report DTO has no entry for it (a candidate the
#: analyzer has not touched). Complete rather than empty, so the template's key access is
#: total under ``StrictUndefined``.
_EMPTY_DETAIL: dict[str, Any] = {
    "description": "",
    "remediation": None,
    "cvss": None,
    "cvss_vector": None,
    "owasp": None,
    "cwe": None,
    "cve": None,
    "low_confidence": False,
}


# --------------------------------------------------------------------------- auth
def _principal_or_redirect(request: Request, context: ContextDep) -> Principal | RedirectResponse:
    principal = identify(request, context.credentials)
    if principal is None:
        target = request.url.path
        return RedirectResponse(f"/ui/login?next={quote(target)}", status_code=303)
    return principal


def _require_write(request: Request, principal: Principal, minimum: Role) -> None:
    """Enforce a role and the htmx CSRF marker on a UI state change."""
    if not principal.allows(minimum):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role {principal.role.value} is not permitted (requires {minimum.value})",
        )
    if request.headers.get("hx-request", "").lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="state-changing UI requests must come from the interface (HX-Request header)",
        )


def _render(context: ContextDep, template: str, **values: Any) -> HTMLResponse:
    assert context.templates is not None  # built by create_app
    return HTMLResponse(context.templates.get_template(template).render(**values))


def _ui_project(request: Request, context: ContextDep, principal: Principal) -> ProjectRecord:
    """The tenant this browser session is viewing (F-07-06).

    ``?project=``, the ``X-Project`` header or the ``arachne_project`` cookie selects it; a
    key bound to a project can only ever get that project. Every list on the page is then
    filtered by the returned record.
    """
    requested = (
        request.query_params.get("project")
        or request.headers.get("x-project")
        or request.cookies.get("arachne_project")
        or ""
    ).strip()
    if principal.project:
        if requested and requested.lower() != principal.project.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"this key is bound to project {principal.project!r}",
            )
        requested = principal.project
    try:
        return context.services.projects.resolve(requested or None)
    except ConfigurationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


async def _form(request: Request) -> dict[str, str]:
    """Parse an ``application/x-www-form-urlencoded`` body without extra dependencies."""
    body = (await request.body()).decode("utf-8", errors="replace")
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items() if values}


# --------------------------------------------------------------------------- login
@ui_router.get("/ui/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    context: ContextDep,
    next_path: Annotated[str, Query(alias="next")] = "/ui/",
) -> Response:
    if identify(request, context.credentials) is not None:
        return RedirectResponse(next_path, status_code=303)
    return _render(
        context,
        "login.html",
        next=next_path,
        error=None,
        keys_configured=context.credentials.enabled,
        sso_enabled=bool(context.oidc and context.oidc.configured),
    )


@ui_router.post("/ui/login")
async def login(request: Request, context: ContextDep) -> Response:
    form = await _form(request)
    key = (form.get("key") or "").strip()
    next_path = form.get("next") or "/ui/"
    principal = context.credentials.verify_key(key)
    if principal is None:
        context.auditor.record(
            AuditAction.API_DENIED,
            outcome=AuditOutcome.BLOCKED,
            target="/ui/login",
            reason="invalid API key",
        )
        return _render(
            context,
            "login.html",
            next=next_path,
            error="That API key was not accepted.",
            keys_configured=context.credentials.enabled,
            sso_enabled=bool(context.oidc and context.oidc.configured),
        )
    destination = next_path if next_path.startswith("/ui") else "/ui/"
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        API_KEY_COOKIE,
        key,
        max_age=context.settings.api.session_max_age_s,
        httponly=True,
        samesite="strict",
        secure=context.settings.api.tls_configured,
        path="/",
    )
    return response


@ui_router.post("/ui/logout")
async def logout(request: Request) -> Response:
    response = RedirectResponse("/ui/login", status_code=303)
    response.delete_cookie(API_KEY_COOKIE, path="/")
    return response


# --------------------------------------------------------------------------- dashboard
@ui_router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/", status_code=307)


@ui_router.get("/ui/", response_class=HTMLResponse)
def dashboard(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    records = context.services.store.list_scans(
        limit=20,
        project_id=project.id,
        include_unassigned=project.slug == DEFAULT_PROJECT_SLUG,
    )
    counts = context.queries.severity_counts_for([record.id for record in records])
    scans = [
        _scan_view(record, counts.get(record.id, {}), context.runner.is_running(record.id))
        for record in records
    ]
    trend = context.queries.scan_trend(
        limit=15, project_id=project.id, include_unassigned=project.slug == DEFAULT_PROJECT_SLUG
    )
    aggregate = dict.fromkeys(_SEVERITY_ORDER, 0)
    for scan in scans:
        for severity, value in scan["counts"].items():
            if severity in aggregate:
                aggregate[severity] += value
    return _render(
        context,
        "dashboard.html",
        principal=principal,
        scans=scans,
        aggregate=aggregate,
        severities=_SEVERITY_ORDER,
        trend=[point.to_dict() for point in trend],
        trend_max=max((point.total for point in trend), default=1) or 1,
    )


# --------------------------------------------------------------------------- scans
@ui_router.get("/ui/scans", response_class=HTMLResponse)
def scans_page(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    records = context.services.store.list_scans(
        limit=50, project_id=project.id, include_unassigned=project.slug == DEFAULT_PROJECT_SLUG
    )
    counts = context.queries.severity_counts_for([record.id for record in records])
    targets = context.services.target_store.list_targets(
        limit=100, project_id=project.id, include_unassigned=project.slug == DEFAULT_PROJECT_SLUG
    )
    return _render(
        context,
        "scans.html",
        principal=principal,
        project=project.to_dict(),
        scans=[
            _scan_view(record, counts.get(record.id, {}), context.runner.is_running(record.id))
            for record in records
        ],
        targets=[record.to_dict() for record in targets],
        severities=_SEVERITY_ORDER,
    )


@ui_router.post("/ui/scans")
async def start_scan(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    project = _ui_project(request, context, principal)
    form = await _form(request)
    payload = _start_request_from_form(form)
    scan_request = _scan_request(payload, context, project=project)
    started = await context.runner.start(
        scan_request, project_id=project.id, project_scope=project.to_scope()
    )
    return RedirectResponse(f"/ui/scans/{started.scan_id}", status_code=303)


@ui_router.post("/ui/scans/{scan_id}/stop")
async def stop_scan(request: Request, scan_id: int, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    project = _ui_project(request, context, principal)
    _require_visible_scan(context, scan_id, project)
    await context.runner.stop(scan_id)
    return RedirectResponse(f"/ui/scans/{scan_id}", status_code=303)


def _require_visible_scan(context: ContextDep, scan_id: int, project: ProjectRecord) -> Any:
    record = context.services.store.get_scan(scan_id)
    if record is None or not _visible(record.project_id, project):
        raise HTTPException(status_code=404, detail=f"scan {scan_id} does not exist")
    return record


@ui_router.get("/ui/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    record = _require_visible_scan(context, scan_id, project)
    filters = _filters(request)
    return _render(
        context,
        "scan_detail.html",
        principal=principal,
        scan=_scan_view(
            record, context.queries.severity_counts(scan_id), context.runner.is_running(scan_id)
        ),
        steps=[
            {
                "step": state.step.value,
                "status": state.status.value,
                "attempts": state.attempts,
                "error": state.error,
            }
            for state in record.steps
        ],
        assets=[
            {"kind": item.kind, "value": item.value}
            for item in context.services.store.list_assets(scan_id)
        ],
        severities=_SEVERITY_ORDER,
        filters=filters,
        findings=_findings_view(context, scan_id, filters, _report_index(context, scan_id)),
    )


@ui_router.get("/ui/scans/{scan_id}/findings", response_class=HTMLResponse)
def scan_findings_partial(request: Request, scan_id: int, context: ContextDep) -> Response:
    """The findings table on its own (htmx swaps this in when a filter changes)."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    _require_visible_scan(context, scan_id, project)
    filters = _filters(request)
    return _render(
        context,
        "_findings.html",
        scan_id=scan_id,
        findings=_findings_view(context, scan_id, filters, _report_index(context, scan_id)),
        filters=filters,
        severities=_SEVERITY_ORDER,
    )


@ui_router.get("/ui/scans/{scan_id}/report", response_class=HTMLResponse)
def scan_report(request: Request, scan_id: int, context: ContextDep) -> Response:
    """The rendered Markdown report, as plain text inside a ``<pre>``."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    _require_visible_scan(context, scan_id, project)
    report = context.reports.build(scan_id)
    from arachne.report import render_markdown

    return _render(
        context,
        "report_text.html",
        principal=principal,
        scan_id=scan_id,
        body=render_markdown(report),
    )


@ui_router.get("/ui/scans/{scan_id}/attack-paths", response_class=HTMLResponse)
def scan_attack_paths(request: Request, scan_id: int, context: ContextDep) -> Response:
    """The attack-path graph for one scan (S26, REQ-ECOS-004).

    The graph is the report's own ``attack_paths`` block rendered as SVG: same data the
    Markdown section and the JSON report carry, so the picture cannot disagree with the
    document an operator forwards.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    _require_visible_scan(context, scan_id, project)
    from arachne.api.ui_visuals import attack_path_svg

    report = context.reports.build(scan_id)
    paths = [entry.model_dump(mode="json") for entry in report.attack_paths]
    record = context.services.store.get_scan(scan_id)
    counts = context.queries.severity_counts(scan_id)
    scan = (
        _scan_view(record, counts, context.runner.is_running(scan_id))
        if record is not None
        else {"id": scan_id, "target": f"scan {scan_id}"}
    )
    return _render(
        context,
        "attack_paths.html",
        principal=principal,
        scan_id=scan_id,
        scan=scan,
        paths=paths,
        graph=attack_path_svg(paths),
    )


# --------------------------------------------------------------------------- executive dashboard
@ui_router.get("/ui/posture", response_class=HTMLResponse)
def posture_page(request: Request, context: ContextDep) -> Response:
    """The executive dashboard: posture trend, drift and control coverage (S26, REQ-ECOS-004).

    Assembled from stored rows only (:func:`~arachne.posture.estate.assemble_estate`) — the same
    join ``arachne posture report`` uses — plus the newest scan's compliance block. Control
    coverage is deliberately taken from *one* scan and labelled with its id rather than averaged
    across scans: "coverage" is a statement about a set of checks that ran, and an average over
    scans that ran different checks would be a number nobody could act on.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    from arachne.api.ui_visuals import coverage_bars_svg, posture_trend_svg
    from arachne.posture.estate import assemble_estate
    from arachne.posture.trend import estate_payload

    project = _ui_project(request, context, principal)
    include_default = project.slug == DEFAULT_PROJECT_SLUG
    estate = assemble_estate(
        context.services,
        project_id=None if include_default else project.id,
        name=project.name,
        limit=15,
    )
    payload = estate_payload(estate)
    coverage: list[dict[str, Any]] = []
    coverage_scan: int | None = None
    if estate.points:
        newest = estate.points[-1].scan_id
        try:
            report = context.reports.build(newest)
        except ArachneError:  # pragma: no cover - a scan that vanished mid-page
            report = None
        if report is not None and report.compliance:
            coverage_scan = newest
            coverage = [block.model_dump(mode="json") for block in report.compliance]
    return _render(
        context,
        "posture.html",
        principal=principal,
        project=project,
        severities=_SEVERITY_ORDER,
        estate=payload,
        trend_svg=posture_trend_svg(payload["scans"]),
        coverage_svg=coverage_bars_svg(coverage),
        coverage=coverage,
        coverage_scan=coverage_scan,
    )


# --------------------------------------------------------------------------- modules
@ui_router.get("/ui/modules", response_class=HTMLResponse)
def modules_page(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    registry = context.services.registry
    stored = {row.key for row in context.queries.list_checks()}
    modules = []
    for group in registry.groups:
        modules.append(
            {
                "id": group.id,
                "version": group.version,
                "step": group.step.value,
                "checks": [
                    {
                        "id": metadata.id,
                        "title": metadata.title,
                        "version": metadata.version,
                        "research_ref": metadata.research_ref,
                        "cwe": metadata.cwe,
                        "active": metadata.requires_active_checks,
                        "opt_in": not metadata.enabled_by_default,
                        "ran": metadata.key in stored,
                    }
                    for metadata in group.metadata()
                ],
            }
        )
    settings = context.settings
    return _render(
        context,
        "modules.html",
        principal=principal,
        modules=modules,
        config={
            "database": settings.database_url,
            "per_host_rate": settings.rate_limit.per_host_rate,
            "global_rate": settings.rate_limit.global_rate,
            "api_rate": settings.api.rate_limit_per_minute,
            "tls_required": settings.api.require_tls,
            "scope_hosts": list(settings.safety.scope.allowed_hosts),
            "scope_domains": list(settings.safety.scope.allowed_domains),
            "webhooks": list(settings.webhooks.configured_targets()),
            "engine": settings.ai.engine or "heuristic",
        },
    )


# --------------------------------------------------------------------------- feeds
@ui_router.get("/ui/feeds", response_class=HTMLResponse)
def feeds_page(request: Request, context: ContextDep) -> Response:
    """The CVE/EPSS ingestion page (F-09-03): status, imported artefacts, upload form."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    services = context.services
    return _render(
        context,
        "feeds.html",
        principal=principal,
        stats=services.feeds.stats(),
        feeds=[record.to_dict() for record in services.feeds.list_feeds(limit=100)],
        active_epss=services.feeds.effective_path("epss"),
        active_kev=services.feeds.effective_path("kev"),
        error=request.query_params.get("error"),
    )


@ui_router.post("/ui/feeds/import")
async def import_feed_ui(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    form = await _form(request)
    kind = (form.get("kind") or "").strip().lower()
    name = (form.get("name") or "").strip()
    content = form.get("content") or ""
    try:
        context.services.feeds.import_text(
            content,
            kind=kind,
            name=name or kind,
            source=f"ui:{principal.label}",
            imported_by=principal.label,
            max_entries=context.settings.feeds.max_entries,
        )
    except ConfigurationError as exc:
        return RedirectResponse(f"/ui/feeds?error={quote(str(exc))}", status_code=303)
    context.auditor.record(
        AuditAction.FEED_IMPORTED,
        target=name or kind,
        meta={"kind": kind, "actor": principal.label},
    )
    return RedirectResponse("/ui/feeds", status_code=303)


@ui_router.post("/ui/feeds/{feed_id}/delete")
async def delete_feed_ui(request: Request, feed_id: int, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    context.services.feeds.delete(feed_id)
    return RedirectResponse("/ui/feeds", status_code=303)


# --------------------------------------------------------------------------- quality (S21)
def _findings_view_scan(context: ContextDep, scan_id: int) -> Any:
    return context.services.store.get_scan(scan_id)


@ui_router.get("/ui/quality", response_class=HTMLResponse)
def quality_page(
    request: Request,
    context: ContextDep,
    error: str | None = None,
    scope: str | None = None,
) -> Response:
    """Tenant self-service for the FP and risk-acceptance workflow (REQ-QUAL-001...003, S26).

    The page is the *tenant's* view: rules and acceptances are scoped to the selected project,
    and the deployment-wide ones (``project_id IS NULL``, which is every pre-S26 row) are shown
    alongside them because they apply here too. ``?scope=all`` is the MSSP operator's
    cross-customer audit view. A viewer may read both; recording or revoking needs the scanner
    role, which is the same boundary the API enforces.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    show_all = (scope or "").strip().lower() == "all"
    store = getattr(context.services, "quality", None)
    suppressions = (
        store.list_suppressions(active_only=False, project_id=None if show_all else project.id)
        if store is not None
        else []
    )
    acceptances = (
        store.list_acceptances(active_only=False, project_id=None if show_all else project.id)
        if store is not None
        else []
    )
    version = max((item.version for item in suppressions), default=0)
    return _render(
        context,
        "quality.html",
        principal=principal,
        project=project,
        scope_all=show_all,
        suppressions=suppressions,
        acceptances=acceptances,
        version=version,
        error=error,
    )


@ui_router.post("/ui/quality/suppressions")
async def add_suppression_ui(request: Request, context: ContextDep) -> Response:
    """Record a suppression from the UI: same rule, same store, same audit trail as the API."""
    from arachne.quality.suppressions import Suppression

    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    store = getattr(context.services, "quality", None)
    if store is None:
        return RedirectResponse("/ui/quality?error=no+quality+store", status_code=303)
    project = _ui_project(request, context, principal)
    form = await _form(request)
    finding_id = (form.get("finding_id") or "").strip()
    try:
        rule = Suppression(
            kind=(form.get("kind") or "rule").strip().lower(),  # type: ignore[arg-type]
            check_id=(form.get("check_id") or "").strip() or None,
            asset_pattern=(form.get("asset_pattern") or "").strip() or None,
            finding_id=int(finding_id) if finding_id.isdigit() else None,
            reason=(form.get("reason") or "").strip(),
            actor=principal.label,
        )
    except (ValueError, ArachneError) as exc:
        return RedirectResponse(f"/ui/quality?error={quote(str(exc))}", status_code=303)
    store.add_suppression(rule, project_id=project.id)
    return RedirectResponse("/ui/quality", status_code=303)


@ui_router.post("/ui/quality/suppressions/{suppression_id}/revoke")
async def revoke_suppression_ui(
    request: Request, suppression_id: int, context: ContextDep
) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    store = getattr(context.services, "quality", None)
    if store is not None:
        store.revoke_suppression(suppression_id, actor=principal.label)
    return RedirectResponse("/ui/quality", status_code=303)


@ui_router.post("/ui/quality/acceptances")
async def add_acceptance_ui(request: Request, context: ContextDep) -> Response:
    """Accept a risk from the UI: owner, justification and an expiry are all required."""
    from datetime import UTC, datetime, timedelta

    from arachne.quality.acceptance import RiskAcceptance

    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    store = getattr(context.services, "quality", None)
    if store is None:
        return RedirectResponse("/ui/quality?error=no+quality+store", status_code=303)
    project = _ui_project(request, context, principal)
    form = await _form(request)
    finding_id = (form.get("finding_id") or "").strip()
    days = (form.get("ttl_days") or "").strip()
    try:
        acceptance = RiskAcceptance(
            finding_id=int(finding_id) if finding_id.isdigit() else None,
            check_id=(form.get("check_id") or "").strip() or None,
            owner=(form.get("owner") or "").strip(),
            justification=(form.get("justification") or "").strip(),
            expires_at=datetime.now(UTC) + timedelta(days=int(days) if days.isdigit() else 30),
            actor=principal.label,
        )
    except (ValueError, ArachneError) as exc:
        return RedirectResponse(f"/ui/quality?error={quote(str(exc))}", status_code=303)
    store.add_acceptance(acceptance, project_id=project.id)
    return RedirectResponse("/ui/quality", status_code=303)


@ui_router.post("/ui/quality/acceptances/{acceptance_id}/revoke")
async def revoke_acceptance_ui(
    request: Request, acceptance_id: int, context: ContextDep
) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    store = getattr(context.services, "quality", None)
    if store is not None:
        store.revoke_acceptance(acceptance_id, actor=principal.label)
    return RedirectResponse("/ui/quality", status_code=303)


@ui_router.post("/ui/quality/expire")
async def expire_acceptances_ui(request: Request, context: ContextDep) -> Response:
    """Re-open every finding whose acceptance expired (REQ-QUAL-003)."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    store = getattr(context.services, "quality", None)
    if store is not None:
        store.reopen_expired()
    return RedirectResponse("/ui/quality", status_code=303)


@ui_router.post("/ui/findings/{finding_id}/fp")
async def mark_false_positive_ui(
    request: Request, finding_id: int, context: ContextDep
) -> Response:
    """Mark a finding a false positive from the finding list (REQ-QUAL-001's UI half).

    The same key and the same feedback row the API's ``PATCH /findings/{id}`` writes, so a
    decision taken in the interface adjusts the same threshold a decision taken through the
    API would (ADR-02: one learner).
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    row = context.queries.finding_row(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"finding {finding_id} does not exist")
    updated = context.queries.set_finding_status(finding_id, "fp")
    from arachne.analyzer.fp import FeedbackRecord, feedback_key_for

    context.services.analyses.record_feedback(
        FeedbackRecord(
            key=feedback_key_for(row.check_id, row.asset_kind),
            is_fp=True,
            finding_id=finding_id,
            note="marked a false positive in the interface",
        ),
        actor=principal.label,
    )
    context.auditor.with_actor(principal.actor).record(
        AuditAction.FINDING_REVIEWED,
        scan_id=updated.scan_id if updated is not None else None,
        target=f"finding:{finding_id}",
        meta={"status": "fp", "is_fp": True, "actor": principal.label},
    )
    return RedirectResponse(request.headers.get("referer") or "/ui/scans", status_code=303)


# --------------------------------------------------------------------------- plugins
@ui_router.get("/ui/plugins", response_class=HTMLResponse)
def plugins_page(request: Request, context: ContextDep) -> Response:
    """Installed check/report-format plugins and the marketplace listing (F-09-01)."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    from arachne.plugins import installed_plugins
    from arachne.plugins.marketplace import load_marketplace
    from arachne.report import default_registry

    catalogue = load_marketplace(context.settings.plugins.marketplace)
    return _render(
        context,
        "plugins.html",
        principal=principal,
        installed=installed_plugins(),
        formats=default_registry().summary(),
        marketplace=catalogue.listing(),
        marketplace_version=catalogue.version,
        install_enabled=context.settings.plugins.allow_install,
    )


# --------------------------------------------------------------------------- schedules
@ui_router.get("/ui/schedules", response_class=HTMLResponse)
def schedules_page(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    from arachne.scheduler.store import ScheduleStore

    rows = ScheduleStore(context.settings.scheduler.state_path).load()
    return _render(
        context,
        "schedules.html",
        principal=principal,
        schedules=[{"spec": row.spec.to_dict(), "state": row.state.to_dict()} for row in rows],
    )


@ui_router.post("/ui/schedules")
async def create_schedule(request: Request, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    from arachne.scheduler.model import ScheduleSpec, ScheduleState
    from arachne.scheduler.store import ScheduleStore

    form = await _form(request)
    try:
        spec = ScheduleSpec(
            id=(form.get("id") or "").strip(),
            target=(form.get("target") or "").strip(),
            cron=(form.get("cron") or "").strip(),
            engine=(form.get("engine") or None),
            active_checks=(form.get("active_checks") == "on") if "active_checks" in form else None,
        )
    except ConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store = ScheduleStore(context.settings.scheduler.state_path)
    next_run = spec.expression.next_after(datetime.now(UTC))
    store.upsert(spec, state=ScheduleState(next_run_at=next_run))
    return RedirectResponse("/ui/schedules", status_code=303)


@ui_router.post("/ui/schedules/{schedule_id}/remove")
async def remove_schedule(request: Request, schedule_id: str, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    from arachne.scheduler.store import ScheduleStore

    ScheduleStore(context.settings.scheduler.state_path).remove(schedule_id)
    return RedirectResponse("/ui/schedules", status_code=303)


@ui_router.post("/ui/schedules/{schedule_id}/run")
async def run_schedule(request: Request, schedule_id: str, context: ContextDep) -> Response:
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    from arachne.scheduler.runner import Scheduler
    from arachne.scheduler.store import ScheduleStore

    row = ScheduleStore(context.settings.scheduler.state_path).get(schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"schedule {schedule_id!r} does not exist")
    run = await Scheduler(context.settings, services=context.services).run_one(row.spec)
    target = run.scan_id if run.scan_id is not None else ""
    return RedirectResponse(f"/ui/scans/{target}" if target else "/ui/scans", status_code=303)


# --------------------------------------------------------------------------- helpers
def _scan_view(record: Any, counts: dict[str, int], running: bool) -> dict[str, Any]:
    target_name = record.stats.get("target_name") or record.plan.get("target_name")
    return {
        "id": record.id,
        "target": target_name or f"scan {record.id}",
        "status": record.status.value,
        "engine": record.engine,
        "created_at": _when(record.created_at),
        "started_at": _when(record.started_at),
        "finished_at": _when(record.finished_at),
        "counts": {severity: int(counts.get(severity, 0)) for severity in _SEVERITY_ORDER},
        "total": sum(int(counts.get(severity, 0)) for severity in _SEVERITY_ORDER),
        "running": running,
    }


def _report_index(context: ContextDep, scan_id: int) -> dict[int, dict[str, Any]]:
    """Enrichment from the report DTO, keyed by the stored finding id.

    The report viewer wants the *analysed* prose (narrative, resolved remediation, score,
    OWASP category) as well as the raw row. Building the report once and indexing it by the
    ``F-000042`` → ``42`` id keeps the page to one store read rather than one per finding.
    """
    try:
        report = context.reports.build(scan_id)
    except Exception:  # a scan with no analysable rows still renders its raw findings
        return {}
    index: dict[int, dict[str, Any]] = {}
    for finding in (*report.findings, *report.low_confidence):
        try:
            db_id = int(finding.id.split("-", 1)[1])
        except (IndexError, ValueError):  # pragma: no cover - id format is ours
            continue
        index[db_id] = {
            "description": finding.description,
            "remediation": {
                "id": finding.remediation.id,
                "summary": finding.remediation.summary,
                "steps": list(finding.remediation.steps),
                "verification": list(finding.remediation.verification),
                "references": list(finding.remediation.references),
                "source": finding.remediation.source,
            },
            "cvss": finding.score.cvss_base,
            "cvss_vector": finding.score.cvss_vector,
            "owasp": finding.classification.owasp_2025,
            "cwe": finding.classification.cwe,
            "cve": finding.classification.cve,
            "low_confidence": finding.low_confidence,
        }
    return index


def _findings_view(
    context: ContextDep,
    scan_id: int,
    filters: dict[str, str],
    index: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = context.queries.finding_rows(
        scan_id=scan_id,
        module=filters.get("module") or None,
        severity=filters.get("severity") or None,
        cwe=filters.get("cwe") or None,
        asset=filters.get("asset") or None,
        query=filters.get("q") or None,
        limit=500,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        payload = row.to_dict()
        result.append(
            {
                "finding": payload,
                "detail": index.get(row.id, _EMPTY_DETAIL),
                # The numeric row id, so a template can address the review actions without
                # parsing the report's ``F-000042`` form (S21).
                "finding_id": row.id,
                "evidence": list(context.queries.evidence_rows(row.id)),
            }
        )
    return result


def _filters(request: Request) -> dict[str, str]:
    return {
        key: (request.query_params.get(key) or "").strip()
        for key in ("module", "severity", "cwe", "asset", "q")
    }


def _when(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value is not None else "—"


def _start_request_from_form(form: dict[str, str]) -> StartScanRequest:
    """Build a :class:`StartScanRequest` from the UI's start form."""
    target_id = (form.get("target_id") or "").strip()
    definition = (form.get("definition") or "").strip()
    options: dict[str, Any] = {}
    engine = (form.get("engine") or "").strip()
    if engine:
        options["engine"] = engine
    if "active_checks" in form:
        options["active_checks"] = form.get("active_checks") == "on"
    if not target_id and not definition:
        raise HTTPException(status_code=400, detail="choose a stored target or paste a definition")
    payload: dict[str, Any] = {"options": options}
    if target_id:
        payload["target_id"] = int(target_id)
    else:
        payload["target"] = _definition_from_payload(_parse_definition(definition)).model_dump(
            mode="json"
        )
    return StartScanRequest.model_validate(payload)


def _parse_definition(text: str) -> dict[str, Any]:
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400, detail=f"definition must be a JSON object: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="definition must be a JSON object")
    # Accept either a bare definition or a {target: {...}} document.
    return data.get("target", data) if isinstance(data.get("target"), dict) else data
