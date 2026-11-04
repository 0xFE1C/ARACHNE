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

import asyncio
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import parse_qs, quote, urlencode

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from arachne.api.auth import API_KEY_COOKIE, Principal, Role, identify
from arachne.api.deps import ContextDep
from arachne.api.filters import FINDING_FILTER_FIELDS
from arachne.api.pagination import (
    build_page,
    clamp_limit,
    cursor_or_400,
    reject_unknown_query_params,
)
from arachne.api.routes_api import (
    _definition_from_payload,
    _require_finding,
    _scan_request,
    _visible,
)
from arachne.api.schemas import StartScanRequest
from arachne.api.workspace import (
    MAX_BULK_FINDINGS,
    TRIAGE_STATUS,
    BulkAction,
    UndoRecord,
    UndoTarget,
    UndoUnavailableError,
    UndoWindowClosedError,
    new_undo_record,
    now_utc,
    parse_bulk_action,
    shortcut_sheet,
    store_for,
)
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import SEVERITY_LEVELS
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.core.logging import get_logger
from arachne.data.keyset import PageWindow
from arachne.data.project_store import DEFAULT_PROJECT_SLUG, ProjectRecord
from arachne.i18n import format_number, pluralize, translate
from arachne.modules.coverage import build_ledger

__all__ = ["ui_router"]

_logger = get_logger("api.ui")

ui_router = APIRouter(include_in_schema=False)

#: Display order and colours of the severity ladder (most severe first).
_SEVERITY_ORDER = tuple(reversed(SEVERITY_LEVELS))

#: The two preference cookies (REQ-UIX-009). Written only by ``POST /ui/preferences`` and
#: validated again on every read, so a hand-edited cookie cannot put an arbitrary string into
#: the ``data-theme``/``data-density`` attributes.
THEME_COOKIE = "arachne_theme"
DENSITY_COOKIE = "arachne_density"
_THEMES: tuple[str, ...] = ("light", "dark")
_DENSITIES: tuple[str, ...] = ("comfortable", "compact")

#: How many findings the workspace lists per page (the API's own default, REQ-UIX-001).
_UI_PAGE_LIMIT = 50

#: How long a display preference lasts in the browser (30 days).
_PREFERENCE_MAX_AGE = 30 * 24 * 3600

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


def _render(
    context: ContextDep,
    template: str,
    *,
    request: Request | None = None,
    **values: Any,
) -> HTMLResponse:
    """Render a screen with the state-matrix and preference defaults filled in.

    ``state``, ``partial`` and ``refused`` are the five-state matrix's inputs (REQ-UIX-005) and
    ``theme``/``density`` are the persisted display preferences (REQ-UIX-009); every screen
    template reads them, so defaulting them here is what keeps a route that forgets one from
    failing under ``StrictUndefined`` instead of rendering the wrong state.
    """
    values.setdefault("state", "ready")
    values.setdefault("empty", False)
    values.setdefault("partial", False)
    values.setdefault("refused", False)
    values.setdefault("theme", _preference(request, THEME_COOKIE, _THEMES))
    values.setdefault("density", _preference(request, DENSITY_COOKIE, _DENSITIES))
    values.setdefault("current_path", request.url.path if request is not None else "/ui/")
    assert context.templates is not None  # built by create_app
    return HTMLResponse(context.templates.get_template(template).render(**values))


def _preference(request: Request | None, name: str, allowed: tuple[str, ...]) -> str | None:
    """The validated value of a display-preference cookie; ``None`` means "follow the system"."""
    if request is None:
        return None
    raw = (request.cookies.get(name) or "").strip().lower()
    return raw if raw in allowed else None


def _read_only(principal: Principal) -> bool:
    """True when the session cannot change anything, which is the §4 screens' ``refused`` state."""
    return not principal.allows(Role.SCANNER)


def _sso_missing_setting(context: ContextDep) -> str | None:
    """The SSO setting that is absent while SSO is switched on (the sign-in screen's partial).

    §4.1 asks the SSO button to name the missing setting when the IdP is misconfigured rather
    than to disappear silently. The provider is only built from a *complete* configuration, so
    this is the one place that can still say which value an operator has to set.
    """
    sso = context.settings.sso
    if not sso.enabled:
        return None
    if not sso.issuer:
        return "ARACHNE_SSO_ISSUER"
    if not sso.client_id:
        return "ARACHNE_SSO_CLIENT_ID"
    if sso.client_secret is None:
        return "ARACHNE_SSO_CLIENT_SECRET"
    return None


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
    missing = _sso_missing_setting(context)
    return _render(
        context,
        "login.html",
        request=request,
        next=next_path,
        error=None,
        keys_configured=context.credentials.enabled,
        sso_enabled=bool(context.oidc and context.oidc.configured),
        partial=missing is not None,
        sso_warning=missing,
    )


@ui_router.post("/ui/login")
async def login(request: Request, context: ContextDep) -> Response:
    form = await _form(request)
    key = (form.get("key") or "").strip()
    next_path = form.get("next") or "/ui/"
    # REQ-SCALE-013 (WP-17): the credential store and the audit sink are synchronous and
    # touch a file/database. Called inline from this ``async def`` they block every other
    # request on the loop for the duration of that I/O; a worker thread keeps the loop free
    # while the answer is identical.
    principal = await asyncio.to_thread(context.credentials.verify_key, key)
    if principal is None:
        await asyncio.to_thread(
            context.auditor.record,
            AuditAction.API_DENIED,
            outcome=AuditOutcome.BLOCKED,
            target="/ui/login",
            reason="invalid API key",
        )
        missing = _sso_missing_setting(context)
        return _render(
            context,
            "login.html",
            request=request,
            next=next_path,
            error=translate("ui.login.rejected"),
            keys_configured=context.credentials.enabled,
            sso_enabled=bool(context.oidc and context.oidc.configured),
            partial=missing is not None,
            sso_warning=missing,
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


@ui_router.post("/ui/preferences")
async def set_preferences(request: Request) -> Response:
    """Persist the display preferences per user (REQ-UIX-009).

    Each button in the header submits only its own name, so one click changes one preference.
    The value is validated against a closed vocabulary before it is stored, and the cookie is
    ``SameSite=strict`` like the session cookie — a cross-site form post therefore carries no
    session and cannot set a preference either. Nothing here is a state change to scanned data,
    so there is no audit event and no ``HX-Request`` requirement: the effect is confined to the
    caller's own browser.
    """
    form = await _form(request)
    response = RedirectResponse(_same_origin(form.get("next") or "/ui/"), status_code=303)
    theme = (form.get("theme") or "").strip().lower()
    density = (form.get("density") or "").strip().lower()
    if theme == "system":
        response.delete_cookie(THEME_COOKIE, path="/")
    elif theme in _THEMES:
        response.set_cookie(
            THEME_COOKIE,
            theme,
            max_age=_PREFERENCE_MAX_AGE,
            httponly=True,
            samesite="strict",
            path="/",
        )
    if density in _DENSITIES:
        response.set_cookie(
            DENSITY_COOKIE,
            density,
            max_age=_PREFERENCE_MAX_AGE,
            httponly=True,
            samesite="strict",
            path="/",
        )
    return response


def _same_origin(next_path: str) -> str:
    """Only ever redirect back into the interface (never an attacker-supplied URL)."""
    return next_path if next_path.startswith("/ui") else "/ui/"


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
    try:
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
    except Exception:  # a failing panel must not blank the page (§4.2 error, REQ-UIX-005)
        _logger.exception("the overview could not be loaded")
        return _render(
            context, "dashboard.html", request=request, principal=principal, state="error"
        )
    aggregate = dict.fromkeys(_SEVERITY_ORDER, 0)
    for scan in scans:
        for severity, value in scan["counts"].items():
            if severity in aggregate:
                aggregate[severity] += value
    return _render(
        context,
        "dashboard.html",
        request=request,
        state="ready",
        empty=not records,
        refused=_read_only(principal),
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
    try:
        project = _ui_project(request, context, principal)
        records = context.services.store.list_scans(
            limit=50, project_id=project.id, include_unassigned=project.slug == DEFAULT_PROJECT_SLUG
        )
        counts = context.queries.severity_counts_for([record.id for record in records])
        targets = context.services.target_store.list_targets(
            limit=100,
            project_id=project.id,
            include_unassigned=project.slug == DEFAULT_PROJECT_SLUG,
        )
    except Exception:  # §4.5 error: an error block, not a blank page
        _logger.exception("the scan history could not be loaded")
        return _render(
            context,
            "scans.html",
            request=request,
            principal=principal,
            state="error",
            targets=[],
            severities=_SEVERITY_ORDER,
        )
    return _render(
        context,
        "scans.html",
        request=request,
        state="ready",
        empty=not records,
        refused=_read_only(principal),
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
    partial = False
    try:
        counts = context.queries.severity_counts(scan_id)
        findings = _findings_view(context, scan_id, filters, _report_index(context, scan_id))
        assets = [
            {"kind": item.kind, "value": item.value}
            for item in context.services.store.list_assets(scan_id)
        ]
    except Exception:
        # §4.6 error: section-level. The status and the pipeline keep rendering (progress
        # keeps polling), so a failed findings read is a partial page, never a blank one.
        _logger.exception("the findings section of scan %s could not be loaded", scan_id)
        counts, findings, assets, partial = {}, [], [], True
    steps = [
        {
            "step": state.step.value,
            "status": state.status.value,
            "attempts": state.attempts,
            "error": state.error,
        }
        for state in record.steps
    ]
    return _render(
        context,
        "scan_detail.html",
        request=request,
        principal=principal,
        # §4.6 empty: a dry run has a plan and no findings, and says so explicitly.
        empty=bool(record.plan.get("dry_run")),
        partial=partial,
        refused=_read_only(principal),
        scan=_scan_view(record, counts, context.runner.is_running(scan_id)),
        steps=steps,
        assets=assets,
        severities=_SEVERITY_ORDER,
        filters=filters,
        findings=findings,
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
        request=request,
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
    record = _require_visible_scan(context, scan_id, project)
    if record.plan.get("dry_run"):
        # §4.7 empty: a dry run produced no report yet.
        return _render(
            context,
            "report_text.html",
            request=request,
            principal=principal,
            empty=True,
            scan_id=scan_id,
        )
    try:
        report = context.reports.build(scan_id)
        from arachne.report import render_markdown

        body = render_markdown(report)
    except Exception:  # §4.7 error: an error block, and the export stays unavailable
        _logger.exception("the report for scan %s could not be rendered", scan_id)
        return _render(
            context,
            "report_text.html",
            request=request,
            principal=principal,
            state="error",
            scan_id=scan_id,
        )
    return _render(
        context,
        "report_text.html",
        request=request,
        principal=principal,
        refused=_read_only(principal),
        scan_id=scan_id,
        body=body,
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
    record = _require_visible_scan(context, scan_id, project)
    from arachne.api.ui_visuals import attack_path_svg

    try:
        report = context.reports.build(scan_id)
        paths = [entry.model_dump(mode="json") for entry in report.attack_paths]
        graph = attack_path_svg(paths)
    except Exception:  # §4.8 error: an error block, not a blank canvas
        _logger.exception("the attack paths for scan %s could not be composed", scan_id)
        return _render(
            context,
            "attack_paths.html",
            request=request,
            principal=principal,
            state="error",
            scan_id=scan_id,
            # The header and the legend render before the state block, so the error render
            # still needs the two values they read.
            scan=_scan_view(record, {}, False),
            paths=[],
        )
    counts = context.queries.severity_counts(scan_id)
    scan = (
        _scan_view(record, counts, context.runner.is_running(scan_id))
        if record is not None
        else {"id": scan_id, "target": f"scan {scan_id}"}
    )
    return _render(
        context,
        "attack_paths.html",
        request=request,
        principal=principal,
        empty=not paths,
        refused=_read_only(principal),
        scan_id=scan_id,
        scan=scan,
        paths=paths,
        graph=graph,
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

    try:
        project = _ui_project(request, context, principal)
        include_default = project.slug == DEFAULT_PROJECT_SLUG
        estate = assemble_estate(
            context.services,
            project_id=None if include_default else project.id,
            name=project.name,
            limit=15,
        )
        payload = estate_payload(estate)
    except Exception:  # §4.9 error: card-level, never a blank dashboard
        _logger.exception("the posture dashboard could not be assembled")
        return _render(context, "posture.html", request=request, principal=principal, state="error")
    coverage: list[dict[str, Any]] = []
    coverage_scan: int | None = None
    partial = False
    if estate.points:
        newest = estate.points[-1].scan_id
        try:
            report = context.reports.build(newest)
        except Exception:
            # §4.9 partial: the trend is intact, the newest scan's coverage is not. The other
            # cards still render and the failure is stated rather than hidden.
            _logger.exception("the coverage block of scan %s could not be read", newest)
            report = None
            partial = True
        if report is not None and report.compliance:
            coverage_scan = newest
            coverage = [block.model_dump(mode="json") for block in report.compliance]
    return _render(
        context,
        "posture.html",
        request=request,
        principal=principal,
        empty=not estate.points,
        partial=partial,
        refused=_read_only(principal),
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
    try:
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
                            "framework": ", ".join(metadata.framework) or "—",
                            "active": metadata.requires_active_checks,
                            "opt_in": not metadata.enabled_by_default,
                            "ran": metadata.key in stored,
                        }
                        for metadata in group.metadata()
                    ],
                }
            )
        # §4.10: "This screen is the coverage ledger rendered ... It has no separate data
        # source, so it can never disagree with the JSON." The ledger is built from the same
        # registry object this view already read (no second query), by the same function the
        # CLI and the committed artefact use.
        ledger = build_ledger(registry)
        coverage = {
            "checks": ledger.check_count,
            "wstg": ledger.wstg_counts(),
            "api": ledger.api_counts(),
            "cwe_only": len(ledger.cwe_only),
            "generated_at": ledger.generated_at,
        }
    except Exception:
        # §4.10 is explicit: a registry that cannot be read is an *error*, not an empty state,
        # because an empty coverage screen would read as "this deployment detects nothing".
        _logger.exception("the check registry could not be read")
        return _render(context, "modules.html", request=request, principal=principal, state="error")
    settings = context.settings
    return _render(
        context,
        "modules.html",
        request=request,
        principal=principal,
        empty=not modules,
        # §4.10 refused: this view read-only for every role — configuration is environment-driven.
        refused=True,
        modules=modules,
        coverage=coverage,
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
    """The CVE/EPSS ingestion page (F-09-03): status and freshness, artefacts, upload form."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    services = context.services
    try:
        stats = services.feeds.stats()
        rows = [record.to_dict() for record in services.feeds.list_feeds(limit=100)]
    except Exception:  # §4.13 error
        _logger.exception("the feed status could not be read")
        return _render(context, "feeds.html", request=request, principal=principal, state="error")
    total_feeds = sum(int(entry["feeds"]) for entry in stats["by_kind"].values())
    return _render(
        context,
        "feeds.html",
        request=request,
        principal=principal,
        empty=not total_feeds,
        refused=_read_only(principal),
        stats=stats,
        feeds=rows,
        freshness=_feed_freshness(context, rows),
        active_epss=services.feeds.effective_path("epss"),
        active_kev=services.feeds.effective_path("kev"),
        error=request.query_params.get("error"),
    )


def _feed_freshness(context: ContextDep, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-kind freshness of the newest imported feed, against the configured SLA.

    REQ-INTEL-006 asks the report to state feed freshness and to warn when a severity feed is
    stale; §4.13 asks the same of this page. The age comes from the newest import of that kind,
    and the SLA from ``intel.freshness_ttl`` — so the warning appears when the deployment's own
    configuration says it should, not at a number hard-coded here.
    """
    now = datetime.now(UTC)
    report: list[dict[str, Any]] = []
    for kind in ("epss", "kev"):
        sla = float(context.settings.intel.ttl_hours(kind))
        newest: datetime | None = None
        for row in rows:
            if row.get("kind") != kind or not row.get("created_at"):
                continue
            try:
                moment = datetime.fromisoformat(str(row["created_at"]))
            except ValueError:  # pragma: no cover - the column is written by this module
                continue
            if newest is None or moment > newest:
                newest = moment
        if newest is None:
            report.append(
                {
                    "kind": kind,
                    "age_hours": None,
                    "sla_hours": sla,
                    "stale": False,
                    "label": translate("ui.feeds.shipped_snapshot_label"),
                }
            )
            continue
        age = round((now - newest).total_seconds() / 3600, 1)
        stale = bool(sla) and age > sla
        report.append(
            {
                "kind": kind,
                "age_hours": age,
                "sla_hours": sla,
                "stale": stale,
                # The age label is a catalogue string (REQ-UIX-008): "3 h old" and its French
                # "3 h — périmé" are one key apart, and the number is formatted for the locale.
                "label": translate(
                    "ui.feeds.age_stale_label" if stale else "ui.feeds.age_label",
                    age=format_number(age, 1),
                ),
            }
        )
    return report


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
        # REQ-SCALE-013 (WP-17): the feed store is synchronous; a database write on the loop
        # blocks every other UI request while it runs.
        await asyncio.to_thread(
            context.services.feeds.import_text,
            content,
            kind=kind,
            name=name or kind,
            source=f"ui:{principal.label}",
            imported_by=principal.label,
            max_entries=context.settings.feeds.max_entries,
        )
    except ConfigurationError as exc:
        return RedirectResponse(f"/ui/feeds?error={quote(str(exc))}", status_code=303)
    await asyncio.to_thread(
        context.auditor.record,
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
    # REQ-SCALE-013 (WP-17): synchronous delete moved off the event loop.
    await asyncio.to_thread(context.services.feeds.delete, feed_id)
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
    try:
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
    except Exception:  # §4.12 error: a table error, not a blank page
        _logger.exception("the quality decisions could not be read")
        return _render(
            context,
            "quality.html",
            request=request,
            principal=principal,
            project=project,
            state="error",
        )
    version = max((item.version for item in suppressions), default=0)
    return _render(
        context,
        "quality.html",
        request=request,
        principal=principal,
        project=project,
        scope_all=show_all,
        empty=not suppressions and not acceptances,
        refused=_read_only(principal),
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
        return RedirectResponse(
            f"/ui/quality?error={quote(translate('ui.quality.error_no_store'))}", status_code=303
        )
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
        return RedirectResponse(
            f"/ui/quality?error={quote(translate('ui.quality.error_no_store'))}", status_code=303
        )
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


# --------------------------------------------------------------------------- findings workspace
#: The workspace's own query fields, on top of the API's finding filters and pagination
#: contract. ``sel``/``focus``/``scroll`` are the client state §4.4 requires to survive a trip
#: to the detail screen and back; keeping them in the URL (rather than only in a script's
#: memory) is what makes "Esc returns with the same selection" assertable.
_WORKSPACE_STATE_PARAMS = frozenset({"sel", "focus", "scroll"})

#: The filter fields the workspace form submits, in one place (the form, the links and the
#: bulk POST all speak the same vocabulary).
_WORKSPACE_FILTER_KEYS = ("severity", "status", "module", "q", "scan")


def _filters_from(values: Mapping[str, str]) -> dict[str, str]:
    return {key: (values.get(key) or "").strip() for key in _WORKSPACE_FILTER_KEYS}


def _parse_selection(raw: str | None) -> tuple[int, ...]:
    """The ids the URL says are selected. Unparseable parts are dropped, never trusted."""
    ids: list[int] = []
    for chunk in (raw or "").split(","):
        text = chunk.strip()
        if text.isdigit() and int(text) >= 1 and int(text) not in ids:
            ids.append(int(text))
    return tuple(ids[:MAX_BULK_FINDINGS])


def _workspace_query(
    filters: Mapping[str, str],
    *,
    selected: tuple[int, ...] = (),
    focused_id: int | None = None,
    scroll: int = 0,
    cursor: str | None = None,
) -> str:
    """The workspace's own query string — filters, pagination and the three state fields."""
    query: dict[str, str] = {key: value for key, value in filters.items() if value}
    if cursor:
        query["cursor"] = cursor
    if selected:
        query["sel"] = ",".join(str(item) for item in selected)
    if focused_id:
        query["focus"] = str(focused_id)
    if scroll:
        query["scroll"] = str(scroll)
    return urlencode(query)


def _workspace_values(
    request: Request,
    context: ContextDep,
    principal: Principal,
    project: ProjectRecord,
    *,
    filters: dict[str, str],
    cursor_raw: str | None,
    selected: tuple[int, ...],
    focused_id: int | None,
    scroll: int,
    limit_raw: str | None = None,
    notice: str | None = None,
    notice_kind: str = "ok",
    error: str | None = None,
    undo: dict[str, Any] | None = None,
    state: str = "ready",
) -> dict[str, Any]:
    """Everything the workspace renders from — the page and the htmx fragment both use this.

    One builder is what keeps the swapped fragment and the full page from drifting: the fragment
    is this same render with a different template name. That is also why the page size, the cursor
    and the filters travel back in the form: a bulk action must not silently re-page the view the
    operator was working in.
    """
    limit = clamp_limit(_positive_int(limit_raw), default=_UI_PAGE_LIMIT)
    cursor = cursor_or_400(cursor_raw)
    can_write = principal.allows(Role.SCANNER)
    findings: list[dict[str, Any]] = []
    next_cursor: str | None = None
    if state == "ready":
        try:
            rows = context.queries.finding_rows(
                project_id=project.id,
                include_unassigned=project.slug == DEFAULT_PROJECT_SLUG,
                severity=filters["severity"] or None,
                status=filters["status"] or None,
                module=filters["module"] or None,
                query=filters["q"] or None,
                scan_id=int(filters["scan"]) if filters["scan"].isdigit() else None,
                window=PageWindow(
                    sort_key="id",
                    descending=True,
                    boundary=None if cursor is None else (cursor.key, cursor.item_id),
                    backward=bool(cursor and cursor.backward),
                ),
                limit=limit + 1,
            )
        except Exception:  # §4.3 error: an error block with the filters kept, not a blank page
            _logger.exception("the findings workspace could not be read")
            state = "error"
        else:
            page = build_page(
                rows,
                limit=limit,
                key_of=lambda row: row.id,
                id_of=lambda row: row.id,
                cursor=cursor,
                backward=bool(cursor and cursor.backward),
            )
            findings = [{"finding": row.to_dict(), "finding_id": row.id} for row in page.items]
            next_cursor = page.next_cursor
    filtered = any(filters.values())
    return {
        "state": state,
        "error": error,
        "notice": notice,
        "notice_kind": notice_kind,
        "undo": undo,
        "filters": filters,
        "filtered": filtered,
        "cursor": cursor_raw or "",
        "limit": str(limit),
        "severities": _SEVERITY_ORDER,
        "findings": findings,
        "total": None,
        "can_write": can_write,
        "selected": selected,
        "focused_id": focused_id,
        "scroll": scroll,
        "shortcuts": shortcut_sheet(),
        "bulk_limit": MAX_BULK_FINDINGS,
        # §4.3's two empty states: nothing in the project at all, or nothing matching the filters
        # (the template picks the copy from ``filtered``, and offers "clear filters" for the
        # second). §4.3 partial: no cross-scan count source exists, so the footer reports the rows
        # shown without a total. Paging and filtering are unaffected.
        "partial": state == "ready",
        "empty": state == "ready" and not findings,
        "refused": not can_write,
        "next_href": (
            "/ui/findings?"
            + _workspace_query(
                filters, selected=selected, focused_id=focused_id, scroll=scroll, cursor=next_cursor
            )
            if next_cursor
            else None
        ),
        "detail_query": _workspace_query(
            filters, selected=selected, scroll=scroll
        ),  # the row links add their own `focus=`
        "project": project,
    }


def _render_workspace(
    request: Request,
    context: ContextDep,
    principal: Principal,
    project: ProjectRecord,
    **values: Any,
) -> HTMLResponse:
    """The workspace fragment alone — what htmx swaps into ``#workspace`` (§4.3)."""
    return _render(
        context,
        "_workspace.html",
        request=request,
        principal=principal,
        **_workspace_values(request, context, principal, project, **values),
    )


@ui_router.get("/ui/findings", response_class=HTMLResponse)
def findings_page(request: Request, context: ContextDep) -> Response:
    """Every finding in the project, filtered, paged and triaged from the keyboard (§4.3).

    Filtering is the server's (REQ-UIX-002's guard is the same one the API uses, so a typo in a
    filter name is a 400 naming the field rather than a silently unfiltered list), and the
    cursor is WP-03's codec. Selection and focus travel in the URL so §4.4's "Esc returns to the
    list with the same scroll position and selection" is a round trip the server renders, not a
    promise a script makes.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    reject_unknown_query_params(request, FINDING_FILTER_FIELDS | _WORKSPACE_STATE_PARAMS)
    return _render(
        context,
        "findings.html",
        request=request,
        principal=principal,
        **_workspace_values(
            request,
            context,
            principal,
            project,
            filters=_filters_from(request.query_params),
            cursor_raw=request.query_params.get("cursor"),
            limit_raw=request.query_params.get("limit"),
            selected=_parse_selection(request.query_params.get("sel")),
            focused_id=_positive_int(request.query_params.get("focus")),
            scroll=_positive_int(request.query_params.get("scroll")) or 0,
        ),
    )


@ui_router.post("/ui/findings/actions")
async def findings_action(request: Request, context: ContextDep) -> Response:
    """The bulk verb: one action, one undo record, one audit event per finding (§4.3).

    Every id is validated against the caller's tenant *before* anything is written, so a
    half-applied batch cannot exist. The request is refused outright when it names no finding or
    when a suppression carries no reason — §4.3's "an absent control is honest", applied to the
    API side of the same rule.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    project = _ui_project(request, context, principal)
    form = await _form(request)
    filters = _filters_from(form)
    selected = _parse_selection(form.get("sel"))
    focused_id = _positive_int(form.get("focus"))
    scroll = _positive_int(form.get("scroll")) or 0

    def _refuse(message: str) -> Response:
        return _render_workspace(
            request,
            context,
            principal,
            project,
            filters=filters,
            cursor_raw=form.get("cursor"),
            limit_raw=form.get("limit"),
            selected=selected,
            focused_id=focused_id,
            scroll=scroll,
            error=message,
        )

    try:
        action = parse_bulk_action(form)
    except ConfigurationError as exc:
        return _refuse(str(exc))
    rows: list[Any] = []
    for finding_id in action.finding_ids:
        try:
            _require_finding(context, finding_id, project)
        except HTTPException:
            return _refuse(translate("ui.workspace.bulk_error_not_in_project"))
        row = context.queries.finding_row(finding_id)
        if row is None:
            return _refuse(translate("ui.workspace.bulk_error_deleted"))
        rows.append(row)

    targets: list[UndoTarget] = []
    try:
        if action.action == "triage":
            targets = _apply_triage(context, principal, rows, action)
        elif action.action == "suppress":
            targets = _apply_suppression(context, principal, project, rows, action)
        else:
            targets = _apply_acceptance(context, principal, project, rows, action)
    except ConfigurationError as exc:
        return _refuse(str(exc))
    token = secrets.token_urlsafe(18)
    store_for(context).put(
        new_undo_record(
            token=token,
            actor=principal.label,
            project_id=project.id,
            action=action.action,
            label=action.label,
            targets=tuple(targets),
        )
    )
    return _render_workspace(
        request,
        context,
        principal,
        project,
        filters=filters,
        cursor_raw=form.get("cursor"),
        limit_raw=form.get("limit"),
        selected=selected,
        focused_id=focused_id,
        scroll=scroll,
        notice=pluralize(f"ui.workspace.notice.{action.action}", len(targets)),
        undo={
            "token": token,
            "label": action.label,
            "count": len(targets),
            "action": action.action,
        },
    )


def _apply_triage(
    context: ContextDep, principal: Principal, rows: list[Any], action: BulkAction
) -> list[UndoTarget]:
    """Set the status, remembering what each row had — that memory *is* the undo."""
    targets: list[UndoTarget] = []
    for row in rows:
        prior = row.status
        updated = context.queries.set_finding_status(row.id, action.status)
        if updated is None:  # deleted between the validation pass and now
            continue
        context.auditor.with_actor(principal.actor).record(
            AuditAction.FINDING_REVIEWED,
            scan_id=updated.scan_id,
            target=f"finding:{row.id}",
            meta={
                "status": action.status,
                "triaged": True,
                "prior_status": prior,
                "actor": principal.label,
                "identity": principal.actor,
                "bulk": True,
            },
        )
        targets.append(UndoTarget(finding_id=row.id, kind="status", prior=prior))
    return targets


def _apply_suppression(
    context: ContextDep,
    principal: Principal,
    project: ProjectRecord,
    rows: list[Any],
    action: BulkAction,
) -> list[UndoTarget]:
    """Record one attributed, reason-carrying suppression per finding (REQ-QUAL-002).

    The store writes the ``suppression.changed`` audit event per rule, which is why a bulk
    suppression is N events and never one untraceable batch.
    """
    from arachne.quality.suppressions import Suppression

    store = getattr(context.services, "quality", None)
    if store is None:
        raise ConfigurationError("no quality store is configured, so nothing can be suppressed")
    targets: list[UndoTarget] = []
    for row in rows:
        rule = store.add_suppression(
            Suppression(
                kind="finding",
                finding_id=row.id,
                reason=action.reason,
                actor=principal.label,
            ),
            project_id=project.id,
        )
        targets.append(UndoTarget(finding_id=row.id, kind="suppression", created_id=rule.id))
    return targets


def _apply_acceptance(
    context: ContextDep,
    principal: Principal,
    project: ProjectRecord,
    rows: list[Any],
    action: BulkAction,
) -> list[UndoTarget]:
    """Record one risk acceptance per finding, each with an owner and a future expiry."""
    from arachne.quality.acceptance import RiskAcceptance

    store = getattr(context.services, "quality", None)
    if store is None:
        raise ConfigurationError("no quality store is configured, so no risk can be accepted")
    expires_at = datetime.now(UTC) + timedelta(days=action.ttl_days)
    targets: list[UndoTarget] = []
    for row in rows:
        acceptance = store.add_acceptance(
            RiskAcceptance(
                finding_id=row.id,
                owner=action.owner,
                justification=action.justification,
                expires_at=expires_at,
                actor=principal.label,
            ),
            project_id=project.id,
        )
        targets.append(UndoTarget(finding_id=row.id, kind="acceptance", created_id=acceptance.id))
    return targets


@ui_router.post("/ui/findings/undo")
async def findings_undo(request: Request, context: ContextDep) -> Response:
    """Undo the last bulk action: put the prior state back, and audit the restoration.

    Undo *restores*; it does not re-run (§4.3, the WP-05 pitfall). A row whose state has been
    changed again since the action is left alone and reported as skipped, because restoring it
    would be a new change wearing undo's clothes.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    _require_write(request, principal, Role.SCANNER)
    project = _ui_project(request, context, principal)
    form = await _form(request)
    filters = _filters_from(form)
    selected = _parse_selection(form.get("sel"))
    focused_id = _positive_int(form.get("focus"))
    scroll = _positive_int(form.get("scroll")) or 0

    def _refuse(message: str) -> Response:
        return _render_workspace(
            request,
            context,
            principal,
            project,
            filters=filters,
            cursor_raw=form.get("cursor"),
            limit_raw=form.get("limit"),
            selected=selected,
            focused_id=focused_id,
            scroll=scroll,
            error=message,
        )

    try:
        record = store_for(context).consume(
            (form.get("token") or "").strip(),
            actor=principal.label,
            project_id=project.id,
            now=now_utc(),
        )
    except (UndoWindowClosedError, UndoUnavailableError) as exc:
        return _refuse(str(exc))
    restored, skipped = _restore(context, principal, project, record)
    # Both halves of the undo report are catalogue strings (REQ-UIX-008): the count picks the
    # plural form, and the "some rows had moved on" clause is its own sentence.
    notice = pluralize("ui.workspace.undone", restored)
    if skipped:
        notice += " " + pluralize("ui.workspace.undone_skipped", skipped)
    return _render_workspace(
        request,
        context,
        principal,
        project,
        filters=filters,
        cursor_raw=form.get("cursor"),
        limit_raw=form.get("limit"),
        selected=selected,
        focused_id=focused_id,
        scroll=scroll,
        notice=notice,
    )


def _restore(
    context: ContextDep, principal: Principal, project: ProjectRecord, record: UndoRecord
) -> tuple[int, int]:
    """Apply one undo record's inverse operations. Returns ``(restored, skipped)``."""
    store = getattr(context.services, "quality", None)
    restored = skipped = 0
    for target in record.targets:
        row = context.queries.finding_row(target.finding_id)
        # The record was built for this tenant, but it is re-checked here: an undo is a write,
        # and every write in this interface re-resolves the row's tenant rather than trusting a
        # token. A row that has since vanished (or been rehomed) is skipped, not resurrected.
        if row is None or not _visible(_scan_project(context, target.finding_id), project):
            skipped += 1
            continue
        if target.kind == "status" and target.prior is not None:
            if record.action == "triage" and row.status != TRIAGE_STATUS:
                # Somebody decided again after the batch; that decision wins.
                skipped += 1
                continue
            context.queries.set_finding_status(target.finding_id, target.prior)
            context.auditor.with_actor(principal.actor).record(
                AuditAction.FINDING_REVIEWED,
                scan_id=row.scan_id,
                target=f"finding:{target.finding_id}",
                meta={
                    "status": target.prior,
                    "restored_status": target.prior,
                    "undo": True,
                    "undo_of": record.action,
                    "actor": principal.label,
                    "identity": principal.actor,
                },
            )
            restored += 1
        elif target.kind == "suppression" and store is not None and target.created_id is not None:
            # Revoked, never re-created: undo puts the prior state back rather than replaying.
            store.revoke_suppression(target.created_id, actor=principal.label)
            restored += 1
        elif target.kind == "acceptance" and store is not None and target.created_id is not None:
            store.revoke_acceptance(target.created_id, actor=principal.label)
            restored += 1
        else:
            skipped += 1
    return restored, skipped


def _scan_project(context: ContextDep, finding_id: int) -> int | None:
    """The tenant of the finding's scan (``None`` for a pre-S14 unassigned one)."""
    scan_id = context.queries.finding_scan_id(finding_id)
    if scan_id is None:
        return None
    record = context.services.store.get_scan(scan_id)
    return None if record is None else record.project_id


def _positive_int(raw: str | None) -> int | None:
    text = (raw or "").strip()
    return int(text) if text.isdigit() else None


@ui_router.get("/ui/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail_page(request: Request, finding_id: int, context: ContextDep) -> Response:
    """One finding, with its verification record (06-ui-ux.md §4.4).

    A finding with no verification record is *not* hidden behind a 404: §4.4 asks it to render
    with its severity forced to INFO and a banner, because "unverified" is the honest state of a
    candidate the analyzer has not confirmed, not an error. "Verified" here means the report
    carries the finding as a confirmed one: a candidate below the analyzer's confidence threshold
    is an unverified candidate, and that is exactly the case the severity override exists for.
    """
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    project = _ui_project(request, context, principal)
    reject_unknown_query_params(
        request, FINDING_FILTER_FIELDS | _WORKSPACE_STATE_PARAMS | {"evidence"}
    )
    row = context.queries.finding_row(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"finding {finding_id} does not exist")
    record = context.services.store.get_scan(row.scan_id)
    if record is None or not _visible(record.project_id, project):
        raise HTTPException(status_code=404, detail=f"finding {finding_id} does not exist")
    finding = row.to_dict()
    selected = _parse_selection(request.query_params.get("sel"))
    # §4.4: Esc returns to the list *with the same scroll position and selection*, so the way
    # back is a link that carries both — plus the focus it should land on (the row you opened).
    back_query = _workspace_query(
        _filters_from(request.query_params),
        selected=selected,
        focused_id=finding_id,
        scroll=_positive_int(request.query_params.get("scroll")) or 0,
    )
    try:
        index = _report_index(context, row.scan_id)
    except Exception:
        _logger.exception("finding %s could not be read", finding_id)
        return _render(
            context,
            "finding_detail.html",
            request=request,
            principal=principal,
            state="error",
            finding=finding,
            detail=_EMPTY_DETAIL,
            evidence=[],
            list_href=f"/ui/findings?{back_query}",
            selection_count=len(selected),
            authorization=(),
            history=None,
        )
    detail = index.get(finding_id, _EMPTY_DETAIL)
    # §4.4 partial: the verification record is intact and only the raw evidence failed.
    partial = False
    try:
        evidence = list(context.queries.evidence_rows(finding_id))
    except Exception:
        _logger.exception("the evidence of finding %s could not be read", finding_id)
        evidence, partial = [], True
    # §4.4's two lower panels. ``authorization`` is the risk acceptance in force on this finding
    # (the quality store is the same one the workspace writes to); ``history`` is the finding's
    # own audit trail, read from the durable log — ``None`` when that read failed (partial).
    authorization = _finding_authorization(context, project, finding_id)
    history = _finding_history(context, finding_id, row.scan_id)
    if history is None:
        partial = True
    verified = finding_id in index and not bool(detail.get("low_confidence"))
    return _render(
        context,
        "finding_detail.html",
        request=request,
        principal=principal,
        empty=not verified,
        partial=partial,
        refused=not verified,
        finding=finding,
        detail=detail,
        evidence=evidence,
        list_href=f"/ui/findings?{back_query}",
        selection_count=len(selected),
        authorization=authorization,
        history=history,
    )


def _finding_authorization(
    context: ContextDep, project: ProjectRecord, finding_id: int
) -> tuple[Any, ...]:
    """The risk acceptances recorded against this finding (§4.4's Authorization row)."""
    store = getattr(context.services, "quality", None)
    if store is None:
        return ()
    try:
        return tuple(
            store.list_acceptances(finding_id=finding_id, active_only=False, project_id=project.id)
        )
    except Exception:  # §4.4 partial: a panel-level failure, the header stays usable
        _logger.exception("the authorizations of finding %s could not be read", finding_id)
        return ()


def _finding_history(
    context: ContextDep, finding_id: int, scan_id: int
) -> tuple[dict[str, Any], ...] | None:
    """This finding's own audit events, newest first (§4.4's History panel).

    Read from the durable ``audit_log`` the deployment's audit chain writes, filtered to the
    events whose target *is* this finding — so the panel shows the decisions taken on it (a
    triage, a suppression, an acceptance, an undo) and not the scan's thousands of probe lines.
    ``None`` means the read failed, which the panel reports as a partial rather than as "no
    history" (those are different claims).
    """
    from arachne.data.report_store import SqlAuditReader

    try:
        records = SqlAuditReader(context.services.session_factory).events_for_scan(scan_id)
    except Exception:
        _logger.exception("the history of finding %s could not be read", finding_id)
        return None
    target = f"finding:{finding_id}"
    rows: list[dict[str, Any]] = []
    for record in reversed(records):
        meta = dict(record.meta)
        if (record.target or meta.get("target")) != target:
            continue
        nested = meta.get("meta")
        detail = dict(nested) if isinstance(nested, dict) else {}
        rows.append(
            {
                "ts": record.ts.isoformat() if record.ts else None,
                "action": record.action,
                "outcome": record.outcome,
                "actor": meta.get("actor"),
                "detail": detail,
            }
        )
    return tuple(rows[:20])


# --------------------------------------------------------------------------- plugins
@ui_router.get("/ui/plugins", response_class=HTMLResponse)
def plugins_page(request: Request, context: ContextDep) -> Response:
    """Installed check/report-format plugins and the marketplace listing (F-09-01)."""
    principal = _principal_or_redirect(request, context)
    if isinstance(principal, RedirectResponse):
        return principal
    from arachne.core.signing import build_content_keyring
    from arachne.plugins import installed_plugins
    from arachne.plugins.marketplace import load_marketplace
    from arachne.report import default_registry

    # §4.13: "a broken plugin renders as a row with its load error; the rest of the page works".
    # Discovery raises a curated ConfigurationError naming the plugin, so a broken plugin is
    # caught here: the page states that a plugin failed, the failure is in the server log, and
    # the rest of the page — formats, marketplace, install switch — renders as usual.
    plugin_error = False
    try:
        installed = installed_plugins()
    except ConfigurationError:
        _logger.exception("an installed plugin failed to load")
        installed = {"checks": [], "report_formats": []}
        plugin_error = True
    try:
        catalogue = load_marketplace(
            context.settings.plugins.marketplace,
            keyring=build_content_keyring(context.settings),
            allow_unsigned=context.settings.plugins.allow_unsigned_index,
        )
        formats = default_registry().summary()
    except Exception:  # §4.13 error
        _logger.exception("the plugin list could not be read")
        return _render(context, "plugins.html", request=request, principal=principal, state="error")
    return _render(
        context,
        "plugins.html",
        request=request,
        principal=principal,
        # §4.13's plugins-empty is the *Check modules* section, not the whole page: the report
        # formats, the marketplace and the install switch are unaffected by it and stay up.
        empty=not installed["checks"],
        partial=plugin_error,
        plugin_error=plugin_error,
        refused=not principal.allows(Role.ADMIN),
        installed=installed,
        formats=formats,
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

    try:
        rows = ScheduleStore(context.settings.scheduler.state_path).load()
    except Exception:  # §4.11 error
        _logger.exception("the schedules could not be read")
        return _render(
            context, "schedules.html", request=request, principal=principal, state="error"
        )
    return _render(
        context,
        "schedules.html",
        request=request,
        principal=principal,
        empty=not rows,
        refused=_read_only(principal),
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

    ``low_confidence`` is read from the report's **split**, not from the finding's own field:
    the builder puts a below-threshold finding in ``report.low_confidence`` and leaves the
    field on the object at its default, so reading the field would report every finding as
    confirmed — and the interface would then show an unverified candidate at its claimed
    severity, which is the one thing §4.4 refuses.
    """
    try:
        report = context.reports.build(scan_id)
    except Exception:  # a scan with no analysable rows still renders its raw findings
        return {}
    index: dict[int, dict[str, Any]] = {}
    for confirmed, finding in [
        *((True, item) for item in report.findings),
        *((False, item) for item in report.low_confidence),
    ]:
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
            "low_confidence": not confirmed,
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
