"""The FastAPI application: JSON API + web UI in one process (F-07-02/03, S12).

One ASGI app serves both interfaces, because the spec makes the API the deployment and the
UI a *view* of it (docs/spec/02- §1): the UI's pages call the same store, the same report
builder and the same webhook notifier the JSON routes do, so the two cannot disagree.

Three cross-cutting pieces live here:

* **Audit middleware** records one ``api.request`` line per response (method, path, status,
  duration, principal label) and ``api.denied`` for a refusal — F-08-02's "audit logging"
  for the interface layer, reusing the schema the scanner already writes.
* **Rate-limit middleware** answers ``429`` from the per-identity token bucket *before* a
  route runs, so it also bounds unauthenticated probes (F-08-02).
* **Exception handlers** turn an :class:`~arachne.core.errors.ArachneError` into the right
  status (403 for a scope/authorization refusal, 404 for a missing scan, 400 for bad
  configuration) with one JSON error shape, so the UI and a machine client read the same
  thing.
"""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from arachne import __version__
from arachne.api.admission_routes import admission_router
from arachne.api.agent_routes import agent_router
from arachne.api.auth import (
    API_KEY_COOKIE,
    API_KEY_HEADER,
    SSO_SESSION_COOKIE,
    hash_secret,
    identify,
)
from arachne.api.context import AppContext
from arachne.api.purple_routes import purple_router
from arachne.api.resilience_routes import resilience_router
from arachne.api.routes_api import api_router
from arachne.api.routes_ui import ui_router
from arachne.api.sso_routes import sso_router
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import Settings, get_settings
from arachne.core.errors import (
    ArachneError,
    AuthorizationError,
    ConfigurationError,
    IdentityError,
    OutOfScopeError,
    ReportError,
    SafetyError,
    ScanStateError,
)
from arachne.core.logging import get_logger
from arachne.core.metrics import CONTENT_TYPE, REGISTRY, render_metrics, status_class

__all__ = ["create_app"]

_logger = get_logger("api")

#: Paths exempt from rate limiting (the UI's own assets).
#: Paths the rate limiter and the per-request audit middleware skip. ``/static`` is asset
#: serving; ``/metrics`` is scraped every few seconds by a monitoring system, where a token
#: bucket would throttle the monitor and one audit row per scrape would drown the trail. The
#: metrics route authenticates itself and audits its own refusals (S20, REQ-OPS-003).
_EXEMPT_PREFIXES = ("/static", "/metrics")


def _template_dir() -> Path:
    """The real filesystem directory holding the UI templates."""
    resource = files("arachne.templates").joinpath("web")
    return Path(str(resource))


def _build_templates(settings: Settings) -> Any:
    import jinja2

    directory = _template_dir()
    if not directory.is_dir():  # pragma: no cover - packaging failure
        msg = f"web templates are missing at {directory}"
        raise ConfigurationError(msg)
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(directory)),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined,
        enable_async=False,
    )
    environment.globals.update(
        api_version=__version__,
        api_key_header=API_KEY_HEADER,
    )
    return environment


def create_app(
    services: Any = None,
    *,
    settings: Settings | None = None,
    context: AppContext | None = None,
) -> FastAPI:
    """Build the ASGI app.

    ``context`` (a fully-built :class:`AppContext`) wins when supplied — that is what tests
    and an embedded deployment use; otherwise ``services`` (or a fresh stack) is wrapped in
    one, and the app owns its lifetime.
    """
    effective = settings or get_settings()
    if context is None:
        if services is None:
            from arachne.data.services import build_services

            services = build_services(effective)
        context = AppContext.build(effective, services, templates=_build_templates(effective))
    elif context.templates is None:
        context.templates = _build_templates(effective)

    docs_enabled = effective.api.docs_enabled
    if effective.observability.tracing_enabled:
        from arachne.core.tracing import configure_tracing

        configure_tracing(effective)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        try:
            yield
        finally:
            await context.runner.shutdown()
            if context.oidc is not None:
                await context.oidc.aclose()
            # Deliver whatever the last requests traced, then close the collector client.
            from arachne.core.tracing import get_tracer

            tracer = get_tracer()
            aclose = getattr(tracer, "aclose", None)
            if aclose is not None:
                await aclose()
            context.close()

    app = FastAPI(
        title="ARACHNE API",
        version=__version__,
        summary="Defensive vulnerability-detection and reporting API (F-07-02).",
        description=(
            "REST resources over the ARACHNE evidence store: targets, scans, findings and "
            "reports, with API-key authentication and the roles admin/scanner/viewer. The "
            "web UI is served from the same process at '/'."
        ),
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.context = context
    app.state.settings = effective

    _install_middleware(app, effective, context)
    _install_handlers(app)
    app.include_router(api_router, prefix="/api/v1")
    app.include_router(agent_router, prefix="/api/v1")
    app.include_router(admission_router, prefix="/api/v1")
    # S24: the purple-team SIEM ingest and campaign routes (REQ-VALID-002).
    app.include_router(purple_router, prefix="/api/v1")
    # S25: integrity status/verification and the HA (leader/autoscale) view (REQ-TRUST-005,
    # REQ-RESIL-002/003).
    app.include_router(resilience_router, prefix="/api/v1")
    app.include_router(sso_router, prefix="/api/v1")
    app.include_router(ui_router)
    _mount_static(app)

    # A root alias so /health works without the version prefix (readiness probes).
    app.add_api_route("/health", _root_health(context), methods=["GET"], include_in_schema=False)
    # S25 (REQ-TRUST-007): this deployment's own RFC 9116 security.txt, at the well-known
    # path a researcher's tooling looks at. Unauthenticated like /health — the whole point of
    # the file is that someone outside the deployment can read it — and served from the
    # packaged document, so what is published is what shipped.
    app.add_api_route(
        "/.well-known/security.txt",
        _root_security_txt(),
        methods=["GET"],
        include_in_schema=False,
    )
    if effective.observability.metrics_enabled:
        app.add_api_route(
            "/metrics", _root_metrics(context), methods=["GET"], include_in_schema=False
        )
    return app


def _root_health(context: AppContext) -> Callable[[], JSONResponse]:
    def health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "database": "sqlite"
                if context.settings.database_url.startswith("sqlite")
                else context.settings.database_url.split(":", 1)[0],
            }
        )

    return health


def _root_metrics(context: AppContext) -> Callable[[Request], Any]:
    """The Prometheus scrape endpoint (REQ-OPS-003), at the conventional root path.

    Optional bearer authentication: a deployment that publishes its API should publish this
    behind the same proxy, and ``ARACHNE_METRICS_TOKEN`` is the second lock for the case where
    it does not. The body is aggregate only — no target, asset, finding or payload — because
    the endpoint may be reachable without a key at all.
    """

    async def metrics(request: Request) -> Any:
        configured = context.settings.observability.metrics_token
        if configured is not None:
            presented = _bearer_token(request)
            if presented is None or not hmac.compare_digest(
                presented, configured.get_secret_value()
            ):
                context.auditor.record(
                    AuditAction.API_DENIED,
                    outcome=AuditOutcome.BLOCKED,
                    target="/metrics",
                    reason="metrics token required",
                )
                return JSONResponse(
                    {"error": {"code": 401, "message": "metrics token required"}}, status_code=401
                )
        from arachne.data.metrics_source import collect_deployment_metrics

        collect_deployment_metrics(context.services)
        return Response(content=render_metrics(), media_type=CONTENT_TYPE)

    return metrics


def _root_security_txt() -> Callable[[], Any]:
    """Serve the shipped ``security.txt`` verbatim (S25, REQ-TRUST-007).

    Read from the repository's ``docs/security.txt`` rather than a second copy, so the
    published policy cannot drift from the reviewed file. A deployment that ships the
    package without the docs directory gets a minimal, honest fallback pointing at the
    project's disclosure policy instead of a 404.
    """

    def security_txt() -> Any:
        candidate = Path(__file__).resolve().parents[3] / "docs" / "security.txt"
        if candidate.is_file():
            return Response(content=candidate.read_text(encoding="utf-8"), media_type="text/plain")
        return Response(
            content=(
                "# security.txt\n"
                "Contact: https://github.com/0xFE1C/ARACHNE/security/advisories/new\n"
                "Expires: 2027-06-30T00:00:00.000Z\n"
                "Preferred-Languages: en\n"
                "Policy: https://github.com/0xFE1C/ARACHNE/blob/main/SECURITY.md\n"
            ),
            media_type="text/plain",
        )

    return security_txt


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _mount_static(app: FastAPI) -> None:
    static_dir = _template_dir().joinpath("static")
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _install_middleware(app: FastAPI, settings: Settings, context: AppContext) -> None:
    if settings.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.api.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[API_KEY_HEADER, "Content-Type", "HX-Request"],
        )
    allowed_hosts = _allowed_hosts(settings)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.add_middleware(_RateLimitMiddleware, context=context)
    app.add_middleware(_AuditMiddleware, context=context)


def _allowed_hosts(settings: Settings) -> list[str]:
    configured = list(settings.api.trusted_hosts)
    if configured:
        return configured
    hosts = {"localhost", "127.0.0.1", "[::1]", "testserver", settings.api.host}
    return sorted(hosts)


def _identity(request: Request, context: AppContext) -> str:
    """Rate-limit identity: the presented key's digest, else the SSO session's, else client."""
    raw = request.headers.get(API_KEY_HEADER) or request.cookies.get(API_KEY_COOKIE)
    if raw:
        return f"key:{hash_secret(raw.strip())[:16]}"
    session = request.cookies.get(SSO_SESSION_COOKIE)
    if session:
        return f"session:{hash_secret(session.strip())[:16]}"
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}"


def _is_exempt(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


class _RateLimitMiddleware:
    """Per-identity token bucket in front of every route (F-08-02)."""

    def __init__(self, app: Any, *, context: AppContext) -> None:
        self.app = app
        self.context = context

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        if _is_exempt(request.url.path):
            await self.app(scope, receive, send)
            return
        decision = self.context.rate_limiter.check(_identity(request, self.context))
        if decision.allowed:
            await self.app(scope, receive, send)
            return
        self.context.auditor.record(
            AuditAction.API_DENIED,
            outcome=AuditOutcome.BLOCKED,
            target=request.url.path,
            reason="rate limit exceeded",
            meta={
                "method": request.method,
                "path": request.url.path,
                "retry_after_s": decision.retry_after_s,
            },
        )
        response = JSONResponse(
            {"error": {"code": 429, "message": "rate limit exceeded"}},
            status_code=429,
            headers={
                "Retry-After": str(max(1, int(decision.retry_after_s + 0.999))),
                "X-RateLimit-Limit": str(decision.limit),
                "X-RateLimit-Remaining": "0",
            },
        )
        await response(scope, receive, send)


class _AuditMiddleware:
    """One ``api.request`` audit line per response (F-08-02)."""

    def __init__(self, app: Any, *, context: AppContext) -> None:
        self.app = app
        self.context = context

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        path = request.url.path
        if _is_exempt(path):
            await self.app(scope, receive, send)
            return
        started = time.monotonic()
        status_holder = {"code": 500}

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = round((time.monotonic() - started) * 1000.0, 3)
            label, identity = self._identities_of(request)
            # API latency and request counts (REQ-OPS-003). Label cardinality is bounded by
            # construction: the method and the status *class*, never the path or the caller.
            REGISTRY.increment(
                "arachne_api_requests_total",
                {"method": request.method, "status": status_class(status_holder["code"])},
            )
            REGISTRY.observe(
                "arachne_api_request_duration_seconds",
                elapsed_ms / 1000.0,
                {"method": request.method},
            )
            self.context.auditor.with_actor(identity).record(
                AuditAction.API_REQUEST,
                outcome=(
                    AuditOutcome.ALLOWED if status_holder["code"] < 400 else AuditOutcome.BLOCKED
                ),
                target=path,
                meta={
                    "method": request.method,
                    "path": path,
                    "status": status_holder["code"],
                    "elapsed_ms": elapsed_ms,
                    # ``actor`` stays the credential label (back-compatible); ``identity``
                    # is REQ-IDAM-004's "user X via key Y" form, also used as the event actor.
                    "actor": label,
                    "identity": identity,
                    "client": request.client.host if request.client else None,
                },
            )

    def _identities_of(self, request: Request) -> tuple[str, str]:
        principal = identify(request, self.context.credentials)
        if principal is None:
            return "anonymous", "anonymous"
        return principal.label, principal.actor


def _install_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def _http_error(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {"error": {"code": exc.status_code, "message": str(exc.detail)}},
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.exception_handler(ArachneError)
    async def _arachne_error(_request: Request, exc: ArachneError) -> JSONResponse:
        code = _status_for(exc)
        return JSONResponse(
            {"error": {"code": code, "message": str(exc), "type": type(exc).__name__}},
            status_code=code,
        )

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        _logger.error(
            "unhandled API error",
            extra={"event": "api.error", "error": f"{exc.__class__.__name__}: {exc}"},
        )
        return JSONResponse({"error": {"code": 500, "message": "internal error"}}, status_code=500)


def _status_for(exc: ArachneError) -> int:
    if isinstance(exc, IdentityError):
        return 401
    if isinstance(exc, (AuthorizationError, OutOfScopeError, SafetyError)):
        return 403
    if isinstance(exc, ConfigurationError):
        return 400
    if isinstance(exc, ScanStateError):
        return 409 if "does not exist" not in str(exc) else 404
    if isinstance(exc, ReportError):
        return 404
    return 400


# Re-exported for the CLI's ``arachne serve`` and tests.
def build_app(services: Any = None, **kwargs: Any) -> FastAPI:
    return create_app(services, **kwargs)


def get_app() -> FastAPI:
    """Module-level app factory for uvicorn's import-string mode (S22, REQ-OPS-005).

    uvicorn's multi-worker mode (``workers > 1``) spawns subprocesses that must import
    the application themselves, so ``arachne serve --workers N`` passes this factory's
    import string instead of the app object. Each worker builds its own services from
    the environment — the same composition root the single-process path uses.
    """
    from arachne.core.config import get_settings
    from arachne.data.services import build_services

    settings = get_settings()
    services = build_services(settings)
    return create_app(services, settings=settings)
