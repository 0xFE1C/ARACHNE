"""Shared application context for the API and web UI (S12).

One object holds everything a request needs — settings, the key store, the rate limiter,
the store-backed services, the background scan runner, the report service and the webhook
notifier — so a router depends on ``get_context`` and nothing else. The context is built by
:func:`arachne.api.app.create_app` and stored on ``app.state``; tests build one directly
around an in-memory database, which is what keeps the API tests fast and socket-free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import jinja2

from arachne.api.auth import ApiKeyStore, CredentialStore
from arachne.api.oidc import OidcProvider
from arachne.api.ratelimit import ApiRateLimiter
from arachne.api.report_service import ReportService
from arachne.api.runner import ScanRunner
from arachne.core.audit import Auditor, build_auditor
from arachne.core.config import Settings
from arachne.data.api_store import ApiQueryStore
from arachne.data.services import ScanServices

__all__ = ["AppContext"]


@dataclass(slots=True)
class AppContext:
    """Everything a request handler may use."""

    settings: Settings
    services: ScanServices
    auditor: Auditor
    key_store: ApiKeyStore
    #: Every authentication path (static keys, service accounts, SSO sessions) — S17.
    credentials: CredentialStore
    rate_limiter: ApiRateLimiter
    queries: ApiQueryStore
    runner: ScanRunner
    reports: ReportService
    notifier: Any = None
    templates: jinja2.Environment | None = None
    #: Whether the context owns the services (and must close them on shutdown).
    owns_services: bool = True
    #: The OIDC provider, or ``None`` when no IdP is configured (deny-by-default, S17).
    oidc: OidcProvider | None = None
    #: Registered routes' tags, kept for the UI's navigation.
    extras: dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        if self.owns_services:
            self.services.close()

    @classmethod
    def build(
        cls,
        settings: Settings,
        services: ScanServices,
        *,
        auditor: Auditor | None = None,
        notifier: Any = None,
        templates: jinja2.Environment | None = None,
        owns_services: bool = True,
        runner: ScanRunner | None = None,
    ) -> AppContext:
        """Assemble a context around already-built ``services``."""
        audit = auditor or services.auditor or build_auditor(settings)
        key_store = ApiKeyStore.from_settings(settings.api)
        credentials = CredentialStore(
            key_store,
            accounts=services.service_accounts,
            sessions=services.auth_sessions,
        )
        rate_limiter = ApiRateLimiter(
            per_minute=settings.api.rate_limit_per_minute,
            burst=settings.api.rate_limit_burst,
        )
        queries = ApiQueryStore(services.session_factory)
        effective_notifier = notifier
        if effective_notifier is None:
            from arachne.api.webhooks import WebhookNotifier

            effective_notifier = WebhookNotifier(settings, auditor=audit)
        report_service = ReportService(services, settings=settings, notifier=effective_notifier)
        scan_runner = runner or ScanRunner(services, settings=settings, notifier=effective_notifier)
        oidc = OidcProvider(settings, auditor=audit) if settings.sso.configured else None
        return cls(
            settings=settings,
            services=services,
            auditor=audit,
            key_store=key_store,
            credentials=credentials,
            rate_limiter=rate_limiter,
            queries=queries,
            runner=scan_runner,
            reports=report_service,
            notifier=effective_notifier,
            templates=templates,
            owns_services=owns_services,
            oidc=oidc,
        )
