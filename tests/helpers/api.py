"""A REST API + web UI harness on a throwaway SQLite file (S12).

The API is exercised through ``fastapi.testclient`` over the *real* app (middleware, auth,
routers, Jinja templates) and the real store-backed services, with three deliberate
concessions that keep the tests fast and offline:

* **A recon-only pipeline.** The default harness runs a scan over ``(RECON,)`` so a live
  request completes in milliseconds without touching a socket; a test that wants findings
  passes a different pipeline (or seeds them) explicitly.
* **A stub webhook poster.** The notifier is given a capturing ``post_json`` so a delivery
  can be asserted without a server; the wire path is proven separately against a loopback
  stub.
* **A memory audit sink.** Every audit event the app writes is captured, so "the request was
  audited" is an assertion rather than a log scrape.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from arachne.api.context import AppContext
from arachne.api.runner import ScanRunner
from arachne.api.webhooks import WebhookNotifier, WebhookPostResult
from arachne.core.audit import AuditAction, MemoryAuditSink, build_auditor
from arachne.core.config import (
    ApiSettings,
    RateLimitSettings,
    Settings,
    SsoSettings,
    WebhookSettings,
)
from arachne.core.events import EventBus
from arachne.core.planner import ScanStep
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.api_store import ApiQueryStore
from arachne.data.db import create_all, create_db_engine, create_session_factory
from arachne.data.evidence_backend import build_evidence_backend
from arachne.data.evidence_service import EvidenceService
from arachne.data.feed_store import FeedStore
from arachne.data.finding_store import SqlFindingStore
from arachne.data.fix_store import SqlFixProposalStore
from arachne.data.identity_store import ServiceAccountStore, SessionStore, SsoFlowStore
from arachne.data.posture_store import SqlPostureStore
from arachne.data.project_store import SqlProjectStore
from arachne.data.purple_store import SqlPurpleStore
from arachne.data.quality_store import SqlQualityStore
from arachne.data.queue_store import AgentRegistry, WorkQueue
from arachne.data.quota import StorageQuota
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.services import ScanServices, build_orchestrator
from arachne.data.target_store import SqlTargetStore
from arachne.modules.registry import ModuleRegistry

__all__ = [
    "ADMIN_KEY",
    "API_KEYS",
    "SCANNER_KEY",
    "VIEWER_KEY",
    "ApiHarness",
    "StubPoster",
    "auth",
    "make_api_harness",
]

#: ``label:role:secret`` entries the harness configures by default.
ADMIN_KEY = "rootsecret"
SCANNER_KEY = "scansecret"
VIEWER_KEY = "viewsecret"
API_KEYS: tuple[str, ...] = (
    f"admin:admin:{ADMIN_KEY}",
    f"scanner:scanner:{SCANNER_KEY}",
    f"viewer:viewer:{VIEWER_KEY}",
)


def auth(secret: str) -> dict[str, str]:
    """The header dict a machine client sends."""
    return {"X-API-Key": secret}


@dataclass
class StubPoster:
    """A capturing :data:`~arachne.api.webhooks.PostJson` seam."""

    ok: bool = True
    status_code: int | None = 200
    error: str | None = None
    calls: list[tuple[str, Mapping[str, Any], Mapping[str, str]]] = field(default_factory=list)

    async def __call__(self, url, body, headers):  # type: ignore[no-untyped-def]
        self.calls.append((url, body, headers))
        return WebhookPostResult(status_code=self.status_code, error=self.error)

    @property
    def names(self) -> list[str]:
        return [url for url, _body, _headers in self.calls]


def build_api_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Fast, offline-friendly settings for an API test."""
    api_kwargs: dict[str, Any] = {
        "keys": API_KEYS,
        "require_tls": False,
        "rate_limit_per_minute": 100_000,
        "rate_limit_burst": 100_000,
        "docs_enabled": True,
    }
    api_kwargs.update(overrides.pop("api", {}))
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        log_level="CRITICAL",
        log_json=False,
        actor="pytest",
        api=ApiSettings(**api_kwargs),
        **overrides,
    )


@dataclass
class ApiHarness:
    """Everything a test needs to drive the API."""

    settings: Settings
    services: ScanServices
    context: AppContext
    app: Any
    sink: MemoryAuditSink
    poster: StubPoster
    tmp_path: Path

    # ------------------------------------------------------------------ convenience
    def actions(self) -> list[str]:
        return [event.action.value for event in self.sink.events]

    def events_of(self, action: AuditAction) -> list[Any]:
        return [event for event in self.sink.events if event.action is action]

    def client(self, **kwargs: Any) -> Any:
        from fastapi.testclient import TestClient

        kwargs.setdefault("raise_server_exceptions", False)
        return TestClient(self.app, **kwargs)

    def close(self) -> None:
        self.services.close()

    def seed_scan(self, *, project: str | None = None) -> int:
        """Create a scan shell (with its target) without running anything.

        ``project`` assigns the scan to a tenant (S26): a scan with no project is "unassigned"
        and is visible to the default workspace in a project-scoped listing, which is exactly
        the distinction a tenant-scoping test needs to exercise.
        """
        target_id = self.services.target_store.save(_seed_definition())
        project_id = self.services.projects.resolve(project).id if project is not None else None
        record = self.services.store.create_scan(
            target_id=target_id,
            engine="heuristic",
            plan={"target_name": "seeded"},
            stats={"target_name": "seeded"},
            project_id=project_id,
        )
        return int(record.id)

    def seed_finding(
        self,
        *,
        scan_id: int | None = None,
        title: str = "planted finding",
        check_key: str = "M4/env-file-probe@1.0",
        asset: tuple[str, str] = ("url", "https://example.com/"),
        severity: str | None = None,
    ) -> int:
        """Insert one finding row directly (so findings CRUD needs no full scan)."""
        from arachne.core.results import CheckResult, Evidence

        record = self.services.store.get_scan(scan_id) if scan_id is not None else None
        if record is None:  # create a scan shell when the test only wants findings
            target_id = self.services.target_store.save(_seed_definition())
            record = self.services.store.create_scan(
                target_id=target_id,
                engine="heuristic",
                plan={"target_name": "seeded"},
                stats={"target_name": "seeded"},
            )
            scan_id = record.id
        asset_row = self.services.store.add_asset(scan_id, kind=asset[0], value=asset[1])
        asset_id = asset_row.id
        check_ids = self.services.findings.record_checks(
            [
                _Metadata(
                    module=check_key.split("/")[0],
                    name=check_key.split("/")[1].split("@")[0],
                    version=check_key.split("@")[1],
                    title=title,
                    cwe="CWE-200",
                    research_ref="ch04#1",
                )
            ]
        )
        candidate = self.services.findings.record_candidate(
            scan_id,
            result=CheckResult(
                module="M4",
                check="m4.env-file-probe",
                title=title,
                status="vulnerable",
                detail="seeded by the API test harness",
                confidence=0.7,
                evidence=(Evidence(kind="http_response", payload={"status_code": 200}),),
            ),
            check_id=check_ids.get(check_key),
            asset_id=asset_id,
            asset=asset,
        )
        if severity is not None and candidate.id is not None:
            _set_severity(self.services.session_factory, candidate.id, severity)
        assert candidate.id is not None
        return candidate.id


@dataclass(frozen=True, slots=True)
class _Metadata:
    """Minimal check metadata for ``record_checks`` (duck-typed by the store)."""

    module: str
    name: str
    version: str
    title: str
    cwe: str | None = None
    research_ref: str | None = None
    description: str | None = None

    @property
    def key(self) -> str:
        return f"{self.module}/{self.name}@{self.version}"


def _seed_definition():  # type: ignore[no-untyped-def]
    """A minimal persisted target for a seeded scan row (the ``target_id`` FK is NOT NULL)."""
    from arachne.core.target import TargetDefinition

    return TargetDefinition(
        name="seed-target",
        targets=({"kind": "url", "value": "https://example.com/"},),  # type: ignore[arg-type]
    )


def _set_severity(factory: sessionmaker[Session], finding_id: int, severity: str) -> None:
    from arachne.data.models import Finding

    with factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        finding.severity = severity
        session.commit()


def make_api_harness(
    tmp_path: Path,
    *,
    settings: Settings | None = None,
    pipeline: tuple[ScanStep, ...] = (ScanStep.RECON,),
    post_json: Any = None,
    webhooks: WebhookSettings | None = None,
    keys: tuple[str, ...] | None = None,
    sso: SsoSettings | None = None,
    oidc_transport: Any = None,
    oidc_resolver: Any = None,
) -> ApiHarness:
    """Build an app + services + audit sink over a temp database.

    ``sso`` installs an IdP configuration; ``oidc_transport`` (an ``httpx.MockTransport``
    from :mod:`tests.helpers.idp`) replaces the provider's network with the canned IdP, so
    the whole authorization-code flow runs in-process (REQ-IDAM-001's acceptance test).
    """
    effective = settings or build_api_settings(tmp_path)
    if keys is not None:
        effective = Settings(
            **{
                **_as_kwargs(effective),
                "api": ApiSettings(
                    keys=keys,
                    require_tls=False,
                    rate_limit_per_minute=effective.api.rate_limit_per_minute,
                    rate_limit_burst=effective.api.rate_limit_burst,
                    docs_enabled=effective.api.docs_enabled,
                ),
            }
        )
    if webhooks is not None:
        effective = Settings(**{**_as_kwargs(effective), "webhooks": webhooks})
    if sso is not None:
        effective = Settings(
            **{
                **_as_kwargs(effective),
                "sso": sso,
                # The OIDC flow makes a handful of client calls; a test must not wait on
                # the scanner's per-host budget. Only this SSO harness relaxes it.
                "rate_limit": RateLimitSettings(
                    per_host_rate=1000.0,
                    per_host_burst=1000,
                    global_rate=1000.0,
                    global_burst=1000,
                ),
            }
        )

    engine = create_db_engine(effective.database_url, settings=effective)
    create_all(engine)
    factory = create_session_factory(engine)
    sink = MemoryAuditSink()
    auditor = build_auditor(effective, sinks=[sink], actor="pytest")
    # S20: the evidence backend, its quota ledger and the offload seam, wired exactly as the
    # composition root does (a harness without them would skip offload and quota silently).
    evidence_backend = build_evidence_backend(effective, auditor=auditor)
    quota = StorageQuota(
        factory,
        default_limit_bytes=effective.evidence.default_quota_bytes,
        warn_ratio=effective.evidence.quota_warn_ratio,
    )
    evidence = EvidenceService(evidence_backend, settings=effective, quota=quota, auditor=auditor)
    services = ScanServices(
        settings=effective,
        engine=engine,
        session_factory=factory,
        store=SqlScanStateStore(factory),
        target_store=SqlTargetStore(factory),
        findings=SqlFindingStore(factory),
        analyses=SqlAnalysisStore(factory),
        projects=SqlProjectStore(factory),
        feeds=FeedStore(factory, directory=tmp_path / "feeds"),
        registry=ModuleRegistry.discover(),
        auditor=auditor,
        bus=EventBus(),
        queue=WorkQueue(factory, dialect=engine.dialect.name),
        agents=AgentRegistry(factory),
        service_accounts=ServiceAccountStore(factory),
        identity_flows=SsoFlowStore(factory),
        auth_sessions=SessionStore(factory),
        evidence_backend=evidence_backend,
        evidence=evidence,
        quota=quota,
        # S21: the FP workflow's store, so the quality routes and the UI page are served by the
        # same wired stack a deployment runs (a missing one answers 503 by design).
        quality=SqlQualityStore(factory, auditor=auditor),
        # S23: continuous exposure management (drift baselines, fix verifications, CMDB).
        posture=SqlPostureStore(factory, auditor=auditor),
        # S24: detection validation (purple team) — campaigns, runs and defender alerts.
        purple=SqlPurpleStore(factory),
        # S27: remediation as code — one row per proposed artifact, its approval, the
        # repository's own test verdict and the fix-verification act that closed it.
        fix_proposals=SqlFixProposalStore(factory),
    )
    poster = post_json or StubPoster()
    notifier = WebhookNotifier(effective, auditor=auditor, post_json=poster)
    runner = ScanRunner(
        services,
        settings=effective,
        orchestrator_factory=lambda svc, actor: build_orchestrator(
            svc,
            pipeline=pipeline,
            auditor=svc.auditor.with_actor(actor) if actor else None,
        ),
        notifier=notifier,
    )
    context = AppContext.build(
        effective,
        services,
        auditor=auditor,
        notifier=notifier,
        owns_services=False,
        runner=runner,
    )
    context.queries = ApiQueryStore(factory)
    if sso is not None:
        from arachne.api.oidc import OidcProvider
        from arachne.core.safety import StaticResolver
        from tests.helpers.idp import IDP_PUBLIC_IP

        context.oidc = OidcProvider(
            effective,
            transport=oidc_transport,
            resolver=oidc_resolver or StaticResolver((IDP_PUBLIC_IP,)),
            auditor=auditor,
        )

    from arachne.api.app import create_app

    app = create_app(services, settings=effective, context=context)
    return ApiHarness(
        settings=effective,
        services=services,
        context=context,
        app=app,
        sink=sink,
        poster=poster,
        tmp_path=tmp_path,
    )


def _as_kwargs(settings: Settings) -> dict[str, Any]:
    """Rebuild a dataclass with an overridden field (frozen dataclasses have no replace)."""
    from dataclasses import fields

    return {item.name: getattr(settings, item.name) for item in fields(settings)}


def wait_for_scan(
    client: Any, headers: Mapping[str, str], scan_id: int, *, timeout: float = 15.0
) -> dict[str, Any]:
    """Poll ``GET /scans/{id}`` until the scan leaves pending/running (or time out)."""
    deadline = time.monotonic() + timeout
    payload: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload["status"] not in {"pending", "running"}:
            return payload
        time.sleep(0.05)
    return payload


@pytest.fixture
def api(tmp_path: Path) -> Iterator[ApiHarness]:
    harness = make_api_harness(tmp_path)
    try:
        yield harness
    finally:
        harness.close()
