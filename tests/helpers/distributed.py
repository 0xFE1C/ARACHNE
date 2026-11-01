"""A services stack over a SQLite file for the distributed (S16) tests.

The distributed tests need *several* nodes over one store — an API process, two agents,
a scheduler — and the honest way to model that is several independently built
:class:`~arachne.data.services.ScanServices` stacks over the same database file, each
with its own engine and connections. This helper is that construction in one place, with
a memory audit sink so audit assertions read events instead of scraping logs.
"""

from __future__ import annotations

from pathlib import Path

from arachne.core.audit import AuditAction, AuditEvent, MemoryAuditSink, build_auditor
from arachne.core.config import (
    ApiSettings,
    DistributedSettings,
    SchedulerSettings,
    Settings,
)
from arachne.core.events import EventBus
from arachne.core.vault import build_vault
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_all, create_db_engine, create_session_factory
from arachne.data.evidence_backend import build_evidence_backend
from arachne.data.evidence_service import EvidenceService
from arachne.data.feed_store import FeedStore
from arachne.data.finding_store import SqlFindingStore
from arachne.data.posture_store import SqlPostureStore
from arachne.data.project_store import SqlProjectStore
from arachne.data.purple_store import SqlPurpleStore
from arachne.data.queue_store import AgentRegistry, WorkQueue
from arachne.data.quota import StorageQuota
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.services import ScanServices
from arachne.data.target_store import SqlTargetStore
from arachne.modules.registry import ModuleRegistry

__all__ = ["DistributedStack", "build_stack", "distributed_settings"]


def distributed_settings(db_path: Path, **distributed: object) -> Settings:
    """Settings for a distributed deployment over ``db_path`` (all nodes share it)."""
    return Settings(
        database_url=f"sqlite:///{db_path}",
        log_level="CRITICAL",
        log_json=False,
        actor="distributed-test",
        api=ApiSettings(
            keys=("admin:admin:rootsecret", "scanner:scanner:scansecret",
                  "viewer:viewer:viewsecret"),
            require_tls=False,
            rate_limit_per_minute=100_000,
            rate_limit_burst=100_000,
        ),
        # A per-deployment scheduler state file: the default path is relative to the
        # working directory, which would leak schedule state between tests.
        scheduler=SchedulerSettings(
            state_path=str(db_path.parent / "schedules.json"), diff_on_run=True
        ),
        distributed=DistributedSettings(enabled=True, **distributed),  # type: ignore[arg-type]
    )


class DistributedStack:
    """One node's view of the shared store, plus the audit events it wrote."""

    def __init__(self, services: ScanServices, sink: MemoryAuditSink) -> None:
        self.services = services
        self.sink = sink

    @property
    def settings(self) -> Settings:
        return self.services.settings

    def events_of(self, action: AuditAction) -> list[AuditEvent]:
        return [event for event in self.sink.events if event.action is action]

    def actions(self) -> list[str]:
        return [event.action.value for event in self.sink.events]

    def close(self) -> None:
        self.services.close()


def build_stack(
    db_path: Path,
    *,
    settings: Settings | None = None,
) -> DistributedStack:
    """Build one node over ``db_path`` (creating the schema on the first call)."""
    effective = settings or distributed_settings(db_path)
    engine = create_db_engine(effective.database_url, settings=effective)
    create_all(engine)
    factory = create_session_factory(engine)
    sink = MemoryAuditSink()
    auditor = build_auditor(effective, sinks=[sink], actor="distributed-test")
    # S20: the same evidence stack the composition root builds, so a distributed test's scans
    # exercise offload and quota rather than silently skipping them.
    evidence_backend = build_evidence_backend(effective, auditor=auditor)
    quota = StorageQuota(
        factory,
        default_limit_bytes=effective.evidence.default_quota_bytes,
        warn_ratio=effective.evidence.quota_warn_ratio,
    )
    evidence = EvidenceService(
        evidence_backend, settings=effective, quota=quota, auditor=auditor
    )
    services = ScanServices(
        settings=effective,
        engine=engine,
        session_factory=factory,
        store=SqlScanStateStore(factory),
        target_store=SqlTargetStore(factory),
        findings=SqlFindingStore(factory),
        analyses=SqlAnalysisStore(factory),
        projects=SqlProjectStore(factory),
        feeds=FeedStore(factory, directory=db_path.parent / "feeds"),
        registry=ModuleRegistry.discover(),
        auditor=auditor,
        bus=EventBus(),
        queue=WorkQueue(factory, dialect=engine.dialect.name),
        agents=AgentRegistry(factory),
        # S19: the node-local credential vault, when the settings configure one. Mirrors
        # ``build_services``: a node that has not configured ``ARACHNE_VAULT_PATH`` has no
        # vault, which is what makes "this node does not hold that label" the honest answer.
        credentials=build_vault(effective),
        evidence_backend=evidence_backend,
        evidence=evidence,
        quota=quota,
        # S23: continuous exposure management (drift baselines, fix verifications, CMDB).
        posture=SqlPostureStore(factory, auditor=auditor),
        purple=SqlPurpleStore(factory),
    )
    return DistributedStack(services, sink)
