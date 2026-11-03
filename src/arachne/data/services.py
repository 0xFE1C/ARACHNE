"""Composition root: assemble a working store/audit/event stack from settings.

The CLI and the integration tests both need "a scanner wired to the configured database",
and neither should hand-assemble an engine, a session factory, three stores, an auditor
with the table sink attached, and an event bus. This is that one place.

The schema is **not** created here. ``alembic upgrade head`` owns it (F-09-02), so a
missing schema produces an actionable error rather than a half-migrated database.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, Auditor, build_auditor
from arachne.core.config import Settings, get_settings
from arachne.core.errors import ConfigurationError
from arachne.core.events import EventBus
from arachne.core.lifecycle import DEFAULT_PIPELINE, StepHandler
from arachne.core.orchestrator import ClientFactory, Orchestrator
from arachne.core.pii import PIIPolicy
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.signing import build_signer
from arachne.core.vault import FileCredentialVault, build_vault
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.content_pack_store import ContentPackStore
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.evidence_backend import EvidenceBackend, build_evidence_backend
from arachne.data.evidence_service import EvidenceService
from arachne.data.feed_store import FeedStore
from arachne.data.finding_store import SqlFindingStore
from arachne.data.fix_store import FixProposalStore, SqlFixProposalStore
from arachne.data.identity_store import ServiceAccountStore, SessionStore, SsoFlowStore
from arachne.data.integrity_store import IntegrityService, IntegrityVerifier, SqlAuditChain
from arachne.data.leader_store import LeaderElector
from arachne.data.posture_store import SqlPostureStore
from arachne.data.project_store import SqlProjectStore
from arachne.data.purple_store import PurpleStore, SqlPurpleStore
from arachne.data.quality_store import SqlQualityStore
from arachne.data.queue_store import AgentRegistry, QueueBackend, WorkQueue
from arachne.data.quota import StorageQuota
from arachne.data.retention import RetentionPruner
from arachne.data.review_store import PackReviewStore
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.sim_store import MemorySimulationStore, SqlSimulationStore
from arachne.data.target_store import SqlTargetStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry
from arachne.purple.campaign import PurpleRunner
from arachne.sim.model import EstateGraph
from arachne.sim.resim import Resimulator, build_resimulator

__all__ = [
    "ScanServices",
    "build_estate_graph_for_scan",
    "build_hypothesis_factory",
    "build_integrity_verifier",
    "build_intel_snapshotter",
    "build_orchestrator",
    "build_purple_runner",
    "build_retention_pruner",
    "build_services",
    "require_schema",
]


@dataclass(frozen=True, slots=True)
class ScanServices:
    """A configured, storage-backed stack."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]
    store: SqlScanStateStore
    target_store: SqlTargetStore
    findings: SqlFindingStore
    analyses: SqlAnalysisStore
    #: Tenant/workspace rows (F-07-06, S14).
    projects: SqlProjectStore
    #: Ingested CVE/EPSS artefacts (F-09-03, S14).
    feeds: FeedStore
    registry: ModuleRegistry
    auditor: Auditor
    bus: EventBus
    #: The distributed work queue (S16, area SCALE). Built over the same session
    #: factory; ``None`` only for stacks constructed before S16 that have not been
    #: given one. Typed as the backend protocol, so a Redis adapter (REQ-SCALE-001's
    #: reserved seam) can replace the Postgres table without touching callers.
    queue: QueueBackend | None = None
    #: The registered agent fleet (S16, REQ-SCALE-002).
    agents: AgentRegistry | None = None
    #: API keys as service accounts (S17, REQ-IDAM-003).
    service_accounts: ServiceAccountStore | None = None
    #: Pending OIDC authorization-code flows (S17, REQ-IDAM-001).
    identity_flows: SsoFlowStore | None = None
    #: Minted SSO sessions (S17, REQ-IDAM-001).
    auth_sessions: SessionStore | None = None
    #: The credential vault (S19, area CREDS, REQ-CREDS-002). ``None`` means this deployment
    #: has no vault, so every credential-dependent check reports itself skipped and a scan
    #: that names a credential runs unauthenticated with an audited refusal. Deliberately
    #: node-local (a file, not a table): a credential never travels a control plane.
    credentials: FileCredentialVault | None = None
    #: Where oversized evidence payloads go (S20, REQ-DATA-002). The local filesystem by
    #: default; an S3-compatible object store when the deployment configures one.
    evidence_backend: EvidenceBackend | None = None
    #: The offload/quota seam the checks step uses (S20, REQ-DATA-002/003).
    evidence: EvidenceService | None = None
    #: Per-project storage accounting (S20, REQ-DATA-003).
    quota: StorageQuota | None = None
    #: The FP workflow (S21, area QUAL, REQ-QUAL-001...004): suppression rules, risk
    #: acceptances and the FP-feedback history the trend view reads. ``None`` means the
    #: deployment has none wired, and every caller then behaves as if no rule existed.
    quality: SqlQualityStore | None = None
    #: Continuous exposure management (S23, area POSTURE): drift baselines, the
    #: fix-verification history and CMDB criticality. ``None`` means the continuous
    #: checks report themselves skipped ("no baseline store") instead of failing.
    posture: Any | None = None
    #: Detection validation (S24, area VALID): purple-team campaigns, their runs and the
    #: ingested defender alerts. ``None`` means this deployment cannot run a campaign (the
    #: service refuses loudly rather than reporting an empty result), and a scan that asks
    #: for purple mode is refused by the orchestrator's gate.
    purple: PurpleStore | None = None
    #: Tamper-evidence (S25, REQ-TRUST-005): the audit chain lives in ``auditor``; this is
    #: the seal/anchor/verify seam the scan machine and the CLI use. ``None`` means the
    #: deployment cannot seal or verify, and ``arachne verify-chain`` says so.
    integrity: IntegrityService | None = None
    #: The HA leader electors (S25, REQ-RESIL-002), one per singleton job, keyed by name.
    leader: LeaderElector | None = None
    #: Provenance of imported offline content packs (S25, REQ-RESIL-001).
    content_packs: ContentPackStore | None = None
    #: Provenance of the marketplace review pipeline (S26, REQ-ECOS-001): one row per
    #: reviewed pack, so "why is this pack listed?" is answerable from the database.
    pack_reviews: PackReviewStore | None = None
    #: Remediation as code (S27, area FIX): one row per proposed artifact, with its
    #: approval, its test and self-scan verdicts, the branch it created and the
    #: fix-verification act that closed it. ``None`` means this deployment cannot propose
    #: fixes at all — the CLI says so rather than reporting an empty list.
    fix_proposals: FixProposalStore | None = None
    #: Simulation & what-if modeling (S28, area SIM): the re-simulation trend — one row per
    #: event-driven re-run of the estate model (REQ-SIM-006). ``None`` means this deployment
    #: keeps no simulation trend: a what-if run still works (it is a pure computation over
    #: stored scan data), but continuous re-simulation has nowhere to record its points.
    simulations: SqlSimulationStore | None = None

    def close(self) -> None:
        self.engine.dispose()


def require_schema(engine: Engine) -> None:
    """Fail with an actionable message when migrations have not been applied (F-09-02)."""
    present = set(inspect(engine).get_table_names())
    if "scans" not in present:
        msg = (
            "the database has no ARACHNE schema (table 'scans' is missing); "
            "run `arachne db upgrade` first"
        )
        raise ConfigurationError(msg)


def build_integrity_verifier(services: ScanServices) -> IntegrityVerifier:
    """The verifier ``arachne verify-chain`` drives (S25, REQ-TRUST-005).

    Built from the same key and the same store the writer used, so a signature or a seal the
    writer produced is checked against exactly the material it was produced with.
    """
    return IntegrityVerifier(
        services.session_factory,
        signer=build_signer(services.settings),
        require_signatures=services.settings.integrity.require_signatures,
    )


def build_retention_pruner(services: ScanServices) -> RetentionPruner:
    """The pruning job for this deployment (S20, REQ-DATA-001; S25 PII, WP-14).

    Its evidence backend is the *same* object the scan writes through, so a pruned row's
    object is unlinked from the store it actually lives in. The PII resolver is the same one
    the evidence service masks with, so the re-mask applies the *project's* policy rather
    than a second opinion about it (REQ-DATA-005), and the integrity service is the same
    seal/anchor seam, so a re-masked blob's row signature and its scan's seal are refreshed
    rather than left to fail verification.
    """
    default_pii = PIIPolicy.from_settings(services.settings.pii)
    return RetentionPruner(
        services.session_factory,
        settings=services.settings,
        auditor=services.auditor,
        quota=services.quota,
        evidence=services.evidence_backend,
        pii_policy=lambda project_id: services.projects.pii_policy(
            project_id, fallback=default_pii
        ),
        integrity=services.integrity,
    )


def build_services(settings: Settings | None = None, *, check_schema: bool = True) -> ScanServices:
    """Build the stack for ``settings`` (the configured database)."""
    effective = settings or get_settings()
    engine = create_db_engine(settings=effective)
    if check_schema:
        require_schema(engine)
    factory = create_session_factory(engine)
    store = SqlScanStateStore(factory)
    target_store = SqlTargetStore(factory)
    # S25 (REQ-TRUST-005): the deployment key and the audit hash chain. The chain *is* the
    # durable audit sink — computing a link and writing its row are one transaction, so a
    # reserved-but-unwritten position cannot masquerade as a deleted row. A deployment
    # without a key still chains (the chain detects edits); only the signatures are absent.
    signer = build_signer(effective)
    chain = SqlAuditChain(factory, signer=signer)
    # The table sink is gone from this list on purpose: ``SqlAuditChain`` writes the audit_log
    # rows itself (see its docstring). Log/JSONL sinks still receive the chained event.
    auditor = build_auditor(effective, chain=chain)
    integrity = IntegrityService(
        factory,
        signer=signer,
        auditor=auditor,
        anchor_every=effective.integrity.anchor_every,
        require_signatures=effective.integrity.require_signatures,
    )
    # S20: evidence storage, its quota ledger and the seam the checks step uses. The backend
    # is built here so the scan, the retention job and the API all address the same store.
    evidence_backend = build_evidence_backend(effective, auditor=auditor)
    quota = StorageQuota(
        factory,
        default_limit_bytes=effective.evidence.default_quota_bytes,
        warn_ratio=effective.evidence.quota_warn_ratio,
    )
    projects = SqlProjectStore(factory)
    default_pii = PIIPolicy.from_settings(effective.pii)
    evidence = EvidenceService(
        evidence_backend,
        settings=effective,
        quota=quota,
        auditor=auditor,
        pii_policy=lambda project_id: projects.pii_policy(project_id, fallback=default_pii),
        region=effective.resilience.region,
    )
    return ScanServices(
        settings=effective,
        engine=engine,
        session_factory=factory,
        store=store,
        target_store=target_store,
        # S25: findings and evidence are signed as they are written, and every evidence row
        # is stamped with this deployment's region (REQ-RESIL-004). WP-14 (REQ-PROOF-018):
        # the auditor records each blob's content hash in the chain at capture, which is
        # what makes a later edit to a stored payload detectable by `verify-chain`.
        findings=SqlFindingStore(
            factory,
            signer=signer,
            region=effective.resilience.region,
            auditor=auditor,
        ),
        analyses=SqlAnalysisStore(factory),
        projects=projects,
        feeds=FeedStore(factory, directory=effective.feeds_dir),
        registry=ModuleRegistry.discover(),
        auditor=auditor,
        bus=EventBus(),
        queue=WorkQueue(factory, dialect=engine.dialect.name),
        agents=AgentRegistry(factory),
        service_accounts=ServiceAccountStore(factory),
        identity_flows=SsoFlowStore(factory),
        auth_sessions=SessionStore(factory),
        credentials=build_vault(effective),
        evidence_backend=evidence_backend,
        evidence=evidence,
        quota=quota,
        # S21: the quality workflow's store, over the same session factory and the same audit
        # trail, so a suppression or an acceptance is recorded where every other decision is.
        quality=SqlQualityStore(factory, auditor=auditor),
        # S23: continuous exposure management (drift baselines, fix verifications, CMDB
        # criticality) over the same session factory and audit trail.
        posture=SqlPostureStore(factory, auditor=auditor),
        # S24: detection validation (purple team) — campaigns, their runs and the ingested
        # defender alerts, over the same session factory.
        purple=SqlPurpleStore(factory),
        # S27: remediation as code — one row per proposed artifact, over the same session
        # factory so a proposal's whole life is in the deployment's own database.
        fix_proposals=SqlFixProposalStore(factory),
        # S25: the seal/anchor/verify seam, the HA leader lease and the content-pack ledger.
        integrity=integrity,
        leader=LeaderElector(
            factory,
            name="scheduler",
            ttl_s=effective.resilience.leader_ttl_s,
            auditor=auditor,
        ),
        content_packs=ContentPackStore(factory),
        pack_reviews=PackReviewStore(factory),
        # S28: the simulation trend's store, over the same session factory. It is the only
        # S28 table, and it holds observations of a *computation* — no finding row is written
        # anywhere by area SIM, which is what keeps a simulated result out of every gate.
        simulations=SqlSimulationStore(factory),
    )


def build_purple_runner(services: ScanServices) -> PurpleRunner:
    """The purple-team handlers seam for this deployment (S24, area VALID).

    Returns the runner built from the deployment settings (the shipped ATT&CK replay map,
    or ``ARACHNE_PURPLE_MAP`` when set). It is a *leaf*: no store, no service, no
    orchestrator — a scan can tag what it emits and enforce its own window, and nothing
    more.
    """
    return PurpleRunner.build(services.settings)


def build_hypothesis_factory(
    services: ScanServices, auditor: Auditor | None = None
) -> Callable[[Any], StepHandler]:
    """The agentic hypothesis step's factory (S21, area AGENT).

    Returns a callable that the orchestrator calls with **itself**: the step's executor plans
    every probe through ``Orchestrator.plan_hypothesis``, so there is no way to construct the
    agentic step without the gates it must pass (REQ-AGENT-005). The collaborators are resolved
    once, here — the check index from the catalogue, the rule corpus, the module configuration,
    the OSINT access — and the AI engine is built lazily on first use, so a heuristic-only
    deployment never constructs a provider.
    """
    from arachne.core.catalog import load_catalog
    from arachne.modules.handlers import module_config_from_settings, osint_from_settings
    from arachne.reasoning.control import build_hypothesis_control
    from arachne.reasoning.index import CheckIndex
    from arachne.reasoning.step import build_hypothesis_step, load_rules

    effective_auditor = auditor or services.auditor
    index = CheckIndex.from_catalog(load_catalog())
    rules = load_rules(services.settings)
    module_config = module_config_from_settings(services.settings, services.feeds)
    osint = osint_from_settings(services.settings, auditor=effective_auditor)
    control = build_hypothesis_control(services.settings.hypotheses.control_path)

    def factory(gate: Any) -> StepHandler:
        return build_hypothesis_step(
            gate=gate,
            index=index,
            registry=services.registry,
            findings=services.findings,
            analyses=services.analyses,
            settings=services.settings,
            rules=rules,
            config=module_config,
            osint=osint,
            control=control,
            auditor=effective_auditor,
        )

    return factory


def build_orchestrator(
    services: ScanServices,
    *,
    handlers: Mapping[ScanStep, StepHandler] | None = None,
    client_factory: ClientFactory | None = None,
    pipeline: tuple[ScanStep, ...] = DEFAULT_PIPELINE,
    project_id: int | None = None,
    project_scope: Scope | None = None,
    auditor: Auditor | None = None,
) -> Orchestrator:
    """Assemble an :class:`Orchestrator` over ``services``.

    ``handlers=None`` builds the module-backed set against this deployment's settings, so a
    live scan runs the registered checks and persists the candidates they raise (F-01-03,
    F-02-08). Passing an explicit mapping replaces it (the crash/resume tests do).

    ``pipeline`` narrows the steps a scan runs (S12): the API's tests and a deployment that
    wants, say, recon only, pass a shorter pipeline here rather than subclassing the
    orchestrator.

    ``auditor`` (S16) overrides the trail the scan and its handlers sign with — the agent
    executor passes an auditor carrying the agent's identity (REQ-SCALE-004), built over
    the same sink.
    """
    effective_auditor = auditor or services.auditor
    effective_handlers = (
        build_handlers(
            settings=services.settings,
            registry=services.registry,
            findings=services.findings,
            auditor=effective_auditor,
            analyses=services.analyses,
            feeds=services.feeds,
            vault=services.credentials,
            posture=services.posture,
            # S24: the purple-team seam — the ATT&CK replay catalogue plus a clock. A
            # deployment without it cannot run a detection test, because there is nothing
            # to tag the emitted artifacts with (REQ-VALID-003).
            purple=build_purple_runner(services),
        )
        if handlers is None
        else handlers
    )
    return Orchestrator(
        settings=services.settings,
        store=services.store,
        target_store=services.target_store,
        auditor=effective_auditor,
        bus=services.bus,
        handlers=effective_handlers,
        client_factory=client_factory,
        registry=services.registry,
        pipeline=pipeline,
        project_id=project_id,
        project_scope=project_scope,
        # S18: every admitted scan records which threat-intel data it was planned against, so
        # the report can state its own freshness (REQ-INTEL-001).
        intel_snapshot=build_intel_snapshotter(services),
        # S20: the checks step offloads oversized evidence and enforces the project quota
        # before a finding is written (REQ-DATA-002/003).
        evidence=services.evidence,
        # S25: the tamper-evidence seam. The scan machine seals the completed scan's findings
        # and evidence, which is what makes a deleted row detectable (REQ-TRUST-005).
        integrity=services.integrity,
        # S21: the agentic hypothesis step, wired to *this* orchestrator as its gate. The step
        # exists but stays inert until a scan (or the deployment) enables a hypothesis mode.
        hypothesis_factory=build_hypothesis_factory(services, effective_auditor),
    )


def build_intel_snapshotter(services: ScanServices) -> Callable[[], dict[str, Any]]:
    """A callable that snapshots the feed freshness for one scan (S18).

    Built here — the composition root — because it needs both the feed store and the settings,
    and because ``core`` must stay free of the data layer (the same reason the handlers are
    assembled here).
    """
    from arachne.intel.freshness import intel_snapshot

    return lambda: intel_snapshot(services.feeds, settings=services.settings)


#: How many of a project's newest scans one estate model is built from. The same bound the
#: S23 estate report uses, for the same reason: a model of everything ever scanned would
#: answer a question nobody asked.
DEFAULT_ESTATE_SCAN_LIMIT: Final = 20

#: The checks whose findings prove an authenticated session reached a host (S19). A
#: credential binding is only recorded where one of these ran, because that is the only
#: evidence ARACHNE holds that the identity actually reached that host.
AUTHENTICATED_CHECKS: Final = ("m3.authenticated-surface", "m3.session-logout", "m2.smb-auth")


def build_estate_graph_for_scan(
    services: ScanServices,
    *,
    scan_id: int | None = None,
    project_id: int | None = None,
    limit: int = DEFAULT_ESTATE_SCAN_LIMIT,
    estate_key: str = "",
    auditor: Auditor | None = None,
) -> EstateGraph:
    """Read the stores and build the estate model for one scan or a project's recent scans.

    This is the *only* place area SIM touches a store, and it does so read-only: assets,
    stored findings (with their evidence payloads, from which reachability is read) and the
    analyzer's output. The graph itself is built by the pure ``build_estate_graph``, so
    everything the simulation engine ever sees is plain values.

    Identity relationships are derived here rather than in the model, and only from evidence:
    a credential label is bound to the host a credentialed scan actually authenticated to
    (its plan's target, plus any host that produced an authenticated-area finding), because
    "which identity reaches which host" is an authorization claim and a guess would be a
    false one (REQ-SIM-001).
    """
    from arachne.data.analysis_store import analysis_from_log
    from arachne.sim.model import build_estate_graph

    effective = auditor or services.auditor
    scans = _estate_scans(services, scan_id=scan_id, project_id=project_id, limit=limit)
    if not scans:
        msg = "no scan to model: run a scan first, or name a scan that exists"
        raise ConfigurationError(msg)
    assets: list[Any] = []
    candidates: list[Any] = []
    analyses: list[Any] = []
    scanned: list[int] = []
    for record in scans:
        current = int(record.id)
        scanned.append(current)
        assets.extend(services.store.list_assets(current))
        candidates.extend(services.findings.list_candidates(current))
        for row in services.analyses.list_analyses(current):
            rebuilt = analysis_from_log(row)
            if rebuilt is not None:
                analyses.append(rebuilt)

    # Identity relationships are read from evidence, once, over every modelled scan: the
    # host a credentialed scan authenticated to, and any host an authenticated-area finding
    # proves the session reached (REQ-SIM-001).
    bindings = _binding_set(scans, candidates)

    graph = build_estate_graph(
        estate_key=estate_key or _estate_key(services, scans),
        assets=assets,
        candidates=candidates,
        analyses=analyses,
        identity_bindings=bindings,
        built_from_scans=scanned,
        criticality=_criticality_index(services),
    )
    effective.record(
        AuditAction.SIMULATION_MODEL_BUILT,
        target=graph.estate_key,
        reason="estate model built from stored scan data (no target interaction)",
        meta={
            "scans": scanned,
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "weaknesses": len(graph.weaknesses),
            "services": len(graph.services),
            "identity_bindings": len(graph.identity_bindings),
        },
    )
    return graph


def build_resimulator_for(
    services: ScanServices,
    *,
    estate_key: str,
    hypotheses: Sequence[Any] = (),
    scan_id: int | None = None,
    project_id: int | None = None,
) -> Resimulator:
    """The deployment's re-simulator (S28, REQ-SIM-006).

    ``ARACHNE_SIM_RESIMULATE`` decides whether it is *active*; the object is always built so
    an operator can drive one run by hand (``arachne simulate trend --run``) without turning
    continuous simulation on for the whole deployment.
    """
    effective = services.settings.sim

    def provider(event_scan_id: int | None) -> EstateGraph | None:
        try:
            return build_estate_graph_for_scan(
                services,
                scan_id=event_scan_id or scan_id,
                project_id=project_id,
                estate_key=estate_key,
            )
        except ConfigurationError:
            # No scan data yet: nothing to model, so the trend simply gets no point. A trend
            # line standing for "no data" would read as "no exposure", which is a lie.
            return None

    return build_resimulator(
        store=services.simulations or MemorySimulationStore(),
        graph_provider=provider,
        hypotheses=tuple(hypotheses),
        auditor=services.auditor,
        enabled=effective.resimulate,
        max_paths=effective.max_paths,
        min_confidence=effective.min_confidence,
    )


def _estate_scans(
    services: ScanServices, *, scan_id: int | None, project_id: int | None, limit: int
) -> tuple[Any, ...]:
    """The scans a model is built from: the named one, or a project's newest ``limit``."""
    if scan_id is not None:
        record = services.store.get_scan(scan_id)
        if record is None:
            msg = f"scan {scan_id} does not exist"
            raise ConfigurationError(msg)
        return (record,)
    rows = services.store.list_scans(limit=limit)
    if project_id is not None:
        rows = tuple(row for row in rows if getattr(row, "project_id", None) == project_id)
    return tuple(rows)


def _estate_key(services: ScanServices, scans: Sequence[Any]) -> str:
    projects = {getattr(row, "project_id", None) for row in scans}
    if len(projects) == 1 and None not in projects:
        return f"project:{next(iter(projects))}"
    if len(scans) == 1:
        return f"scan:{scans[0].id}"
    return "estate:default"


def _binding_set(scans: Sequence[Any], candidates: Sequence[Any]) -> tuple[Any, ...]:
    """The identity relationships the modelled scans proved (S19 credential labels).

    Two sources, both evidence rather than inference: the host a credentialed scan was
    pointed at (that is the application it established a session with) and every host that
    produced an authenticated-area finding (that is proof the session reached there).
    """
    from arachne.analyzer.paths import host_of, normalise_check_id
    from arachne.sim.model import IdentityBinding

    authenticated_hosts: set[str] = set()
    for record in candidates:
        key = normalise_check_id(str(getattr(record, "check_key", "") or ""))
        if key in AUTHENTICATED_CHECKS:
            asset = str(getattr(record, "asset_value", "") or "")
            if asset:
                authenticated_hosts.add(host_of(asset))

    out: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for scan in scans:
        labels = _credential_labels(scan)
        if not labels:
            continue
        hosts = set(authenticated_hosts)
        plan = dict(getattr(scan, "plan", None) or {})
        target = str(plan.get("target_name") or "").strip()
        if target:
            hosts.add(host_of(target))
        for label in labels:
            for host in sorted(hosts):
                if (label, host) in seen:
                    continue
                seen.add((label, host))
                out.append(
                    IdentityBinding(
                        identity=label,
                        host=host,
                        kind="credential",
                        source=f"scan {scan.id}",
                    )
                )
    return tuple(out)


def _credential_labels(scan: Any) -> tuple[str, ...]:
    block = (getattr(scan, "stats", None) or {}).get("credentials") or {}
    labels = block.get("labels") if isinstance(block, dict) else None
    return tuple(str(label) for label in labels or () if str(label).strip())


def _criticality_index(services: ScanServices) -> Any:
    """The CMDB criticality import, when this deployment has one (S23, REQ-POSTURE-006).

    It is passed to the composer as an opaque value: area SIM may not import
    :mod:`arachne.posture` (which owns a re-scan path), and the composer already knows how to
    read a ``CriticalityIndex`` or a plain mapping.
    """
    posture = services.posture
    if posture is None:
        return None
    try:
        return posture.criticality_index()
    except Exception:  # a missing CMDB import must not break a simulation
        return None
