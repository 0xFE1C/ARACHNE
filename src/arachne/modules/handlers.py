"""Module-backed pipeline handlers: what a scan actually runs (F-01-03, F-02-01).

The pipeline steps are S2's; this module supplies the handlers that give the ``recon`` and
``checks`` steps detection work to do:

``recon``
    S2's offline seeding first (the declared targets become the inventory), then every
    selected check whose module maps to the recon step — today all of M1. M1 runs *before*
    endpoint discovery, because its whole purpose is to feed the inventory the later modules
    attach to .
``discovery``
    S2's offline endpoint derivation first (web endpoint candidates from the seeded hosts),
    then the M2 checks (S4). M2's checks form a pipeline of their own — liveness → open ports
    → service identity → protocol posture → CVE correlation — and they share a
    :class:`~arachne.modules.m2.inventory.NetworkInventory` built once per step and handed to
    every check through the step context (ADR-080.2).
``checks``
    every selected check whose module maps to the checks step (M3-M6, stages S6+). With no
    such check implemented, the step reports itself skipped rather than pretending. S7 adds
    one ordering rule: a check that *publishes* routes into the shared crawl
    (:data:`INVENTORY_PRODUCERS`, today ``m4.api-doc-exposure``) runs before the checks that
    consume the inventory, so an exposed OpenAPI document feeds ``m3.api-surface`` in the
    same run.

Design rules that keep this honest and testable:

* **Selection happens here, per scan** (F-02-09): ``ctx.options.modules`` and the
  active-checks switch decide; the registry only describes.
* **One check failure never ends a step.** ``guard_check`` turns an exception into a single
  ``status="error"`` result, which is recorded and counted .
* **Candidates are persisted, info results are not.** A ``vulnerable`` result becomes a
  ``findings`` row with its evidence; an ``info`` result (an asset discovered) shows up in
  the asset inventory and the step statistics, which is where it belongs.
* **OSINT is built once per step** and closed on the way out, so a scan cannot leak a
  connection pool, and ``None`` (the default) means the offline path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from arachne.analyzer.correlation import CorrelationEngine
from arachne.analyzer.engine import HeuristicEngine
from arachne.analyzer.handlers import build_analysis_handlers
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import Settings
from arachne.core.errors import StorageQuotaError
from arachne.core.events import Event
from arachne.core.lifecycle import StepContext, StepHandler, StepOutcome
from arachne.core.logging import get_logger
from arachne.core.planner import MODULE_STEP, ScanStep
from arachne.core.results import CheckResult, Evidence, guard_check
from arachne.core.steps import discovery_step, recon_step
from arachne.data.analysis_store import AnalysisStore
from arachne.data.finding_store import CandidateRecord, FindingStore, MemoryFindingStore
from arachne.modules.base import Asset, Module
from arachne.modules.context import CheckContext, ModuleConfig, collect_results
from arachne.modules.m2.inventory import NetworkInventory
from arachne.modules.m3.inventory import WebInventory, build_web_inventory
from arachne.modules.m3.support import step_fetcher
from arachne.modules.providers import (
    OsintAccess,
    build_osint_access,
    build_osint_access_for_fixtures,
    load_fixture_routes,
)
from arachne.modules.registry import ModuleRegistry
from arachne.proof.access import ProofAccess
from arachne.proof.ledger import ProofLedger, audit_repair_instructions
from arachne.purple.attack import NO_EVASION_POLICY
from arachne.purple.window import window_payload

__all__ = [
    "build_handlers",
    "crawl_web_surface",
    "make_checks_handler",
    "make_discovery_handler",
    "make_recon_handler",
    "module_config_from_settings",
    "osint_from_settings",
    "run_checks",
]

_logger = get_logger("modules.handlers")

#: The marker a skipped check leaves in its evidence (see :meth:`CheckContext.skipped`).
SKIP_MARKER = "skipped"

#: Checks that add routes to the shared crawl, and so must run before a check that replays
#: them (S7: the API-document check feeds ``m3.api-surface``). Ordering is otherwise stable.
INVENTORY_PRODUCERS: frozenset[str] = frozenset({"m4.api-doc-exposure"})


def module_config_from_settings(settings: Settings | None, feeds: Any = None) -> ModuleConfig:
    """Build the checks' configuration, resolving ingested feeds when a store is supplied.

    An imported EPSS/KEV artefact overrides ``ARACHNE_M6_*_FEED`` for this run (F-09-03).
    A feed-store error must not stop a scan — the checks then fall back to the configured
    path and the shipped snapshot, which is what the offline default already does.
    """
    if settings is None:
        return ModuleConfig()
    epss_feed: str | None = None
    kev_feed: str | None = None
    if feeds is not None:
        try:
            epss_feed = feeds.effective_path("epss")
            kev_feed = feeds.effective_path("kev")
        except Exception as exc:  # pragma: no cover - a broken feed store must not stop a scan
            _logger.warning(
                "could not resolve ingested feeds; using configured paths",
                extra={"event": "feeds.resolve_failed", "error": str(exc)},
            )
    return ModuleConfig.from_settings(settings, epss_feed=epss_feed, kev_feed=kev_feed)


def build_handlers(
    *,
    settings: Settings | None = None,
    registry: ModuleRegistry | None = None,
    findings: FindingStore | None = None,
    osint: OsintAccess | None = None,
    auditor: Auditor | None = None,
    analyses: AnalysisStore | None = None,
    analysis_engine: HeuristicEngine | None = None,
    correlation_engine: CorrelationEngine | None = None,
    feeds: Any = None,
    callback_service: Any = None,
    vault: Any = None,
    hypothesis: StepHandler | None = None,
    posture: Any = None,
    purple: Any = None,
) -> dict[ScanStep, StepHandler]:
    """The full handler set a live scan runs, with the module steps wired in.

    ``osint=None`` builds the OSINT access from ``settings``; when ``ARACHNE_OSINT_ENABLED``
    is not set (the default) that is ``None`` as well, and every M1 check reports a skipped
    result — which is what keeps a default scan offline. The OSINT client shares the scan's
    auditor, so a third-party query and a blocked one land in the same trail as every other
    request (F-01-08).

    ``callback_service`` is the in-process out-of-band callback service (S15, tests and
    single-node deployments). ``None`` means standalone mode: an L2 check talks to
    ``ARACHNE_WEB_SSRF_CALLBACK`` over HTTP like any other request.

    ``vault`` is this node's credential vault (S19, REQ-CREDS-002). ``None`` — the default —
    means credentialed scanning is unavailable here: a scan that names a credential runs
    unauthenticated and the refusal is audited, never silently borrowed from elsewhere.

    The ``analysis`` and ``correlation`` steps are wired here too (S5), over the same
    finding store the checks step writes to: the analyzer is part of the scan, not an
    optional command, so a live scan produces analysed findings by default.

    ``hypothesis`` is the S21 agentic step. It is passed in **only** by an orchestrator that
    can supply the gate the executor needs (the planner plus the scope/authorization/proof
    checks), and it is absent otherwise — a scan cannot enable agentic reasoning and then run
    it without a gate, because there is no handler to run.

    ``posture`` is the continuous-posture baseline store (S23, area POSTURE). ``None`` — the
    default — means the continuous checks run stateless (point-in-time policies only, with a
    recorded note): a plain scan never invents a drift baseline.

    ``purple`` is the purple-team seam (S24, area VALID): the shipped ATT&CK replay
    catalogue plus a clock. ``None`` — the default — means no scan this handler set runs can
    be a detection test, because there is nothing to tag its artifacts with. It holds no
    store and no service: a check cannot start a campaign from inside a scan, it can only
    label what it emits.
    """
    effective_registry = registry or ModuleRegistry.discover()
    effective_findings = findings or MemoryFindingStore()
    effective_osint = osint if osint is not None else osint_from_settings(settings, auditor=auditor)
    module_config = module_config_from_settings(settings, feeds)
    analysis_handlers = build_analysis_handlers(
        settings=settings,
        registry=effective_registry,
        findings=effective_findings,
        analyses=analyses,
        engine=analysis_engine,
        correlation=correlation_engine,
        # The AI engine audits every stage call on the scan's trail (S9).
        auditor=auditor,
    )
    handlers: dict[ScanStep, StepHandler] = {
        ScanStep.RECON: make_recon_handler(
            registry=effective_registry,
            findings=effective_findings,
            osint=effective_osint,
            config=module_config,
        ),
        ScanStep.DISCOVERY: make_discovery_handler(
            registry=effective_registry,
            findings=effective_findings,
            osint=effective_osint,
            config=module_config,
        ),
        ScanStep.CHECKS: make_checks_handler(
            registry=effective_registry,
            findings=effective_findings,
            osint=effective_osint,
            config=module_config,
            callback_service=callback_service,
            vault=vault,
            posture=posture,
            purple=purple,
        ),
        **analysis_handlers,
    }
    if hypothesis is not None:
        handlers[ScanStep.HYPOTHESIS] = hypothesis
    return handlers


#: Backwards-compatible alias: the S18 tests and out-of-tree callers used the private name
#: before S21 made it public for the hypothesis step's runtime.
_module_config = module_config_from_settings


def osint_from_settings(
    settings: Settings | None, *, auditor: Auditor | None = None
) -> OsintAccess | None:
    if settings is None:
        return None
    osint = settings.osint
    if not osint.enabled:
        # The master switch: a deployment that has not enabled OSINT contacts no third party,
        # even when recordings are configured (F-02-09, safe defaults).
        return None
    if osint.is_fixture_mode() and osint.fixtures_dir:
        return build_osint_access_for_fixtures(
            load_fixture_routes(osint.fixtures_dir),
            providers=osint.providers,
            budget=osint.request_budget,
            auditor=auditor,
            extra_hosts=osint.extra_hosts,
            search_url=osint.search_url,
            whois_url=osint.provider_url("whois") if "whois" in osint.providers else None,
            rate_limits=dict(osint.provider_rate_limits),
            usable=osint.usable_provider,
        )
    return build_osint_access(
        enabled=osint.enabled,
        providers=osint.providers,
        budget=osint.request_budget,
        auditor=auditor,
        extra_hosts=osint.extra_hosts,
        search_url=osint.search_url,
        whois_url=osint.provider_url("whois") if "whois" in osint.providers else None,
        rate_limits=dict(osint.provider_rate_limits),
        usable=osint.usable_provider,
    )


# --------------------------------------------------------------------------- recon
def make_recon_handler(
    *,
    registry: ModuleRegistry,
    findings: FindingStore,
    osint: OsintAccess | None,
    config: ModuleConfig | None = None,
) -> StepHandler:
    """Seed the inventory, then run the recon-step modules (M1) over it."""

    async def handler(ctx: StepContext) -> StepOutcome:
        seeded = await recon_step(ctx)
        stats: dict[str, Any] = dict(seeded.stats)
        stats.update(
            await run_checks(
                ctx,
                step=ScanStep.RECON,
                registry=registry,
                findings=findings,
                osint=osint,
                config=config,
            )
        )
        return StepOutcome(stats=stats)

    return handler


# --------------------------------------------------------------------------- discovery
def make_discovery_handler(
    *,
    registry: ModuleRegistry,
    findings: FindingStore,
    osint: OsintAccess | None,
    config: ModuleConfig | None = None,
) -> StepHandler:
    """Derive endpoint candidates offline, then run the network-discovery modules (M2).

    The inventory is created here — once for the step — because M2's checks are a pipeline:
    the port scan consumes the liveness results, the fingerprinter consumes the open ports,
    and the protocol checks consume the identities. The step context carries it to every
    check, so a check that finds nothing to work on costs zero packets and says why
    (``m2.support.inventory_or_skip``).
    """

    async def handler(ctx: StepContext) -> StepOutcome:
        seeded = await discovery_step(ctx)
        stats: dict[str, Any] = dict(seeded.stats)
        # ``None`` in dry-run mode: no client means no probes, and the M2 checks report
        # themselves skipped rather than pretending to have looked (F-01-10).
        if ctx.net is None:
            stats.update({"net_checks_skipped": True})
            return StepOutcome(stats=stats)
        effective = config or ModuleConfig()
        inventory = NetworkInventory(max_hosts=effective.max_hosts, max_ports=effective.max_ports)
        ctx.inventory = inventory
        stats.update(
            await run_checks(
                ctx,
                step=ScanStep.DISCOVERY,
                registry=registry,
                findings=findings,
                osint=osint,
                config=effective,
            )
        )
        stats["inventory"] = inventory.summary()
        stats["net_probes"] = getattr(ctx.net, "probes", 0)
        return StepOutcome(stats=stats)

    return handler


# --------------------------------------------------------------------------- checks
def make_checks_handler(
    *,
    registry: ModuleRegistry,
    findings: FindingStore,
    osint: OsintAccess | None,
    config: ModuleConfig | None = None,
    callback_service: Any = None,
    vault: Any = None,
    posture: Any = None,
    purple: Any = None,
) -> StepHandler:
    """Crawl the web surface once, then run the checks-step modules (M3).

    The crawl is built here — once for the step — for the same reason M2's inventory is built
    in the discovery handler: M3's checks must not each re-crawl the application. It is
    handed to every check through ``ctx.web``; ``None`` in dry-run mode (there is no HTTP
    client) turns every M3 check into a skipped result rather than pretending it looked
    (F-01-10). Steps with no enabled check report themselves skipped.

    **Credentialed scans (S19, REQ-CREDS-001) run the crawl twice.** The *unauthenticated*
    crawl happens first, before anything authenticates, and is kept on ``ctx.web_baseline``
    for the checks that need the difference; then the credential broker logs in through the
    same scoped client, and a second crawl picks up the authenticated surface as ``ctx.web``.
    Ordering is what makes the baseline honest: the ``httpx`` jar is per client, so a
    baseline taken first cannot contain a session cookie. It also means the whole M3 pass
    afterwards is authenticated — which is the point of a credentialed scan.

    ``callback_service`` is the in-process OOB callback service (S15); ``None`` keeps the
    standalone mode where an L2 check talks to the configured callback base over HTTP.
    """
    broker_vault = vault

    async def handler(ctx: StepContext) -> StepOutcome:
        effective = config or ModuleConfig()
        stats: dict[str, Any] = {}
        selected = _checks_step_selected(ctx, registry)
        broker = _credential_broker(ctx, broker_vault)
        if broker is not None:
            ctx.credentials = broker
        if ctx.http is not None and selected:
            inventory = await crawl_web_surface(ctx, effective)
            ctx.web = inventory
            ctx.web_baseline = inventory
            stats["web"] = inventory.summary()
            authenticated = await _authenticate_web(ctx, effective, broker, inventory)
            if authenticated is not None:
                ctx.web = authenticated
                stats["web_authenticated"] = authenticated.summary()
            if broker is not None:
                stats["credentials"] = broker.describe()
        elif ctx.http is None:
            # Dry run: no client, so no crawl and every M3 check reports itself skipped
            # (F-01-10). Reported distinctly from "no M3 check was selected at all".
            stats["web_checks_skipped"] = True
            if broker is not None:
                stats["credentials"] = broker.describe()
        await _keep_session_alive(ctx, broker)
        check_stats = await run_checks(
            ctx,
            step=ScanStep.CHECKS,
            registry=registry,
            findings=findings,
            osint=osint,
            config=effective,
            callback_service=callback_service,
            posture=posture,
            purple=purple,
        )
        stats.update(check_stats)
        if broker is not None:
            # Re-read after the checks ran: the session's re-authentication count, the
            # logout verdict and any refusal a check triggered are all richer now.
            stats["credentials"] = broker.describe()
            _persist_credential_summary(ctx, broker)
        if check_stats["checks_selected"] == 0:
            return StepOutcome(
                stats=stats,
                skipped=True,
                note="no implemented check targets this step in this build",
            )
        return StepOutcome(stats=stats)

    return handler


def _purple_access(ctx: StepContext, purple: Any) -> Any:
    """The purple-team seam for this scan (S24, area VALID), or ``None``.

    ``None`` for an ordinary scan *and* for a deployment that wired no runner: a scan
    cannot be a detection test unless the handler set carries the ATT&CK replay catalogue
    to tag its artifacts with. Built per scan, because the nonce, the window and the
    emission list are all run-scoped.
    """
    if purple is None:
        return None
    return purple.access(ctx)


def _tag_purple(results: list[CheckResult], access: Any, action: Any) -> list[CheckResult]:
    """Append the purple-team tag to every *finding* an action emitted (REQ-VALID-003).

    Only ``vulnerable`` results are tagged: an info note or a skip is not an emitted test
    artifact, and dressing one up as one would inflate the coverage denominator. The tag
    carries the run nonce verbatim, so the artifact is visibly this run's test and a
    defender's alert can be matched back to it.
    """
    payload = access.emission_payload(action)
    source = f"purple/{access.campaign}/{action.check_id}"
    return [
        replace(
            result,
            evidence=(*result.evidence, Evidence.of("purple", payload, source=source)),
        )
        if result.status == "vulnerable"
        else result
        for result in results
    ]


def _purple_stats(access: Any) -> dict[str, Any]:
    """The purple half of the step statistics (``scans.stats["purple"]``).

    Written by the step that emitted the artifacts, so the report and the campaign service
    read one record of "what this run did" rather than reconstructing it.
    """
    return {
        "campaign": access.campaign,
        "nonce": access.nonce,
        "window": window_payload(access.window, access.now()),
        "actions": sorted(access.actions),
        "emissions": [emission.to_dict() for emission in access.emissions],
        "stopped_at": access.stopped_at.isoformat() if access.stopped_at else None,
        "stop_reason": access.stop_reason,
        "no_evasion": NO_EVASION_POLICY,
    }


def _posture_access(ctx: StepContext, asset: Any, posture: Any) -> Any:
    """The continuous-posture capability boundary for one asset (S23, REQ-POSTURE-001).

    ``None`` when the step wired no baseline store: a check then runs stateless rather
    than pretending to drift-compare. The scope key is the asset's own value, so a check
    can only ever read and replace the baseline of the surface it was planned against.
    """
    if posture is None:
        return None
    from arachne.posture.access import PostureAccess

    return PostureAccess(
        posture,
        scope_key=asset.value,
        auditor=ctx.auditor,
        scan_id=ctx.scan_id,
    )


def _credential_broker(ctx: StepContext, vault: Any) -> Any:
    """The per-scan broker, or ``None`` when this scan named no credential.

    Built from the scan's own options and targets so the broker can answer the only question
    that matters for REQ-CREDS-005: is this credential scoped to something this scan may
    touch? A label this node does not hold, or one whose scope covers none of the scan's
    targets, is refused and audited once here rather than silently degrading every check.
    """
    labels = tuple(ctx.options.credentials)
    if not labels:
        return None
    from arachne.creds.broker import CredentialBroker

    roots = _web_roots(ctx)
    hosts = tuple(
        host
        for host in (
            [asset.value for asset in ctx.store.list_assets(ctx.scan_id) if asset.kind == "host"]
            + [selector.host or "" for selector in ctx.definition.targets]
        )
        if host
    )
    # ``vault=None`` on a scan that *named* a credential is the internal-agent case worth
    # recording: this node does not hold the label, and the scan must not silently borrow one
    # from elsewhere. Building the broker anyway is what makes that refusal audited
    # (``credential.unresolved``) instead of invisible.
    broker = CredentialBroker(
        store=vault,
        labels=labels,
        auditor=ctx.auditor,
        scan_id=ctx.scan_id,
        targets=roots,
        hosts=tuple(dict.fromkeys(hosts)),
    )
    broker.validate_selection()
    return broker


async def _authenticate_web(
    ctx: StepContext, config: ModuleConfig, broker: Any, baseline: Any
) -> Any | None:
    """Log in through the scan's own client, then crawl again as the authenticated user.

    Returns the authenticated crawl, or ``None`` when the scan is anonymous (no credential,
    no covering credential, or a refused login — all already audited).
    """
    from arachne.core.vault import WEB_CREDENTIAL_KINDS

    if broker is None or ctx.http is None:
        return None
    if not broker.selected_labels(WEB_CREDENTIAL_KINDS):
        return None
    roots = _web_roots(ctx)
    if not roots:
        return None
    session = await broker.login(client=ctx.http, inventory=baseline, url=roots[0])
    if session is None or not session.authenticated:
        return None
    ctx.web_session = session
    authenticated = await crawl_web_surface(ctx, config)
    session.authenticated_only = _authenticated_surface(baseline, authenticated)
    ctx.auditor.record(
        AuditAction.AUTH_SESSION_ESTABLISHED,
        scan_id=ctx.scan_id,
        target=session.origin,
        meta={
            "label": session.label,
            "authenticated_only": len(session.authenticated_only),
            "pages": len(authenticated.order),
        },
    )
    return authenticated


def _authenticated_surface(baseline: Any, authenticated: Any) -> tuple[str, ...]:
    """URLs the authenticated crawl reached that the anonymous one did not.

    Either the page was never fetched anonymously, or it came back different — a login wall's
    ``302``/``401`` where the authenticated client got content. Both are additional surface,
    and the difference is the whole value of scanning with a credential (REQ-CREDS-001).
    """
    if baseline is None or authenticated is None:
        return ()
    extra: list[str] = []
    for url in authenticated.order:
        page = authenticated.pages.get(url)
        if page is None:
            continue
        before = baseline.pages.get(url)
        if before is None or before.body_fingerprint != page.body_fingerprint:
            extra.append(url)
    return tuple(extra)


async def _keep_session_alive(ctx: StepContext, broker: Any) -> None:
    """Re-establish the session before the checks run (REQ-CREDS-001 session keep-alive)."""
    if broker is None or ctx.http is None or ctx.web_session is None:
        return
    was = ctx.web_session.authenticated
    still = await broker.keep_alive(client=ctx.http)
    if was and not still:
        ctx.auditor.record(
            AuditAction.AUTH_SESSION_EXPIRED,
            outcome=AuditOutcome.ERROR,
            scan_id=ctx.scan_id,
            target=ctx.web_session.origin,
            reason="the session could not be kept alive; authenticated checks degrade to anonymous",
            meta={"label": ctx.web_session.label},
        )


def _persist_purple_summary(ctx: StepContext, block: dict[str, Any]) -> None:
    """Record the purple run's own record on the *scan*, so the report and the campaign
    service can state it (S24, REQ-VALID-003).

    Same discipline as the S15 proof journal and the S19 credential summary: step statistics
    live on the step row, but these are scan-scoped *facts about the run* — the campaign,
    the nonce every artifact carried, the window it fired inside and what it emitted — so
    they are written where a report reader looks. Every value is a technique, an ISO
    timestamp or the nonce, so nothing here can carry target data.
    """
    try:
        record = ctx.store.get_scan(ctx.scan_id)
        if record is None:
            return
        stats = dict(record.stats)
        stats["purple"] = block
        ctx.store.update_scan(ctx.scan_id, stats=stats)
    except Exception as exc:  # a bookkeeping failure must not fail a scan that ran
        _logger.warning(
            "could not record the purple run summary",
            extra={"event": "purple.summary_failed", "error": str(exc)},
        )


def _persist_credential_summary(ctx: StepContext, broker: Any) -> None:
    """Record the credentialed facts on the *scan*, so the report can state them (S19).

    Labels and outcomes only — every value here is a label, a boolean or a refusal reason, so
    the scan record (and therefore the report built from it) carries no credential material.
    Same discipline as the S15 proof journal, which also lives in ``scans.stats``.
    """
    try:
        record = ctx.store.get_scan(ctx.scan_id)
        if record is None:
            return
        described = broker.describe()
        session = described.get("session") or {}
        stats = dict(record.stats)
        stats["credentials"] = {
            "labels": list(described.get("labels") or ()),
            "vault": bool(described.get("vault")),
            "authenticated": bool(session.get("authenticated")),
            "session": session or None,
            "refusals": list(described.get("refusals") or ()),
        }
        ctx.store.update_scan(ctx.scan_id, stats=stats)
    except Exception as exc:  # a bookkeeping failure must not fail a scan that ran
        _logger.warning(
            "could not record the credential summary",
            extra={"event": "credentials.summary_failed", "error": str(exc)},
        )


def _web_roots(ctx: StepContext) -> tuple[str, ...]:
    """The scan's URL assets — the crawl roots, and what a credential's scope is checked to."""
    return tuple(
        f"{record.value}" for record in ctx.store.list_assets(ctx.scan_id) if record.kind == "url"
    )


def _checks_step_selected(ctx: StepContext, registry: ModuleRegistry) -> bool:
    """True when at least one checks-step check (M3+) will actually run for this scan.

    The crawl costs requests, so it happens only when a check that reads it is selected — a
    scan that runs M1 alone must not pay for an M3 crawl (and a plan that withheld every
    active M3 check must not either).
    """
    selected = registry.select(
        ctx.options.modules,
        active_checks_allowed=_active_checks_allowed(ctx),
        check_ids=ctx.options.modules.only or None,
        enabled_check_ids=ctx.options.modules.checks or None,
    )
    return any(MODULE_STEP[check.metadata.module] is ScanStep.CHECKS for check in selected)


async def crawl_web_surface(ctx: StepContext, config: ModuleConfig) -> WebInventory:
    """Crawl the scan's URL assets into the shared M3 inventory (ADR-100.2).

    The roots are the URL assets of this scan (declared, and the ones the discovery step
    derived from host targets). The crawl is bounded by ``ARACHNE_WEB_MAX_PAGES``/``_DEPTH``
    and every request goes through the scan's scoped client, so it is rate-limited and audited
    like any other exchange.
    """
    roots = tuple(
        f"{record.value}" for record in ctx.store.list_assets(ctx.scan_id) if record.kind == "url"
    )
    return await build_web_inventory(
        roots,
        step_fetcher(ctx, config),
        max_pages=config.web.max_pages,
        max_depth=config.web.max_depth,
        max_endpoints=config.web.max_endpoints,
    )


# --------------------------------------------------------------------------- the engine
async def run_checks(
    ctx: StepContext,
    *,
    step: ScanStep,
    registry: ModuleRegistry,
    findings: FindingStore,
    osint: OsintAccess | None,
    config: ModuleConfig | None = None,
    callback_service: Any = None,
    posture: Any = None,
    purple: Any = None,
) -> dict[str, Any]:
    """Run every selected check of ``step`` over the assets it applies to.

    Returns the step's statistics, which the lifecycle machine persists (F-01-04) and which
    is how a later stage (or an operator reading the database) sees what ran.

    The proof journal (S15) is attached here: one :class:`~arachne.proof.ledger.ProofLedger`
    per scan (loaded from the persisted stats, so a resume continues it) and one
    :class:`~arachne.proof.access.ProofAccess` per check — the capability boundary derived
    from that check's declared proof level. At the end of the step the L4 cleanup pass runs
    and any unrestored change is audited as a repair instruction (REQ-PROOF-008/010).

    **Purple-team runs (S24, area VALID) add three things and change nothing else.** Each
    action's capability boundary is built with the *run nonce*, so every payload the check
    emits carries the run's visible tag (REQ-VALID-003); every artifact it produces gets a
    ``purple`` evidence entry naming the technique and tactic it replays; and the
    coordinated detection window is enforced *here*, per action — once it closes the
    remaining actions are skipped and the stop is audited (``purple.window_closed``)
    rather than left to the next gate to notice.
    """
    selected = registry.select(
        ctx.options.modules,
        active_checks_allowed=_active_checks_allowed(ctx),
        # ``only`` is an exact allowlist (S21, REQ-AGENT-001): a hypothesis run selects
        # precisely the checks it decided to run. ``checks`` stays the S7 opt-in addition —
        # naming one adds it, it never bounds the set.
        check_ids=ctx.options.modules.only or None,
        enabled_check_ids=ctx.options.modules.checks or None,
    )
    in_step = tuple(check for check in selected if MODULE_STEP[check.metadata.module] is step)
    # Inventory producers first, in their selected order; everything else keeps its order.
    in_step = tuple(sorted(in_step, key=lambda check: check.metadata.id not in INVENTORY_PRODUCERS))
    stats: dict[str, Any] = {
        "checks_selected": len(in_step),
        "checks_run": 0,
        "checks_skipped": 0,
        "checks_failed": 0,
        "candidates": 0,
        "results": 0,
        "assets_recorded": 0,
    }
    if not in_step:
        return stats

    ledger = getattr(ctx, "proof", None)
    if ledger is None:
        ledger = ProofLedger(ctx.store, ctx.scan_id, auditor=ctx.auditor)
        ctx.proof = ledger
    attestation = ctx.definition.attestation
    state_authorized = bool(attestation is not None and attestation.state_changes_authorized)
    access = _purple_access(ctx, purple)
    if access is not None:
        # The checks step's own view of the run: the same object the report reads.
        ctx.purple = access

    check_ids: dict[str, int] = {}
    try:
        check_ids = findings.record_checks(check.metadata for check in in_step)
    except Exception as exc:  # a store outage must not abort the check run
        _logger.warning(
            "could not version the checks in the store",
            extra={"event": "checks.record_failed", "error": str(exc)},
        )

    module_config = config or ModuleConfig()
    assets = _assets_for(ctx)
    asset_ids = {asset.key: _asset_id(ctx, asset) for asset in assets}
    before_assets = len(ctx.store.list_assets(ctx.scan_id))
    before_budget = osint.used if osint is not None else 0
    run_index = 0

    for check in in_step:
        action = access.action_for(check.metadata.id) if access is not None else None
        if access is not None and action is not None and not access.allows():
            # The auto-stop (REQ-VALID-003): the coordinated window ended, so this and
            # every remaining purple action is skipped — audited once, by ``stop``.
            access.stop(
                reason=(
                    "the detection window closed; remaining purple-team actions were "
                    "skipped rather than fired outside the coordinated interval"
                )
            )
            stats["checks_skipped"] += 1
            stats.setdefault("purple_stopped", 0)
            stats["purple_stopped"] = int(stats["purple_stopped"]) + 1
            continue
        emission_recorded = False
        for asset in assets:
            instance = check()
            if not instance.supports(asset):
                continue
            if not asset.declared and not instance.metadata.runs_on_discovered:
                # A check that ran on its own discoveries would multiply its own request
                # count; "declared assets only" is the default, which keeps the plan honest.
                continue
            run_index += 1
            context = CheckContext(
                step=ctx,
                module=instance,
                asset=asset,
                config=module_config,
                osint=osint,
                run_index=run_index,
                posture=_posture_access(ctx, asset, posture),
                proof=ProofAccess(
                    level=instance.metadata.proof,
                    check_id=instance.metadata.id,
                    scan_id=ctx.scan_id,
                    ledger=ledger,
                    auditor=ctx.auditor,
                    service=callback_service,
                    callback_base=module_config.web.ssrf_callback_url,
                    state_changes_authorized=state_authorized,
                    http=ctx.http,
                    # S24: a purple run's payloads all carry the run's visible nonce.
                    run_nonce=access.nonce if access is not None else None,
                ),
            )
            await _start_check(context)
            collected = [
                result
                async for result in collect_results(
                    context,
                    guard_check(
                        instance.metadata.id,
                        instance.run(context),
                        check=instance.metadata.key,
                        module=instance.metadata.module,
                    ),
                )
            ]
            if access is not None and action is not None:
                if not emission_recorded:
                    # One emission per action, tagged with the technique it replays: the
                    # test fired, so the defender had something to see (REQ-VALID-003).
                    access.record_emission(action)
                    emission_recorded = True
                collected = _tag_purple(collected, access, action)
            await _record_results(
                ctx,
                context=context,
                asset=asset,
                results=collected,
                findings=findings,
                check_id=check_ids.get(instance.metadata.key),
                asset_id=asset_ids.get(asset.key),
                stats=stats,
            )

    stats["assets_recorded"] = len(ctx.store.list_assets(ctx.scan_id)) - before_assets
    if osint is not None:
        stats["osint_requests"] = osint.used - before_budget
        stats["osint_budget"] = osint.budget

    if access is not None:
        stats["purple"] = _purple_stats(access)
        # The scan-scoped record of the run (S24): the campaign, the run nonce, the window
        # and what was emitted — what the report and the campaign service both read.
        _persist_purple_summary(ctx, stats["purple"])

    # The proof ladder's end-of-step obligations (S15): the cleanup pass over every L4
    # helper that ran, then one audit line per leftover (REQ-PROOF-008/010). Cheap when
    # nothing registered — the common case, since all shipped checks are L1/L2.
    cleanup = await ledger.run_cleanup_pass()
    stats["proof_cleanup"] = cleanup.to_dict()
    if cleanup.attempted or cleanup.restored or ledger.state_changes:
        await ctx.audit(
            AuditAction.PROOF_CLEANUP_COMPLETED,
            meta={
                "attempted": cleanup.attempted,
                "restored": cleanup.restored,
                "still_unrestored": list(cleanup.still_unrestored),
            },
        )
    repairs = audit_repair_instructions(ledger, ctx.auditor)
    if repairs:
        stats["proof_repairs_required"] = repairs
    return stats


def _active_checks_allowed(ctx: StepContext) -> bool:
    """Both switches of F-01-09: the operator's opt-in *and* the attestation's authority."""
    attestation = ctx.definition.attestation
    authorized = bool(attestation is not None and attestation.active_checks_authorized)
    return ctx.options.active_checks and authorized


def _assets_for(ctx: StepContext) -> tuple[Asset, ...]:
    """The assets a check may run against, in insertion order."""
    return tuple(
        Asset.from_meta(record.kind, record.value, dict(record.meta))
        for record in ctx.store.list_assets(ctx.scan_id)
    )


def _asset_id(ctx: StepContext, asset: Asset) -> int | None:
    for record in ctx.store.list_assets(ctx.scan_id):
        if record.kind == asset.kind and record.value == asset.value:
            return record.id
    return None


async def _start_check(context: CheckContext) -> None:
    metadata = context.metadata
    await context.audit(
        AuditAction.CHECK_STARTED, target=context.asset.key, meta={"module": metadata.module}
    )
    context.logger.info(
        "check started",
        extra={
            "event": "check.started",
            "check": metadata.id,
            "asset": context.asset.key,
            "scan_id": context.scan_id,
        },
    )


def _is_skip(result: CheckResult) -> bool:
    return any(bool(item.payload.get(SKIP_MARKER)) for item in result.evidence)


async def _record_results(
    ctx: StepContext,
    *,
    context: CheckContext,
    asset: Asset,
    results: Sequence[CheckResult],
    findings: FindingStore,
    check_id: int | None,
    asset_id: int | None,
    stats: dict[str, Any],
) -> None:
    """Persist and announce one (check, asset) run's results."""
    metadata = context.metadata
    statuses: list[str] = []
    failed = False
    candidates = 0

    for result in results:
        statuses.append(result.status)
        stats["results"] += 1
        if result.status == "error":
            failed = True
            stats["checks_failed"] += 1
            await ctx.audit(
                AuditAction.CHECK_FAILED,
                outcome=AuditOutcome.ERROR,
                target=asset.key,
                reason=result.detail,
                meta={"check": metadata.id, "module": metadata.module},
            )
            continue
        if result.status == "vulnerable":
            candidates += 1
            stats["candidates"] += 1
            staged = await _stage_evidence(ctx, result=result, asset=asset, check=metadata.id)
            record = _persist(
                findings,
                ctx.scan_id,
                result=staged,
                check_id=check_id,
                asset_id=asset_id,
                asset=(asset.kind, asset.value),
            )
            await ctx.audit(
                AuditAction.CANDIDATE_RECORDED,
                target=asset.key,
                meta={
                    "check": metadata.id,
                    "finding_id": record.id if record is not None else None,
                    "evidence_items": len(result.evidence),
                },
            )
            await ctx.emit(
                Event.finding_raised(
                    scan_id=ctx.scan_id,
                    module=metadata.module,
                    check=metadata.key,
                    title=result.title,
                    # No severity: scoring is the analyzer's job (ADR-02).
                    severity=None,
                    asset=asset.value,
                    cwe=result.cwe,
                )
            )

    skipped = bool(results) and all(_is_skip(result) for result in results)
    stats["checks_run"] += 1
    if skipped:
        stats["checks_skipped"] += 1
    await ctx.audit(
        AuditAction.CHECK_SKIPPED if skipped else AuditAction.CHECK_COMPLETED,
        outcome=AuditOutcome.ERROR if failed else AuditOutcome.ALLOWED,
        target=asset.key,
        meta={
            "check": metadata.id,
            "module": metadata.module,
            "statuses": statuses,
            "results": len(results),
            "candidates": candidates,
        },
    )
    context.logger.info(
        "check completed",
        extra={
            "event": "check.completed",
            "check": metadata.id,
            "asset": asset.key,
            "results": len(results),
            "candidates": candidates,
            "statuses": statuses,
            "scan_id": ctx.scan_id,
        },
    )
    await ctx.emit(
        Event.check_completed(
            scan_id=ctx.scan_id,
            module=metadata.module,
            check=metadata.key,
            status=statuses[-1] if statuses else "info",
            asset=asset.value,
            detail=f"{len(results)} result(s), {candidates} candidate(s)",
        )
    )


async def _stage_evidence(
    ctx: StepContext,
    *,
    result: CheckResult,
    asset: Asset,
    check: str,
) -> CheckResult:
    """Offload oversized payloads and enforce the project quota (S20, REQ-DATA-002/003).

    A quota refusal is an *operator-visible stop*, not a per-result failure: the error
    already names the project, the limit and the refused bytes, and it is audited here once
    with the check and asset that crossed it. Re-raising is what makes the scan fail (and
    therefore become resumable) instead of quietly dropping a finding whose evidence could
    not be stored.
    """
    evidence = getattr(ctx, "evidence", None)
    if evidence is None:
        return result
    try:
        staged: CheckResult = await evidence.stage(
            result, scan_id=ctx.scan_id, project_id=getattr(ctx, "project_id", None)
        )
        return staged
    except StorageQuotaError as exc:
        await ctx.audit(
            AuditAction.QUOTA_EXCEEDED,
            outcome=AuditOutcome.ERROR,
            target=asset.key,
            reason=str(exc),
            meta={"check": check, "evidence_items": len(result.evidence)},
        )
        raise


def _persist(
    findings: FindingStore,
    scan_id: int,
    *,
    result: CheckResult,
    check_id: int | None,
    asset_id: int | None,
    asset: tuple[str, str] | None = None,
) -> CandidateRecord | None:
    try:
        return findings.record_candidate(
            scan_id, result=result, check_id=check_id, asset_id=asset_id, asset=asset
        )
    except StorageQuotaError:
        # A quota refusal is a deliberate stop, not a store hiccup: it must reach the scan
        # machine (which fails the step, leaving a resumable scan), never be swallowed.
        raise
    except Exception as exc:  # a store failure must not lose the rest of the scan
        _logger.warning(
            "could not persist a candidate",
            extra={"event": "candidate.persist_failed", "error": str(exc), "check": result.check},
        )
        return None


def iter_checks(registry: ModuleRegistry, step: ScanStep) -> dict[str, type[Module]]:
    """Registered checks belonging to ``step``, keyed by check id (used by the CLI)."""
    return {
        check.metadata.id: check
        for check in registry.checks()
        if MODULE_STEP[check.metadata.module] is step
    }
