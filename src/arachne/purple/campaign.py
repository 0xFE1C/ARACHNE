"""Purple-team campaigns: the spec, the per-scan seam and the service (S24, REQ-VALID-001/006).

Three pieces, deliberately separated:

:class:`PurpleCampaignSpec`
    what a campaign *is* — the replayed actions, the attested target, the optional
    recurrence. Stored as JSON on the campaign row, validated on the way in and on the way
    out, so a hand-edited row cannot smuggle an unvetted action list into a live run.
:class:`PurpleAccess`
    what one *scan* may know about being a detection test — the run nonce every artifact
    carries, the coordinated window it stops at, and the technique each action maps to.
    The checks step holds this and nothing else; ``None`` means an ordinary scan.
:class:`PurpleCampaignService`
    the run loop: gate on the window, admit a real scan through the orchestrator (every
    existing gate applies), collect the defender's alerts, score control coverage, detect
    regressions against the previous run, and hand the pieces to the defender report.

The hard rule lives in the gate, not in the prose: an action outside the coordinated
window never fires — it is refused and audited (``purple.window_refused``), and a window
that closes mid-run stops the remaining actions (``purple.window_closed``).
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import PurpleSettings, Settings
from arachne.core.errors import ConfigurationError, DetectionWindowError, ScanStateError
from arachne.core.target import (
    AuthorizationAttestation,
    DetectionWindow,
    EngineName,
    ModuleSelection,
    PurpleRunOptions,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
)
from arachne.purple.attack import ReplayAction, TechniqueMap, load_technique_map
from arachne.purple.coverage import (
    CoveragePoint,
    CoverageReport,
    Emission,
    coverage_points,
    detect_regressions,
    score_coverage,
)
from arachne.purple.sigma import RuleAlignment, align_actions
from arachne.purple.window import WindowState, assert_window_open, window_payload, window_state

if TYPE_CHECKING:  # the store lives beside the other stores; this package stays data-free
    from arachne.data.purple_store import AlertRecord, PurpleStore

__all__ = [
    "CampaignRunResult",
    "PurpleAccess",
    "PurpleCampaign",
    "PurpleCampaignService",
    "PurpleCampaignSpec",
    "PurpleRunner",
]

_MODEL = ConfigDict(frozen=True, extra="forbid")


class PurpleCampaignSpec(BaseModel):
    """A stored campaign definition (S24, REQ-VALID-001/006).

    ``target`` names a *stored, attested target*: the detection window is a property of
    the attestation (REQ-VALID-001), so a campaign cannot carry its own window and thereby
    invent authorization. ``actions`` are the proof check ids to replay — validated
    against the shipped technique map when the campaign is created *and* re-validated when
    it runs, so a map that loses an action turns into a loud refusal, not a short run.
    ``cron`` makes it recurring (REQ-VALID-006); ``None`` means "runs when an operator asks".
    """

    model_config = _MODEL

    target: str = Field(min_length=1, max_length=255)
    actions: tuple[str, ...] = Field(min_length=1)
    engine: EngineName = EngineName.HEURISTIC
    cron: str | None = Field(default=None, max_length=128)
    enabled: bool = True
    #: Seconds after the window closes before a run collects the defender's alerts. A
    #: forwarder's pipeline is not instant; the delay is the honest allowance for it.
    collect_delay_s: int = 0
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("actions")
    @classmethod
    def _validate_actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        from arachne.purple.attack import _CHECK_ID  # local: the id grammar lives with the map

        if not value:
            msg = "a purple campaign must replay at least one action"
            raise ValueError(msg)
        for check in value:
            if not _CHECK_ID.match(check):
                msg = f"{check!r} is not a check id (expected mN.check-name)"
                raise ValueError(msg)
        return tuple(dict.fromkeys(value))

    @field_validator("cron")
    @classmethod
    def _validate_cron(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from arachne.scheduler.cron import CronExpression

        try:
            CronExpression.parse(value)
        except Exception as exc:  # the cron module owns the grammar and the message
            msg = f"purple campaign cron {value!r} is invalid: {exc}"
            raise ValueError(msg) from exc
        return value

    @field_validator("collect_delay_s")
    @classmethod
    def _validate_delay(cls, value: int) -> int:
        if not 0 <= value <= 86_400:
            msg = "collect_delay_s must be within 0..86400"
            raise ValueError(msg)
        return value


@dataclass(frozen=True, slots=True)
class PurpleCampaign:
    """A stored campaign: its spec plus the row identity."""

    name: str
    spec: PurpleCampaignSpec
    enabled: bool = True
    last_run_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.spec.target,
            "actions": list(self.spec.actions),
            "engine": self.spec.engine.value,
            "cron": self.spec.cron,
            "enabled": self.enabled,
            "collect_delay_s": self.spec.collect_delay_s,
            "notes": self.spec.notes,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
        }


def campaign_from_record(record: Any) -> PurpleCampaign:
    """Validate a stored row into a :class:`PurpleCampaign` (refusing a hand-edited one)."""
    try:
        spec = PurpleCampaignSpec.model_validate(record.spec)
    except Exception as exc:
        msg = f"stored purple campaign {record.name!r} is invalid: {exc}"
        raise ConfigurationError(msg) from exc
    return PurpleCampaign(
        name=record.name,
        spec=spec,
        enabled=bool(record.enabled),
        last_run_at=record.last_run_at,
    )


# --------------------------------------------------------------------------- the seam


@dataclass
class PurpleAccess:
    """What one scan may know about being a purple-team detection test (REQ-VALID-003).

    Built by the checks step from the scan's :class:`~arachne.core.target.PurpleRunOptions`
    plus the shipped map. It answers exactly three questions — which technique does this
    check replay, is the window still open, and what has been emitted so far — and it is
    the only place a run nonce or a technique tag enters a finding.
    """

    campaign: str
    nonce: str
    window: DetectionWindow | None
    actions: Mapping[str, ReplayAction]
    scan_id: int
    auditor: Auditor | None = None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    emissions: list[Emission] = field(default_factory=list)
    #: Set once the window closes mid-run: the remaining actions are skipped and the stop
    #: is audited exactly once.
    stopped_at: datetime | None = None
    stop_reason: str | None = None

    def action_for(self, check_id: str) -> ReplayAction | None:
        return self.actions.get(check_id)

    def now(self) -> datetime:
        return self.clock().astimezone(UTC)

    def state(self, now: datetime | None = None) -> WindowState:
        return window_state(self.window, now or self.now())

    def allows(self, now: datetime | None = None) -> bool:
        """True when a purple action may fire right now."""
        return self.state(now) is WindowState.OPEN

    def stop(self, *, reason: str, now: datetime | None = None) -> None:
        """Auto-stop the run at the window's end (REQ-VALID-003).

        Idempotent, and audited once: a run that fires six actions past the window would
        write six identical lines, which is noise, not evidence.
        """
        moment = (now or self.now()).astimezone(UTC)
        if self.stopped_at is not None:
            return
        self.stopped_at = moment
        self.stop_reason = reason
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.PURPLE_WINDOW_CLOSED,
                outcome=AuditOutcome.BLOCKED,
                target=self.campaign,
                reason=reason,
                scan_id=self.scan_id,
                meta={
                    "nonce": self.nonce,
                    "stopped_at": moment.isoformat(),
                    "window": window_payload(self.window, moment),
                    "emitted": len(self.emissions),
                },
            )

    def record_emission(self, action: ReplayAction, *, now: datetime | None = None) -> Emission:
        """One emitted test artifact, tagged with the technique, tactic and run nonce."""
        moment = (now or self.now()).astimezone(UTC)
        emission = Emission(
            check_id=action.check_id,
            title=action.title,
            technique=action.techniques[0],
            tactic=action.tactic,
            severity=action.severity,
            nonce=self.nonce,
            emitted_at=moment,
        )
        self.emissions.append(emission)
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.PURPLE_ACTION_EMITTED,
                target=action.check_id,
                scan_id=self.scan_id,
                meta={
                    "campaign": self.campaign,
                    "nonce": self.nonce,
                    "techniques": list(action.techniques),
                    "tactic": action.tactic,
                    "level": action.level,
                },
            )
        return emission

    def emission_payload(
        self, action: ReplayAction, *, now: datetime | None = None
    ) -> dict[str, Any]:
        """The evidence payload appended to every artifact this action emits.

        Carries the nonce verbatim: that is what makes the artifact *visibly* a test
        (REQ-VALID-003) and what a defender's alert has to quote to be matched to this run.
        """
        moment = (now or self.now()).astimezone(UTC)
        return {
            "campaign": self.campaign,
            "nonce": self.nonce,
            "check_id": action.check_id,
            "level": action.level,
            "techniques": list(action.techniques),
            "tactic": action.tactic,
            "severity": action.severity,
            "emitted_at": moment.isoformat(),
            "window": window_payload(self.window, moment),
            "detection_note": (
                "purple-team detection test: emitted verbatim, tagged and rate-limited so "
                "the defender can see it"
            ),
        }


@dataclass(frozen=True, slots=True)
class PurpleRunner:
    """The checks-step seam: the technique map plus a clock (built from settings).

    Holds no store and no service — the checks step must not be able to *run* a campaign
    from inside a scan; it can only tag what it emits.
    """

    technique_map: TechniqueMap
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    @classmethod
    def build(cls, settings: Settings | None = None) -> PurpleRunner:
        """Build from the deployment settings (``ARACHNE_PURPLE_MAP`` overrides the map)."""
        path = settings.purple.map_path if settings is not None else None
        return cls(technique_map=load_technique_map(path))

    def access(self, ctx: Any) -> PurpleAccess | None:
        """The access for ``ctx``, or ``None`` when the scan is not a purple run."""
        options = getattr(ctx, "options", None)
        purple = getattr(options, "purple", None)
        if purple is None:
            return None
        actions: dict[str, ReplayAction] = {}
        for check_id in purple.actions:
            action = self.technique_map.get(check_id)
            if action is None:
                # The planner refuses unknown actions before a scan can start; reaching
                # here would mean the map changed under a running scan.
                msg = (
                    f"purple action {check_id!r} is not in the shipped technique map; "
                    "refusing to emit an untagged test"
                )
                raise ConfigurationError(msg)
            actions[check_id] = action
        attestation = getattr(getattr(ctx, "definition", None), "attestation", None)
        window = attestation.detection_window if attestation is not None else None
        return PurpleAccess(
            campaign=purple.campaign,
            nonce=purple.nonce or "",
            window=window,
            actions=actions,
            scan_id=int(getattr(ctx, "scan_id", 0)),
            auditor=getattr(ctx, "auditor", None),
            clock=self.clock,
        )


# --------------------------------------------------------------------------- the service


@dataclass(frozen=True, slots=True)
class CampaignRunResult:
    """What one campaign run did (the CLI/API/scheduler all read this)."""

    campaign: str
    status: str
    run_id: int | None = None
    scan_id: int | None = None
    nonce: str | None = None
    coverage: CoverageReport | None = None
    sigma: tuple[RuleAlignment, ...] = ()
    regressions: tuple[str, ...] = ()
    alerts_ingested: int = 0
    note: str | None = None

    @property
    def coverage_pct(self) -> float:
        return self.coverage.coverage_pct if self.coverage is not None else 0.0

    @property
    def gaps(self) -> tuple[str, ...]:
        return tuple(item.technique for item in self.coverage.gaps) if self.coverage else ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign,
            "status": self.status,
            "run_id": self.run_id,
            "scan_id": self.scan_id,
            "nonce": self.nonce,
            "coverage_pct": self.coverage_pct,
            "gaps": list(self.gaps),
            "regressions": list(self.regressions),
            "alerts_ingested": self.alerts_ingested,
            "sigma": [item.to_dict() for item in self.sigma],
            "coverage": self.coverage.to_dict() if self.coverage is not None else None,
            "note": self.note,
        }


class PurpleCampaignService:
    """Run campaigns, ingest alerts, score coverage, report (S24)."""

    def __init__(
        self,
        services: Any,
        *,
        auditor: Auditor | None = None,
        technique_map: TechniqueMap | None = None,
        clock: Callable[[], datetime] | None = None,
        alert_fetcher: Callable[[datetime, datetime], Awaitable[tuple[Any, ...]]] | None = None,
    ) -> None:
        self.services = services
        self.settings: Settings = services.settings
        self.auditor = auditor or services.auditor
        store: PurpleStore | None = services.purple
        if store is None:
            msg = (
                "this deployment has no purple-team store wired; build the stack with "
                "build_services (ScanServices.purple) before running a campaign"
            )
            raise ScanStateError(msg)
        self.store: PurpleStore = store
        self.technique_map = technique_map or load_technique_map()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._alert_fetcher = alert_fetcher

    # ------------------------------------------------------------------ campaigns
    def create_campaign(
        self, name: str, spec: PurpleCampaignSpec, *, now: datetime | None = None
    ) -> PurpleCampaign:
        """Store (or replace) a campaign; every action must be replayable."""
        self._validate_actions(spec.actions)
        record = self.store.upsert_campaign(
            name, spec.model_dump(mode="json"), enabled=spec.enabled, now=now
        )
        self.auditor.record(
            AuditAction.PURPLE_CAMPAIGN_CHANGED,
            target=name,
            meta={
                "action": "upsert",
                "target": spec.target,
                "actions": list(spec.actions),
                "cron": spec.cron,
                "enabled": spec.enabled,
            },
        )
        return campaign_from_record(record)

    def list_campaigns(self) -> tuple[PurpleCampaign, ...]:
        return tuple(campaign_from_record(record) for record in self.store.campaigns())

    def get_campaign(self, name: str) -> PurpleCampaign | None:
        record = self.store.campaign(name)
        return campaign_from_record(record) if record is not None else None

    def set_enabled(
        self, name: str, enabled: bool, *, now: datetime | None = None
    ) -> PurpleCampaign | None:
        record = self.store.set_campaign_enabled(name, enabled, now=now)
        if record is None:
            return None
        self.auditor.record(
            AuditAction.PURPLE_CAMPAIGN_CHANGED,
            target=name,
            meta={"action": "enable" if enabled else "disable"},
        )
        return campaign_from_record(record)

    def remove_campaign(self, name: str) -> bool:
        removed = self.store.delete_campaign(name)
        if removed:
            self.auditor.record(
                AuditAction.PURPLE_CAMPAIGN_CHANGED, target=name, meta={"action": "remove"}
            )
        return removed

    def _validate_actions(self, actions: Iterable[str]) -> None:
        self.technique_map.select(actions)  # raises naming what is replayable

    # ------------------------------------------------------------------ the run
    async def run_campaign(
        self, name: str, *, now: datetime | None = None
    ) -> CampaignRunResult:
        """Run one campaign: gate on the window, scan, collect alerts, score, trend."""
        moment = (now or self.clock()).astimezone(UTC)
        campaign = self.get_campaign(name)
        if campaign is None:
            msg = f"purple campaign {name!r} does not exist"
            raise ScanStateError(msg)
        if not campaign.enabled:
            msg = f"purple campaign {name!r} is disabled"
            raise ScanStateError(msg)
        actions = self.technique_map.select(campaign.spec.actions)
        definition = self._definition_for(campaign)
        window = self._window_of(definition)
        nonce = secrets.token_hex(self.settings.purple.nonce_bytes)

        # The window gate comes *first*: a refusal must not create a scan, send a packet or
        # leave an admission record behind (REQ-VALID-001).
        try:
            assert_window_open(window, moment, what=f"purple campaign {name!r}")
        except DetectionWindowError as exc:
            self.store.record_run(
                campaign=name,
                nonce=nonce,
                window=window.to_dict() if window is not None else None,
                status="window_refused",
                now=moment,
                note=exc.reason,
            )
            self.auditor.record(
                AuditAction.PURPLE_WINDOW_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                target=name,
                reason=exc.reason,
                meta={
                    "nonce": nonce,
                    "window": window_payload(window, moment),
                    "state": window_state(window, moment).value,
                },
            )
            return CampaignRunResult(
                campaign=name, status="window_refused", nonce=nonce, note=exc.reason
            )

        request = self._request_for(definition, campaign, actions, nonce)
        self.auditor.record(
            AuditAction.PURPLE_RUN_STARTED,
            target=name,
            meta={
                "nonce": nonce,
                "actions": [action.check_id for action in actions],
                "techniques": self.technique_map.techniques(campaign.spec.actions),
                "window": window_payload(window, moment),
                "target": definition.name,
            },
        )
        from arachne.data.services import build_orchestrator

        try:
            orchestrator = build_orchestrator(self.services)
            session = await orchestrator.scan(request)
        except Exception as exc:
            # A failed run is recorded, never swallowed: "the test did not run" belongs in
            # the trend, exactly like a refused window does.
            self.store.record_run(
                campaign=name,
                nonce=nonce,
                window=window.to_dict() if window is not None else None,
                status="failed",
                now=self.clock(),
                note=f"{exc.__class__.__name__}: {exc}",
            )
            raise
        scan_id = session.scan_id
        stats = (session.record.stats if session.record is not None else {}) or {}
        purple_stats = dict(stats.get("purple") or {})
        emissions = tuple(purple_stats.get("emissions") or ())
        alignments = align_actions(actions)
        record = self.store.record_run(
            campaign=name,
            nonce=nonce,
            window=window.to_dict() if window is not None else None,
            scan_id=scan_id,
            status="completed",
            emissions=[dict(item) for item in emissions],
            sigma=[item.to_dict() for item in alignments],
            now=self.clock(),
        )
        run_id = record.id if record is not None else None
        ingested = await self.collect_alerts(now=self.clock())
        coverage = self.score(name, run_id=run_id, now=self.clock())
        regressions = self._regressions(name)
        if regressions:
            self.auditor.record(
                AuditAction.PURPLE_COVERAGE_REGRESSED,
                outcome=AuditOutcome.BLOCKED,
                target=name,
                reason=f"control coverage regressed for: {', '.join(regressions)}",
                meta={"nonce": nonce, "techniques": list(regressions)},
            )
        return CampaignRunResult(
            campaign=name,
            status="completed",
            run_id=run_id,
            scan_id=scan_id,
            nonce=nonce,
            coverage=coverage,
            sigma=alignments,
            regressions=regressions,
            alerts_ingested=ingested,
        )

    def _regressions(self, campaign: str) -> tuple[str, ...]:
        """Techniques the previous run saw and the latest one does not (REQ-VALID-006)."""
        points = self.trend(campaign, limit=10_000)
        if len(points) < 2:
            return ()
        return detect_regressions(points[-2], points[-1])

    # ------------------------------------------------------------------ alerts
    async def collect_alerts(self, *, now: datetime | None = None) -> int:
        """Pull the defender's alerts from the configured SIEM (REQ-VALID-002).

        A deployment with no ``ARACHNE_PURPLE_ALERTS_URL`` (or an injected fetcher for
        tests) collects nothing here — alerts then arrive by webhook or export. A failing
        SIEM must never fail the run: the coverage simply scores against what has arrived,
        and the failure is audited.
        """
        settings: PurpleSettings = self.settings.purple
        if self._alert_fetcher is None and not settings.pull_enabled:
            return 0
        moment = (now or self.clock()).astimezone(UTC)
        since = moment - timedelta(days=7)
        try:
            if self._alert_fetcher is not None:
                alerts = await self._alert_fetcher(since, moment)
            else:
                alerts = await self._pull_from_siem(since, moment)
        except Exception as exc:
            self.auditor.record(
                AuditAction.PURPLE_ALERT_INGESTED,
                outcome=AuditOutcome.ERROR,
                target="siem-pull",
                reason=f"{exc.__class__.__name__}: {exc}",
            )
            return 0
        return self.ingest(alerts, source="pull")

    async def _pull_from_siem(self, since: datetime, until: datetime) -> tuple[Any, ...]:
        """Fetch the window's alerts over the shared scoped HTTP client (one egress path)."""
        from urllib.parse import urlsplit

        from arachne.core.http import ScopedHttpClient
        from arachne.core.safety import Scope
        from arachne.purple.alerts import parse_alert_text

        settings: PurpleSettings = self.settings.purple
        url = settings.alerts_url or ""
        host = urlsplit(url).hostname or ""
        if not host:
            msg = "purple.alerts_url has no host"
            raise ConfigurationError(msg)
        # The SIEM host is the only host this client is scoped to (ADR-05: one egress
        # path, bound to an explicit scope, never a bare library).
        client = ScopedHttpClient(scope=Scope(allowed_hosts=(host,)), auditor=self.auditor)
        headers = {"accept": "application/json"}
        if settings.alerts_token is not None:
            headers["authorization"] = f"Bearer {settings.alerts_token.get_secret_value()}"
        separator = "&" if "?" in url else "?"
        query = f"since={since.isoformat()}&until={until.isoformat()}"
        async with client:
            exchange = await client.get(f"{url}{separator}{query}", headers=headers)
        return parse_alert_text(exchange.body, source="pull")

    def ingest(self, alerts: Iterable[Any], *, source: str = "webhook") -> int:
        """Store normalized alerts; returns how many were new (deduplicated)."""
        items = tuple(alerts)
        added = self.store.ingest_alerts(items, now=self.clock())
        for alert in items:
            self.auditor.record(
                AuditAction.PURPLE_ALERT_INGESTED,
                target=alert.alert_id,
                meta={
                    "source": alert.source or source,
                    "technique": alert.technique,
                    "nonce": alert.nonce,
                    "observed_at": alert.observed_at.isoformat(),
                },
            )
        return added

    def ingest_text(self, text: str, *, source: str = "file") -> int:
        from arachne.purple.alerts import parse_alert_text

        return self.ingest(parse_alert_text(text, source=source), source=source)

    # ------------------------------------------------------------------ scoring
    def score(
        self, campaign: str, *, run_id: int | None = None, now: datetime | None = None
    ) -> CoverageReport:
        """Score a run's emissions against the ingested alerts (REQ-VALID-002).

        Re-runnable by design: a defender's SIEM reports asynchronously, so scoring again
        after more alerts arrive must update the same run rather than need a new scan.
        """
        moment = (now or self.clock()).astimezone(UTC)
        record = self.store.run(run_id) if run_id is not None else None
        if record is None:
            runs = self.store.runs(campaign, limit=1)
            record = runs[-1] if runs else None
        if record is None:
            msg = f"purple campaign {campaign!r} has no run to score"
            raise ScanStateError(msg)
        window = self._window_from_payload(record.window)
        emissions = self._emissions_of(record)
        alerts = tuple(item.to_alert() for item in self.store.alerts(limit=100_000))
        report = score_coverage(
            emissions,
            alerts,
            campaign=campaign,
            nonce=record.nonce,
            window=window,
            now=moment,
        )
        self.store.update_run(
            record.id,
            coverage=report.to_dict(),
            gaps=[item.technique for item in report.gaps],
            now=moment,
        )
        self.auditor.record(
            AuditAction.PURPLE_COVERAGE_SCORED,
            target=campaign,
            meta={
                "run_id": record.id,
                "nonce": record.nonce,
                "coverage_pct": report.coverage_pct,
                "seen": report.seen_count,
                "total": report.total,
                "gaps": [item.technique for item in report.gaps],
                "alerts_ingested": report.alerts_ingested,
            },
        )
        return report

    # ------------------------------------------------------------------ trend
    def trend(self, campaign: str, *, limit: int = 30) -> tuple[CoveragePoint, ...]:
        """Control coverage over time for one campaign (REQ-VALID-006)."""
        payloads = []
        for record in self.store.runs(campaign, limit=limit):
            payloads.append(
                {
                    "run_id": record.id,
                    "scan_id": record.scan_id,
                    "started_at": record.started_at.isoformat(),
                    "coverage": record.coverage or {},
                }
            )
        return coverage_points(payloads)

    def alerts(self, **kwargs: Any) -> tuple[AlertRecord, ...]:
        """The ingested defender alerts (the operator's view of the ingest)."""
        return self.store.alerts(**kwargs)

    # ------------------------------------------------------------------ internals
    def _definition_for(self, campaign: PurpleCampaign) -> TargetDefinition:
        matches = [
            record
            for record in self.services.target_store.list_targets(limit=1000)
            if record.name == campaign.spec.target
        ]
        if not matches:
            msg = (
                f"purple campaign {campaign.name!r} names target {campaign.spec.target!r}, "
                "which is not stored in this deployment"
            )
            raise ScanStateError(msg)
        definition: TargetDefinition = matches[0].to_definition()
        return definition

    @staticmethod
    def _window_of(definition: TargetDefinition) -> DetectionWindow | None:
        attestation: AuthorizationAttestation | None = definition.attestation
        return attestation.detection_window if attestation is not None else None

    @staticmethod
    def _window_from_payload(payload: Mapping[str, Any] | None) -> DetectionWindow | None:
        if not payload:
            return None
        return DetectionWindow.from_dict(payload)

    @staticmethod
    def _emissions_of(record: Any) -> tuple[Emission, ...]:
        return tuple(Emission.from_dict(item) for item in (record.emissions or ()))

    def _request_for(
        self,
        definition: TargetDefinition,
        campaign: PurpleCampaign,
        actions: Sequence[ReplayAction],
        nonce: str,
    ) -> ScanRequest:
        """Build the admitted request: exactly the campaign's actions, and nothing else.

        ``ModuleSelection.only`` is the exact-allowlist primitive (S21): naming the actions
        there withholds every other check, so a purple run cannot quietly do more than the
        defender agreed to watch for.
        """
        options = ScanOptions(
            engine=campaign.spec.engine,
            active_checks=True,
            modules=ModuleSelection(only=tuple(action.check_id for action in actions)),
            purple=PurpleRunOptions(
                campaign=campaign.name,
                actions=tuple(action.check_id for action in actions),
                nonce=nonce,
            ),
            notes=f"purple-team detection validation for campaign {campaign.name}",
        )
        return ScanRequest(target=definition, options=options)
