"""What a check is given: :class:`CheckContext` (F-02-01).

A check receives **one** context and nothing else. It names exactly four capabilities:

``http``
    the target-scoped, rate-limited, audited client (``None`` in dry-run mode, where
    nothing may be sent). A check never constructs a client and never imports an HTTP
    library (ADR-05, enforced by ``tests/unit/test_http_hygiene.py``).
``osint``
    a *separately* scoped client for third-party passive sources (certificate
    transparency, web archives, scan databases). It exists because "look up crt.sh" is not
    a request to the target and must not be forced through the target scope — but it is
    still an explicit, deny-by-default allowlist (:class:`~arachne.modules.providers.OsintAccess`).
``logger`` / ``config``
    the structured logger and the module configuration (corpus path, budgets, results caps).
``scope`` / ``record_asset``
    the compiled scope, and the only sanctioned way to add a discovered asset, which
    applies the scope guard and discards (with an audit line) anything out of scope
    (F-01-02).

Plus small, deliberate conveniences that keep checks short and uniform: :meth:`result`,
:meth:`info`, :meth:`candidate`, :meth:`skipped`, :meth:`error`, :meth:`evidence` and
:func:`mask_secret`. Everything a check yields therefore has the same shape, and
``modules.handlers`` can persist it without guessing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import (
    DEFAULT_WHOIS_RDAP_URL,
    M4Settings,
    M5Settings,
    M6Settings,
    Settings,
    WebSettings,
)
from arachne.core.events import Event
from arachne.core.lifecycle import AssetRecord, StepContext
from arachne.core.logging import get_logger
from arachne.core.redaction import mask_secret
from arachne.core.results import CheckResult, Evidence, EvidenceKind
from arachne.core.safety import Scope
from arachne.core.target import ScanOptions, TargetDefinition
from arachne.modules.base import Asset, CheckMetadata, Module

if TYPE_CHECKING:
    from arachne.modules.providers import OsintAccess

#: Default Common Crawl crawl the harvest check queries when none is configured. Pinned so
#: a scan is reproducible and a recorded fixture keeps its meaning.
CommonCrawlIndexDefault = "CC-MAIN-2024-51"

__all__ = [
    "CheckContext",
    "ModuleConfig",
    "collect_results",
    "mask_secret",
    "require_osint",
]


def require_osint(
    context: CheckContext, provider: str
) -> tuple[OsintAccess | None, CheckResult | None]:
    """Return ``(access, None)`` when ``provider`` may be queried, else ``(None, skipped)``.

    The single place a check asks "may I call out to a third party?", so the answer —
    disabled, not selected, credential missing — is reported the same way by every check
    (F-02-09: safe defaults, and an unconfigured source is a skipped check, not a failure).
    """
    access = context.osint
    if access is None:
        return None, context.skipped(
            "OSINT access is disabled for this scan "
            "(set ARACHNE_OSINT_ENABLED=true to query third-party passive sources)"
        )
    if not access.available(provider):
        reason = access.unavailable_reason(provider)
        # A provider that was asked for and refused is an event worth recording: S18's
        # strictly opt-in providers must be provably uncontacted, not merely unused
        # (REQ-INTEL-005, ``intel.provider_blocked``).
        access.note_blocked(provider, reason)
        return None, context.skipped(reason)
    return access, None


@dataclass(frozen=True, slots=True)
class ModuleConfig:
    """The configuration a check may read .

    Deliberately a frozen value object built once per run from :class:`Settings`, so a
    check cannot mutate the scan's configuration, and so tests can construct the exact
    configuration they exercise without an environment.
    """

    osint_enabled: bool = False
    providers: tuple[str, ...] = ()
    search_url: str | None = None
    fixtures_dir: str | None = None
    request_budget: int = 60
    max_results: int = 100
    max_assets: int = 500
    max_hosts_per_network: int = 256
    #: Path to the dork corpus (F-09-04: dorks are managed data, not code) and the pinned
    #: Common Crawl crawl a harvest check queries.
    dork_corpus: str | None = None
    commoncrawl_index: str = CommonCrawlIndexDefault
    github_token: SecretStr | None = None
    #: S18 strictly opt-in provider credentials. Read from the environment only (F-08-01),
    #: wrapped in ``SecretStr``, and never placed in a plan, a log line or a report — a check
    #: uses one to build an ``Authorization``/``api-key`` header, nothing more.
    shodan_api_key: SecretStr | None = None
    censys_api_id: str | None = None
    censys_api_secret: SecretStr | None = None
    hibp_api_key: SecretStr | None = None
    #: RDAP base for the ``whois`` provider (``{query}`` placeholder).
    whois_url: str | None = None
    #: How many days back a certificate counts as a "surprise" for ``m1.ct-surprise`` (S18).
    osint_ct_window_days: int = 14
    # ------------------------------------------------------------------ network probes (M2)
    #: UDP probing needs a deployment-level opt-in on top of the per-check one (F-01-09).
    net_allow_udp: bool = False
    #: Read-only OT/ICS protocol probing (S7comm, DNP3) needs its own deployment-level opt-in
    #: on top of the check's own (S29, REQ-DEPTH-006): ``ARACHNE_NET_OT_PROBE``.
    net_ot_probe: bool = False
    #: Bounds copied from NetSettings so a check can report *why* it stopped.
    max_hosts: int = 64
    max_ports: int = 100
    #: Lockout-safe pacing for Kerberos user enumeration (research ch02#19).
    kerberos_pacing_s: float = 1.5
    kerberos_max_names: int = 12
    #: Delay between SMTP VRFY/EXPN/RCPT probes (research ch02#20): a mail server's
    #: anti-automation controls are the thing this check must not trip, so the gap is both
    #: a default and a knob.
    smtp_pacing_s: float = 0.4
    #: Opt-in external deep-TLS tool (``testssl.sh``/``sslscan``), and whether nmap may be used.
    tls_tool: str | None = None
    nmap_enabled: bool = True
    #: Managed-data overrides (F-09-03/04): an operator's own port catalogue, CVE index and
    #: wordlists replace the shipped ones without touching code.
    port_catalog: str | None = None
    cve_index: str | None = None
    #: The generated CVE-index baseline merged under ``cve_index`` (S18): ``None`` = the
    #: bundled baseline, a path = that file, ``"off"`` = overlay only.
    cve_index_baseline: str | None = None
    wordlists_dir: str | None = None
    #: Optional online CVE/EPSS enrichment (F-09-03); the offline index is the default path.
    vulners_api_key: SecretStr | None = None
    #: M3 web-application probe bounds and switches (S6). ``web.session_cookie`` /
    #: ``web.auth_header`` are the operator's demo session, read from the environment only
    #: (F-08-01); ``web_payloads`` points at the M3 payload corpus (managed data, F-09-04).
    web: WebSettings = field(default_factory=WebSettings)
    web_payloads: str | None = None
    #: M4 misconfiguration/exposure bounds and its two opt-in switches (S7), plus the
    #: managed-data override for the M4 probe corpus and wordlists.
    m4: M4Settings = field(default_factory=M4Settings)
    m4_probes: str | None = None
    #: M5 cloud/container/supply-chain bounds and switches (S10), plus the managed-data
    #: override for the M5 probe corpus and wordlists.
    m5: M5Settings = field(default_factory=M5Settings)
    m5_probes: str | None = None
    #: M6 automation/AI-era/post-exploit bounds and switches (S11), plus the managed-data
    #: override for the M6 probe corpus, wordlists and Sigma rules.
    m6: M6Settings = field(default_factory=M6Settings)
    m6_probes: str | None = None

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        epss_feed: str | None = None,
        kev_feed: str | None = None,
    ) -> ModuleConfig:
        """Project the process settings onto what checks actually need.

        ``epss_feed``/``kev_feed`` override ``settings.m6``'s paths with the normalised
        artefact an operator *ingested* (F-09-03, S14). The composition root passes the
        active feed's path here, so an imported feed is used with no environment change and
        the modules keep reading a path rather than importing the data layer.
        """
        from dataclasses import replace

        osint = settings.osint
        m6 = settings.m6
        if epss_feed is not None or kev_feed is not None:
            m6 = replace(
                m6,
                epss_feed=epss_feed if epss_feed is not None else m6.epss_feed,
                kev_feed=kev_feed if kev_feed is not None else m6.kev_feed,
            )
        return cls(
            osint_enabled=osint.enabled,
            providers=tuple(osint.providers),
            search_url=osint.search_url,
            fixtures_dir=osint.fixtures_dir,
            request_budget=osint.request_budget,
            max_results=osint.max_results,
            max_assets=osint.max_assets,
            max_hosts_per_network=settings.planner.max_hosts_per_network,
            dork_corpus=osint.dork_corpus,
            commoncrawl_index=osint.commoncrawl_index,
            github_token=osint.github_token,
            net_allow_udp=settings.net.allow_udp,
            net_ot_probe=settings.net.ot_probe,
            max_hosts=settings.net.max_hosts,
            max_ports=settings.net.max_ports,
            kerberos_pacing_s=settings.net.kerberos_pacing_s,
            kerberos_max_names=settings.net.kerberos_max_names,
            smtp_pacing_s=settings.net.smtp_pacing_s,
            tls_tool=settings.net.tls_tool,
            nmap_enabled=settings.net.nmap_enabled,
            port_catalog=settings.net.port_catalog,
            cve_index=settings.net.cve_index,
            cve_index_baseline=settings.net.cve_index_baseline,
            wordlists_dir=settings.net.wordlists_dir,
            vulners_api_key=osint.vulners_api_key,
            shodan_api_key=osint.shodan_api_key,
            censys_api_id=osint.censys_api_id,
            censys_api_secret=osint.censys_api_secret,
            hibp_api_key=osint.hibp_api_key,
            whois_url=osint.whois_url or DEFAULT_WHOIS_RDAP_URL,
            osint_ct_window_days=settings.osint.ct_window_days,
            web=settings.web,
            web_payloads=settings.web_payloads,
            m4=settings.m4,
            m4_probes=settings.m4_probes,
            m5=settings.m5,
            m5_probes=settings.m5_probes,
            m6=m6,
            m6_probes=settings.m6_probes,
        )

    def session_headers(self, *, second: bool = False) -> dict[str, str]:
        """The extra request headers the operator's demo session contributes.

        Returned as a fresh mapping per call so a check cannot mutate shared state. The values
        are secrets; the HTTP client redacts ``cookie``/``authorization`` at capture time, so
        they never reach evidence, logs or a report (F-08-01, F-08-04).
        """
        headers: dict[str, str] = {}
        token = self.web.session_b_cookie if second else self.web.session_cookie
        if token is not None:
            value = token.get_secret_value().strip()
            if value:
                headers["Cookie"] = value
        if not second and self.web.auth_header is not None:
            raw = self.web.auth_header.get_secret_value().strip()
            name, separator, value = raw.partition(":")
            if separator and name.strip() and value.strip():
                headers[name.strip()] = value.strip()
        return headers

    def provider_enabled(self, name: str) -> bool:
        return name in self.providers


@dataclass
class CheckContext:
    """Everything one check may use for one asset ."""

    step: StepContext
    module: Module
    asset: Asset
    config: ModuleConfig = field(default_factory=ModuleConfig)
    osint: OsintAccess | None = None
    #: Sequence number of this check run, for stable ordering in tests and reports.
    run_index: int = 0
    #: The continuous-posture capability boundary (S23, area POSTURE): a
    #: :class:`~arachne.posture.access.PostureAccess` bound to this asset's scope key, or
    #: ``None`` when the step wired no baseline store (a continuous check then runs
    #: stateless — point-in-time policies only, note recorded).
    posture: Any = None
    #: The proof capability boundary (S15, area PROOF): an
    #: :class:`~arachne.proof.access.ProofAccess` granting exactly what the check's
    #: declared proof level allows. ``None`` when the step did not wire proof support
    #: (a passive-only step), which every ``ctx.proof`` use must treat as "no proof
    #: capability", never as an implicit grant.
    proof: Any = None

    # ------------------------------------------------------------------ passthroughs
    @property
    def metadata(self) -> CheckMetadata:
        return self.module.metadata

    @property
    def scan_id(self) -> int:
        return self.step.scan_id

    @property
    def scope(self) -> Scope:
        return self.step.scope

    @property
    def definition(self) -> TargetDefinition:
        return self.step.definition

    @property
    def options(self) -> ScanOptions:
        return self.step.options

    @property
    def http(self) -> Any:
        """The target-scoped HTTP client, or ``None`` in dry-run mode."""
        return self.step.http

    @property
    def net(self) -> Any:
        """The target-scoped raw-network client (S4/M2), or ``None`` in dry-run mode.

        M2's checks call this for every TCP/UDP/TLS exchange; ``None`` is the dry run's
        "nothing may be sent" and each check turns it into a skipped result rather than an
        error (``m2.support.net_or_skip``).
        """
        return self.step.net

    @property
    def inventory(self) -> Any:
        """The per-step network inventory the discovery handler builds (ADR-080.2)."""
        return self.step.inventory

    @property
    def web(self) -> Any:
        """The per-step web crawl the checks handler builds (S6/M3, ADR-100.2)."""
        return self.step.web

    @property
    def web_session(self) -> Any:
        """The authenticated web session (S19), or ``None`` when the scan is anonymous.

        A :class:`~arachne.creds.session.WebSession`: whether a session was established, what
        it reached, whether it survived a logout. It carries no credential — a check asks for
        authenticated reach through :attr:`credentials`, never for a value.
        """
        return self.step.web_session

    @property
    def web_baseline(self) -> Any:
        """The *unauthenticated* crawl (S19): what an anonymous client could see.

        The authenticated crawl in :attr:`web` is diffed against it, which is how a check
        establishes that the authenticated area is additional surface rather than a
        re-description of the same one.
        """
        return self.step.web_baseline

    @property
    def credentials(self) -> Any:
        """The per-scan credential broker (S19), or ``None`` when the step wired none.

        The one sanctioned way for a check to authenticate: ``ctx.credentials.login(...)``
        returns a session, ``ctx.credentials.authenticate(authenticator)`` offers a credential
        to a protocol attempt. Both return outcomes; neither returns a secret. ``None`` means
        "no credential capability in this step", which every use must treat as "run
        unauthenticated", never as an implicit grant.
        """
        return self.step.credentials

    @property
    def logger(self) -> Any:
        return get_logger(f"modules.{self.metadata.module.lower()}.{self.metadata.name}")

    # ------------------------------------------------------------------ side effects
    async def emit(self, event: Event) -> None:
        await self.step.emit(event)

    async def audit(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        target: str | None = None,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        await self.step.audit(
            action, outcome=outcome, target=target, reason=reason, meta=self._audit_meta(meta)
        )

    def _audit_meta(self, meta: dict[str, Any] | None) -> dict[str, Any]:
        return {"check": self.metadata.id, **dict(meta or {})}

    async def record_asset(
        self,
        kind: str,
        value: str,
        *,
        meta: Mapping[str, Any] | None = None,
        source: str | None = None,
    ) -> AssetRecord | None:
        """Persist a discovered asset through the scope guard (F-01-02)."""
        return await self.step.record_asset(
            kind, value, meta=meta, source=source or self.metadata.id
        )

    async def record_host(self, host: str, *, source: str | None = None) -> bool:
        """Record a discovered host (asset + ``host_discovered`` event); False if discarded."""
        record = await self.record_asset(
            "host", host, meta={"discovered_by": self.metadata.id}, source=source
        )
        if record is None:
            return False
        await self.step.emit(
            Event.host_discovered(
                scan_id=self.step.scan_id,
                host=host,
                kind="host",
                source=source or self.metadata.id,
            )
        )
        return True

    # ------------------------------------------------------------------ results
    def result(
        self,
        status: str,
        title: str,
        *,
        detail: str | None = None,
        cwe: str | None = None,
        evidence: tuple[Evidence, ...] | list[Evidence] = (),
        confidence: float = 0.5,
    ) -> CheckResult:
        """Build a result tagged with this check's identity (never with a severity)."""
        return CheckResult(
            status=status,  # type: ignore[arg-type]
            title=title,
            detail=detail,
            cwe=cwe if cwe is not None else self.metadata.cwe,
            evidence=tuple(evidence),
            confidence=confidence,
            check=self.metadata.key,
            module=self.metadata.module,
        )

    def info(self, title: str, *, detail: str | None = None, **kwargs: Any) -> CheckResult:
        """A non-finding observation (an asset discovered, an index consulted)."""
        return self.result("info", title, detail=detail, **kwargs)

    def candidate(
        self,
        title: str,
        *,
        detail: str | None = None,
        confidence: float = 0.5,
        **kwargs: Any,
    ) -> CheckResult:
        """A candidate finding: analysis decides severity and truth (ADR-02)."""
        return self.result("vulnerable", title, detail=detail, confidence=confidence, **kwargs)

    def clean(self, title: str, *, detail: str | None = None, **kwargs: Any) -> CheckResult:
        return self.result("not_vulnerable", title, detail=detail, **kwargs)

    def skipped(self, reason: str) -> CheckResult:
        """The check could not run (unconfigured source, no applicable asset); not a failure.

        The reason is carried as a ``note`` evidence item tagged ``skipped``, so the checks
        step can tell "there was nothing to ask" from "we asked and found nothing" without
        matching on prose, and an operator reading the evidence store sees why.
        """
        return self.result(
            "info",
            f"{self.metadata.title}: not run",
            detail=reason,
            confidence=0.0,
            evidence=[
                Evidence.of(
                    "note",
                    {"skipped": True, "reason": reason, "check": self.metadata.id},
                    source=self.asset.key,
                )
            ],
        )

    def error(self, exc: BaseException) -> CheckResult:
        return CheckResult.from_error(
            self.metadata.title,
            exc,
            cwe=self.metadata.cwe,
            check=self.metadata.key,
            module=self.metadata.module,
            context={"asset": self.asset.key},
        )

    @staticmethod
    def evidence(
        kind: EvidenceKind, payload: dict[str, Any], *, source: str | None = None
    ) -> Evidence:
        """Redacted, hashed, timestamped evidence (F-02-08, F-08-04)."""
        return Evidence.of(kind, payload, source=source)

    def now(self) -> datetime:
        return datetime.now(UTC)

    def evidence_from_exchange(self, exchange: Any) -> tuple[Evidence, Evidence]:
        """``(request evidence, response evidence)`` for one captured exchange."""
        request, response = exchange.to_evidence()
        return request, response


async def collect_results(
    context: CheckContext, results: AsyncIterator[CheckResult]
) -> AsyncIterator[CheckResult]:
    """Stream a check's results unchanged.

    A named seam (rather than calling ``module.run`` directly) so the checks step has one
    place to add cross-cutting behaviour — currently: keeping the module's identity on
    every result even when a check forgets to use :meth:`CheckContext.result`.
    """
    async for result in results:
        if result.check is None or result.module is None:
            yield CheckResult(
                status=result.status,
                title=result.title,
                detail=result.detail,
                cwe=result.cwe,
                evidence=result.evidence,
                confidence=result.confidence,
                error=result.error,
                check=result.check or context.metadata.key,
                module=result.module or context.metadata.module,
            )
        else:
            yield result
