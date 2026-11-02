"""Configuration, read from the environment only (F-08-01).

There is no config file format in this stage on purpose: secrets and deployment knobs
come from environment variables (F-04-02 keeps provider keys env-only too), so nothing
sensitive can be committed. ``Settings.from_env`` is pure — it takes an explicit
mapping — which makes it trivially testable and keeps ``os.environ`` out of business
logic.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Final
from urllib.parse import quote, urlsplit, urlunsplit

from pydantic import SecretStr

from arachne.core.errors import ConfigurationError
from arachne.core.ratelimit import RateLimitSettings
from arachne.core.safety import Scope, UrlSafetyPolicy

# The hypothesis-mode vocabulary (a leaf module: it imports nothing from ``core``), so a scan
# option and this settings group cannot disagree about the words ``off``/``heuristic``/``ai``.
from arachne.reasoning.model import HypothesisMode

__all__ = [
    "API_ROLES",
    "PII_KNOWN_CATEGORIES",
    "SEVERITY_LEVELS",
    "SSO_ALGORITHMS",
    "AiSettings",
    "AirgapSettings",
    "AnalysisSettings",
    "ApiSettings",
    "FeedsSettings",
    "HttpSettings",
    "IntegritySettings",
    "IntelSettings",
    "M4Settings",
    "M5Settings",
    "M6Settings",
    "NetSettings",
    "OsintSettings",
    "PiiSettings",
    "PlannerSettings",
    "PluginsSettings",
    "PostureSettings",
    "PurpleSettings",
    "ReportSettings",
    "ResilienceSettings",
    "SafetySettings",
    "SchedulerSettings",
    "SecretsSettings",
    "Settings",
    "SsoSettings",
    "WebSettings",
    "WebhookSettings",
    "get_settings",
    "reset_settings_cache",
]

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})

DEFAULT_DATABASE_FILENAME = "arachne.db"
#: Sibling directory of the default SQLite database holding offloaded evidence blobs
#: (S20, REQ-DATA-002). A sibling, not a temp dir: "move the database" moves the evidence.
DEFAULT_EVIDENCE_DIRNAME = "evidence"
#: Sibling directory of the default SQLite database holding imported offline content packs
#: (S25, REQ-RESIL-001).
DEFAULT_CONTENT_DIRNAME = "content"
DEFAULT_USER_AGENT = "ARACHNE/0.1 (+https://localhost/arachne) defensive-security-scanner"


@dataclass(frozen=True, slots=True)
class HttpSettings:
    """Timeout, body-capture and retry policy for the shared client."""

    timeout_s: float = 15.0
    connect_timeout_s: float = 5.0
    max_redirects: int = 5
    max_body_bytes: int = 64 * 1024
    retries: int = 1
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    follow_redirects: bool = True

    def __post_init__(self) -> None:
        if self.timeout_s <= 0 or self.connect_timeout_s <= 0:
            msg = "timeouts must be > 0"
            raise ConfigurationError(msg)
        if self.max_redirects < 0 or self.retries < 0:
            msg = "max_redirects and retries must be >= 0"
            raise ConfigurationError(msg)
        if self.max_body_bytes < 1:
            msg = "max_body_bytes must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class SafetySettings:
    """URL safety policy plus the ADR/policy knobs it derives from."""

    policy: UrlSafetyPolicy = field(default_factory=UrlSafetyPolicy)
    scope: Scope = field(default_factory=Scope.deny_all)
    redaction_enabled: bool = True

    @classmethod
    def permissive_local(cls) -> SafetySettings:
        """Policy for lab fixtures on loopback (used by tests and the dry-run lab)."""
        return cls(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True))


@dataclass(frozen=True, slots=True)
class NetSettings:
    """Bounds and switches for raw network probes (S4/M2, F-01-07/09).

    Every knob here exists because M2 contacts the target directly and the cost of a
    mistake is measured in packets, not milliseconds. The timeouts bound a *single*
    connection; ``max_ports``/``max_hosts`` bound how much of an estate one check may
    touch per run; and the two switches are the safety gates of F-01-09:

    ``allow_udp``
        UDP probing is off by default. A UDP probe is unacknowledged and unreliably
        attributed, and the protocols it reaches (SNMP, BACnet) are read-only but
        aggregating — so it needs an explicit deployment-level opt-in on top of the
        per-check opt-in. An ICS/UDP check reports itself skipped while this is False.
    ``tls_tool``
        An external deep-TLS tool (``testssl.sh`` or ``sslscan``) to run *in addition to*
        the stdlib probe. Off by default, and invoked with a fixed argument vector and no
        shell: the stdlib probe is the offline/fallback path;
        the external tool adds depth when an operator asks for it.
    """

    connect_timeout_s: float = 3.0
    read_timeout_s: float = 2.0
    banner_wait_s: float = 0.75
    max_read_bytes: int = 8192
    max_ports: int = 100
    max_hosts: int = 64
    concurrency: int = 24
    allow_udp: bool = False
    #: **Off by default** (S29, REQ-DEPTH-006). Whether the read-only OT/ICS protocol checks
    #: (``m2.ot-protocol-probe``: S7comm and DNP3 discovery and bad-configuration detection)
    #: may address an industrial port at all. OT protocols predate authentication, so
    #: reaching one is itself the sensitive act: this is a deployment-level opt-in on top of
    #: the check's own opt-in, exactly like ``allow_udp`` for datagram probes.
    ot_probe: bool = False
    tls_tool: str | None = None
    tls_tool_timeout_s: float = 120.0
    nmap_enabled: bool = True
    nmap_timeout_s: float = 120.0
    #: Lockout-safe pacing for Kerberos user enumeration (research ch02#19): a delay
    #: between AS-REQ probes and a hard cap on candidate names, so the check cannot turn
    #: into the account-lockout event it is supposed to detect the exposure of.
    kerberos_pacing_s: float = 1.5
    kerberos_max_names: int = 12
    #: Delay between SMTP enumeration probes (lockout-safe pacing, research ch02#20).
    smtp_pacing_s: float = 0.4
    #: Cipher suites the stdlib TLS probe tries one at a time (``ARACHNE_NET_TLS_CIPHERS``).
    #: ``None`` means the shipped weak-suite list; a shorter list trades probe depth for scan
    #: time, which is what a lab fixture or a large estate wants.
    tls_cipher_probes: tuple[str, ...] | None = None
    #: Managed-data overrides (F-09-03/04): an operator's port catalogue, CVE/EPSS index and
    #: wordlist directory. ``None`` means "use the shipped files".
    port_catalog: str | None = None
    cve_index: str | None = None
    #: S18: the *generated* CVE-index layer merged under ``cve_index``. ``None`` loads the
    #: bundled baseline, a path loads that file, ``"off"`` disables the layer.
    cve_index_baseline: str | None = None
    wordlists_dir: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("connect_timeout_s", self.connect_timeout_s),
            ("read_timeout_s", self.read_timeout_s),
            ("banner_wait_s", self.banner_wait_s),
            ("tls_tool_timeout_s", self.tls_tool_timeout_s),
            ("nmap_timeout_s", self.nmap_timeout_s),
            ("kerberos_pacing_s", self.kerberos_pacing_s),
            ("smtp_pacing_s", self.smtp_pacing_s),
        ):
            if value <= 0:
                msg = f"net.{label} must be > 0, got {value}"
                raise ConfigurationError(msg)
        for label, value in (
            ("max_read_bytes", self.max_read_bytes),
            ("max_ports", self.max_ports),
            ("max_hosts", self.max_hosts),
            ("concurrency", self.concurrency),
            ("kerberos_max_names", self.kerberos_max_names),
        ):
            if value < 1:
                msg = f"net.{label} must be >= 1, got {value}"
                raise ConfigurationError(msg)


#: Host each known OSINT provider talks to. This is the **deployment allowlist** the OSINT
#: client is bound to (F-01-02): a check can only reach a third-party index that appears
#: here, so "query crt.sh" is as explicit a declaration as "scan example.com". The
#: provider layer asserts agreement with this table (``tests/unit/test_providers.py``),
#: so the two cannot drift.
OSINT_PROVIDER_HOSTS: Final[dict[str, str]] = {
    "crtsh": "crt.sh",
    "circl": "www.circl.lu",
    "wayback": "web.archive.org",
    "commoncrawl": "index.commoncrawl.org",
    "internetdb": "internetdb.shodan.io",
    "github": "api.github.com",
    "vulners": "vulners.com",
    # DNS-over-HTTPS: how M4 reads SPF/DKIM/DMARC records without a local resolver
    # (S7, research ch04#18). Still a third party, so still off unless enabled.
    "dns": "dns.google",
    # S18 (area INTEL): the keyed, strictly opt-in passive-OSINT providers. None of them is
    # in DEFAULT_OSINT_PROVIDERS — naming one in ARACHNE_OSINT_PROVIDERS *is* the opt-in —
    # and each one additionally needs its credential (see OSINT_PROVIDER_CREDENTIALS), so a
    # half-configured provider is out of scope rather than a failing request.
    "shodan": "api.shodan.io",
    "censys": "search.censys.io",
    # Certificate Transparency from a second, independent log aggregator: the S18
    # certificate-surprise check reads it beside crt.sh so "one log knew, the other did not"
    # is itself a signal.
    "certspotter": "api.certspotter.com",
    "hibp": "haveibeenpwned.com",
    # No fixed host: the RDAP base comes from ARACHNE_OSINT_WHOIS_URL.
    "whois": "",
    # No fixed host: the endpoint comes from ARACHNE_OSINT_SEARCH_URL.
    "search": "",
}

#: Providers enabled when ``ARACHNE_OSINT_ENABLED`` is set and no explicit list is given:
#: every one of them is keyless, so OSINT can be turned on without any credential.
DEFAULT_OSINT_PROVIDERS: Final[tuple[str, ...]] = (
    "crtsh",
    "circl",
    "wayback",
    "commoncrawl",
    "internetdb",
)

#: Providers that are **never** enabled implicitly (S18, REQ-INTEL-003). Naming one in
#: ``ARACHNE_OSINT_PROVIDERS`` is the opt-in; the check that uses it is opt-in too, so two
#: deliberate declarations stand between a deployment and a provider call.
OPT_IN_OSINT_PROVIDERS: Final[tuple[str, ...]] = (
    "shodan",
    "censys",
    "certspotter",
    "hibp",
    "whois",
)

#: Configuration field each keyed provider must have filled in. A provider whose credential
#: is absent has its host removed from the OSINT scope, so a missing key refuses the request
#: instead of sending an unauthenticated one (F-02-09).
OSINT_PROVIDER_CREDENTIALS: Final[dict[str, tuple[str, ...]]] = {
    "github": ("github_token",),
    "vulners": ("vulners_api_key",),
    "shodan": ("shodan_api_key",),
    "censys": ("censys_api_id", "censys_api_secret"),
    "hibp": ("hibp_api_key",),
}

#: Providers whose host is not a constant: the deployment supplies the endpoint URL. The
#: value is the :class:`OsintSettings` field carrying the template.
OSINT_DYNAMIC_PROVIDER_URLS: Final[dict[str, str]] = {
    "search": "search_url",
    "whois": "whois_url",
}

#: Default request pacing (requests/second) for the S18 providers, applied by the provider
#: layer in addition to the shared client's per-host limiter (REQ-INTEL-003). The values are
#: deliberately conservative: these are somebody else's free/paid tiers, and a scan is not
#: the only consumer of the key. Overridable per deployment
#: (``ARACHNE_OSINT_PROVIDER_RATE_LIMITS``).
DEFAULT_OSINT_PROVIDER_RATE_LIMITS: Final[tuple[tuple[str, float], ...]] = (
    ("shodan", 1.0),
    ("censys", 0.5),
    ("hibp", 0.5),
    ("certspotter", 1.0),
    ("whois", 1.0),
)

#: The default RDAP base for the ``whois`` provider. RDAP is the IETF's HTTPS replacement for
#: the port-43 WHOIS protocol, which is the only form that can pass through the one HTTP
#: egress path (ADR-05). ``{query}`` is substituted with the registrable name.
DEFAULT_WHOIS_RDAP_URL: Final[str] = "https://rdap.org/domain/{query}"

#: Pinned Common Crawl crawl used by ``m1.webarchive-harvest`` unless configured otherwise.
COMMONCRAWL_DEFAULT_INDEX: Final = "CC-MAIN-2024-51"


@dataclass(frozen=True, slots=True)
class OsintSettings:
    """Third-party OSINT access for M1 (F-02-02, F-02-09).

    Passive reconnaissance queries *other people's* indexes (certificate transparency,
    web archives, scan databases), so two switches decide whether it happens at all:

    * ``enabled`` — **off by default**. Nothing in M1 is allowed to contact a third party
      unless the deployment says so, which is what keeps a default scan offline (the
      offline demo) and keeps the test suite internet-free.
    * ``providers`` — which sources are allowed; the OSINT client's scope is exactly the
      hosts of this list (plus ``search_url``'s host and ``extra_hosts``), so an index that
      is not named here is out of scope and the request is refused and audited.

    ``fixtures_dir`` replays recorded responses instead of contacting anything
    (vcrpy-style): the checks run end to end, with no packet leaving the
    process. ``github_token`` is a secret read from the environment only (F-08-01); it is
    wrapped in :class:`~pydantic.SecretStr`, so it cannot be printed or logged by accident.
    """

    enabled: bool = False
    providers: tuple[str, ...] = DEFAULT_OSINT_PROVIDERS
    search_url: str | None = None
    fixtures_dir: str | None = None
    extra_hosts: tuple[str, ...] = ()
    request_budget: int = 60
    max_results: int = 100
    max_assets: int = 500
    #: The dork corpus is managed data (F-09-04, ADR-04): point this at a project's own
    #: corpus to replace the shipped one.
    dork_corpus: str | None = None
    #: Pinned Common Crawl crawl (reproducibility; F-09-03 offline-friendly correlation).
    commoncrawl_index: str = COMMONCRAWL_DEFAULT_INDEX
    github_token: SecretStr | None = None
    #: Vulners API key for the *optional* online CVE/EPSS enrichment of M2's correlation
    #: check (F-09-03). The offline table is the default path; online lookup happens only
    #: when this is set *and* the ``vulners`` provider is in ``providers``.
    vulners_api_key: SecretStr | None = None
    # -------------------------------------------------- S18 opt-in keyed providers
    # Every credential below is read from the environment only (F-08-01) and wrapped in
    # ``SecretStr``, so it cannot be printed, logged or serialised by accident. ``None``
    # means "this provider is not configured": its host leaves the OSINT scope and a check
    # that asks for it reports a skip with the reason, which is the graceful degradation
    # REQ-INTEL-005 asks for.
    shodan_api_key: SecretStr | None = None
    #: Censys Platform API. The identifier is not a secret; the secret is.
    censys_api_id: str | None = None
    censys_api_secret: SecretStr | None = None
    hibp_api_key: SecretStr | None = None
    #: RDAP base for the ``whois`` provider (``{query}`` placeholder). ``None`` uses
    #: :data:`DEFAULT_WHOIS_RDAP_URL`. A deployment behind a proxy points this at its own
    #: RDAP mirror, which is also how the referral hop (to an authoritative RDAP server) is
    #: kept inside the allowlist rather than followed blindly.
    whois_url: str | None = None
    #: Per-provider pacing in requests/second, applied by the provider layer on top of the
    #: shared client's per-host limiter (REQ-INTEL-003). Empty means "no extra pacing".
    provider_rate_limits: tuple[tuple[str, float], ...] = DEFAULT_OSINT_PROVIDER_RATE_LIMITS
    #: How many days back a certificate counts as a "surprise" for ``m1.ct-surprise`` (S18):
    #: long enough to survive a weekly scan cadence, short enough that "new" means something.
    ct_window_days: int = 14

    def __post_init__(self) -> None:
        unknown = sorted(set(self.providers) - set(OSINT_PROVIDER_HOSTS))
        if unknown:
            msg = (
                f"unknown OSINT provider(s) {unknown}; "
                f"known providers are {sorted(OSINT_PROVIDER_HOSTS)}"
            )
            raise ConfigurationError(msg)
        if self.request_budget < 1:
            msg = "osint.request_budget must be >= 1"
            raise ConfigurationError(msg)
        if self.max_results < 1:
            msg = "osint.max_results must be >= 1"
            raise ConfigurationError(msg)
        unknown_limits = sorted(
            {name for name, _ in self.provider_rate_limits} - set(OSINT_PROVIDER_HOSTS)
        )
        if unknown_limits:
            msg = (
                f"unknown OSINT provider(s) in osint.provider_rate_limits {unknown_limits}; "
                f"known providers are {sorted(OSINT_PROVIDER_HOSTS)}"
            )
            raise ConfigurationError(msg)
        if any(rate <= 0 for _, rate in self.provider_rate_limits):
            msg = "osint.provider_rate_limits values must be > 0"
            raise ConfigurationError(msg)
        if self.ct_window_days < 0:
            msg = "osint.ct_window_days must be >= 0"
            raise ConfigurationError(msg)

    @property
    def has_credential_for_github(self) -> bool:
        return self.github_token is not None

    @property
    def has_credential_for_vulners(self) -> bool:
        return self.vulners_api_key is not None

    def credential_present(self, field: str) -> bool:
        """True when the named :class:`OsintSettings` credential is configured."""
        return getattr(self, field, None) is not None

    def provider_credential_problem(self, provider: str) -> str | None:
        """The missing-credential reason for ``provider``, or ``None`` when it is usable."""
        missing = [
            field
            for field in OSINT_PROVIDER_CREDENTIALS.get(provider, ())
            if not self.credential_present(field)
        ]
        if not missing:
            return None
        return f"provider {provider!r} needs {' and '.join(missing)} in the environment"

    def usable_provider(self, provider: str) -> bool:
        """True when the provider may be contacted: it has every credential it needs.

        Used by the provider layer's builder to drop a half-configured provider entirely, so
        "no key" means "out of scope and disabled", never "send it anyway".
        """
        return self.provider_credential_problem(provider) is None

    def provider_url(self, provider: str) -> str | None:
        """The configured endpoint of a dynamic provider (``search``, ``whois``)."""
        field = OSINT_DYNAMIC_PROVIDER_URLS.get(provider)
        if field is None:
            return None
        value = getattr(self, field, None)
        if provider == "whois" and not value:
            return DEFAULT_WHOIS_RDAP_URL
        return value if isinstance(value, str) and value.strip() else None

    def rate_limit_for(self, provider: str) -> float | None:
        """Requests/second the provider layer paces ``provider`` at, or ``None``."""
        return dict(self.provider_rate_limits).get(provider)

    def provider_hosts(self) -> tuple[str, ...]:
        """Hosts the OSINT client may contact, derived from the enabled providers."""
        names = list(self.providers)
        for provider, field_name in OSINT_DYNAMIC_PROVIDER_URLS.items():
            # An explicitly configured endpoint is as deliberate a declaration as naming the
            # provider, so it turns that provider on. The ``whois`` *default* endpoint is not
            # (it is only used once ``whois`` is enabled), so enabling it can never widen the
            # scope on its own.
            configured = getattr(self, field_name, None)
            if configured and provider not in names:
                names.append(provider)
        hosts: list[str] = [
            OSINT_PROVIDER_HOSTS[name] for name in names if OSINT_PROVIDER_HOSTS.get(name)
        ]
        # A provider that cannot authenticate is not contacted; leaving its host out of
        # the scope makes that a refusal rather than a failed request.
        for name in names:
            if OSINT_PROVIDER_CREDENTIALS.get(name) and not all(
                self.credential_present(field) for field in OSINT_PROVIDER_CREDENTIALS[name]
            ):
                host = OSINT_PROVIDER_HOSTS.get(name)
                if host and host in hosts:
                    hosts.remove(host)
        for provider in OSINT_DYNAMIC_PROVIDER_URLS:
            url = self.provider_url(provider)
            if url and provider in names:
                host = urlsplit(url).hostname
                if host:
                    hosts.append(host)
        hosts.extend(self.extra_hosts)
        return tuple(dict.fromkeys(host.strip().lower() for host in hosts if host.strip()))

    def is_fixture_mode(self) -> bool:
        """True when responses come from recorded fixtures rather than the network."""
        return bool(self.fixtures_dir)


@dataclass(frozen=True, slots=True)
class WebSettings:
    """Bounds and switches for the M3 web-application checks (S6, F-01-07/09).

    Every knob exists because M3 sends *payloads* at a target, not just reads: the crawl and
    each oracle are bounded so "one check" can never become "a fuzzing campaign", and the two
    switches are the safety gates on top of the per-check active-checks opt-in (F-01-09).

    ``max_pages``/``max_depth``
        The crawl that feeds every M3 check (parameters, forms, endpoints) is breadth-first,
        same-origin and GET-only; these bound it.
    ``max_params_per_check``
        How many (endpoint, parameter) pairs one oracle will probe. A page with 30 form
        fields must not turn one check into 30 times the probes.
    ``time_delay_s``/``time_delta_s``
        The blocking delay a time-based injection probe asks the server to sleep for, and the
        measured excess over the baseline that counts as a positive. Only used when the
        error- and boolean-based oracles did not already confirm the parameter.
    ``hidden_path_limit``
        How many entries of the hidden-endpoint wordlist ``m3.api-surface`` probes.
    ``rate_limit_probes``
        The strictly bounded request count ``m3.rate-limit-audit`` uses per endpoint — the
        check characterizes anti-automation controls; it never mounts a brute-force.
    ``upload_probe``
        Whether ``m3.upload-audit`` may store its inert marker file. **Off by default**: the
        M3 safety text says "no stored payloads", so an operator must opt in
        explicitly (``ARACHNE_WEB_UPLOAD_PROBE=true``) before the single benign marker is
        written. With it off the check still reports what the endpoint's validation *response*
        reveals, but does not confirm fetchability.
    ``follow_redirects``
        M3 needs the raw 3xx it asked for (open-redirect reads ``Location``), so the oracle
        requests do not follow redirects even though the shared client's default would.
    """

    max_pages: int = 20
    max_depth: int = 2
    max_params_per_check: int = 6
    max_endpoints: int = 200
    time_delay_s: float = 3.0
    time_delta_s: float = 2.0
    hidden_path_limit: int = 40
    rate_limit_probes: int = 5
    upload_probe: bool = False
    follow_redirects: bool = False
    #: Out-of-band callback base on **ARACHNE's own infrastructure** (research ch03#5). When
    #: set, ``m3.ssrf-probe`` injects ``<callback>/<nonce>`` into server-side fetch sinks and
    #: confirms a hit by asking the callback service whether the nonce arrived. Unset (the
    #: default) means no OOB probe is ever sent and the check reports itself skipped.
    ssrf_callback_url: str | None = None
    #: **Off by default.** Whether ``m3.ssrf-probe`` may inject the callback URL at all; the
    #: SSRF probe is the one M3 family that reaches a service *other than the target* through
    #: the target, so it carries its own deployment switch on top of the active-checks gate.
    ssrf_probe: bool = False
    #: **Off by default** (S15). Whether the L3 one-shot command proof
    #: (``m3.rce-echo``) may inject its allowlisted ``echo arachne-<nonce>`` payload at
    #: all. The check additionally requires the active-checks opt-in *and* an attestation
    #: that authorizes state changes (REQ-PROOF-007).
    rce_probe: bool = False
    #: **Off by default** (S15). Whether the L4 state-marker proof (``m3.state-marker``)
    #: may perform its INSERT-first, auto-restored marker write at all. The check
    #: additionally requires the active-checks opt-in *and* an attestation that authorizes
    #: state changes (REQ-PROOF-008).
    state_probe: bool = False
    #: **Off by default** (S29, REQ-DEPTH-001). Whether the GraphQL depth/cost and
    #: anonymous-resolver probes (``m3.graphql-depth-abuse``, ``m3.graphql-resolver-auth``)
    #: may send their crafted queries. Both are read-only and select only ``__typename`` —
    #: they never ask for document content — but they deliberately make a server do
    #: amplification-shaped work, so they carry a deployment switch on top of the
    #: active-checks and per-check opt-ins.
    graphql_probe: bool = False
    #: **Off by default** (S29, REQ-DEPTH-002). Whether ``m3.websocket-injection`` may send
    #: its single inert marker frame after the handshake. The handshake-only checks need no
    #: switch; sending any application message does, because that is the step that turns a
    #: WebSocket probe from a read into a conversation.
    ws_probe: bool = False
    #: Bounded probe counts for the extended families (S10): these oracles must never become a
    #: fuzzing campaign .
    smuggling_probes: int = 4
    race_concurrency: int = 8
    jwt_max_tokens: int = 4
    graphql_batch_size: int = 8
    takeover_max_names: int = 40
    #: Operator-supplied demo session (F-08-01: env only). ``session_cookie`` is applied as a
    #: ``Cookie`` header and ``session_b_cookie`` is the *second* identity the IDOR check uses
    #: for its cross-account differential (research ch03#18). ``auth_header`` is a raw
    #: ``Name: value`` header (e.g. ``Authorization: Bearer ...``). All three are
    #: :class:`~pydantic.SecretStr` so they cannot be logged, and the HTTP client redacts
    #: ``cookie``/``authorization`` at capture time, so they never reach evidence either.
    session_cookie: SecretStr | None = None
    session_b_cookie: SecretStr | None = None
    auth_header: SecretStr | None = None

    def __post_init__(self) -> None:
        for label, value in (("max_pages", self.max_pages), ("max_endpoints", self.max_endpoints)):
            if value < 1:
                msg = f"web.{label} must be >= 1, got {value}"
                raise ConfigurationError(msg)
        for label, value in (
            ("max_depth", self.max_depth),
            ("max_params_per_check", self.max_params_per_check),
            ("hidden_path_limit", self.hidden_path_limit),
            ("rate_limit_probes", self.rate_limit_probes),
        ):
            if value < 0:
                msg = f"web.{label} must be >= 0, got {value}"
                raise ConfigurationError(msg)
        if self.time_delay_s <= 0 or self.time_delta_s <= 0:
            msg = "web.time_delay_s and web.time_delta_s must be > 0"
            raise ConfigurationError(msg)

    def has_second_identity(self) -> bool:
        """True when a second session is configured (IDOR's cross-account differential)."""
        return self.session_b_cookie is not None


@dataclass(frozen=True, slots=True)
class M4Settings:
    """Bounds and switches for the M4 misconfiguration/exposure checks (S7, F-01-07/09).

    M4 is mostly read-only path probing, which is cheap; the knobs exist where a check
    could turn into something else:

    ``max_paths`` / ``max_findings_per_check``
        One check must not become a content-discovery sweep or flood the report. Both are
        hard caps enforced per check run.
    ``max_bucket_names``
        How many name candidates ``m4.bucket-exposure`` derives from a declared domain.
    ``default_credentials``
        **Off by default.** Trying a vendor-default credential pair is an authentication
        attempt, not a read: it needs the active-checks gate, an explicit check selection
        *and* this switch. ``default_credentials_pacing_s`` and
        ``default_credentials_max_attempts`` make it lockout-safe (one paced attempt per
        detected product, never a spray, never a retry).
    ``metadata_ssrf_probe``
        **Off by default.** Whether ``m4.metadata-ssrf`` may send the provider's metadata
        GET; with it off the check only reports the SSRF sinks it can see in the crawl and
        never touches a link-local address.
    """

    max_paths: int = 60
    max_findings_per_check: int = 8
    max_bucket_names: int = 8
    default_credentials: bool = False
    default_credentials_pacing_s: float = 1.5
    default_credentials_max_attempts: int = 3
    metadata_ssrf_probe: bool = False

    def __post_init__(self) -> None:
        for label, value in (
            ("max_paths", self.max_paths),
            ("max_findings_per_check", self.max_findings_per_check),
            ("max_bucket_names", self.max_bucket_names),
            ("default_credentials_max_attempts", self.default_credentials_max_attempts),
        ):
            if value < 1:
                msg = f"m4.{label} must be >= 1, got {value}"
                raise ConfigurationError(msg)
        if self.default_credentials_pacing_s < 0:
            msg = "m4.default_credentials_pacing_s must be >= 0"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class M5Settings:
    """Bounds and switches for the M5 cloud/container/supply-chain checks (S10, F-02-06).

    M5 is the module that most often needs *credentials* or a *local artifact*: a cloud
    account (read-only), a repository clone, an image reference. Every switch here exists to
    keep the default posture offline and non-destructive :

    ``max_paths`` / ``max_findings_per_check``
        The usual per-check hard caps; a cloud/exposure probe must not become a sweep.
    ``max_bucket_names``
        Name candidates ``m5.bucket-enumerator`` derives from a declared domain.
    ``imds_probe``
        **Off by default.** Whether ``m5.imds-ssrf`` may send the metadata GET (link-local).
    ``validate_cloud_keys``
        **Off by default.** Whether ``m5.leaked-cloud-keys`` may make the read-only
        ``sts:GetCallerIdentity``-class validation call for a key it found. Documented
        permission list: the single call needs no IAM permission beyond the identity itself.
    ``registry_scan``
        **Off by default.** Whether ``m5.registry-scan`` may invoke the external image scanner
        (Trivy/Syft/Grype class) — running a container-image tool is a deployment decision.
    ``docker_socket``
        Whether ``m5.docker-socket`` probes the local daemon socket in addition to any
        reachable TCP API. Read-only (``/version``, ``/containers/json``).
    ``iac_tool`` / ``sbom_tool``
        Optional external binaries (tfsec/checkov, trivy/syft). When unset the checks use the
        built-in pattern review, so they still work with nothing installed.
    ``max_file_bytes``
        How much of one local artifact (a state file, a lockfile, a workflow) is read.
    """

    max_paths: int = 40
    max_findings_per_check: int = 8
    max_bucket_names: int = 8
    imds_probe: bool = False
    validate_cloud_keys: bool = False
    registry_scan: bool = False
    docker_socket: bool = True
    iac_tool: str | None = None
    sbom_tool: str | None = None
    max_file_bytes: int = 262144
    #: Bounded repository file walk (a clone can be large; the checks only read artifacts).
    max_repo_files: int = 4000
    #: Continuous cloud-config posture (S23, REQ-POSTURE-001). ``posture_max_resources``
    #: bounds one snapshot's inventory (a CSPM-style export can be large) and
    #: ``posture_max_bytes`` the snapshot body itself. ``posture_token`` is the optional
    #: bearer credential a read-only config endpoint needs (Azure/GCP management-style
    #: APIs); environment only (F-08-01), never logged, never stored.
    posture_max_resources: int = 200
    posture_max_bytes: int = 1_048_576
    posture_token: SecretStr | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("max_paths", self.max_paths),
            ("max_findings_per_check", self.max_findings_per_check),
            ("max_bucket_names", self.max_bucket_names),
            ("max_file_bytes", self.max_file_bytes),
            ("max_repo_files", self.max_repo_files),
            ("posture_max_resources", self.posture_max_resources),
            ("posture_max_bytes", self.posture_max_bytes),
        ):
            if value < 1:
                msg = f"m5.{label} must be >= 1, got {value}"
                raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class M6Settings:
    """Bounds and switches for the M6 automation/AI-era/post-exploit checks (S11, F-02-07).

    M6 is the module that looks at *files, logs and feeds* rather than at the live web
    surface: "YARA scanning is file-read-only; telemetry checks
    require explicit log-access grants"). Every knob exists to keep that boundary explicit:

    ``max_paths`` / ``max_findings_per_check`` / ``max_file_bytes`` / ``max_repo_files``
        The usual per-check hard caps: a webshell/secret scan must not become a full-disk
        walk, and one check must not flood the report.
    ``max_webshell_probes``
        How many served shell-path candidates ``m6.webshell-yara`` fetches (GET only, bounded
        and already hinted by the crawl); zero requests go out for the local-file half.
    ``max_git_objects``
        How many loose ``.git`` objects ``m6.secret-scan-at-scale`` decompresses to look into
        history (read-only; object bytes are never written anywhere).
    ``epss_feed`` / ``kev_feed`` / ``resolved_versions``
        Offline-first enrichment (F-09-03): an operator may point these at a FIRST EPSS CSV,
        a CISA KEV JSON and an asset/version inventory export; with none set the shipped
        snapshots are used, so a scan needs no network to correlate CVE/EPSS (ch06#7).
    ``log_access`` / ``log_paths``
        **Off by default.** The explicit log-access grant of : without it
        ``m6.sigma-hunt-rules`` only ships the rule set and ingests nothing.
    ``deception``
        **Off by default.** Whether ``m6.deception-listeners`` may read the honeytoken
        trigger log (the optional deception module of ch06#25).
    ``sigma_rules`` / ``lpe_index`` / ``webshell_paths``
        Managed-data overrides (F-09-04) for the Sigma rule directory, the local-privilege-
        escalation index and the served-shell-path wordlist.
    """

    max_paths: int = 40
    max_findings_per_check: int = 8
    max_file_bytes: int = 262144
    max_repo_files: int = 4000
    max_webshell_probes: int = 12
    max_git_objects: int = 200
    epss_feed: str | None = None
    kev_feed: str | None = None
    resolved_versions: str | None = None
    log_access: bool = False
    log_paths: tuple[str, ...] = ()
    deception: bool = False
    sigma_rules: str | None = None
    lpe_index: str | None = None
    webshell_paths: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("max_paths", self.max_paths),
            ("max_findings_per_check", self.max_findings_per_check),
            ("max_file_bytes", self.max_file_bytes),
            ("max_repo_files", self.max_repo_files),
            ("max_webshell_probes", self.max_webshell_probes),
            ("max_git_objects", self.max_git_objects),
        ):
            if value < 1:
                msg = f"m6.{label} must be >= 1, got {value}"
                raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class SchedulerSettings:
    """The recurring-scan scheduler (S11, F-01-05).

    ``state_path`` is where the scheduler persists its state (schedule definitions, last run
    time, last scan id per schedule) — a JSON document, committed nowhere, safe to delete.
    ``max_runs_per_tick`` bounds how many due scans one ``arachne schedule run`` executes, so
    a long-idle scheduler cannot start an unbounded number of scans at once.
    ``diff_on_run`` turns on the change-detection half: each scheduled run compares itself
    with the previous run of the same schedule and persists a ``scans_diff`` row (F-06-05).
    """

    state_path: str | None = None
    max_runs_per_tick: int = 4
    diff_on_run: bool = True

    def __post_init__(self) -> None:
        if self.max_runs_per_tick < 1:
            msg = "scheduler.max_runs_per_tick must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class PostureSettings:
    """Continuous exposure management (S23, area POSTURE).

    ``default_max_runs_per_day`` / ``default_max_requests`` are the cost guardrails a
    *continuous* schedule (risk R-13) inherits when it declares no budget of its own: the
    scheduler refuses — audited — to fire a run past the daily cap or to admit a run whose
    plan estimates more requests than the cap. Admission control itself stays the
    orchestrator's (every continuous scan passes the same gates).

    ``admission_mode`` is the Kubernetes admission posture (REQ-POSTURE-005):
    ``monitor`` (the default — evaluate, record, always allow), ``enforce`` (deny on
    policy violations inside the staged namespace list), or ``off`` (route refuses).
    ``admission_enforce_namespaces`` is the staged rollout: enforce applies only to the
    namespaces named here (``*`` means every namespace and must be written on purpose);
    an empty list in enforce mode denies nothing and says so in the audit line.
    ``admission_deny_on`` is the enforce threshold on the severity ladder.

    ``cmdb_max_rows`` bounds one criticality import (a CMDB export can be huge; the index
    is a small lookup, not a mirror).
    """

    default_max_runs_per_day: int = 24
    default_max_requests: int = 5000
    admission_mode: str = "monitor"
    admission_enforce_namespaces: tuple[str, ...] = ()
    admission_deny_on: str = "high"
    cmdb_max_rows: int = 10_000
    cmdb_max_bytes: int = 4_194_304

    #: The admission modes; ``off`` keeps the route registered but refusing (so a cluster
    #: webhook pointing at a deployment with the feature disabled fails loudly, not
    #: silently allows).
    ADMISSION_MODES: ClassVar[tuple[str, ...]] = ("monitor", "enforce", "off")

    def __post_init__(self) -> None:
        if self.default_max_runs_per_day < 1:
            msg = "posture.default_max_runs_per_day must be >= 1"
            raise ConfigurationError(msg)
        if self.default_max_requests < 1:
            msg = "posture.default_max_requests must be >= 1"
            raise ConfigurationError(msg)
        if self.admission_mode not in self.ADMISSION_MODES:
            msg = (
                f"posture.admission_mode must be one of {', '.join(self.ADMISSION_MODES)}, "
                f"got {self.admission_mode!r}"
            )
            raise ConfigurationError(msg)
        if self.admission_deny_on not in SEVERITY_LEVELS:
            msg = f"posture.admission_deny_on must be one of {SEVERITY_LEVELS}"
            raise ConfigurationError(msg)
        if self.cmdb_max_rows < 1 or self.cmdb_max_bytes < 1:
            msg = "posture.cmdb_max_rows/cmdb_max_bytes must be >= 1"
            raise ConfigurationError(msg)

    @property
    def enforce_namespaces(self) -> tuple[str, ...]:
        """The staged enforce list, normalised (``*`` kept as the explicit wildcard)."""
        return tuple(name.strip() for name in self.admission_enforce_namespaces if name.strip())


@dataclass(frozen=True, slots=True)
class FixSettings:
    """Remediation as code (S27, area FIX).

    ``grants`` is the operator's authorization file and the single most important setting
    here: **unset means no repository is authorized**, so a deployment that has not written
    a grant file can only receive guidance proposals, never a diff against a repo
    (REQ-FIX-001). ``plans`` replaces the shipped fix-plan catalog the way
    ``ARACHNE_REMEDIATION_CATALOG`` replaces the remediation catalog.

    ``artifacts_dir`` is where a submitted proposal's reviewable artifacts (the patch and
    the PR body) are written; unset means the diff lives only in the database row, which is
    the default and keeps a deployment from scattering files it did not ask for.

    ``ai_authoring`` is the opt-in for REQ-FIX-006. It is off by default *and* inert without
    an injected author: no prompt stage is shipped for patch authoring, so the template
    engine authors every proposal and the parity field reads ``n/a``.
    """

    #: Fix-plan catalog override: a file or a directory of per-plan files.
    plans: str | None = None
    #: The operator's repo-grant file (``ARACHNE_FIX_GRANTS``); unset authorizes nothing.
    grants: str | None = None
    #: Where submitted proposals' patch/PR artifacts are written (``None`` = database only).
    artifacts_dir: str | None = None
    #: Opt in to a model-authored proposal for classes no plan covers (REQ-FIX-006).
    ai_authoring: bool = False
    #: The default budget for a proposal's diff when a grant does not set its own.
    max_diff_lines: int = 400
    max_files: int = 12
    #: The default bound on a repository's test run when a grant does not set its own.
    test_timeout_seconds: int = 900

    def __post_init__(self) -> None:
        if self.max_diff_lines < 1 or self.max_files < 1:
            msg = "fix.max_diff_lines/fix.max_files must be >= 1"
            raise ConfigurationError(msg)
        if self.test_timeout_seconds < 1:
            msg = "fix.test_timeout_seconds must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class SimSettings:
    """Simulation & what-if modeling (S28, area SIM).

    The knobs here bound a *pure* computation: a what-if run reads the stored estate model
    and composes attack paths over it, and nothing in this area ever contacts a target
    (REQ-SIM-001/002/003). There is deliberately no URL, host, timeout or credential setting
    for the simulation engine, because there is no request to configure — the absence is
    part of the structural guarantee.

    ``max_hypotheses`` and ``max_paths`` bound a simulation the way the S21 composer bounds
    a report section: a what-if run is an unbounded search otherwise, and an operator
    asking "what if every host were exposed?" should get a bounded, readable answer.

    ``resimulate`` is the REQ-SIM-006 opt-in: when true, the deployment subscribes the
    re-simulator to the model-update events, so a finished scan refreshes the estate model
    and appends a point to the simulation trend the posture view renders. It is off by
    default, consistent with every other capability that watches the estate continuously.
    """

    #: How many hypotheses one run may carry (``ARACHNE_SIM_MAX_HYPOTHESES``).
    max_hypotheses: int = 32
    #: How many composed paths one run may report (``ARACHNE_SIM_MAX_PATHS``).
    max_paths: int = 25
    #: The verified-hop threshold, mirroring ``analyzer.paths.DEFAULT_MIN_CONFIDENCE``.
    min_confidence: int = 55
    #: Opt in to event-driven re-simulation feeding the posture trend (REQ-SIM-006).
    resimulate: bool = False
    #: How many trend points a re-simulation read returns (``ARACHNE_SIM_TREND_LIMIT``).
    trend_limit: int = 50

    def __post_init__(self) -> None:
        if self.max_hypotheses < 1:
            msg = "sim.max_hypotheses must be >= 1"
            raise ConfigurationError(msg)
        if self.max_paths < 1:
            msg = "sim.max_paths must be >= 1"
            raise ConfigurationError(msg)
        if not 0 <= self.min_confidence <= 100:
            msg = "sim.min_confidence must be between 0 and 100"
            raise ConfigurationError(msg)
        if self.trend_limit < 1:
            msg = "sim.trend_limit must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class FuzzSettings:
    """Bounded safe fuzzing (S30, area FUZZ) — the deployment's hard ceilings.

    Every value here is a *ceiling*, not a preference: fuzzing's P0 requirement is that the
    bounds are hard (REQ-FUZZ-001), so an operator's plan may ask for less than this and never
    for more. The three budget axes are separate because each catches a failure the others do
    not — ``max_cases`` bounds the work, ``max_requests`` bounds the target's load even when
    a case costs several packets, and ``max_seconds`` bounds wall-clock time even when a
    target answers slowly enough to make a request count meaningless.

    ``engine`` names the fuzzing engine a run uses when its plan names none. The default is
    ``grammar``: the built-in engine that mutates within a message grammar, needs no target
    instrumentation and adds no dependency (REQ-FUZZ-006). ``allow_production`` is the
    deployment-level floor under the fuzzing attestation's own ``allow_production`` flag: an
    attestation that permits production fuzzing is still refused unless the *deployment* also
    opted in, so one mis-scoped grant cannot turn a lab-only install into a production
    fuzzer. Both default to the safe value.

    The three degradation thresholds are the abort guard's defaults (REQ-FUZZ-005). They are
    deliberately conservative: a fuzzing run that stops early costs coverage, while one that
    keeps hammering a struggling service costs the service.
    """

    #: Cases (mutated messages) one target may receive (``ARACHNE_FUZZ_MAX_CASES``).
    max_cases: int = 200
    #: Requests one target may receive, counted across cases and health probes
    #: (``ARACHNE_FUZZ_MAX_REQUESTS``).
    max_requests: int = 220
    #: Wall-clock seconds one target may be fuzzed for (``ARACHNE_FUZZ_MAX_SECONDS``).
    max_seconds: float = 60.0
    #: Cases per batch, between the health probes that bracket it (``ARACHNE_FUZZ_BATCH_SIZE``).
    batch_size: int = 25
    #: The engine used when a plan names none (``ARACHNE_FUZZ_ENGINE``).
    engine: str = "grammar"
    #: The deployment's own permission for production-target fuzzing
    #: (``ARACHNE_FUZZ_ALLOW_PRODUCTION``).
    allow_production: bool = False
    #: Samples the guard needs before it will judge a target's health.
    health_min_samples: int = 3
    #: Abort when the batch's probe error rate exceeds this (``ARACHNE_FUZZ_MAX_ERROR_RATE``).
    max_error_rate: float = 0.34
    #: Abort when a probe is this many times slower than the baseline
    #: (``ARACHNE_FUZZ_MAX_LATENCY_RATIO``).
    max_latency_ratio: float = 4.0
    #: Abort when the share of timing-out probes exceeds this (``ARACHNE_FUZZ_MAX_TIMEOUT_RATE``).
    max_timeout_rate: float = 0.25
    #: Abort when the target fails this many *consecutive* health probes.
    max_consecutive_failures: int = 2

    def __post_init__(self) -> None:
        if self.max_cases < 1:
            msg = "fuzz.max_cases must be >= 1"
            raise ConfigurationError(msg)
        if self.max_requests < 1:
            msg = "fuzz.max_requests must be >= 1"
            raise ConfigurationError(msg)
        if self.max_seconds <= 0:
            msg = "fuzz.max_seconds must be > 0"
            raise ConfigurationError(msg)
        if self.batch_size < 1:
            msg = "fuzz.batch_size must be >= 1"
            raise ConfigurationError(msg)
        if self.health_min_samples < 1:
            msg = "fuzz.health_min_samples must be >= 1"
            raise ConfigurationError(msg)
        if not 0.0 <= self.max_error_rate <= 1.0:
            msg = "fuzz.max_error_rate must be within [0, 1]"
            raise ConfigurationError(msg)
        if self.max_latency_ratio < 1.0:
            msg = "fuzz.max_latency_ratio must be >= 1"
            raise ConfigurationError(msg)
        if not 0.0 <= self.max_timeout_rate <= 1.0:
            msg = "fuzz.max_timeout_rate must be within [0, 1]"
            raise ConfigurationError(msg)
        if self.max_consecutive_failures < 1:
            msg = "fuzz.max_consecutive_failures must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class PurpleSettings:
    """Purple-team detection validation (S24, area VALID).

    ``alerts_url`` is the SIEM's *pull* endpoint: when set, a campaign run collects
    defender alerts from it through the shared scoped HTTP client (the one egress path),
    pinned to that host. ``alerts_token`` is the bearer credential for it and is read from
    the environment only (F-08-01) — never written into a scan request, a report or a log.
    Both unset (the default) means pull ingest is off and alerts arrive by webhook or file.

    ``max_actions`` bounds how many proof actions one purple run replays and
    ``max_alerts`` bounds one ingest, because both are cost and blast-radius guardrails:
    a purple run is a *test*, and a test that runs an unbounded number of live proof
    actions is neither coordinated nor rate-limited (REQ-VALID-003). ``nonce_bytes`` is
    the entropy of a generated run nonce (the run's visible tag). ``map_path`` overrides
    the shipped ATT&CK replay catalogue (which actions are replayable and what telemetry
    each emits) — an operator choice, checked against the registry at plan time.
    """

    alerts_url: str | None = None
    alerts_token: SecretStr | None = None
    max_actions: int = 12
    max_alerts: int = 1000
    nonce_bytes: int = 12
    map_path: str | None = None

    def __post_init__(self) -> None:
        if self.max_actions < 1:
            msg = "purple.max_actions must be >= 1"
            raise ConfigurationError(msg)
        if self.max_alerts < 1:
            msg = "purple.max_alerts must be >= 1"
            raise ConfigurationError(msg)
        if not 8 <= self.nonce_bytes <= 32:
            msg = "purple.nonce_bytes must be between 8 and 32"
            raise ConfigurationError(msg)
        if self.alerts_url is not None and not self.alerts_url.startswith(("http://", "https://")):
            msg = "purple.alerts_url must be an http(s) URL"
            raise ConfigurationError(msg)

    @property
    def pull_enabled(self) -> bool:
        """True when a campaign run should collect alerts from the configured SIEM."""
        return bool(self.alerts_url)


@dataclass(frozen=True, slots=True)
class SecretsSettings:
    """The operator-side secrets manifest (F-08-04, S7).

    ``manifest_path`` is where the encrypted ledger is written; unset (the default) means
    no manifest at all. ``manifest_key`` is the passphrase and is **required** when a path
    is set: the writer refuses to produce an unencrypted ledger. Both come from the
    environment only (F-08-01).
    """

    manifest_path: str | None = None
    manifest_key: SecretStr | None = None
    max_records: int = 500

    def __post_init__(self) -> None:
        if self.max_records < 1:
            msg = "secrets.max_records must be >= 1"
            raise ConfigurationError(msg)

    @property
    def enabled(self) -> bool:
        return bool(self.manifest_path)


@dataclass(frozen=True, slots=True)
class VaultSettings:
    """The credential vault (S19, area CREDS: REQ-CREDS-002).

    ``path`` is the encrypted sidecar file; unset (the default) means credentialed scanning
    is simply unavailable and every credential-dependent check reports itself skipped.
    ``key`` is the passphrase and is **required** when a path is set — the vault refuses to
    store or read credentials without it. Both come from the environment only (F-08-01), and
    the vault is node-local by design, so credential material never travels a control plane
    (ADR-240.2).
    """

    path: str | None = None
    key: SecretStr | None = None
    max_entries: int = 256

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            msg = "vault.max_entries must be >= 1"
            raise ConfigurationError(msg)

    @property
    def enabled(self) -> bool:
        return bool(self.path)


@dataclass(frozen=True, slots=True)
class PlannerSettings:
    """Assumptions the dry-run planner uses to estimate request counts (F-01-10).

    The planner must never resolve a name or contact a host, so anything it cannot know
    offline is an explicit, configurable assumption printed with the plan rather than a
    hidden guess. An empty deployment ``scope`` means "no extra restriction"; a non-empty
    one is an additional allowlist every target definition must fit inside (F-01-02).
    """

    assumed_subdomains_per_domain: int = 0
    max_hosts_per_network: int = 256

    def __post_init__(self) -> None:
        if self.assumed_subdomains_per_domain < 0:
            msg = "assumed_subdomains_per_domain must be >= 0"
            raise ConfigurationError(msg)
        if self.max_hosts_per_network < 1:
            msg = "max_hosts_per_network must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    """The heuristic engine's managed data and its analysis knobs (S5, F-05-*, F-09-04).

    Every ``*_path`` is an override for a file the package ships: rules, correlation rules,
    narrative templates, the remediation catalog, the CVSS vector table, the FP filter corpus
    and extra signature directories. They exist because these are **data an operator tunes**
    — a rule corpus is not a release artefact in the same sense as code — while the shipped
    defaults keep a default scan working with nothing configured.

    ``criticality`` is the OWASP impact input : ``pattern=level`` pairs,
    where a pattern is an asset value or a suffix such as ``*.example.com`` and a level is
    ``critical|high|normal|low|internal``. Everything unmatched is ``normal``.
    """

    rules: str | None = None
    correlation_rules: str | None = None
    narrative_templates: str | None = None
    remediation_catalog: str | None = None
    scoring_vectors: str | None = None
    fp_filters: str | None = None
    #: Per-check confidence thresholds (F-05-07); overrides the shipped table.
    fp_thresholds: str | None = None
    signature_dirs: tuple[str, ...] = ()
    #: Re-request ``verifiable`` candidates once before accepting them (F-05-07).
    verify: bool = True
    #: A high/critical finding must have been re-requested before it is accepted as
    #: confirmed; one that could not be re-verified is flagged and its confidence reduced
    #: (F-05-07, "verification re-request before accepting high-severity findings").
    verify_high_severity: bool = True
    max_verifications: int = 25
    #: Below this confidence a finding is a low-confidence observation .
    min_confidence: int = 55
    correlation_enabled: bool = True
    fp_tuner_enabled: bool = True
    drop_on_contradiction: bool = True
    drop_on_placeholder: bool = True
    criticality: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.min_confidence <= 100:
            msg = f"analysis.min_confidence must be within [0, 100], got {self.min_confidence}"
            raise ConfigurationError(msg)
        if self.max_verifications < 0:
            msg = "analysis.max_verifications must be >= 0"
            raise ConfigurationError(msg)
        for entry in self.criticality:
            self.criticality_level(entry)  # validates the shape

    def criticality_level(self, entry: str) -> str:
        """Validate and return the level of one ``pattern=level`` entry."""
        _, separator, level = entry.partition("=")
        level = level.strip().lower()
        if not separator or not entry.partition("=")[0].strip() or not level:
            msg = f"asset criticality entry {entry!r} is not 'pattern=level'"
            raise ConfigurationError(msg)
        if level not in {"critical", "high", "normal", "low", "internal", "medium"}:
            msg = (
                f"asset criticality level {level!r} is not one of "
                "critical|high|normal|medium|low|internal"
            )
            raise ConfigurationError(msg)
        return level

    def criticality_map(self) -> dict[str, str]:
        """``{pattern: level}`` — the input the analyzer's ScanContext takes."""
        out: dict[str, str] = {}
        for entry in self.criticality:
            pattern, _, _level = entry.partition("=")
            out[pattern.strip().lower()] = self.criticality_level(entry)
        return out


@dataclass(frozen=True, slots=True)
class AiSettings:
    """The AI integration layer's deployment knobs (S9, /§8).

    The *provider table* is not here: the registry puts it in a file
    (``ARACHNE_AI_CONFIG``, see ``arachne.ai.config``), because a deployment configures several
    providers with different models and endpoints. What lives here is the environment's share —
    the one default provider override and the policy knobs — so a local demo needs no file at
    all::

        ARACHNE_AI_PROVIDER=ollama
        ARACHNE_AI_BASE_URL=http://localhost:11434
        ARACHNE_AI_MODEL=qwen3:32b
        arachne scan --target lab.yaml --engine ai

    ``privacy`` defaults to ``redact`` and ``local-only`` is enforced in
    ``ai.privacy`` before any call. ``budget_tokens``/``budget_cost_usd`` are ``None`` until an
    operator sets them, so the file's ``budget`` block wins when present (F-04-07).

    ``authoritative_checks`` is the escape hatch from the parity anchor: an empty list means
    every check keeps its deterministic verdict . ``prompts``/``pricing`` are
    managed-data overrides (F-09-04) and ``cache_dir`` makes the analysis cache durable.
    """

    config_path: str | None = None
    #: The mode the AI configuration declares (``ai``/``heuristic``/``hybrid``). A scan's own
    #: ``options.engine`` still decides what actually runs; this is the deployment default.
    #: ``None`` means "not set in the environment", which is what lets a config *file* choose
    #: (an env default would otherwise silently override the file — S9).
    engine: str | None = None
    default_provider: str | None = None
    privacy: str | None = None
    budget_tokens: int | None = None
    budget_cost_usd: float | None = None
    stages: tuple[str, ...] = ()
    retries: int | None = None
    correlate_threshold: int | None = None
    authoritative_checks: tuple[str, ...] = ()
    prompts: str | None = None
    pricing: str | None = None
    cache_dir: str | None = None

    def __post_init__(self) -> None:
        if self.engine is not None and self.engine not in {"ai", "heuristic", "hybrid"}:
            msg = f"ai.engine must be ai, heuristic or hybrid, got {self.engine!r}"
            raise ConfigurationError(msg)
        if self.privacy is not None and self.privacy not in {"local-only", "redact", "default"}:
            msg = f"ai.privacy must be local-only, redact or default, got {self.privacy!r}"
            raise ConfigurationError(msg)
        if self.budget_tokens is not None and self.budget_tokens < 0:
            msg = "ai.budget_tokens must be >= 0 (0 disables the token gate)"
            raise ConfigurationError(msg)
        if self.budget_cost_usd is not None and self.budget_cost_usd < 0:
            msg = "ai.budget_cost_usd must be >= 0 (0 disables the cost gate)"
            raise ConfigurationError(msg)
        if self.retries is not None and not 1 <= self.retries <= 10:
            msg = "ai.retries must be within [1, 10]"
            raise ConfigurationError(msg)
        if self.correlate_threshold is not None and self.correlate_threshold < 2:
            msg = "ai.correlate_threshold must be >= 2"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class ReportSettings:
    """Report-engine knobs (F-06-*).

    ``min_confidence`` is the threshold below which a finding is a *low-confidence
    observation* rather than a confirmed finding . It defaults to the
    spec's 55 and is deliberately separate from the analyzer's own ``min_confidence``: the
    analyzer decides what to call a finding, the report decides what to publish as one.

    ``evidence_body_limit`` is the §5 body truncation (default 8 KB). The capture limit is
    larger because a detector may need more; a report carries a readable excerpt plus the
    hash of the full capture.

    ``owasp_map`` and ``summary_templates`` are managed-data overrides (F-09-04) for the
    CWE→OWASP category map and the executive-summary corpus.
    """

    min_confidence: int = 55
    evidence_body_limit: int = 8192
    #: Keep low-confidence observations in the report . Turning this
    #: off omits the section but not the count in the executive summary.
    include_low_confidence: bool = True
    owasp_map: str | None = None
    summary_templates: str | None = None
    #: White-label branding document (YAML/JSON) for MSSP reports (S14). ``None`` renders
    #: the neutral ARACHNE presentation.
    branding_path: str | None = None
    #: White-label/MSSP mode (S26, REQ-ECOS-006): when on, every report drops ARACHNE's own
    #: attribution and names the vendor instead. A *deployment* choice — a tenant cannot
    #: switch it back on.
    white_label: bool = False
    #: The language reports render their labels in (S26, REQ-ECOS-005): a BCP-47 primary
    #: subtag such as ``en`` or ``fr``. ``""`` defers to the i18n module's own default
    #: (``ARACHNE_LOCALE``, else ``en``), which keeps a deployment that sets nothing on the
    #: pre-S26 path. A per-report ``--locale`` / ``?locale=`` wins over this.
    locale: str = ""
    #: Compliance frameworks every report maps its findings onto (S22, REQ-TRUST-001),
    #: e.g. ``("cis", "pci-dss")``. Empty (the default) renders no framework section —
    #: a pre-S22 report is byte-identical — and an unknown name fails the report loudly.
    compliance_frameworks: tuple[str, ...] = ()
    #: Directory of managed-data compliance maps (``<framework>.yaml``, ADR-04) that
    #: override the bundled ones. ``None`` uses the shipped ``templates/compliance/``.
    compliance_map_dir: str | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.min_confidence <= 100:
            msg = f"report.min_confidence must be within [0, 100], got {self.min_confidence}"
            raise ConfigurationError(msg)
        if self.evidence_body_limit < 0:
            msg = "report.evidence_body_limit must be >= 0"
            raise ConfigurationError(msg)


#: Roles the REST API knows (F-07-02). Ordered least → most privileged.
API_ROLES: Final[tuple[str, ...]] = ("viewer", "scanner", "admin")

#: Severity vocabulary, least → most severe. Kept local so ``core.config`` does not import
#: the report layer (which imports this module).
SEVERITY_LEVELS: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """The REST API and web UI surface (F-07-02/03, F-08-02, S12).

    The API is part of the *interface* layer, never a dependency of the
    scanner: the CLI and the orchestrator run with no API installed or configured.

    ``keys``
        The API keys, each ``label:role:secret`` (roles from :data:`API_ROLES`). They come
        from ``ARACHNE_API_KEYS`` (``;``-separated) or ``ARACHNE_API_KEYS_FILE`` (one per
        line); the secret is hashed at startup and never stored in the clear. An empty list
        means the API refuses every request (deny by default) rather than running open.
    ``require_tls``
        **TLS by default** (F-08-02). :func:`arachne.api.server.serve` refuses to bind a
        non-loopback address without a certificate unless this is turned off explicitly for
        a loopback-only development deployment.
    ``rate_limit_per_minute``/``rate_limit_burst``
        A per-identity token bucket in front of every endpoint (F-08-02). Identity is the
        presented API key when there is one, otherwise the client address, so an
        unauthenticated flood is bounded too.
    ``base_url``
        Public base URL used to build the report link a webhook card carries.
    """

    host: str = "127.0.0.1"
    port: int = 8080
    keys: tuple[str, ...] = ()
    rate_limit_per_minute: int = 120
    rate_limit_burst: int = 30
    require_tls: bool = True
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    base_url: str | None = None
    docs_enabled: bool = True
    cors_origins: tuple[str, ...] = ()
    #: Host header allowlist (a cheap defense against DNS-rebinding against the operator's
    #: browser). Empty means "accept the configured host and loopback names".
    trusted_hosts: tuple[str, ...] = ()
    #: uvicorn worker processes (S22, REQ-OPS-005). ``1`` (the default) is the single
    #: process the API has always been; more runs one worker per process sharing the
    #: ASGI app (a K8s deployment usually scales pods instead — the Helm chart does).
    #: Counters stay per worker; gauges are database-derived (S20 decision 7).
    workers: int = 1
    #: Seconds a UI session cookie stays valid. The cookie carries the API key, so this is
    #: a convenience bound, not a token lifetime.
    session_max_age_s: int = 12 * 3600

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            msg = f"api.port must be within [1, 65535], got {self.port}"
            raise ConfigurationError(msg)
        if self.workers < 1:
            msg = f"api.workers must be >= 1, got {self.workers}"
            raise ConfigurationError(msg)
        if self.rate_limit_per_minute < 1 or self.rate_limit_burst < 1:
            msg = "api rate limits must be >= 1"
            raise ConfigurationError(msg)
        if self.session_max_age_s < 1:
            msg = "api.session_max_age_s must be >= 1"
            raise ConfigurationError(msg)
        if bool(self.tls_certfile) != bool(self.tls_keyfile):
            msg = "api.tls_certfile and api.tls_keyfile must be set together"
            raise ConfigurationError(msg)
        for entry in self.keys:
            _validate_api_key_entry(entry)

    @property
    def tls_configured(self) -> bool:
        return bool(self.tls_certfile and self.tls_keyfile)


def _validate_api_key_entry(entry: str) -> None:
    """``label:role:secret[:project]`` — cheap structural check, so a typo fails at startup.

    The optional fourth field binds the key to one tenant (F-07-06): a key issued to an
    MSSP customer can only read and run that customer's project, while a three-field key is
    deployment-wide. The secret is the third field, so a secret containing ``:`` still works
    as long as no project is declared.
    """
    parts = entry.split(":", 3)
    if len(parts) not in (3, 4) or not all(part.strip() for part in parts):
        msg = (
            f"API key entry {entry!r} must be 'label:role:secret' or "
            f"'label:role:secret:project' with non-empty parts "
            f"(roles: {', '.join(API_ROLES)})"
        )
        raise ConfigurationError(msg)
    label, role, _secret, *_project = parts
    if role.strip().lower() not in API_ROLES:
        msg = f"API key {label!r} has unknown role {role!r}; roles are {', '.join(API_ROLES)}"
        raise ConfigurationError(msg)


#: JWT signing algorithms the OIDC verifier accepts (S17, REQ-IDAM-001).
SSO_ALGORITHMS: Final[tuple[str, ...]] = ("RS256", "RS384", "RS512", "HS256", "HS384", "HS512")


@dataclass(frozen=True, slots=True)
class SsoSettings:
    """Enterprise single sign-on (S17, area IDAM: REQ-IDAM-001/002).

    OIDC authorization-code login **alongside** API keys, not instead of them: the API
    stays closed unless *something* (a key, a service account, or an IdP) is configured,
    so a deployment that sets none of these still refuses every request — the same
    deny-by-default posture the scanner uses for scope.

    ``enabled``
        The explicit opt-in (``ARACHNE_SSO_ENABLED``). An IdP is configured only when this
        is true *and* ``issuer`` and ``client_id`` are set; otherwise the SSO surface is
        absent and every OIDC route refuses.
    ``issuer``/``client_id``/``client_secret``
        The provider coordinates. ``issuer`` is also the ``iss`` the ID token must carry.
    ``authorization_endpoint``/``token_endpoint``/``jwks_url``/``userinfo_endpoint``
        Optional explicit endpoints; when omitted they are discovered from
        ``{issuer}/.well-known/openid-configuration`` (the standard OIDC discovery
        document) on first use.
    ``group_roles``
        The group→role binding (REQ-IDAM-002): ``group:role`` entries that map an IdP group
        claim value onto one of the three existing roles (viewer/scanner/admin). A user
        whose groups match none of these, with no ``default_role``, is refused — the
        deny-by-default half of the requirement.
    ``default_role``
        The role an authenticated user with no matching group receives. ``None`` (the
        default) means *no* role: a valid login that maps to nothing is denied, and the
        refusal is audited.
    """

    enabled: bool = False
    issuer: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    redirect_url: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    role_claim: str = "groups"
    group_roles: tuple[str, ...] = ()
    default_role: str | None = None
    algorithms: tuple[str, ...] = ("RS256", "HS256")
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_url: str | None = None
    session_max_age_s: int = 8 * 3600
    flow_ttl_s: int = 600
    leeway_s: int = 60
    #: Host the IdP endpoints must resolve to for the scoped HTTP client to reach them; the
    #: issuer's host is used automatically, and this adds an explicit override (an internal
    #: IdP behind a different name).
    allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.session_max_age_s < 1:
            msg = "sso.session_max_age_s must be >= 1"
            raise ConfigurationError(msg)
        if self.flow_ttl_s < 30:
            msg = "sso.flow_ttl_s must be >= 30 seconds"
            raise ConfigurationError(msg)
        if self.leeway_s < 0:
            msg = "sso.leeway_s must be >= 0"
            raise ConfigurationError(msg)
        unknown = [alg for alg in self.algorithms if alg not in SSO_ALGORITHMS]
        if unknown:
            msg = (
                f"sso.algorithms contains unsupported algorithms {unknown}; "
                f"supported: {', '.join(SSO_ALGORITHMS)}"
            )
            raise ConfigurationError(msg)
        if "openid" not in self.scopes:
            msg = "sso.scopes must include 'openid' (this is an OIDC login)"
            raise ConfigurationError(msg)
        if self.default_role is not None and self.default_role not in API_ROLES:
            msg = (
                f"sso.default_role must be one of {', '.join(API_ROLES)}, got {self.default_role!r}"
            )
            raise ConfigurationError(msg)
        for entry in self.group_roles:
            group, _, role = entry.partition(":")
            if not group.strip() or role.strip().lower() not in API_ROLES:
                msg = (
                    f"sso.group_roles entry {entry!r} must be 'group:role' with role one of "
                    f"{', '.join(API_ROLES)}"
                )
                raise ConfigurationError(msg)
        if self.redirect_url is not None and not self.redirect_url.startswith(
            ("http://", "https://")
        ):
            msg = "sso.redirect_url must be an absolute http(s) URL"
            raise ConfigurationError(msg)
        if self.client_secret is not None and not self.client_secret.get_secret_value().strip():
            msg = "sso.client_secret must not be blank when set"
            raise ConfigurationError(msg)

    @property
    def configured(self) -> bool:
        """Whether an IdP is configured — the single check the SSO surface consults.

        Deny-by-default (REQ-IDAM-002): with no issuer/client id (or ``enabled`` false) the
        OIDC routes refuse and no session can be minted, so the API is exactly as closed as
        it was before SSO existed.
        """
        return bool(self.enabled and self.issuer and self.client_id)

    @property
    def client_secret_value(self) -> str | None:
        return self.client_secret.get_secret_value() if self.client_secret else None

    def role_for(self, groups: tuple[str, ...] | list[str]) -> str | None:
        """Map IdP groups onto a role, or ``None`` for a deny (REQ-IDAM-002).

        The highest-ranked matching role wins, so a user in both ``arachne-viewers`` and
        ``arachne-admins`` is an admin; a user matching nothing falls back to
        ``default_role`` — and when that is ``None`` the login is refused.
        """
        granted: str | None = None
        present = {group.strip() for group in groups if group.strip()}
        for entry in self.group_roles:
            group, _, role = entry.partition(":")
            candidate = role.strip().lower()
            if group.strip() in present and (
                granted is None or API_ROLES.index(candidate) > API_ROLES.index(granted)
            ):
                granted = candidate
        if granted is not None:
            return granted
        return self.default_role


@dataclass(frozen=True, slots=True)
class WebhookSettings:
    """Outbound scan-completion integrations (F-06-06, S12).

    Every endpoint is optional and every secret is a :class:`~pydantic.SecretStr`, so a
    deployment that configures nothing sends nothing (and the default scan stays offline).

    ``min_severity``
        The severity at or above which the summary card reports a scan as actionable, and
        the floor for the per-finding Jira issues. ```` asks for "Jira issue
        per high/critical finding", which is ``min_severity = "high"``.
    ``max_findings``
        A hard cap on how many issues one notification creates, so a scan that finds 300
        criticals cannot open 300 tickets in one call.
    ``templates_dir``
        Managed-data override (ADR-04, F-09-04) for the Slack/Teams/Jira/DefectDojo payload
        templates.
    """

    enabled: bool = False
    slack_url: SecretStr | None = None
    teams_url: SecretStr | None = None
    jira_url: SecretStr | None = None
    jira_project: str | None = None
    jira_user: SecretStr | None = None
    jira_token: SecretStr | None = None
    defectdojo_url: SecretStr | None = None
    defectdojo_token: SecretStr | None = None
    #: ServiceNow (S22, REQ-OPS-002): the instance base URL (``https://<instance>``
    #: without a path — the incidents endpoint is appended) and a service account. All
    #: three parts are required together; a URL without credentials is refused at
    #: construction rather than failing mid-scan.
    servicenow_url: SecretStr | None = None
    servicenow_user: SecretStr | None = None
    servicenow_password: SecretStr | None = None
    #: SIEM export (S22, REQ-OPS-002): an HTTP collector that receives the scan's
    #: findings and audit events as newline-delimited JSON. The token is optional (an
    #: internal collector may have none) and is sent as a bearer header only when set.
    siem_url: SecretStr | None = None
    siem_token: SecretStr | None = None
    min_severity: str = "high"
    max_findings: int = 25
    timeout_s: float = 10.0
    templates_dir: str | None = None

    def __post_init__(self) -> None:
        if self.min_severity not in SEVERITY_LEVELS:
            msg = (
                f"webhooks.min_severity must be one of {', '.join(SEVERITY_LEVELS)}, "
                f"got {self.min_severity!r}"
            )
            raise ConfigurationError(msg)
        if self.max_findings < 1:
            msg = "webhooks.max_findings must be >= 1"
            raise ConfigurationError(msg)
        if self.timeout_s <= 0:
            msg = "webhooks.timeout_s must be > 0"
            raise ConfigurationError(msg)
        if self.servicenow_url is not None and (
            self.servicenow_user is None or self.servicenow_password is None
        ):
            msg = (
                "webhooks.servicenow_url requires servicenow_user and servicenow_password: "
                "a ServiceNow endpoint is never written anonymously"
            )
            raise ConfigurationError(msg)

    # ------------------------------------------------------------------ inspection
    def configured_targets(self) -> tuple[str, ...]:
        """Names of the integrations that have a URL (``slack``, ``teams``, ``jira``, ...)."""
        names: list[str] = []
        if self.slack_url is not None:
            names.append("slack")
        if self.teams_url is not None:
            names.append("teams")
        if self.jira_url is not None and self.jira_project:
            names.append("jira")
        if self.servicenow_url is not None:
            names.append("servicenow")
        if self.defectdojo_url is not None:
            names.append("defectdojo")
        if self.siem_url is not None:
            names.append("siem")
        return tuple(names)

    def endpoint_urls(self) -> tuple[str, ...]:
        """Every configured URL, for the egress scope (which hosts a webhook may reach)."""
        urls: list[str] = []
        for value in (
            self.slack_url,
            self.teams_url,
            self.jira_url,
            self.defectdojo_url,
            self.servicenow_url,
            self.siem_url,
        ):
            if value is not None:
                urls.append(value.get_secret_value())
        return tuple(urls)


@dataclass(frozen=True, slots=True)
class FeedsSettings:
    """Ingested CVE/EPSS feed artefacts (F-09-03, S14).

    ``dir`` is where normalised feed files are written; ``None`` means "next to the SQLite
    database" (or ``./feeds`` for a server database). ``max_entries`` bounds one import so a
    mistaken 5 GB file cannot fill the evidence store. Ingestion is entirely offline: an
    operator brings the file, ARACHNE validates and normalises it, and the M6 correlation
    check consumes the normalised file exactly as it would a hand-configured path.
    """

    dir: str | None = None
    max_entries: int = 50_000

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            msg = "feeds.max_entries must be >= 1"
            raise ConfigurationError(msg)


#: The feeds a sync can fetch, and the host each one is fetched from. This is the *deployment
#: allowlist* of the sync client, exactly as :data:`OSINT_PROVIDER_HOSTS` is for the provider
#: layer: the sync's scope is precisely these hosts, so "fetch the CISA KEV catalogue" is as
#: explicit a declaration as "scan example.com" (F-01-02, ADR-05).
INTEL_FEED_HOSTS: Final[dict[str, str]] = {
    "nvd": "services.nvd.nist.gov",
    "kev": "www.cisa.gov",
    "epss": "api.first.org",
}

#: Sources a sync fetches when none is named (``arachne intel sync``).
DEFAULT_INTEL_FEED_SOURCES: Final[tuple[str, ...]] = ("nvd", "kev", "epss")

#: Verification modes (REQ-INTEL-002). There is deliberately no "off": a feed payload whose
#: integrity cannot be established is refused, never imported (ADR-230.2).
FEED_VERIFICATION_MODES: Final[tuple[str, ...]] = ("checksum", "signature")

#: Hours after which a kind of feed is reported *stale* by the report's freshness section
#: (REQ-INTEL-001). Configurable per deployment (``ARACHNE_INTEL_FRESHNESS_TTL``).
DEFAULT_FRESHNESS_TTL_HOURS: Final[tuple[tuple[str, float], ...]] = (
    ("nvd", 168.0),
    ("kev", 168.0),
    ("epss", 48.0),
    ("cve", 720.0),
    ("nvd-baseline", 720.0),
)


@dataclass(frozen=True, slots=True)
class IntelSettings:
    """Live threat intelligence: feed sync, verification and freshness (S18, area INTEL).

    ``enabled`` is the master switch. With it off — the default — no feed is fetched and the
    scanner keeps the offline posture of the S14 workflow (an operator imports a file, and
    nothing leaves the process): the sync service is simply not constructed.

    ``verify`` must be ``checksum`` or ``signature`` (REQ-INTEL-002). The expected digests
    come from ``checksums`` (inline ``source=sha256:...``) or ``checksums_file`` (a JSON/YAML
    manifest); signing mode additionally needs ``public_key`` (a PEM file with the RSA key the
    feed publisher or the deployment's mirror signs with). A payload that does not verify is
    refused **before** it reaches the feed store, so a tampered mirror cannot poison the CVE
    correlation.

    ``fixtures_dir`` replays recorded responses instead of contacting anything, which is how
    the sync is tested and how an offline demonstration runs end to end — including
    verification, because the fixtures carry their own pinned digests.
    """

    enabled: bool = False
    sources: tuple[str, ...] = DEFAULT_INTEL_FEED_SOURCES
    verify: str = "checksum"
    #: ``(source, digest)`` pins; the digest is ``sha256:<hex>`` (or a bare hex digest).
    checksums: tuple[tuple[str, str], ...] = ()
    checksums_file: str | None = None
    #: PEM public key for ``verify = signature`` (path).
    public_key: str | None = None
    #: Recorded responses to replay instead of fetching (tests, air-gapped demos).
    fixtures_dir: str | None = None
    #: Bounds so a hostile or broken mirror cannot exhaust memory or disk.
    max_bytes: int = 64 * 1024 * 1024
    max_pages: int = 20
    #: Politeness delay between paginated requests (NVD asks for <= 1 request per 6 s
    #: without a key, 0.6 s with one; the default is the polite one).
    request_delay_s: float = 6.0
    nvd_api_key: SecretStr | None = None
    #: Hours per feed kind after which the report marks the feed stale.
    freshness_ttl: tuple[tuple[str, float], ...] = DEFAULT_FRESHNESS_TTL_HOURS
    #: The product map ``arachne intel build-index`` generates from (``None`` uses the packaged
    #: ``templates/m2/cve-index-products.yaml``); its output path is
    #: ``NetSettings.cve_index_baseline`` — the same file the loader reads.
    index_products: str | None = None
    index_max_entries: int = 500

    def __post_init__(self) -> None:
        unknown = sorted(set(self.sources) - set(INTEL_FEED_HOSTS))
        if unknown:
            msg = (
                f"unknown intel feed source(s) {unknown}; "
                f"known sources are {sorted(INTEL_FEED_HOSTS)}"
            )
            raise ConfigurationError(msg)
        if self.verify not in FEED_VERIFICATION_MODES:
            msg = (
                f"intel.verify must be one of {', '.join(FEED_VERIFICATION_MODES)}, "
                f"got {self.verify!r}"
            )
            raise ConfigurationError(msg)
        if self.verify == "signature" and not self.public_key:
            msg = "intel.verify=signature needs intel.public_key (a PEM public key)"
            raise ConfigurationError(msg)
        if self.max_bytes < 1:
            msg = "intel.max_bytes must be >= 1"
            raise ConfigurationError(msg)
        if self.max_pages < 1:
            msg = "intel.max_pages must be >= 1"
            raise ConfigurationError(msg)
        if self.index_max_entries < 1:
            msg = "intel.index_max_entries must be >= 1"
            raise ConfigurationError(msg)
        if any(hours <= 0 for _, hours in self.freshness_ttl):
            msg = "intel.freshness_ttl values must be > 0"
            raise ConfigurationError(msg)

    @property
    def is_fixture_mode(self) -> bool:
        """True when the sync replays recorded responses instead of fetching."""
        return bool(self.fixtures_dir)

    def source_hosts(self) -> tuple[str, ...]:
        """The hosts the sync client may contact: the enabled sources' hosts."""
        return tuple(
            dict.fromkeys(
                INTEL_FEED_HOSTS[source] for source in self.sources if INTEL_FEED_HOSTS.get(source)
            )
        )

    def ttl_hours(self, kind: str) -> float:
        """Hours after which ``kind`` is stale (0 when the kind has no configured TTL)."""
        return dict(self.freshness_ttl).get(kind.strip().lower(), 0.0)

    def checksum_for(self, source: str) -> str | None:
        """The pinned digest for ``source``, if one is configured in this deployment."""
        return dict(self.checksums).get(source.strip().lower()) or None


@dataclass(frozen=True, slots=True)
class DistributedSettings:
    """Distributed scan execution (S16, area SCALE).

    ``enabled`` switches the deployment from single-process scan ownership to the
    Postgres work queue (REQ-SCALE-001): producers (the API and the scheduler) enqueue
    admitted scans instead of running them, and ``arachne agent`` workers lease and
    execute them. The default is off — a single-node deployment keeps the in-process
    runner, and no new server dependency is introduced (Postgres is the only planned
    one, and only for deployments that opt in).

    ``agent_name``/``concurrency``/``lease_ttl_s``/``heartbeat_interval_s``/
    ``poll_interval_s`` are the defaults an ``arachne agent`` runs with: one scan
    leased at a time by default (``concurrency = 1`` is the per-agent cap,
    REQ-SCALE-002), a lease that expires after ``lease_ttl_s`` without a heartbeat
    becomes re-leasable (REQ-SCALE-003), and ``api_url`` points a remote agent at its
    deployment (omitted: the agent is in-process with the store).

    ``mode`` (S19, REQ-CREDS-003) is ``external`` or ``internal``. An internal agent runs
    inside the target network: it holds its own credential vault and its own deployment
    scope, and it resolves credential handles locally *after* leasing. The mode changes no
    gate — every gate is re-run on the executing node either way — it changes where a
    credential may come from, which is what keeps credential material off the control plane.
    """

    enabled: bool = False
    agent_name: str | None = None
    concurrency: int = 1
    lease_ttl_s: int = 300
    heartbeat_interval_s: float = 15.0
    poll_interval_s: float = 1.0
    api_url: str | None = None
    mode: str = "external"

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            msg = "distributed.concurrency must be >= 1"
            raise ConfigurationError(msg)
        if self.lease_ttl_s < 1:
            msg = "distributed.lease_ttl_s must be >= 1"
            raise ConfigurationError(msg)
        if self.heartbeat_interval_s <= 0 or self.poll_interval_s <= 0:
            msg = "distributed heartbeat/poll intervals must be > 0"
            raise ConfigurationError(msg)
        if self.mode not in {"external", "internal"}:
            msg = f"distributed.mode must be 'external' or 'internal', got {self.mode!r}"
            raise ConfigurationError(msg)

    @property
    def internal(self) -> bool:
        """True for an agent deployed inside the target network (REQ-CREDS-003)."""
        return self.mode == "internal"


@dataclass(frozen=True, slots=True)
class PluginsSettings:
    """Plugin installation policy (F-09-01, S14).

    Installing a plugin runs ``pip``, which mutates the running environment — an operator
    action, not something a remote API caller should trigger by default. ``allow_install``
    is therefore **off by default**; the CLI always works (an operator at a shell has
    already made the decision), while ``POST /plugins/install`` refuses unless a deployment
    opts in. ``marketplace`` points at a custom catalogue (``ARACHNE_MARKETPLACE``), and
    ``install_timeout_s`` bounds one pip run.
    """

    allow_install: bool = False
    marketplace: str | None = None
    install_timeout_s: float = 600.0
    #: Require a content pack to have passed the review pipeline before it is listed or
    #: installed (S26, REQ-ECOS-001). **On by default**: fail closed is the whole point, so a
    #: deployment opts *out* explicitly rather than opting in by forgetting.
    require_review: bool = True
    #: Accept an unsigned content pack (S26). Off by default: an unsigned pack is refused by
    #: the review pipeline before any gate even runs.
    allow_unsigned_packs: bool = False

    def __post_init__(self) -> None:
        if self.install_timeout_s <= 0:
            msg = "plugins.install_timeout_s must be > 0"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class RetentionSettings:
    """Deployment-wide retention defaults (S20, REQ-DATA-001).

    A retention policy is *per project* — a tenant's contract decides how long its evidence
    may live — so these values are the **fallback** a project inherits when it declares no
    policy of its own (``projects.retention_json``). ``0`` means "keep forever" for that
    category, which is how a deployment with a statutory holding period turns retention off
    for audit records without turning it off for everything.

    ``enabled`` is the master switch: with it off the pruning job plans nothing and deletes
    nothing (it still reports, so an operator can see what *would* be eligible).
    ``batch_limit`` bounds one pruning run: a first prune on a years-old database deletes in
    repeatable batches rather than one unbounded transaction.
    """

    enabled: bool = True
    findings_days: int = 365
    evidence_days: int = 180
    scans_days: int = 90
    audit_days: int = 730
    batch_limit: int = 10_000

    def __post_init__(self) -> None:
        for name in ("findings_days", "evidence_days", "scans_days", "audit_days"):
            if getattr(self, name) < 0:
                msg = f"retention.{name} must be >= 0 (0 means keep forever)"
                raise ConfigurationError(msg)
        if self.batch_limit < 1:
            msg = "retention.batch_limit must be >= 1"
            raise ConfigurationError(msg)

    @property
    def defaults(self) -> dict[str, int]:
        """The policy a project inherits when it declares none."""
        return {
            "findings_days": self.findings_days,
            "evidence_days": self.evidence_days,
            "scans_days": self.scans_days,
            "audit_days": self.audit_days,
        }


@dataclass(frozen=True, slots=True)
class EvidenceSettings:
    """Where evidence payloads are stored (S20, REQ-DATA-002/003/004).

    Evidence lives inline in the ``evidences`` table by default — that is what keeps a
    single-node deployment dependency-free, and every payload below
    ``offload_threshold_bytes`` still goes there. A larger payload is written to the
    configured **backend** instead and the row keeps a content-addressed reference to it, so
    a scan's database stays small while its evidence stays complete.

    ``backend`` is ``local`` (a directory beside the database) or ``s3`` (any
    S3-compatible object store: ``endpoint`` + ``bucket`` + static credentials). The S3 path
    is *fail-closed*: a half-configured backend is a configuration error, not a silent
    fallback to local, because evidence that lands somewhere the operator did not choose is
    worse than a scan that refuses to start.

    ``compress``/``dedup`` implement REQ-DATA-004 at the backend: payloads are zlib-compressed
    and stored under their content hash, so writing the same 64 KB response body a hundred
    times costs one object.
    """

    backend: str = "local"
    dir: str | None = None
    offload_threshold_bytes: int = 16 * 1024
    #: Characters of every string field kept inline in an offloaded payload's stub, so a
    #: report and the UI can still show the capture without fetching the object.
    preview_chars: int = 2048
    #: The deployment-wide quota a project inherits when it declares none (REQ-DATA-003).
    #: ``None`` means no quota, which is the pre-S20 behaviour.
    default_quota_bytes: int | None = None
    #: Fraction of a quota at which the deployment warns before it refuses.
    quota_warn_ratio: float = 0.8
    compress: bool = True
    compress_level: int = 6
    dedup: bool = True
    presign_ttl_s: int = 900
    s3_endpoint: str | None = None
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    s3_prefix: str = "evidence"
    s3_access_key: SecretStr | None = None
    s3_secret_key: SecretStr | None = None
    s3_session_token: SecretStr | None = None
    s3_path_style: bool = True
    s3_allow_private_ips: bool = False

    def __post_init__(self) -> None:
        if self.backend not in {"local", "s3"}:
            msg = f"evidence.backend must be 'local' or 's3', got {self.backend!r}"
            raise ConfigurationError(msg)
        if self.offload_threshold_bytes < 0:
            msg = "evidence.offload_threshold_bytes must be >= 0 (0 offloads everything)"
            raise ConfigurationError(msg)
        if not 0 <= self.compress_level <= 9:
            msg = "evidence.compress_level must be between 0 and 9"
            raise ConfigurationError(msg)
        if self.preview_chars < 0:
            msg = "evidence.preview_chars must be >= 0"
            raise ConfigurationError(msg)
        if self.default_quota_bytes is not None and self.default_quota_bytes < 0:
            msg = "evidence.default_quota_bytes must be >= 0"
            raise ConfigurationError(msg)
        if not 0.0 < self.quota_warn_ratio <= 1.0:
            msg = "evidence.quota_warn_ratio must be in (0, 1]"
            raise ConfigurationError(msg)
        if not 1 <= self.presign_ttl_s <= 7 * 24 * 3600:
            msg = "evidence.presign_ttl_s must be between 1 second and 7 days"
            raise ConfigurationError(msg)
        if self.backend == "s3":
            missing = [
                name
                for name, value in (
                    ("endpoint", self.s3_endpoint),
                    ("bucket", self.s3_bucket),
                )
                if not value
            ]
            if missing:
                msg = "evidence.backend 's3' requires " + ", ".join(
                    f"evidence.s3_{name}" for name in missing
                )
                raise ConfigurationError(msg)
            if self.s3_access_key is None or self.s3_secret_key is None:
                msg = (
                    "evidence.backend 's3' requires static credentials "
                    "(ARACHNE_EVIDENCE_S3_ACCESS_KEY / _SECRET_KEY); instance-role "
                    "credentials are not supported"
                )
                raise ConfigurationError(msg)

    @property
    def is_s3(self) -> bool:
        return self.backend == "s3"


@dataclass(frozen=True, slots=True)
class ObservabilitySettings:
    """Prometheus metrics and OpenTelemetry traces (S20, REQ-OPS-003/004).

    ``metrics_enabled`` mounts ``GET /metrics``. It is on by default because a metrics
    endpoint that has to be switched on is one that is never scraped, and it exposes
    aggregate counts and latencies only — never a target, an asset, or an evidence payload.
    ``metrics_token`` optionally requires a bearer token (the endpoint is otherwise as public
    as ``/health``, so a deployment that publishes the API must publish it behind the same
    proxy).

    Tracing is **opt-in and sampled**: ``tracing_enabled`` requires ``otlp_endpoint`` (an
    OTLP/HTTP collector base URL), and ``tracing_sample_ratio`` decides what fraction of
    scans are traced. Off by default because a trace is a second egress path and a
    performance cost — and because the scan itself never depends on it: an exporter failure
    is logged and dropped, never propagated.
    """

    metrics_enabled: bool = True
    metrics_token: SecretStr | None = None
    tracing_enabled: bool = False
    tracing_sample_ratio: float = 0.1
    otlp_endpoint: str | None = None
    otlp_timeout_s: float = 10.0
    #: A collector inside the deployment's own network is the common case (an agent
    #: deployment already runs with ``ARACHNE_ALLOW_PRIVATE_IPS``); this is the switch for it.
    otlp_allow_private_ips: bool = False
    service_name: str = "arachne"

    def __post_init__(self) -> None:
        if not 0.0 <= self.tracing_sample_ratio <= 1.0:
            msg = "observability.tracing_sample_ratio must be between 0.0 and 1.0"
            raise ConfigurationError(msg)
        if self.otlp_timeout_s <= 0:
            msg = "observability.otlp_timeout_s must be > 0"
            raise ConfigurationError(msg)
        if self.tracing_enabled and not self.otlp_endpoint:
            msg = (
                "observability.tracing_enabled requires observability.otlp_endpoint "
                "(ARACHNE_OBSERVABILITY_OTLP_ENDPOINT)"
            )
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class HypothesisSettings:
    """Agentic reasoning (S21, area AGENT) — **off by default**.

    ``mode`` is the deployment default a scan inherits when its own options say nothing:
    ``off`` (no hypothesis step, no extra request — the pre-S21 pipeline exactly), ``heuristic``
    (reason without any AI provider: the parity requirement's operating point), ``hybrid``
    (ask the model when one is configured, keep the heuristic reading) or ``ai`` (prefer the
    model; a failure still degrades to the heuristic engine rather than to silence).

    The budget is per scan and hard: a hypothesis that does not fit is recorded as *deferred*
    and never executed. ``max_proposals`` bounds how many hypotheses one reasoning pass may
    return, so a hostile input cannot turn one pass into unbounded work.

    ``control_path`` is the operator kill switch's file (REQ-AGENT-007) and ``journal_path``
    an optional JSONL mirror of every journal the step persists, for an operator who wants the
    replay material outside the database. Neither is required for the loop to work.
    """

    mode: HypothesisMode = HypothesisMode.OFF
    max_hypotheses: int = 5
    max_probes: int = 50
    max_proposals: int = 32
    #: Below this confidence (or with no successful re-verification) a finding earns a
    #: confirming hypothesis.
    verify_below: int = 70
    min_confidence: int = 30
    control_path: str | None = None
    journal_path: str | None = None

    def __post_init__(self) -> None:
        if self.max_hypotheses < 0:
            msg = "hypotheses.max_hypotheses must be >= 0"
            raise ConfigurationError(msg)
        if self.max_probes < 0:
            msg = "hypotheses.max_probes must be >= 0"
            raise ConfigurationError(msg)
        if self.max_proposals < 0:
            msg = "hypotheses.max_proposals must be >= 0"
            raise ConfigurationError(msg)
        if not 0 <= self.verify_below <= 100:
            msg = "hypotheses.verify_below must be within [0, 100]"
            raise ConfigurationError(msg)


#: The PII categories this build can detect (S25, REQ-TRUST-006). The single source of
#: truth: :mod:`arachne.core.pii` re-exports it as ``CATEGORIES`` and a policy naming a
#: category outside this set is refused at configuration time.
PII_KNOWN_CATEGORIES: Final[tuple[str, ...]] = (
    "email",
    "phone",
    "ssn",
    "credit-card",
    "iban",
    "ipv4",
)


@dataclass(frozen=True, slots=True)
class IntegritySettings:
    """Tamper-evident audit and signed evidence (S25, REQ-TRUST-005).

    ``key`` (``ARACHNE_INTEGRITY_KEY``, or a file via ``ARACHNE_INTEGRITY_KEY_FILE``) is the
    deployment key that signs the audit chain heads, the per-row signatures and the scan
    seals. It is **optional**: without it the hash chain still exists and still detects an
    edited row, but ``arachne verify-chain --require-signatures`` refuses to report "intact"
    (see ADR-300.5 for why absence is a refusal, not a pass).

    ``seal_on_finish`` writes a signed manifest when a scan completes, which is what makes a
    *deleted* finding or evidence row detectable. ``anchor_every`` auto-writes an anchor
    every N audit rows so a truncated tail (the failure a hash chain alone cannot see) is
    caught by the next verification; ``0`` disables automatic anchoring and leaves the
    explicit ``arachne integrity anchor`` act.
    """

    key: SecretStr | None = None
    key_file: str | None = None
    #: Non-secret label carried in every signature; defaults to a digest of the key.
    key_id: str | None = None
    seal_on_finish: bool = True
    require_signatures: bool = False
    anchor_every: int = 1000

    def __post_init__(self) -> None:
        if self.anchor_every < 0:
            msg = "integrity.anchor_every must be >= 0 (0 disables automatic anchoring)"
            raise ConfigurationError(msg)

    @property
    def configured(self) -> bool:
        return self.key is not None or self.key_file is not None


@dataclass(frozen=True, slots=True)
class AirgapSettings:
    """Air-gapped mode (S25, REQ-RESIL-001) — **off by default**.

    When on, the only hosts the deployment may reach are the configured scan targets plus
    whatever the operator names in ``allowed_hosts`` (an on-premises model server, an
    internal feed mirror). Everything else — feeds, OSINT providers, cloud AI, webhook
    targets, an OTLP collector, an IdP — is refused at the shared HTTP/non-HTTP egress
    path and audited. Content arrives as a signed offline pack instead.

    ``content_dir`` is where imported packs are unpacked (checks, rules, feeds, templates);
    ``require_signature`` is the fail-closed switch. It is **on** and should stay on: a pack
    with no signature, or one whose signature does not verify against the deployment's
    content key, is refused and nothing is installed (REQ-RESIL-001's hard rule). An
    operator who genuinely needs an unsigned pack must pass ``--allow-unsigned`` to
    ``arachne packs import``, which is an explicit, audited act rather than a default.
    """

    enabled: bool = False
    allowed_hosts: tuple[str, ...] = ()
    content_dir: str | None = None
    require_signature: bool = True


@dataclass(frozen=True, slots=True)
class PiiSettings:
    """PII detection and masking — the deployment default (S25, REQ-TRUST-006).

    A project's own policy (``projects.pii_json``) overrides this wholesale; these values
    are what a project without one inherits. ``enabled`` is off by default, because masking
    is irreversible and a deployment that has not decided what its evidence may contain
    should not have its payloads silently rewritten.

    ``retention_days`` is the REQ-DATA-001 hook: evidence older than that many days is
    re-masked by the retention pruner even if it was captured before the policy existed
    (``0`` means "mask at capture only, never re-mask"). ``salt`` keys the ``hash`` action,
    so two occurrences stay correlatable without the value being recoverable.
    """

    enabled: bool = False
    categories: tuple[str, ...] = PII_KNOWN_CATEGORIES
    action: str = "mask"
    salt: SecretStr | None = None
    retention_days: int = 0

    def __post_init__(self) -> None:
        if self.action not in ("mask", "hash", "drop"):
            msg = f"pii.action must be mask, hash or drop, got {self.action!r}"
            raise ConfigurationError(msg)
        if self.action == "hash" and (self.salt is None or not self.salt.get_secret_value()):
            msg = "pii.action 'hash' requires pii.salt (ARACHNE_PII_SALT)"
            raise ConfigurationError(msg)
        if self.retention_days < 0:
            msg = "pii.retention_days must be >= 0"
            raise ConfigurationError(msg)
        unknown = [name for name in self.categories if name not in PII_KNOWN_CATEGORIES]
        if unknown:
            msg = (
                f"unknown pii categor(ies): {', '.join(sorted(unknown))}; "
                f"known: {PII_KNOWN_CATEGORIES}"
            )
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class ResilienceSettings:
    """Multi-region residency and the autoscaling planner's knobs (S25, REQ-RESIL-003/004).

    ``region`` is this deployment's region. Evidence written here is stamped with it, and a
    project may pin its own region (``projects.residency_region``); a read or a write that
    crosses the boundary is refused (REQ-RESIL-004). ``None`` means the deployment does not
    declare a region — residency enforcement is then off, which is the pre-S25 behaviour.

    The autoscaling knobs describe how the queue-depth planner turns depth into a desired
    replica count. The Kubernetes objects that act on it (a KEDA ``ScaledObject`` or an HPA)
    ship in the Helm chart; these values are what the planner and the metrics it exposes are
    built from.
    """

    region: str | None = None
    queue_depth_per_replica: int = 4
    min_replicas: int = 0
    max_replicas: int = 8
    #: Leader-election lease length for the singleton work (the scheduler, the pruner) in a
    #: multi-replica deployment (REQ-RESIL-002).
    leader_ttl_s: int = 30

    def __post_init__(self) -> None:
        if self.queue_depth_per_replica < 1:
            msg = "resilience.queue_depth_per_replica must be >= 1"
            raise ConfigurationError(msg)
        if self.min_replicas < 0:
            msg = "resilience.min_replicas must be >= 0"
            raise ConfigurationError(msg)
        if self.max_replicas < self.min_replicas:
            msg = "resilience.max_replicas must be >= min_replicas"
            raise ConfigurationError(msg)
        if self.leader_ttl_s < 1:
            msg = "resilience.leader_ttl_s must be >= 1"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class Settings:
    """Top-level settings bundle."""

    database_url: str = f"sqlite:///{DEFAULT_DATABASE_FILENAME}"
    #: Path of a file holding the database password (``ARACHNE_DATABASE_PASSWORD_FILE``).
    #: When set, the password is read from the file and injected into ``database_url`` —
    #: the docker-compose secrets path (F-08-01, F-07-04).
    database_password_file: str | None = None
    http: HttpSettings = field(default_factory=HttpSettings)
    net: NetSettings = field(default_factory=NetSettings)
    rate_limit: RateLimitSettings = field(default_factory=RateLimitSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    planner: PlannerSettings = field(default_factory=PlannerSettings)
    osint: OsintSettings = field(default_factory=OsintSettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    log_level: str = "INFO"
    log_json: bool = True
    audit_log_path: str | None = None
    actor: str = "cli"
    #: Directory (or file) of recorded HTTP responses for the *target* client. Setting it
    #: turns any scan into a replay: the shared client still validates, throttles, audits and
    #: redacts, but its transport reads recordings instead of opening a socket, so a scan can
    #: be demonstrated and tested with no network at all (§9.1).
    http_fixtures: str | None = None
    #: M3 web-application probe bounds and switches (S6). Appended last so every existing
    #: positional/keyword construction of ``Settings`` keeps its meaning.
    web: WebSettings = field(default_factory=WebSettings)
    #: Path to the M3 payload/wordlist corpus (managed data, F-09-04). ``None`` uses the
    #: packaged ``templates/m3/`` files.
    web_payloads: str | None = None
    #: M4 misconfiguration/exposure bounds and the two opt-in switches (S7).
    m4: M4Settings = field(default_factory=M4Settings)
    #: Path to the M4 probe corpus and wordlists (managed data, F-09-04).
    m4_probes: str | None = None
    #: M5 cloud/container/supply-chain bounds and switches (S10).
    m5: M5Settings = field(default_factory=M5Settings)
    #: Path to the M5 probe corpus and wordlists (managed data, F-09-04).
    m5_probes: str | None = None
    #: M6 automation/AI-era/post-exploit bounds and switches (S11).
    m6: M6Settings = field(default_factory=M6Settings)
    #: Path to the M6 probe corpus, wordlists and Sigma rules (managed data, F-09-04).
    m6_probes: str | None = None
    #: The recurring-scan scheduler (F-01-05, S11).
    scheduler: SchedulerSettings = field(default_factory=SchedulerSettings)
    #: The operator-side secrets manifest (F-08-04); off unless a path is configured.
    secrets: SecretsSettings = field(default_factory=SecretsSettings)
    #: The credential vault (S19, REQ-CREDS-002); off unless a path is configured. A
    #: node-local encrypted sidecar, so credentialed scanning never needs a shared store.
    vault: VaultSettings = field(default_factory=VaultSettings)
    #: Report-engine knobs and managed-data overrides (S8).
    report: ReportSettings = field(default_factory=ReportSettings)
    #: AI integration layer (S9). Empty until a deployment configures a provider, which is what
    #: keeps a default scan offline (F-03-03).
    ai: AiSettings = field(default_factory=AiSettings)
    #: REST API / web UI surface (S12, F-07-02/03, F-08-02).
    api: ApiSettings = field(default_factory=ApiSettings)
    #: Outbound scan-completion integrations (S12, F-06-06).
    webhooks: WebhookSettings = field(default_factory=WebhookSettings)
    #: Ingested CVE/EPSS feed artefacts (S14, F-09-03).
    feeds: FeedsSettings = field(default_factory=FeedsSettings)
    #: Live threat-intel feed sync, verification and freshness (S18, area INTEL) — off by
    #: default, so a deployment that never opts in keeps the offline ingestion path.
    intel: IntelSettings = field(default_factory=IntelSettings)
    #: Plugin installation policy and marketplace catalogue (S14, F-09-01).
    plugins: PluginsSettings = field(default_factory=PluginsSettings)
    #: Distributed scan execution (S16, area SCALE) — off by default (single-process).
    distributed: DistributedSettings = field(default_factory=DistributedSettings)
    #: Enterprise single sign-on (S17, area IDAM) — off by default (deny-by-default).
    sso: SsoSettings = field(default_factory=SsoSettings)
    #: Per-project retention defaults and the pruning job's bounds (S20, area DATA).
    retention: RetentionSettings = field(default_factory=RetentionSettings)
    #: Where evidence payloads are stored and what happens to the large ones (S20).
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    #: Prometheus metrics and opt-in sampled traces (S20, area OPS).
    observability: ObservabilitySettings = field(default_factory=ObservabilitySettings)
    #: Agentic reasoning (S21, area AGENT) — off by default, so a deployment that never opts
    #: in runs exactly the pre-S21 pipeline.
    hypotheses: HypothesisSettings = field(default_factory=HypothesisSettings)
    #: Continuous exposure management (S23, area POSTURE): schedule-budget defaults and the
    #: Kubernetes admission posture (monitor by default).
    posture: PostureSettings = field(default_factory=PostureSettings)
    #: Remediation as code (S27, area FIX): the repo-grant file, the fix-plan catalog
    #: override, where submitted artifacts are written and whether a model may author a
    #: proposal for a class no plan covers. ``grants`` unset authorizes no repository.
    fix: FixSettings = field(default_factory=FixSettings)
    #: Purple-team detection validation (S24, area VALID): the SIEM pull endpoint, the
    #: per-run action/alerts bounds and the run-nonce entropy. Off by default — with no
    #: ``alerts_url`` there is no pull ingest, and purple mode itself is opt-in per scan.
    purple: PurpleSettings = field(default_factory=PurpleSettings)
    #: Tamper-evident audit and signed findings/evidence (S25, area TRUST,
    #: REQ-TRUST-005): the deployment key, the scan seal and the anchor cadence.
    integrity: IntegritySettings = field(default_factory=IntegritySettings)
    #: Air-gapped mode (S25, REQ-RESIL-001) — off by default, so a connected deployment is
    #: unchanged and an air-gapped one refuses every non-target host at the egress path.
    airgap: AirgapSettings = field(default_factory=AirgapSettings)
    #: PII detection and masking defaults (S25, REQ-TRUST-006) — off by default, because
    #: masking is irreversible; a project's own policy overrides these.
    pii: PiiSettings = field(default_factory=PiiSettings)
    #: Multi-region evidence residency and the queue-depth autoscaling planner
    #: (S25, REQ-RESIL-003/004). No region declared means residency is not enforced.
    resilience: ResilienceSettings = field(default_factory=ResilienceSettings)
    #: Simulation & what-if modeling (S28, area SIM): the bounds of a what-if run and the
    #: opt-in to event-driven re-simulation feeding the posture trend. A simulation reads
    #: stored scan data and computes; it never contacts a target, so there is no egress
    #: setting here to get wrong.
    sim: SimSettings = field(default_factory=SimSettings)
    #: Bounded safe fuzzing (S30, area FUZZ): the hard per-target budgets, the default
    #: engine and the abort guard's thresholds. The *permission* to fuzz is not here — it
    #: is a fuzzing attestation, and it is absent by default, so an unconfigured
    #: deployment cannot fuzz at all.
    fuzz: FuzzSettings = field(default_factory=FuzzSettings)

    @property
    def feeds_dir(self) -> Path:
        """Directory normalised feed files are written to (feeds.dir, or beside the DB)."""
        if self.feeds.dir:
            return Path(self.feeds.dir).expanduser()
        database = self.database_file()
        if database is not None:
            return database.parent / "feeds"
        return Path("feeds")

    @property
    def content_dir(self) -> Path:
        """Directory imported offline content packs are unpacked into (S25, REQ-RESIL-001).

        A sibling of the database by default, for the same reason the evidence directory is:
        moving the deployment moves its content, and one mounted volume carries both.
        """
        if self.airgap.content_dir:
            return Path(self.airgap.content_dir).expanduser()
        database = self.database_file()
        if database is not None:
            return database.parent / DEFAULT_CONTENT_DIRNAME
        return Path(DEFAULT_CONTENT_DIRNAME)

    @property
    def evidence_dir(self) -> Path:
        """Directory the local evidence backend writes to (evidence.dir, or beside the DB).

        ``DEFAULT_EVIDENCE_DIRNAME`` is a sibling of the database so that "move the SQLite
        file" moves the evidence with it, and a container that mounts one volume mounts both.
        """
        if self.evidence.dir:
            return Path(self.evidence.dir).expanduser()
        database = self.database_file()
        if database is not None:
            return database.parent / DEFAULT_EVIDENCE_DIRNAME
        return Path(DEFAULT_EVIDENCE_DIRNAME)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``env`` (defaults to ``os.environ``)."""
        source: Mapping[str, str] = os.environ if env is None else env
        scope = Scope(
            allowed_hosts=_env_list(source, "ARACHNE_SCOPE_HOSTS"),
            allowed_domains=_env_list(source, "ARACHNE_SCOPE_DOMAINS"),
            excluded_hosts=_env_list(source, "ARACHNE_SCOPE_EXCLUDE_HOSTS"),
            allowed_networks=_env_list(source, "ARACHNE_SCOPE_NETWORKS"),
            excluded_domains=_env_list(source, "ARACHNE_SCOPE_EXCLUDE_DOMAINS"),
            excluded_networks=_env_list(source, "ARACHNE_SCOPE_EXCLUDE_NETWORKS"),
            url_prefixes=_env_list(source, "ARACHNE_SCOPE_URL_PREFIXES"),
            allowed_refs=_env_list(source, "ARACHNE_SCOPE_REFS"),
            excluded_url_prefixes=_env_list(source, "ARACHNE_SCOPE_EXCLUDE_URL_PREFIXES"),
            excluded_refs=_env_list(source, "ARACHNE_SCOPE_EXCLUDE_REFS"),
        )
        return cls(
            database_url=_resolve_database_url(source),
            database_password_file=_env_str(source, "ARACHNE_DATABASE_PASSWORD_FILE") or None,
            http=HttpSettings(
                timeout_s=_env_float(source, "ARACHNE_HTTP_TIMEOUT_S", 15.0),
                connect_timeout_s=_env_float(source, "ARACHNE_HTTP_CONNECT_TIMEOUT_S", 5.0),
                max_redirects=_env_int(source, "ARACHNE_HTTP_MAX_REDIRECTS", 5),
                max_body_bytes=_env_int(source, "ARACHNE_HTTP_MAX_BODY_BYTES", 64 * 1024),
                retries=_env_int(source, "ARACHNE_HTTP_RETRIES", 1),
                user_agent=_env_str(source, "ARACHNE_HTTP_USER_AGENT") or DEFAULT_USER_AGENT,
                verify_tls=_env_bool(source, "ARACHNE_HTTP_VERIFY_TLS", default=True),
                follow_redirects=_env_bool(source, "ARACHNE_HTTP_FOLLOW_REDIRECTS", default=True),
            ),
            net=NetSettings(
                connect_timeout_s=_env_float(source, "ARACHNE_NET_CONNECT_TIMEOUT_S", 3.0),
                read_timeout_s=_env_float(source, "ARACHNE_NET_READ_TIMEOUT_S", 2.0),
                banner_wait_s=_env_float(source, "ARACHNE_NET_BANNER_WAIT_S", 0.75),
                max_read_bytes=_env_int(source, "ARACHNE_NET_MAX_READ_BYTES", 8192),
                max_ports=_env_int(source, "ARACHNE_NET_MAX_PORTS", 100),
                max_hosts=_env_int(source, "ARACHNE_NET_MAX_HOSTS", 64),
                concurrency=_env_int(source, "ARACHNE_NET_CONCURRENCY", 24),
                allow_udp=_env_bool(source, "ARACHNE_NET_ALLOW_UDP", default=False),
                ot_probe=_env_bool(source, "ARACHNE_NET_OT_PROBE", default=False),
                tls_tool=_env_str(source, "ARACHNE_NET_TLS_TOOL") or None,
                tls_tool_timeout_s=_env_float(source, "ARACHNE_NET_TLS_TOOL_TIMEOUT_S", 120.0),
                nmap_enabled=_env_bool(source, "ARACHNE_NET_NMAP_ENABLED", default=True),
                nmap_timeout_s=_env_float(source, "ARACHNE_NET_NMAP_TIMEOUT_S", 120.0),
                kerberos_pacing_s=_env_float(source, "ARACHNE_KERBEROS_PACING_S", 1.5),
                kerberos_max_names=_env_int(source, "ARACHNE_KERBEROS_MAX_NAMES", 12),
                smtp_pacing_s=_env_float(source, "ARACHNE_SMTP_PACING_S", 0.4),
                tls_cipher_probes=_env_csv_tuple(source, "ARACHNE_NET_TLS_CIPHERS"),
                port_catalog=_env_str(source, "ARACHNE_PORT_CATALOG") or None,
                cve_index=_env_str(source, "ARACHNE_CVE_INDEX") or None,
                cve_index_baseline=_env_str(source, "ARACHNE_CVE_INDEX_BASELINE") or None,
                wordlists_dir=_env_str(source, "ARACHNE_WORDLISTS_DIR") or None,
            ),
            rate_limit=RateLimitSettings(
                per_host_rate=_env_float(source, "ARACHNE_RATE_LIMIT_PER_HOST", 5.0),
                per_host_burst=_env_int(source, "ARACHNE_RATE_LIMIT_PER_HOST_BURST", 5),
                global_rate=_env_float(source, "ARACHNE_RATE_LIMIT_GLOBAL", 20.0),
                global_burst=_env_int(source, "ARACHNE_RATE_LIMIT_GLOBAL_BURST", 20),
            ),
            safety=SafetySettings(
                policy=UrlSafetyPolicy(
                    allow_private_ips=_env_bool(source, "ARACHNE_ALLOW_PRIVATE_IPS", default=False),
                    allow_loopback=_env_bool(source, "ARACHNE_ALLOW_LOOPBACK", default=False),
                    allow_link_local=_env_bool(source, "ARACHNE_ALLOW_LINK_LOCAL", default=False),
                ),
                scope=scope,
                redaction_enabled=_env_bool(source, "ARACHNE_REDACTION_ENABLED", default=True),
            ),
            planner=PlannerSettings(
                assumed_subdomains_per_domain=_env_int(
                    source, "ARACHNE_PLAN_ASSUMED_SUBDOMAINS", 0
                ),
                max_hosts_per_network=_env_int(source, "ARACHNE_PLAN_MAX_HOSTS_PER_NETWORK", 256),
            ),
            osint=OsintSettings(
                enabled=_env_bool(source, "ARACHNE_OSINT_ENABLED", default=False),
                providers=_env_list(source, "ARACHNE_OSINT_PROVIDERS") or DEFAULT_OSINT_PROVIDERS,
                search_url=_env_str(source, "ARACHNE_OSINT_SEARCH_URL") or None,
                fixtures_dir=_env_str(source, "ARACHNE_OSINT_FIXTURES") or None,
                extra_hosts=_env_list(source, "ARACHNE_OSINT_EXTRA_HOSTS"),
                request_budget=_env_int(source, "ARACHNE_OSINT_REQUEST_BUDGET", 60),
                max_results=_env_int(source, "ARACHNE_OSINT_MAX_RESULTS", 100),
                max_assets=_env_int(source, "ARACHNE_OSINT_MAX_ASSETS", 500),
                dork_corpus=_env_str(source, "ARACHNE_OSINT_DORK_CORPUS") or None,
                commoncrawl_index=(
                    _env_str(source, "ARACHNE_OSINT_COMMONCRAWL_INDEX") or COMMONCRAWL_DEFAULT_INDEX
                ),
                github_token=_env_secret(source, "ARACHNE_GITHUB_TOKEN"),
                vulners_api_key=_env_secret(source, "ARACHNE_VULNERS_API_KEY"),
                shodan_api_key=_env_secret(source, "ARACHNE_SHODAN_API_KEY"),
                censys_api_id=_env_str(source, "ARACHNE_CENSYS_API_ID") or None,
                censys_api_secret=_env_secret(source, "ARACHNE_CENSYS_API_SECRET"),
                hibp_api_key=_env_secret(source, "ARACHNE_HIBP_API_KEY"),
                whois_url=_env_str(source, "ARACHNE_OSINT_WHOIS_URL") or None,
                provider_rate_limits=(
                    _env_pairs_float(source, "ARACHNE_OSINT_PROVIDER_RATE_LIMITS")
                    or DEFAULT_OSINT_PROVIDER_RATE_LIMITS
                ),
                ct_window_days=_env_int(source, "ARACHNE_OSINT_CT_WINDOW_DAYS", 14),
            ),
            analysis=AnalysisSettings(
                rules=_env_str(source, "ARACHNE_ANALYSIS_RULES") or None,
                correlation_rules=_env_str(source, "ARACHNE_ANALYSIS_CORRELATION") or None,
                narrative_templates=_env_str(source, "ARACHNE_ANALYSIS_NARRATIVE") or None,
                remediation_catalog=_env_str(source, "ARACHNE_REMEDIATION_CATALOG") or None,
                scoring_vectors=_env_str(source, "ARACHNE_ANALYSIS_SCORING") or None,
                fp_filters=_env_str(source, "ARACHNE_FP_FILTERS") or None,
                fp_thresholds=_env_str(source, "ARACHNE_FP_THRESHOLDS") or None,
                signature_dirs=_env_list(source, "ARACHNE_SIGNATURE_DIRS"),
                verify=_env_bool(source, "ARACHNE_ANALYSIS_VERIFY", default=True),
                verify_high_severity=_env_bool(
                    source, "ARACHNE_ANALYSIS_VERIFY_HIGH_SEVERITY", default=True
                ),
                max_verifications=_env_int(source, "ARACHNE_ANALYSIS_MAX_VERIFICATIONS", 25),
                min_confidence=_env_int(source, "ARACHNE_MIN_CONFIDENCE", 55),
                correlation_enabled=_env_bool(source, "ARACHNE_CORRELATION_ENABLED", default=True),
                fp_tuner_enabled=_env_bool(source, "ARACHNE_FP_TUNER", default=True),
                drop_on_contradiction=_env_bool(
                    source, "ARACHNE_ANALYSIS_DROP_ON_CONTRADICTION", default=True
                ),
                drop_on_placeholder=_env_bool(
                    source, "ARACHNE_ANALYSIS_DROP_ON_PLACEHOLDER", default=True
                ),
                criticality=_env_list(source, "ARACHNE_ASSET_CRITICALITY"),
            ),
            log_level=_env_str(source, "ARACHNE_LOG_LEVEL") or "INFO",
            log_json=_env_bool(source, "ARACHNE_LOG_JSON", default=True),
            audit_log_path=_env_str(source, "ARACHNE_AUDIT_LOG_PATH") or None,
            actor=_env_str(source, "ARACHNE_ACTOR") or "cli",
            http_fixtures=_env_str(source, "ARACHNE_HTTP_FIXTURES") or None,
            web=WebSettings(
                max_pages=_env_int(source, "ARACHNE_WEB_MAX_PAGES", 20),
                max_depth=_env_int(source, "ARACHNE_WEB_MAX_DEPTH", 2),
                max_params_per_check=_env_int(source, "ARACHNE_WEB_MAX_PARAMS", 6),
                max_endpoints=_env_int(source, "ARACHNE_WEB_MAX_ENDPOINTS", 200),
                time_delay_s=_env_float(source, "ARACHNE_WEB_TIME_DELAY_S", 3.0),
                time_delta_s=_env_float(source, "ARACHNE_WEB_TIME_DELTA_S", 2.0),
                hidden_path_limit=_env_int(source, "ARACHNE_WEB_HIDDEN_PATHS", 40),
                rate_limit_probes=_env_int(source, "ARACHNE_WEB_RATE_PROBES", 5),
                upload_probe=_env_bool(source, "ARACHNE_WEB_UPLOAD_PROBE", default=False),
                follow_redirects=_env_bool(source, "ARACHNE_WEB_FOLLOW_REDIRECTS", default=False),
                ssrf_callback_url=_env_str(source, "ARACHNE_WEB_SSRF_CALLBACK") or None,
                ssrf_probe=_env_bool(source, "ARACHNE_WEB_SSRF_PROBE", default=False),
                rce_probe=_env_bool(source, "ARACHNE_WEB_RCE_PROBE", default=False),
                state_probe=_env_bool(source, "ARACHNE_WEB_STATE_PROBE", default=False),
                graphql_probe=_env_bool(source, "ARACHNE_WEB_GRAPHQL_PROBE", default=False),
                ws_probe=_env_bool(source, "ARACHNE_WEB_WS_PROBE", default=False),
                smuggling_probes=_env_int(source, "ARACHNE_WEB_SMUGGLING_PROBES", 4),
                race_concurrency=_env_int(source, "ARACHNE_WEB_RACE_CONCURRENCY", 8),
                jwt_max_tokens=_env_int(source, "ARACHNE_WEB_JWT_MAX_TOKENS", 4),
                graphql_batch_size=_env_int(source, "ARACHNE_WEB_GRAPHQL_BATCH", 8),
                takeover_max_names=_env_int(source, "ARACHNE_WEB_TAKEOVER_NAMES", 40),
                session_cookie=_env_secret(source, "ARACHNE_WEB_SESSION_COOKIE"),
                session_b_cookie=_env_secret(source, "ARACHNE_WEB_SESSION_B_COOKIE"),
                auth_header=_env_secret(source, "ARACHNE_WEB_AUTH_HEADER"),
            ),
            web_payloads=_env_str(source, "ARACHNE_WEB_PAYLOADS") or None,
            m4=M4Settings(
                max_paths=_env_int(source, "ARACHNE_M4_MAX_PATHS", 60),
                max_findings_per_check=_env_int(source, "ARACHNE_M4_MAX_FINDINGS", 8),
                max_bucket_names=_env_int(source, "ARACHNE_M4_MAX_BUCKET_NAMES", 8),
                default_credentials=_env_bool(
                    source, "ARACHNE_M4_DEFAULT_CREDENTIALS", default=False
                ),
                default_credentials_pacing_s=_env_float(
                    source, "ARACHNE_M4_DEFAULT_CREDS_PACING_S", 1.5
                ),
                default_credentials_max_attempts=_env_int(
                    source, "ARACHNE_M4_DEFAULT_CREDS_MAX_ATTEMPTS", 3
                ),
                metadata_ssrf_probe=_env_bool(source, "ARACHNE_M4_METADATA_SSRF", default=False),
            ),
            m4_probes=_env_str(source, "ARACHNE_M4_PROBES") or None,
            m5=M5Settings(
                max_paths=_env_int(source, "ARACHNE_M5_MAX_PATHS", 40),
                max_findings_per_check=_env_int(source, "ARACHNE_M5_MAX_FINDINGS", 8),
                max_bucket_names=_env_int(source, "ARACHNE_M5_MAX_BUCKET_NAMES", 8),
                imds_probe=_env_bool(source, "ARACHNE_M5_IMDS_PROBE", default=False),
                validate_cloud_keys=_env_bool(
                    source, "ARACHNE_M5_VALIDATE_CLOUD_KEYS", default=False
                ),
                registry_scan=_env_bool(source, "ARACHNE_M5_REGISTRY_SCAN", default=False),
                docker_socket=_env_bool(source, "ARACHNE_M5_DOCKER_SOCKET", default=True),
                iac_tool=_env_str(source, "ARACHNE_M5_IAC_TOOL") or None,
                sbom_tool=_env_str(source, "ARACHNE_M5_SBOM_TOOL") or None,
                max_file_bytes=_env_int(source, "ARACHNE_M5_MAX_FILE_BYTES", 262144),
                max_repo_files=_env_int(source, "ARACHNE_M5_MAX_REPO_FILES", 4000),
                posture_max_resources=_env_int(source, "ARACHNE_M5_POSTURE_MAX_RESOURCES", 200),
                posture_max_bytes=_env_int(source, "ARACHNE_M5_POSTURE_MAX_BYTES", 1_048_576),
                posture_token=_env_secret(source, "ARACHNE_M5_POSTURE_TOKEN"),
            ),
            m5_probes=_env_str(source, "ARACHNE_M5_PROBES") or None,
            m6=M6Settings(
                max_paths=_env_int(source, "ARACHNE_M6_MAX_PATHS", 40),
                max_findings_per_check=_env_int(source, "ARACHNE_M6_MAX_FINDINGS", 8),
                max_file_bytes=_env_int(source, "ARACHNE_M6_MAX_FILE_BYTES", 262144),
                max_repo_files=_env_int(source, "ARACHNE_M6_MAX_REPO_FILES", 4000),
                max_webshell_probes=_env_int(source, "ARACHNE_M6_WEBSHELL_PROBES", 12),
                max_git_objects=_env_int(source, "ARACHNE_M6_MAX_GIT_OBJECTS", 200),
                epss_feed=_env_str(source, "ARACHNE_M6_EPSS_FEED") or None,
                kev_feed=_env_str(source, "ARACHNE_M6_KEV_FEED") or None,
                resolved_versions=_env_str(source, "ARACHNE_M6_RESOLVED_VERSIONS") or None,
                log_access=_env_bool(source, "ARACHNE_M6_LOG_ACCESS", default=False),
                log_paths=_env_list(source, "ARACHNE_M6_LOG_PATHS"),
                deception=_env_bool(source, "ARACHNE_M6_DECEPTION", default=False),
                sigma_rules=_env_str(source, "ARACHNE_M6_SIGMA_RULES") or None,
                lpe_index=_env_str(source, "ARACHNE_M6_LPE_INDEX") or None,
                webshell_paths=_env_str(source, "ARACHNE_M6_WEBSHELL_PATHS") or None,
            ),
            m6_probes=_env_str(source, "ARACHNE_M6_PROBES") or None,
            scheduler=SchedulerSettings(
                state_path=_env_str(source, "ARACHNE_SCHEDULER_STATE") or None,
                max_runs_per_tick=_env_int(source, "ARACHNE_SCHEDULER_MAX_RUNS", 4),
                diff_on_run=_env_bool(source, "ARACHNE_SCHEDULER_DIFF", default=True),
            ),
            secrets=SecretsSettings(
                manifest_path=_env_str(source, "ARACHNE_SECRETS_MANIFEST") or None,
                manifest_key=_env_secret(source, "ARACHNE_SECRETS_MANIFEST_KEY"),
                max_records=_env_int(source, "ARACHNE_SECRETS_MANIFEST_MAX", 500),
            ),
            vault=VaultSettings(
                path=_env_str(source, "ARACHNE_VAULT_PATH") or None,
                key=_env_secret(source, "ARACHNE_VAULT_KEY"),
                max_entries=_env_int(source, "ARACHNE_VAULT_MAX_ENTRIES", 256),
            ),
            report=ReportSettings(
                min_confidence=_env_int(source, "ARACHNE_REPORT_MIN_CONFIDENCE", 55),
                evidence_body_limit=_env_int(source, "ARACHNE_REPORT_EVIDENCE_LIMIT", 8192),
                include_low_confidence=_env_bool(
                    source, "ARACHNE_REPORT_LOW_CONFIDENCE", default=True
                ),
                owasp_map=_env_str(source, "ARACHNE_REPORT_OWASP_MAP") or None,
                summary_templates=_env_str(source, "ARACHNE_REPORT_SUMMARY") or None,
                branding_path=_env_str(source, "ARACHNE_REPORT_BRANDING") or None,
                white_label=_env_bool(source, "ARACHNE_REPORT_WHITE_LABEL", default=False),
                locale=_env_str(source, "ARACHNE_REPORT_LOCALE") or "",
                compliance_frameworks=tuple(
                    _env_list(source, "ARACHNE_REPORT_COMPLIANCE_FRAMEWORKS")
                ),
                compliance_map_dir=_env_str(source, "ARACHNE_REPORT_COMPLIANCE_MAPS") or None,
            ),
            ai=AiSettings(
                config_path=_env_str(source, "ARACHNE_AI_CONFIG") or None,
                engine=_env_str(source, "ARACHNE_AI_ENGINE") or None,
                default_provider=_env_str(source, "ARACHNE_AI_PROVIDER") or None,
                privacy=_env_str(source, "ARACHNE_AI_PRIVACY") or None,
                budget_tokens=(
                    _env_int(source, "ARACHNE_AI_MAX_TOKENS_PER_SCAN", 200_000)
                    if _env_str(source, "ARACHNE_AI_MAX_TOKENS_PER_SCAN")
                    else None
                ),
                budget_cost_usd=(
                    _env_float(source, "ARACHNE_AI_MAX_COST_USD", 1.5)
                    if _env_str(source, "ARACHNE_AI_MAX_COST_USD")
                    else None
                ),
                stages=_env_list(source, "ARACHNE_AI_STAGES"),
                retries=(
                    _env_int(source, "ARACHNE_AI_RETRIES", 3)
                    if _env_str(source, "ARACHNE_AI_RETRIES")
                    else None
                ),
                correlate_threshold=(
                    _env_int(source, "ARACHNE_AI_CORRELATE_THRESHOLD", 3)
                    if _env_str(source, "ARACHNE_AI_CORRELATE_THRESHOLD")
                    else None
                ),
                authoritative_checks=_env_list(source, "ARACHNE_AI_AUTHORITATIVE_CHECKS"),
                prompts=_env_str(source, "ARACHNE_AI_PROMPTS") or None,
                pricing=_env_str(source, "ARACHNE_AI_PRICING") or None,
                cache_dir=_env_str(source, "ARACHNE_AI_CACHE_DIR") or None,
            ),
            api=ApiSettings(
                host=_env_str(source, "ARACHNE_API_HOST") or "127.0.0.1",
                port=_env_int(source, "ARACHNE_API_PORT", 8080),
                keys=_api_keys(source),
                rate_limit_per_minute=_env_int(source, "ARACHNE_API_RATE_LIMIT", 120),
                rate_limit_burst=_env_int(source, "ARACHNE_API_RATE_BURST", 30),
                require_tls=_env_bool(source, "ARACHNE_API_REQUIRE_TLS", default=True),
                tls_certfile=_env_str(source, "ARACHNE_API_TLS_CERT") or None,
                tls_keyfile=_env_str(source, "ARACHNE_API_TLS_KEY") or None,
                base_url=_env_str(source, "ARACHNE_API_BASE_URL") or None,
                docs_enabled=_env_bool(source, "ARACHNE_API_DOCS", default=True),
                cors_origins=_env_list(source, "ARACHNE_API_CORS_ORIGINS"),
                trusted_hosts=_env_list(source, "ARACHNE_API_TRUSTED_HOSTS"),
                session_max_age_s=_env_int(source, "ARACHNE_API_SESSION_MAX_AGE", 12 * 3600),
                workers=_env_int(source, "ARACHNE_API_WORKERS", 1),
            ),
            webhooks=WebhookSettings(
                enabled=_env_bool(source, "ARACHNE_WEBHOOKS_ENABLED", default=False),
                slack_url=_env_secret(source, "ARACHNE_WEBHOOK_SLACK_URL"),
                teams_url=_env_secret(source, "ARACHNE_WEBHOOK_TEAMS_URL"),
                jira_url=_env_secret(source, "ARACHNE_WEBHOOK_JIRA_URL"),
                jira_project=_env_str(source, "ARACHNE_WEBHOOK_JIRA_PROJECT") or None,
                jira_user=_env_secret(source, "ARACHNE_WEBHOOK_JIRA_USER"),
                jira_token=_env_secret(source, "ARACHNE_WEBHOOK_JIRA_TOKEN"),
                defectdojo_url=_env_secret(source, "ARACHNE_WEBHOOK_DEFECTDOJO_URL"),
                defectdojo_token=_env_secret(source, "ARACHNE_WEBHOOK_DEFECTDOJO_TOKEN"),
                servicenow_url=_env_secret(source, "ARACHNE_WEBHOOK_SERVICENOW_URL"),
                servicenow_user=_env_secret(source, "ARACHNE_WEBHOOK_SERVICENOW_USER"),
                servicenow_password=_env_secret(source, "ARACHNE_WEBHOOK_SERVICENOW_PASSWORD"),
                siem_url=_env_secret(source, "ARACHNE_WEBHOOK_SIEM_URL"),
                siem_token=_env_secret(source, "ARACHNE_WEBHOOK_SIEM_TOKEN"),
                min_severity=_env_str(source, "ARACHNE_WEBHOOK_MIN_SEVERITY") or "high",
                max_findings=_env_int(source, "ARACHNE_WEBHOOK_MAX_FINDINGS", 25),
                timeout_s=_env_float(source, "ARACHNE_WEBHOOK_TIMEOUT_S", 10.0),
                templates_dir=_env_str(source, "ARACHNE_WEBHOOK_TEMPLATES") or None,
            ),
            feeds=FeedsSettings(
                dir=_env_str(source, "ARACHNE_FEEDS_DIR") or None,
                max_entries=_env_int(source, "ARACHNE_FEEDS_MAX_ENTRIES", 50_000),
            ),
            intel=IntelSettings(
                enabled=_env_bool(source, "ARACHNE_INTEL_ENABLED", default=False),
                sources=_env_list(source, "ARACHNE_INTEL_FEED_SOURCES")
                or DEFAULT_INTEL_FEED_SOURCES,
                verify=_env_str(source, "ARACHNE_INTEL_FEED_VERIFY") or "checksum",
                checksums=_env_pairs(source, "ARACHNE_INTEL_FEED_CHECKSUMS"),
                checksums_file=_env_str(source, "ARACHNE_INTEL_FEED_CHECKSUMS_FILE") or None,
                public_key=_env_str(source, "ARACHNE_INTEL_FEED_PUBLIC_KEY") or None,
                fixtures_dir=_env_str(source, "ARACHNE_INTEL_FIXTURES") or None,
                max_bytes=_env_int(source, "ARACHNE_INTEL_MAX_BYTES", 64 * 1024 * 1024),
                max_pages=_env_int(source, "ARACHNE_INTEL_MAX_PAGES", 20),
                request_delay_s=_env_float(source, "ARACHNE_INTEL_REQUEST_DELAY_S", 6.0),
                nvd_api_key=_env_secret(source, "ARACHNE_NVD_API_KEY"),
                freshness_ttl=(
                    _env_pairs_float(source, "ARACHNE_INTEL_FRESHNESS_TTL")
                    or DEFAULT_FRESHNESS_TTL_HOURS
                ),
                index_products=_env_str(source, "ARACHNE_CVE_INDEX_PRODUCTS") or None,
                index_max_entries=_env_int(source, "ARACHNE_CVE_INDEX_MAX_ENTRIES", 500),
            ),
            plugins=PluginsSettings(
                allow_install=_env_bool(source, "ARACHNE_PLUGIN_INSTALL", default=False),
                marketplace=_env_str(source, "ARACHNE_MARKETPLACE") or None,
                install_timeout_s=_env_float(source, "ARACHNE_PLUGIN_TIMEOUT_S", 600.0),
                require_review=_env_bool(source, "ARACHNE_PLUGIN_REQUIRE_REVIEW", default=True),
                allow_unsigned_packs=_env_bool(
                    source, "ARACHNE_PLUGIN_ALLOW_UNSIGNED", default=False
                ),
            ),
            distributed=DistributedSettings(
                enabled=_env_bool(source, "ARACHNE_DISTRIBUTED", default=False),
                mode=_env_str(source, "ARACHNE_AGENT_MODE") or "external",
                agent_name=_env_str(source, "ARACHNE_AGENT_NAME") or None,
                concurrency=_env_int(source, "ARACHNE_AGENT_CONCURRENCY", 1),
                lease_ttl_s=_env_int(source, "ARACHNE_LEASE_TTL_S", 300),
                heartbeat_interval_s=_env_float(source, "ARACHNE_AGENT_HEARTBEAT_S", 15.0),
                poll_interval_s=_env_float(source, "ARACHNE_AGENT_POLL_S", 1.0),
                api_url=_env_str(source, "ARACHNE_API_URL") or None,
            ),
            sso=SsoSettings(
                enabled=_env_bool(source, "ARACHNE_SSO_ENABLED", default=False),
                issuer=_env_str(source, "ARACHNE_SSO_ISSUER") or None,
                client_id=_env_str(source, "ARACHNE_SSO_CLIENT_ID") or None,
                client_secret=_env_secret(source, "ARACHNE_SSO_CLIENT_SECRET"),
                redirect_url=_env_str(source, "ARACHNE_SSO_REDIRECT_URL") or None,
                scopes=_env_list(source, "ARACHNE_SSO_SCOPES") or ("openid", "profile", "email"),
                role_claim=_env_str(source, "ARACHNE_SSO_ROLE_CLAIM") or "groups",
                group_roles=_env_list(source, "ARACHNE_SSO_GROUP_ROLES"),
                default_role=_env_str(source, "ARACHNE_SSO_DEFAULT_ROLE") or None,
                algorithms=_env_list(source, "ARACHNE_SSO_ALGORITHMS") or ("RS256", "HS256"),
                authorization_endpoint=(
                    _env_str(source, "ARACHNE_SSO_AUTHORIZATION_ENDPOINT") or None
                ),
                token_endpoint=_env_str(source, "ARACHNE_SSO_TOKEN_ENDPOINT") or None,
                userinfo_endpoint=_env_str(source, "ARACHNE_SSO_USERINFO_ENDPOINT") or None,
                jwks_url=_env_str(source, "ARACHNE_SSO_JWKS_URL") or None,
                session_max_age_s=_env_int(source, "ARACHNE_SSO_SESSION_MAX_AGE", 8 * 3600),
                flow_ttl_s=_env_int(source, "ARACHNE_SSO_FLOW_TTL", 600),
                leeway_s=_env_int(source, "ARACHNE_SSO_LEEWAY", 60),
                allowed_hosts=_env_list(source, "ARACHNE_SSO_ALLOWED_HOSTS"),
            ),
            retention=RetentionSettings(
                enabled=_env_bool(source, "ARACHNE_RETENTION_ENABLED", default=True),
                findings_days=_env_int(source, "ARACHNE_RETENTION_FINDINGS_DAYS", 365),
                evidence_days=_env_int(source, "ARACHNE_RETENTION_EVIDENCE_DAYS", 180),
                scans_days=_env_int(source, "ARACHNE_RETENTION_SCANS_DAYS", 90),
                audit_days=_env_int(source, "ARACHNE_RETENTION_AUDIT_DAYS", 730),
                batch_limit=_env_int(source, "ARACHNE_RETENTION_BATCH_LIMIT", 10_000),
            ),
            evidence=EvidenceSettings(
                backend=_env_str(source, "ARACHNE_EVIDENCE_BACKEND") or "local",
                dir=_env_str(source, "ARACHNE_EVIDENCE_DIR") or None,
                offload_threshold_bytes=_env_int(
                    source, "ARACHNE_EVIDENCE_OFFLOAD_THRESHOLD_BYTES", 16 * 1024
                ),
                preview_chars=_env_int(source, "ARACHNE_EVIDENCE_PREVIEW_CHARS", 2048),
                default_quota_bytes=_env_int(source, "ARACHNE_EVIDENCE_DEFAULT_QUOTA_BYTES", 0)
                or None,
                quota_warn_ratio=_env_float(source, "ARACHNE_EVIDENCE_QUOTA_WARN_RATIO", 0.8),
                compress=_env_bool(source, "ARACHNE_EVIDENCE_COMPRESS", default=True),
                compress_level=_env_int(source, "ARACHNE_EVIDENCE_COMPRESS_LEVEL", 6),
                dedup=_env_bool(source, "ARACHNE_EVIDENCE_DEDUP", default=True),
                presign_ttl_s=_env_int(source, "ARACHNE_EVIDENCE_PRESIGN_TTL_S", 900),
                s3_endpoint=_env_str(source, "ARACHNE_EVIDENCE_S3_ENDPOINT") or None,
                s3_bucket=_env_str(source, "ARACHNE_EVIDENCE_S3_BUCKET") or None,
                s3_region=_env_str(source, "ARACHNE_EVIDENCE_S3_REGION") or "us-east-1",
                s3_prefix=_env_str(source, "ARACHNE_EVIDENCE_S3_PREFIX") or "evidence",
                s3_access_key=_env_secret(source, "ARACHNE_EVIDENCE_S3_ACCESS_KEY"),
                s3_secret_key=_env_secret(source, "ARACHNE_EVIDENCE_S3_SECRET_KEY"),
                s3_session_token=_env_secret(source, "ARACHNE_EVIDENCE_S3_SESSION_TOKEN"),
                s3_path_style=_env_bool(source, "ARACHNE_EVIDENCE_S3_PATH_STYLE", default=True),
                s3_allow_private_ips=_env_bool(
                    source, "ARACHNE_EVIDENCE_S3_ALLOW_PRIVATE_IPS", default=False
                ),
            ),
            observability=ObservabilitySettings(
                metrics_enabled=_env_bool(source, "ARACHNE_METRICS_ENABLED", default=True),
                metrics_token=_env_secret(source, "ARACHNE_METRICS_TOKEN"),
                tracing_enabled=_env_bool(source, "ARACHNE_TRACING_ENABLED", default=False),
                tracing_sample_ratio=_env_float(source, "ARACHNE_TRACING_SAMPLE_RATIO", 0.1),
                otlp_endpoint=_env_str(source, "ARACHNE_OTLP_ENDPOINT") or None,
                otlp_timeout_s=_env_float(source, "ARACHNE_OTLP_TIMEOUT_S", 10.0),
                otlp_allow_private_ips=_env_bool(
                    source, "ARACHNE_OTLP_ALLOW_PRIVATE_IPS", default=False
                ),
                service_name=_env_str(source, "ARACHNE_OTLP_SERVICE_NAME") or "arachne",
            ),
            hypotheses=HypothesisSettings(
                mode=_hypothesis_mode(_env_str(source, "ARACHNE_HYPOTHESES")),
                max_hypotheses=_env_int(source, "ARACHNE_HYPOTHESIS_MAX", 5),
                max_probes=_env_int(source, "ARACHNE_HYPOTHESIS_MAX_PROBES", 50),
                max_proposals=_env_int(source, "ARACHNE_HYPOTHESIS_MAX_PROPOSALS", 32),
                verify_below=_env_int(source, "ARACHNE_HYPOTHESIS_VERIFY_BELOW", 70),
                min_confidence=_env_int(source, "ARACHNE_HYPOTHESIS_MIN_CONFIDENCE", 30),
                control_path=_env_str(source, "ARACHNE_HYPOTHESIS_CONTROL") or None,
                journal_path=_env_str(source, "ARACHNE_HYPOTHESIS_JOURNAL") or None,
            ),
            posture=PostureSettings(
                default_max_runs_per_day=_env_int(source, "ARACHNE_POSTURE_MAX_RUNS_PER_DAY", 24),
                default_max_requests=_env_int(source, "ARACHNE_POSTURE_MAX_REQUESTS", 5000),
                admission_mode=(_env_str(source, "ARACHNE_ADMISSION_MODE") or "monitor")
                .strip()
                .lower(),
                admission_enforce_namespaces=(
                    _env_csv_tuple(source, "ARACHNE_ADMISSION_ENFORCE_NAMESPACES") or ()
                ),
                admission_deny_on=(_env_str(source, "ARACHNE_ADMISSION_DENY_ON") or "high")
                .strip()
                .lower(),
                cmdb_max_rows=_env_int(source, "ARACHNE_POSTURE_CMDB_MAX_ROWS", 10_000),
                cmdb_max_bytes=_env_int(source, "ARACHNE_POSTURE_CMDB_MAX_BYTES", 4_194_304),
            ),
            fix=FixSettings(
                plans=_env_str(source, "ARACHNE_FIX_PLANS") or None,
                grants=_env_str(source, "ARACHNE_FIX_GRANTS") or None,
                artifacts_dir=_env_str(source, "ARACHNE_FIX_ARTIFACTS_DIR") or None,
                ai_authoring=_env_bool(source, "ARACHNE_FIX_AI_AUTHORING", default=False),
                max_diff_lines=_env_int(source, "ARACHNE_FIX_MAX_DIFF_LINES", 400),
                max_files=_env_int(source, "ARACHNE_FIX_MAX_FILES", 12),
                test_timeout_seconds=_env_int(source, "ARACHNE_FIX_TEST_TIMEOUT_SECONDS", 900),
            ),
            purple=PurpleSettings(
                alerts_url=_env_str(source, "ARACHNE_PURPLE_ALERTS_URL") or None,
                alerts_token=_env_secret(source, "ARACHNE_PURPLE_ALERTS_TOKEN"),
                max_actions=_env_int(source, "ARACHNE_PURPLE_MAX_ACTIONS", 12),
                max_alerts=_env_int(source, "ARACHNE_PURPLE_MAX_ALERTS", 1000),
                nonce_bytes=_env_int(source, "ARACHNE_PURPLE_NONCE_BYTES", 12),
                map_path=_env_str(source, "ARACHNE_PURPLE_MAP") or None,
            ),
            integrity=IntegritySettings(
                key=_env_secret(source, "ARACHNE_INTEGRITY_KEY")
                or _env_file_secret(source, "ARACHNE_INTEGRITY_KEY_FILE"),
                key_file=_env_str(source, "ARACHNE_INTEGRITY_KEY_FILE") or None,
                key_id=_env_str(source, "ARACHNE_INTEGRITY_KEY_ID") or None,
                seal_on_finish=_env_bool(source, "ARACHNE_INTEGRITY_SEAL", default=True),
                require_signatures=_env_bool(
                    source, "ARACHNE_INTEGRITY_REQUIRE_SIGNATURES", default=False
                ),
                anchor_every=_env_int(source, "ARACHNE_INTEGRITY_ANCHOR_EVERY", 1000),
            ),
            airgap=AirgapSettings(
                enabled=_env_bool(source, "ARACHNE_AIRGAPPED", default=False),
                allowed_hosts=_env_list(source, "ARACHNE_AIRGAP_ALLOWED_HOSTS"),
                content_dir=_env_str(source, "ARACHNE_CONTENT_DIR") or None,
                require_signature=_env_bool(
                    source, "ARACHNE_CONTENT_REQUIRE_SIGNATURE", default=True
                ),
            ),
            pii=PiiSettings(
                enabled=_env_bool(source, "ARACHNE_PII_ENABLED", default=False),
                categories=_env_list(source, "ARACHNE_PII_CATEGORIES") or PII_KNOWN_CATEGORIES,
                action=_env_str(source, "ARACHNE_PII_ACTION") or "mask",
                salt=_env_secret(source, "ARACHNE_PII_SALT"),
                retention_days=_env_int(source, "ARACHNE_PII_RETENTION_DAYS", 0),
            ),
            resilience=ResilienceSettings(
                region=_env_str(source, "ARACHNE_REGION") or None,
                queue_depth_per_replica=_env_int(
                    source, "ARACHNE_AUTOSCALE_QUEUE_DEPTH_PER_REPLICA", 4
                ),
                min_replicas=_env_int(source, "ARACHNE_AUTOSCALE_MIN_REPLICAS", 0),
                max_replicas=_env_int(source, "ARACHNE_AUTOSCALE_MAX_REPLICAS", 8),
                leader_ttl_s=_env_int(source, "ARACHNE_LEADER_TTL_S", 30),
            ),
            sim=SimSettings(
                max_hypotheses=_env_int(source, "ARACHNE_SIM_MAX_HYPOTHESES", 32),
                max_paths=_env_int(source, "ARACHNE_SIM_MAX_PATHS", 25),
                min_confidence=_env_int(source, "ARACHNE_SIM_MIN_CONFIDENCE", 55),
                resimulate=_env_bool(source, "ARACHNE_SIM_RESIMULATE", default=False),
                trend_limit=_env_int(source, "ARACHNE_SIM_TREND_LIMIT", 50),
            ),
            fuzz=FuzzSettings(
                max_cases=_env_int(source, "ARACHNE_FUZZ_MAX_CASES", 200),
                max_requests=_env_int(source, "ARACHNE_FUZZ_MAX_REQUESTS", 220),
                max_seconds=_env_float(source, "ARACHNE_FUZZ_MAX_SECONDS", 60.0),
                batch_size=_env_int(source, "ARACHNE_FUZZ_BATCH_SIZE", 25),
                engine=_env_str(source, "ARACHNE_FUZZ_ENGINE") or "grammar",
                allow_production=_env_bool(source, "ARACHNE_FUZZ_ALLOW_PRODUCTION", default=False),
                health_min_samples=_env_int(source, "ARACHNE_FUZZ_HEALTH_MIN_SAMPLES", 3),
                max_error_rate=_env_float(source, "ARACHNE_FUZZ_MAX_ERROR_RATE", 0.34),
                max_latency_ratio=_env_float(source, "ARACHNE_FUZZ_MAX_LATENCY_RATIO", 4.0),
                max_timeout_rate=_env_float(source, "ARACHNE_FUZZ_MAX_TIMEOUT_RATE", 0.25),
                max_consecutive_failures=_env_int(
                    source, "ARACHNE_FUZZ_MAX_CONSECUTIVE_FAILURES", 2
                ),
            ),
        )

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def database_file(self) -> Path | None:
        """Path of the SQLite file, when the database URL points at one."""
        if not self.is_sqlite:
            return None
        _, _, raw_path = self.database_url.partition("///")
        if not raw_path or raw_path == ":memory:":
            return None
        return Path(raw_path)


def _env_str(env: Mapping[str, str], key: str) -> str:
    return env.get(key, "").strip()


def _env_secret(env: Mapping[str, str], key: str) -> SecretStr | None:
    """Read a credential from the environment (F-08-01). Never logged, never in a plan."""
    raw = _env_str(env, key)
    return SecretStr(raw) if raw else None


def _env_file_secret(env: Mapping[str, str], key: str) -> SecretStr | None:
    """Read a secret from the file ``key`` names (the docker or Helm secrets path, F-07-04).

    A missing or unreadable file is a configuration error rather than "no secret", because
    the surrounding setting (``ARACHNE_INTEGRITY_KEY_FILE``) says the operator intended one.
    """
    path_text = _env_str(env, key)
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigurationError(f"cannot read {key}={path}: {exc}") from exc
    return SecretStr(raw) if raw else None


def _env_list(env: Mapping[str, str], key: str) -> tuple[str, ...]:
    raw = _env_str(env, key)
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = _env_str(env, key)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be a number, got {raw!r}") from exc


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = _env_str(env, key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be an integer, got {raw!r}") from exc


def _env_csv_tuple(env: Mapping[str, str], key: str) -> tuple[str, ...] | None:
    """A comma-separated list from the environment, or ``None`` when unset."""
    raw = _env_str(env, key)
    if not raw:
        return None
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_pairs(env: Mapping[str, str], key: str) -> tuple[tuple[str, str], ...]:
    """A ``name=value,name=value`` list from the environment (``()`` when unset).

    Used for the per-source tables S18 adds (feed checksum pins, per-provider rate limits):
    a mapping is the natural shape for these, and a tuple of pairs keeps the frozen
    settings dataclass hashable and easy to assert on in tests.
    """
    pairs: list[tuple[str, str]] = []
    for item in _env_csv_tuple(env, key) or ():
        name, separator, value = item.partition("=")
        if not separator or not name.strip() or not value.strip():
            raise ConfigurationError(f"{key} expects name=value pairs, got {item!r}")
        pairs.append((name.strip().lower(), value.strip()))
    return tuple(pairs)


def _env_pairs_float(env: Mapping[str, str], key: str) -> tuple[tuple[str, float], ...]:
    """Like :func:`_env_pairs`, with the value parsed as a number."""
    parsed: list[tuple[str, float]] = []
    for name, value in _env_pairs(env, key):
        try:
            parsed.append((name, float(value)))
        except ValueError as exc:
            raise ConfigurationError(f"{key}: {name} must be a number, got {value!r}") from exc
    return tuple(parsed)


def _env_bool(env: Mapping[str, str], key: str, *, default: bool) -> bool:
    raw = _env_str(env, key).lower()
    if not raw:
        return default
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    raise ConfigurationError(f"{key} must be a boolean, got {raw!r}")


def _hypothesis_mode(raw: str) -> HypothesisMode:
    """``ARACHNE_HYPOTHESES=off|heuristic|hybrid|ai`` — an unknown word is refused.

    Refused rather than defaulted, because the two failure directions are not symmetric: a
    typo that silently turned agentic reasoning *on* would add requests to every scan, and one
    that silently turned it *off* would make an operator think a scan reasoned when it did not.
    """
    value = (raw or "").strip().lower()
    if not value:
        return HypothesisMode.OFF
    try:
        return HypothesisMode(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in HypothesisMode)
        msg = f"ARACHNE_HYPOTHESES must be one of {allowed}, got {raw!r}"
        raise ConfigurationError(msg) from exc


def _resolve_database_url(env: Mapping[str, str]) -> str:
    """The database URL, with a password injected from ``ARACHNE_DATABASE_PASSWORD_FILE``.

    A compose secret mounts the password as a file (``/run/secrets/postgres_password``);
    keeping it out of the environment and out of ``docker inspect`` is the whole point
    (F-08-01). A URL that already carries a password is left untouched unless the file is
    set, in which case the file wins.
    """
    url = _env_str(env, "ARACHNE_DATABASE_URL") or f"sqlite:///{DEFAULT_DATABASE_FILENAME}"
    password_file = _env_str(env, "ARACHNE_DATABASE_PASSWORD_FILE")
    if not password_file:
        return url
    try:
        password = Path(password_file).expanduser().read_text(encoding="utf-8").strip()
    except OSError as exc:
        msg = f"ARACHNE_DATABASE_PASSWORD_FILE {password_file!r} could not be read: {exc}"
        raise ConfigurationError(msg) from exc
    if not password:
        return url
    return _inject_url_password(url, password)


def _inject_url_password(url: str, password: str) -> str:
    """``postgresql+psycopg://user@host/db`` + password → ``...://user:<pw>@host/db``."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname or not parts.username:
        return url
    netloc = f"{quote(parts.username, safe='')}:{quote(password, safe='')}@{parts.hostname}"
    if parts.port is not None:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _api_keys(env: Mapping[str, str]) -> tuple[str, ...]:
    """API key entries from ``ARACHNE_API_KEYS`` and/or ``ARACHNE_API_KEYS_FILE``.

    The inline form is ``;``-separated ``label:role:secret`` entries. The file form (one
    entry per line, ``#`` comments ignored) keeps the secrets out of the process
    environment listing (F-08-01); a deployment can point at a mounted secret file.
    """
    entries: list[str] = [
        item.strip() for item in _env_str(env, "ARACHNE_API_KEYS").split(";") if item.strip()
    ]
    path = _env_str(env, "ARACHNE_API_KEYS_FILE")
    if path:
        try:
            lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            msg = f"ARACHNE_API_KEYS_FILE {path!r} could not be read: {exc}"
            raise ConfigurationError(msg) from exc
        entries.extend(
            line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
        )
    return tuple(entries)


_settings_cache: Settings | None = None


def get_settings() -> Settings:
    """Return process settings, read from the environment once."""
    global _settings_cache
    if _settings_cache is None:
        _settings_cache = Settings.from_env()
    return _settings_cache


def reset_settings_cache() -> None:
    """Drop the cached settings (tests, and CLI runs that change the environment)."""
    global _settings_cache
    _settings_cache = None
