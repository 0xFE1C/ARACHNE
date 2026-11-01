"""Provider layer: the only way a check reaches a third-party data source (ADR-05).

Passive reconnaissance lives or dies on other people's indexes — certificate transparency
logs, web archives, scan databases, code search. Those are *not* the target, so they must
not pass through the target scope; but they must not become a hole in ADR-05 either. This
package therefore builds a **second** ``ScopedHttpClient`` whose scope is exactly the
provider hosts the deployment enabled (``ARACHNE_OSINT_PROVIDERS``), and every provider
call goes through it, with the same validation, rate limiting, redaction and audit trail
as a target request.

Three properties keep this testable and safe:

* :class:`ProviderSpec` declares the host a provider talks to, and
  ``tests/unit/test_providers.py`` asserts every spec agrees with
  ``core.config.OSINT_PROVIDER_HOSTS`` — so a provider cannot silently widen the scope.
* :class:`OsintAccess` is **deny by default**: an unconfigured or disabled provider produces
  a refusal with a reason, never an untracked request.
* :class:`~arachne.modules.providers.fixtures.FixtureReplay` can stand in for the network
  (vcrpy-style): the checks run end to end against recorded responses, which is how the
  test suite and the offline demo work without a packet leaving the process.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import OsintError
from arachne.core.http import HttpExchange, ScopedHttpClient
from arachne.core.logging import get_logger
from arachne.core.redaction import redact_url
from arachne.core.safety import Scope
from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes

__all__ = [
    "DYNAMIC_PROVIDERS",
    "PROVIDER_HOSTS",
    "SPECS",
    "OsintAccess",
    "ProviderSpec",
    "build_osint_access",
    "build_osint_access_for_fixtures",
    "load_fixture_routes",
    "provider_scope",
]

_logger = get_logger("modules.providers")

#: Host of each provider. Mirrors ``core.config.OSINT_PROVIDER_HOSTS`` (the deployment
#: allowlist); a unit test fails if the two ever disagree, so the OSINT scope is always
#: exactly what an operator can read in one place. ``search`` and ``whois`` have no fixed
#: host: they talk to the endpoint the deployment configured.
PROVIDER_HOSTS: dict[str, str] = {
    "crtsh": "crt.sh",
    "circl": "www.circl.lu",
    "wayback": "web.archive.org",
    "commoncrawl": "index.commoncrawl.org",
    "internetdb": "internetdb.shodan.io",
    "github": "api.github.com",
    "vulners": "vulners.com",
    "dns": "dns.google",
    "shodan": "api.shodan.io",
    "censys": "search.censys.io",
    "certspotter": "api.certspotter.com",
    "hibp": "haveibeenpwned.com",
    "whois": "",
    "search": "",
}

#: Providers whose host is not a constant (the deployment supplies it).
DYNAMIC_PROVIDERS: frozenset[str] = frozenset({"search", "whois"})


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Static description of one third-party source."""

    name: str
    host: str
    description: str
    keyless: bool = True
    #: Configuration field carrying the provider's API key, when it is not keyless. Kept for
    #: the single-key providers (the original shape); :attr:`credentials` is the general form.
    credential: str | None = None
    #: Every configuration field the provider needs. A provider with a missing credential has
    #: its host removed from the OSINT scope, so the request is refused rather than sent
    #: unauthenticated (REQ-INTEL-005).
    credentials: tuple[str, ...] = ()
    #: Requests a single use of this provider is expected to make (planning honesty).
    estimated_requests: int = 1
    #: S18: true when the provider is never enabled implicitly — naming it in
    #: ``ARACHNE_OSINT_PROVIDERS`` is the opt-in (REQ-INTEL-003).
    opt_in: bool = False
    #: Minimum seconds between two calls to this provider, applied by :class:`OsintAccess` on
    #: top of the shared client's per-host limiter. ``None`` means "no extra pacing".
    rate_limit_rps: float | None = None

    def required_credentials(self) -> tuple[str, ...]:
        if self.credentials:
            return self.credentials
        return (self.credential,) if self.credential else ()


SPECS: dict[str, ProviderSpec] = {
    "crtsh": ProviderSpec(
        "crtsh",
        "crt.sh",
        "Certificate Transparency log aggregator (crt.sh JSON endpoint).",
        estimated_requests=1,
    ),
    "circl": ProviderSpec(
        "circl",
        "www.circl.lu",
        "CIRCL passive DNS query service (keyless JSONL).",
        estimated_requests=1,
    ),
    "wayback": ProviderSpec(
        "wayback",
        "web.archive.org",
        "Internet Archive Wayback Machine CDX index.",
        estimated_requests=1,
    ),
    "commoncrawl": ProviderSpec(
        "commoncrawl",
        "index.commoncrawl.org",
        "Common Crawl columnar URL index.",
        estimated_requests=1,
    ),
    "internetdb": ProviderSpec(
        "internetdb",
        "internetdb.shodan.io",
        "Shodan InternetDB: keyless per-IP ports, CPEs and CVEs.",
        estimated_requests=1,
    ),
    "dns": ProviderSpec(
        "dns",
        "dns.google",
        "DNS-over-HTTPS resolver (SPF/DKIM/DMARC TXT records for M4's email review).",
        estimated_requests=6,
    ),
    "github": ProviderSpec(
        "github",
        "api.github.com",
        "GitHub code search (requires a token; opt-in, token budgeted).",
        keyless=False,
        credential="github_token",
        estimated_requests=1,
    ),
    "vulners": ProviderSpec(
        "vulners",
        "vulners.com",
        "Vulners CVE/EPSS index (requires an API key; opt-in, used by M2's CVE correlation).",
        keyless=False,
        credential="vulners_api_key",
        estimated_requests=1,
    ),
    # ------------------------------------------------------------------ S18 opt-in providers
    "shodan": ProviderSpec(
        "shodan",
        "api.shodan.io",
        "Shodan host lookup: ports, banners, hostnames and known CVEs per address.",
        keyless=False,
        credentials=("shodan_api_key",),
        opt_in=True,
        rate_limit_rps=1.0,
    ),
    "censys": ProviderSpec(
        "censys",
        "search.censys.io",
        "Censys host search: observed services and their transport for one address.",
        keyless=False,
        credentials=("censys_api_id", "censys_api_secret"),
        opt_in=True,
        rate_limit_rps=0.5,
    ),
    "certspotter": ProviderSpec(
        "certspotter",
        "api.certspotter.com",
        "Cert Spotter certificate-transparency issuances (a second CT view beside crt.sh).",
        opt_in=True,
        rate_limit_rps=1.0,
    ),
    "hibp": ProviderSpec(
        "hibp",
        "haveibeenpwned.com",
        "Have I Been Pwned breach index: which breaches exposed accounts at a domain.",
        keyless=False,
        credentials=("hibp_api_key",),
        opt_in=True,
        rate_limit_rps=0.5,
    ),
    "whois": ProviderSpec(
        "whois",
        "",
        "RDAP registration data (the HTTPS successor of WHOIS) for a domain.",
        opt_in=True,
        rate_limit_rps=1.0,
    ),
    "search": ProviderSpec(
        "search",
        "",
        "A deployment-configured search API (a self-hosted SearxNG or equivalent).",
        keyless=True,
        credential=None,
        estimated_requests=1,
    ),
}


def _drop_unusable(
    providers: list[str], usable: Callable[[str], bool] | None
) -> dict[str, str]:
    """Remove providers the deployment cannot use, returning ``{name: reason}``.

    Dropping happens *before* the scope is built, so a provider missing a credential is out of
    ``enabled`` **and** out of the allowlist: no code path can send it an unauthenticated
    request (REQ-INTEL-005), and a check reports the concrete reason.
    """
    blocked: dict[str, str] = {}
    if usable is None:
        return blocked
    for name in list(providers):
        if usable(name):
            continue
        providers.remove(name)
        required = SPECS[name].required_credentials()
        blocked[name] = (
            f"provider {name!r} needs {' and '.join(required)} in the environment"
            if required
            else f"provider {name!r} is not configured"
        )
    return blocked


def provider_scope(hosts: tuple[str, ...]) -> Scope:
    """The scope the OSINT client is bound to: exactly the enabled provider hosts."""
    return Scope(allowed_hosts=tuple(hosts)) if hosts else Scope.deny_all()


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """One provider exchange: the parsed body plus the raw, redacted capture."""

    provider: str
    url: str
    status: int
    exchange: HttpExchange
    cached: bool = False

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def text(self) -> str:
        return self.exchange.body

    def json(self) -> Any:
        """Parse the body as JSON; ``None`` when it is not JSON."""
        return self.exchange.json_body()

    def json_lines(self) -> list[Any]:
        """Parse a JSONL body (CIRCL pDNS, Common Crawl) into a list of documents."""
        rows: list[Any] = []
        for line in self.text.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                rows.append(json.loads(candidate))
            except json.JSONDecodeError:
                continue
        return rows

    def evidence_payload(self, *, limit: int = 4000) -> dict[str, Any]:
        """A bounded, redacted summary of the exchange, suitable for evidence."""
        body = self.text
        return {
            "provider": self.provider,
            "url": self.url,
            "status": self.status,
            "cached": self.cached,
            "body_preview": body[:limit],
            "body_truncated": len(body) > limit,
            "sha256": self.exchange.to_evidence()[1].sha256,
            "captured_at": self.exchange.captured_at.isoformat(),
        }


@dataclass
class OsintAccess:
    """Scoped, budgeted, paced, audited access to the enabled OSINT providers."""

    client: ScopedHttpClient
    enabled: frozenset[str]
    budget: int
    auditor: Auditor | None = None
    #: In-memory per-scan response cache: two checks asking crt.sh for the same domain is
    #: one request, which is what makes "merge sources" (``m1.subdomain-passive``) cheap
    #: and keeps the plan's request estimate meaningful.
    cache: dict[str, ProviderResponse] = field(default_factory=dict)
    used: int = 0
    #: Per-provider minimum interval (seconds per request), S18 REQ-INTEL-003. A provider not
    #: in the mapping is not paced beyond the shared client's per-host limiter.
    rate_limits: dict[str, float] = field(default_factory=dict)
    #: Providers dropped at build time, with the reason (a missing credential). Keeping the
    #: reason is what lets a check report "needs ARACHNE_SHODAN_API_KEY" rather than the
    #: vaguer "not enabled".
    blocked: dict[str, str] = field(default_factory=dict)
    #: Injectable clock/sleeper so the pacing is testable without wall-clock time.
    clock: Callable[[], float] = field(default=time.monotonic)
    sleep: Callable[[float], Awaitable[Any]] = field(default=asyncio.sleep)
    _last_call: dict[str, float] = field(default_factory=dict)

    # ------------------------------------------------------------------ capability
    def spec(self, provider: str) -> ProviderSpec:
        try:
            return SPECS[provider]
        except KeyError as exc:
            msg = f"unknown OSINT provider {provider!r}"
            raise OsintError(msg) from exc

    def available(self, provider: str) -> bool:
        return provider in self.enabled

    def unavailable_reason(self, provider: str) -> str:
        """Why ``provider`` will not be queried (the reason a check reports when skipped)."""
        if not self.enabled:
            return "no OSINT provider is enabled (set ARACHNE_OSINT_ENABLED=true)"
        if provider in self.blocked:
            return self.blocked[provider]
        spec = self.spec(provider)
        if provider not in self.enabled:
            if provider == "search":
                return (
                    "no search endpoint is configured "
                    "(set ARACHNE_OSINT_SEARCH_URL to a search API that returns JSON results)"
                )
            if provider == "whois":
                return (
                    "the RDAP provider is not enabled (add 'whois' to ARACHNE_OSINT_PROVIDERS "
                    "or set ARACHNE_OSINT_WHOIS_URL)"
                )
            if spec.opt_in:
                return (
                    f"provider {provider!r} is strictly opt-in: add it to "
                    "ARACHNE_OSINT_PROVIDERS (and set its credential)"
                )
            return f"provider {provider!r} is not enabled (ARACHNE_OSINT_PROVIDERS)"
        required = spec.required_credentials()
        if required:
            return f"provider {provider!r} needs {' and '.join(required)} in the environment"
        return f"unknown reason for {provider!r}"  # pragma: no cover - defensive

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used)

    def can_spend(self, count: int = 1) -> bool:
        """True when ``count`` more provider requests fit inside the budget."""
        return self.used + count <= self.budget

    def available_names(self) -> tuple[str, ...]:
        """The providers this access object may query, in the deployment's own order."""
        return tuple(sorted(self.enabled))

    def note_blocked(self, provider: str, reason: str) -> None:
        """Audit a provider call that will not happen (opt-in or credential missing).

        Called by :func:`~arachne.modules.context.require_osint` before it returns a skipped
        result, so "we never asked Shodan" is distinguishable from "we asked and found
        nothing" in the trail (REQ-INTEL-005).
        """
        if self.auditor is None:
            return
        self.auditor.record(
            AuditAction.INTEL_PROVIDER_BLOCKED,
            outcome=AuditOutcome.BLOCKED,
            target=self.spec(provider).host or provider,
            reason=reason,
            meta={"provider": provider, "enabled": sorted(self.enabled)},
        )

    # ------------------------------------------------------------------ requests
    async def _pace(self, provider: str) -> float:
        """Wait out the provider's minimum interval; return the seconds waited."""
        rate = self.rate_limits.get(provider)
        if not rate or rate <= 0:
            return 0.0
        interval = 1.0 / rate
        now = self.clock()
        last = self._last_call.get(provider)
        self._last_call[provider] = now
        if last is None:
            return 0.0
        waited = interval - (now - last)
        if waited <= 0:
            return 0.0
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.INTEL_RATE_LIMITED,
                target=self.spec(provider).host or provider,
                meta={"provider": provider, "waited_s": round(waited, 3), "rate_rps": rate},
            )
        await self.sleep(waited)
        self._last_call[provider] = self.clock()
        return float(waited)

    async def fetch(
        self,
        provider: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> ProviderResponse:
        """Query ``provider`` at ``url`` (scope-checked, budgeted, paced, audited, cached).

        The URL a caller passes may carry a credential (Shodan's API takes its key as a query
        parameter). Everything this method records — the audit line, the log line and the
        :class:`ProviderResponse` itself — carries ``redact_url(url)`` instead, so a key in a
        query string never reaches evidence, logs or a report (REQ-INTEL-005).
        """
        spec = self.spec(provider)
        if not self.available(provider):
            self.note_blocked(provider, self.unavailable_reason(provider))
            raise OsintError(f"refusing to query {provider!r}: {self.unavailable_reason(provider)}")
        display_url = redact_url(url)
        cache_key = f"{provider} {url}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            return ProviderResponse(
                provider=cached.provider,
                url=cached.url,
                status=cached.status,
                exchange=cached.exchange,
                cached=True,
            )
        if not self.can_spend():
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.BUDGET_EXHAUSTED,
                    outcome=AuditOutcome.BLOCKED,
                    target=display_url,
                    reason=f"OSINT request budget of {self.budget} is spent",
                    meta={"provider": provider, "used": self.used, "budget": self.budget},
                )
            raise OsintError(
                f"OSINT request budget of {self.budget} is spent; not querying {provider!r}"
            )

        await self._pace(provider)
        self.used += 1
        headers_out = {"accept": "application/json", **dict(headers or {})}
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.OSINT_QUERY,
                target=display_url,
                meta={"provider": provider, "host": spec.host, "budget_used": self.used},
            )
        try:
            exchange = await self.client.get(url, headers=headers_out)
        except Exception as exc:  # SafetyError, RequestError, OsintError — all degrade to data
            raise OsintError(
                f"OSINT query to {provider!r} failed: {exc.__class__.__name__}: {exc}"
            ) from exc
        response = ProviderResponse(
            provider=provider, url=display_url, status=exchange.status_code, exchange=exchange
        )
        self.cache[cache_key] = response
        _logger.info(
            "osint query",
            extra={
                "event": "osint.query",
                "provider": provider,
                "url": display_url,
                "status": exchange.status_code,
                "budget_used": self.used,
            },
        )
        return response

    async def get_json(self, provider: str, url: str, **kwargs: Any) -> Any:
        response = await self.fetch(provider, url, **kwargs)
        return response.json()

    async def aclose(self) -> None:
        await self.client.aclose()


def build_osint_access(
    *,
    enabled: bool,
    providers: tuple[str, ...],
    budget: int = 60,
    auditor: Auditor | None = None,
    extra_hosts: tuple[str, ...] = (),
    search_url: str | None = None,
    whois_url: str | None = None,
    rate_limits: Mapping[str, float] | None = None,
    usable: Callable[[str], bool] | None = None,
    scope: Scope | None = None,
) -> OsintAccess | None:
    """Build the OSINT access object for a live run, or ``None`` when it is switched off.

    ``None`` is a first-class answer: the checks see "no OSINT access" and report a skipped
    result, which is what keeps a default scan offline (F-02-09).

    The client's scope is the hosts of the *enabled* providers only — plus a configured
    search endpoint and any explicitly declared extra host — so an index that is not named
    in the configuration is out of scope and the request is refused and audited.
    """
    if not enabled or not providers:
        return None
    effective_providers = list(providers)
    # A configured endpoint is as explicit a declaration of intent as the provider list, so it
    # turns its own provider on rather than silently doing nothing.
    for name, url in (("search", search_url), ("whois", whois_url)):
        if url and name not in effective_providers:
            effective_providers.append(name)
    blocked = _drop_unusable(effective_providers, usable)
    hosts = [PROVIDER_HOSTS[name] for name in effective_providers if PROVIDER_HOSTS.get(name)]
    for url in (search_url, whois_url):
        if url:
            host = urlsplit(url).hostname
            if host:
                hosts.append(host)
    hosts.extend(extra_hosts)
    effective_scope = scope if scope is not None else provider_scope(tuple(dict.fromkeys(hosts)))
    if effective_scope.is_empty:
        return None
    client = ScopedHttpClient(scope=effective_scope, auditor=auditor)
    return OsintAccess(
        client=client,
        enabled=frozenset(effective_providers),
        budget=budget,
        auditor=auditor,
        rate_limits={
            name: float(rate) for name, rate in dict(rate_limits or {}).items() if float(rate) > 0
        },
        blocked=blocked,
    )


def build_osint_access_for_fixtures(
    routes: Mapping[str, Any],
    *,
    providers: tuple[str, ...],
    budget: int = 60,
    auditor: Auditor | None = None,
    extra_hosts: tuple[str, ...] = (),
    search_url: str | None = None,
    whois_url: str | None = None,
    rate_limits: Mapping[str, float] | None = None,
    usable: Callable[[str], bool] | None = None,
) -> OsintAccess:
    """Build OSINT access that replays recorded responses instead of using the network.

    Used by the test suite and by ``ARACHNE_OSINT_FIXTURES`` (an offline demonstration run).
    The scope is derived exactly as in :func:`build_osint_access` — the enabled providers'
    hosts, a configured search endpoint and any declared extra host — so replay mode does not
    quietly widen what a check may reach. Name resolution is stubbed because the transport
    never dials: the safety pipeline still runs (scheme, scope, IP policy) but no packet can
    leave the process.
    """
    from arachne.core.http import fixture_transport
    from arachne.core.safety import StaticResolver

    replay = FixtureReplay(routes)
    effective_providers = list(providers)
    for name, url in (("search", search_url), ("whois", whois_url)):
        if url and name not in effective_providers:
            effective_providers.append(name)
    blocked = _drop_unusable(effective_providers, usable)
    hosts = [PROVIDER_HOSTS[name] for name in effective_providers if PROVIDER_HOSTS.get(name)]
    for url in (search_url, whois_url):
        if url:
            host = urlsplit(url).hostname
            if host:
                hosts.append(host)
    hosts.extend(extra_hosts)
    client = ScopedHttpClient(
        scope=provider_scope(tuple(dict.fromkeys(hosts))),
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )
    return OsintAccess(
        client=client,
        enabled=frozenset(effective_providers),
        budget=budget,
        auditor=auditor,
        rate_limits={
            name: float(rate) for name, rate in dict(rate_limits or {}).items() if float(rate) > 0
        },
        blocked=blocked,
    )
