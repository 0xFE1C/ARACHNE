"""The S18 passive-OSINT providers and the checks that consume them.

Three things are asserted here, and they are the three the requirements name:

* **REQ-INTEL-003** — Shodan, Censys, Cert Spotter, HIBP and WHOIS/RDAP sit behind the
  existing allowlist: a fixed host each, a declared credential, a pacing rate, and ``opt_in``
  set so nothing enables them implicitly.
* **REQ-INTEL-005** — no opt-in means no call (a skipped result plus a ``intel.provider_blocked``
  audit line), and a missing key degrades the same way rather than sending an unauthenticated
  request. A credential that a provider puts in a URL is redacted everywhere it is recorded.
* **REQ-INTEL-004** — the three new M1 checks consume the parsed provider results and report
  what the provider sees that the scan does not, without inventing a verdict.

Every check runs through the real :class:`CheckContext` over recorded responses, so the
provider layer's scope, budget, pacing and redaction all execute.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from typing import Any

import pytest
from tests.helpers.checks import asset_for, make_osint, run_check

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import (
    DEFAULT_OSINT_PROVIDER_RATE_LIMITS,
    DEFAULT_OSINT_PROVIDERS,
    OPT_IN_OSINT_PROVIDERS,
    OSINT_PROVIDER_CREDENTIALS,
    OSINT_PROVIDER_HOSTS,
    OsintSettings,
    Settings,
)
from arachne.core.errors import ConfigurationError
from arachne.core.target import TargetKind
from arachne.modules.context import ModuleConfig
from arachne.modules.m1.intel import BreachExposure, CertificateSurprise, ServiceExposureDrift
from arachne.modules.providers import PROVIDER_HOSTS, SPECS
from arachne.modules.providers.sources import (
    censys_host_url,
    certspotter_url,
    hibp_breaches_url,
    parse_censys_host,
    parse_certspotter,
    parse_hibp_breaches,
    parse_rdap,
    parse_shodan_host,
    rdap_url_for,
    shodan_display_url,
    shodan_host_url,
)

DOMAIN = asset_for("domain", "example.com")
ADDRESS = asset_for("host", "203.0.113.9")

#: Stand-in credentials. They are deliberately recognisable so a leak is obvious.
SHODAN_KEY = "SHODAN-TEST-KEY-0123456789"
CENSYS_ID = "censys-test-id"
CENSYS_SECRET = "CENSYS-TEST-SECRET-0123456789"
HIBP_KEY = "HIBP-TEST-KEY-0123456789"
WHOIS_URL = "https://rdap.org/domain/{query}"


def _config(**overrides: Any) -> ModuleConfig:
    base = ModuleConfig.from_settings(
        Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    )
    return replace(base, **overrides)


# ------------------------------------------------------------------ the allowlist
def test_the_new_providers_are_strictly_opt_in() -> None:
    assert set(OPT_IN_OSINT_PROVIDERS) == {"shodan", "censys", "certspotter", "hibp", "whois"}
    for name in OPT_IN_OSINT_PROVIDERS:
        assert name not in DEFAULT_OSINT_PROVIDERS
        assert SPECS[name].opt_in is True
    # Enabling OSINT with the defaults cannot reach any of them.
    hosts = OsintSettings(enabled=True).provider_hosts()
    for name in OPT_IN_OSINT_PROVIDERS:
        host = OSINT_PROVIDER_HOSTS[name]
        if host:
            assert host not in hosts


def test_a_keyed_provider_without_its_key_is_out_of_scope() -> None:
    unkeyed = OsintSettings(enabled=True, providers=("shodan", "censys", "hibp"))
    assert "api.shodan.io" not in unkeyed.provider_hosts()
    assert "search.censys.io" not in unkeyed.provider_hosts()
    assert "haveibeenpwned.com" not in unkeyed.provider_hosts()
    keyed = OsintSettings(
        enabled=True,
        providers=("shodan", "censys", "hibp"),
        shodan_api_key=_secret(SHODAN_KEY),
        censys_api_id=CENSYS_ID,
        censys_api_secret=_secret(CENSYS_SECRET),
        hibp_api_key=_secret(HIBP_KEY),
    )
    hosts = keyed.provider_hosts()
    assert {"api.shodan.io", "search.censys.io", "haveibeenpwned.com"} <= set(hosts)


def _secret(value: str) -> Any:
    from pydantic import SecretStr

    return SecretStr(value)


def test_censys_needs_both_halves_of_its_credential() -> None:
    half = OsintSettings(enabled=True, providers=("censys",), censys_api_id=CENSYS_ID)
    assert "search.censys.io" not in half.provider_hosts()
    assert half.provider_credential_problem("censys") is not None


def test_the_whois_default_endpoint_is_only_used_once_the_provider_is_enabled() -> None:
    plain = OsintSettings(enabled=True)
    assert "rdap.org" not in plain.provider_hosts()
    enabled = OsintSettings(enabled=True, providers=(*DEFAULT_OSINT_PROVIDERS, "whois"))
    assert "rdap.org" in enabled.provider_hosts()
    # An explicit endpoint turns the provider on by itself (the search-URL precedent).
    configured = OsintSettings(
        enabled=True, providers=(), whois_url="https://rdap.internal/domain/{query}"
    )
    assert "rdap.internal" in configured.provider_hosts()


def test_the_credentials_table_matches_the_provider_table() -> None:
    """Every declared credential is a real ``OsintSettings`` field (a typo would disable a
    provider silently)."""
    for name, fields in OSINT_PROVIDER_CREDENTIALS.items():
        assert name in OSINT_PROVIDER_HOSTS
        for field in fields:
            assert field in OsintSettings.__dataclass_fields__, field
        assert set(SPECS[name].required_credentials()) == set(fields)


def test_the_pacing_table_names_real_providers_and_rates() -> None:
    for name, rate in DEFAULT_OSINT_PROVIDER_RATE_LIMITS:
        assert name in OSINT_PROVIDER_HOSTS
        assert rate > 0
    assert OsintSettings().rate_limit_for("shodan") == pytest.approx(1.0)
    with pytest.raises(ConfigurationError, match="unknown OSINT provider"):
        OsintSettings(provider_rate_limits=(("nope", 1.0),))
    with pytest.raises(ConfigurationError, match="must be > 0"):
        OsintSettings(provider_rate_limits=(("shodan", 0.0),))


# ------------------------------------------------------------------ pacing
async def test_the_provider_layer_paces_calls_to_one_provider() -> None:
    """Two calls to the same provider are separated by ``1/rate`` seconds (REQ-INTEL-003)."""
    clock = {"now": 100.0}
    waits: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        clock["now"] += seconds

    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    osint = make_osint(providers=("certspotter",), auditor=auditor)
    osint.clock = lambda: clock["now"]  # type: ignore[assignment]
    osint.sleep = fake_sleep  # type: ignore[assignment]
    osint.rate_limits = {"certspotter": 1.0}
    await osint.fetch("certspotter", certspotter_url("example.com"))
    # A second, *different* URL (the cache is keyed by URL), so this really is a new call.
    await osint.fetch("certspotter", certspotter_url("other.example.com"))
    assert waits and waits[0] == pytest.approx(1.0, abs=0.01)
    sink = auditor._sink  # type: ignore[attr-defined]
    assert isinstance(sink, MemoryAuditSink)
    assert sink.of_action(AuditAction.INTEL_RATE_LIMITED)


# ------------------------------------------------------------------ keys never in a record
async def test_a_key_in_a_provider_url_is_redacted_everywhere() -> None:
    """Shodan's API takes its key as a query parameter; no record may keep it."""
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    osint = make_osint(providers=("shodan",), auditor=auditor)
    response = await osint.fetch(
        "shodan", shodan_host_url("203.0.113.9", api_key=SHODAN_KEY)
    )
    assert SHODAN_KEY not in response.url
    assert "key=[REDACTED" in response.url
    payload = response.evidence_payload()
    assert SHODAN_KEY not in str(payload)
    sink = auditor._sink  # type: ignore[attr-defined]
    assert isinstance(sink, MemoryAuditSink)
    assert all(SHODAN_KEY not in str(event.meta) for event in sink.events)
    assert all(SHODAN_KEY not in (event.target or "") for event in sink.events)


def test_the_display_url_never_carries_the_key() -> None:
    assert "key" not in shodan_display_url("203.0.113.9")
    assert SHODAN_KEY not in shodan_display_url("203.0.113.9")


# ------------------------------------------------------------------ parsers
def test_the_shodan_parser_reads_ports_and_vulns() -> None:
    payload = {
        "ip_str": "203.0.113.9",
        "ports": [22, 80],
        "hostnames": ["edge.example.com"],
        "org": "Example Corp",
        "vulns": ["CVE-2024-6387"],
        "last_update": "2026-10-28T10:00:00.000000",
    }
    record = parse_shodan_host(payload, address="203.0.113.9")
    assert record.found and record.ports == (22, 80)
    assert record.vulns == ("CVE-2024-6387",)
    assert record.to_dict()["org"] == "Example Corp"


def test_a_shodan_404_body_is_a_result_not_an_error() -> None:
    record = parse_shodan_host({"error": "No information available"}, address="203.0.113.9")
    assert record.found is False
    assert record.is_empty


def test_the_censys_parser_reads_services_and_products() -> None:
    record = parse_censys_host(
        {
            "code": 200,
            "result": {
                "ip": "203.0.113.9",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTP",
                        "transport_protocol": "TCP",
                        "software": [{"product": "nginx", "version": "1.24.0"}],
                    }
                ],
            },
        },
        address="203.0.113.9",
    )
    assert record.found
    assert record.ports == (443,)
    assert record.services[0].products == ("nginx 1.24.0",)


def test_an_unsuccessful_censys_body_is_not_indexed() -> None:
    assert parse_censys_host({"code": 404, "error": "Not Found"}, address="1.2.3.4").found is False
    assert parse_censys_host("not a mapping", address="1.2.3.4").found is False


def test_the_certspotter_parser_keeps_only_names_under_the_domain() -> None:
    issuances = parse_certspotter(
        [
            {
                "id": "ct-1",
                "dns_names": ["example.com", "www.example.com", "unrelated.invalid"],
                "not_before": "2026-10-26T08:00:00Z",
                "tbs_certificate": {"issuer": {"friendly_name": "Example CA"}},
            }
        ],
        domain="example.com",
    )
    assert len(issuances) == 1
    assert issuances[0].dns_names == ("example.com", "www.example.com")
    assert issuances[0].issuer == "Example CA"


def test_the_hibp_parser_summarises_breaches() -> None:
    breaches = parse_hibp_breaches(
        [
            {
                "Name": "ExampleForum",
                "Title": "Example Forum",
                "Domain": "example.com",
                "BreachDate": "2024-03-01",
                "PwnCount": 125000,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
            }
        ]
    )
    assert breaches[0].name == "ExampleForum"
    assert breaches[0].pwn_count == 125000
    assert "Passwords" in breaches[0].data_classes
    assert parse_hibp_breaches({"error": "none"}) == ()


def test_the_rdap_parser_reads_events_nameservers_and_the_registrar() -> None:
    domain = parse_rdap(
        {
            "handle": "2336799_DOMAIN_COM-VRSN",
            "ldhName": "EXAMPLE.COM",
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
            ],
            "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "A.IANA-SERVERS.NET"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]],
                    ],
                }
            ],
        }
    )
    assert domain.registrar == "Example Registrar"
    assert domain.created == "1995-08-14T04:00:00Z"
    assert domain.nameservers == ("a.iana-servers.net", "b.iana-servers.net")
    assert domain.statuses == ("client transfer prohibited",)


def test_the_rdap_url_template_and_path_form() -> None:
    assert (
        rdap_url_for("https://rdap.org/domain/{query}", "Example.COM")
        == "https://rdap.org/domain/example.com"
    )
    assert (
        rdap_url_for("https://rdap.internal/v1", "example.com")
        == "https://rdap.internal/v1/example.com"
    )


def test_the_new_url_builders_are_exact() -> None:
    assert censys_host_url("203.0.113.9") == "https://search.censys.io/api/v2/hosts/203.0.113.9"
    assert "domain=example.com" in certspotter_url("example.com")
    assert hibp_breaches_url("example.com").endswith("/api/v3/breaches?domain=example.com")
    assert "key=" + SHODAN_KEY in shodan_host_url("203.0.113.9", api_key=SHODAN_KEY)


# ------------------------------------------------------------------ the checks
def _provider_osint(providers: tuple[str, ...], auditor: Auditor | None = None) -> Any:
    return make_osint(providers=providers, auditor=auditor, whois_url=WHOIS_URL)


async def test_exposure_drift_reports_services_outside_the_scan_coverage() -> None:
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    results, _memory = await run_check(
        ServiceExposureDrift,
        ADDRESS,
        osint=_provider_osint(("shodan", "censys"), auditor=auditor),
        config=_config(shodan_api_key=_secret(SHODAN_KEY)),
    )
    assert results, "the check should have produced a comparison"
    artifact = results[0].evidence[0].payload
    assert artifact["scan_view_source"] == "catalogue coverage"
    assert artifact["provider_view"]
    candidates = [item for item in results if item.status == "vulnerable"]
    assert candidates, "ports outside the catalogue coverage are a drift finding"
    detail = candidates[0].detail or ""
    # 31337 is not in the shipped port catalogue, so this scan would never look at it.
    assert "31337" in detail
    assert candidates[0].cwe == "CWE-668"
    # The key never reaches a finding's evidence.
    assert SHODAN_KEY not in str(candidates[0].evidence[0].payload)


async def test_exposure_drift_is_skipped_without_a_provider_and_the_refusal_is_audited() -> None:
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    osint = make_osint(providers=("crtsh",), auditor=auditor)
    results, _memory = await run_check(ServiceExposureDrift, ADDRESS, osint=osint)
    assert results[0].status == "info"
    assert "not run" in results[0].title
    assert "strictly opt-in" in (results[0].detail or "")
    sink = auditor._sink  # type: ignore[attr-defined]
    assert isinstance(sink, MemoryAuditSink)
    blocked = sink.of_action(AuditAction.INTEL_PROVIDER_BLOCKED)
    assert {event.meta["provider"] for event in blocked} == {"shodan", "censys"}


async def test_exposure_drift_needs_osint_at_all() -> None:
    results, _memory = await run_check(ServiceExposureDrift, ADDRESS, osint=None)
    assert results[0].status == "info"
    assert "ARACHNE_OSINT_ENABLED" in (results[0].detail or "")


async def test_ct_surprise_reports_recent_certificates_and_uncovered_names() -> None:
    from arachne.core.target import TargetDefinition, TargetSelector

    # A target whose scope deliberately excludes one CT name, so the "we do not cover this
    # name" half of the check has something to say.
    definition = TargetDefinition(
        name="ct-fixture",
        targets=[
            TargetSelector(kind=TargetKind.DOMAIN, value="example.com"),
        ],
        exclusions=[TargetSelector(kind=TargetKind.DOMAIN, value="staging.example.com")],
    )
    results, _memory = await run_check(
        CertificateSurprise,
        DOMAIN,
        osint=_provider_osint(("certspotter", "whois")),
        config=_config(osint_ct_window_days=36500),
        definition=definition,
    )
    statuses = [item.status for item in results]
    assert "vulnerable" in statuses
    titles = " ".join(item.title for item in results if item.status == "vulnerable")
    assert "issued for example.com" in titles
    artifact = results[0].evidence[0].payload if results[0].evidence else {}
    assert artifact["ct_source"] == "certspotter"
    assert artifact["registration"]["registrar"] == "Example Registrar"
    assert "staging.example.com" in artifact["out_of_scope_names"]


async def test_ct_surprise_is_quiet_when_nothing_is_inside_the_window() -> None:
    results, _memory = await run_check(
        CertificateSurprise,
        DOMAIN,
        osint=_provider_osint(("certspotter",)),
        config=_config(osint_ct_window_days=0),
    )
    assert not any("issued for" in item.title for item in results if item.status == "vulnerable")


async def test_breach_exposure_summarises_the_breaches_it_finds() -> None:
    results, _memory = await run_check(
        BreachExposure,
        DOMAIN,
        osint=_provider_osint(("hibp",)),
        config=_config(hibp_api_key=_secret(HIBP_KEY)),
    )
    assert len(results) == 1
    finding = results[0]
    assert finding.status == "vulnerable"
    assert "1 breach(es) exposed accounts at example.com" in finding.title
    assert "125000" in (finding.detail or "")
    payload = finding.evidence[-1].payload
    assert payload["breaches"][0]["name"] == "ExampleForum"
    assert "Passwords" in payload["data_classes"]
    assert HIBP_KEY not in str(payload)


async def test_breach_exposure_skips_without_its_key() -> None:
    results, _memory = await run_check(
        BreachExposure, DOMAIN, osint=_provider_osint(("hibp",)), config=_config()
    )
    assert results[0].status == "info"
    assert "ARACHNE_HIBP_API_KEY" in (results[0].detail or "")


async def test_breach_exposure_skips_when_the_provider_is_not_opted_in() -> None:
    results, _memory = await run_check(
        BreachExposure,
        DOMAIN,
        osint=_provider_osint(("crtsh",)),
        config=_config(hibp_api_key=_secret(HIBP_KEY)),
    )
    assert results[0].status == "info"
    assert "strictly opt-in" in (results[0].detail or "")


def test_the_intel_checks_declare_their_credential_needs() -> None:
    assert ServiceExposureDrift.metadata.requires_credentials == ("shodan_api_key",)
    assert BreachExposure.metadata.requires_credentials == ("hibp_api_key",)
    assert CertificateSurprise.metadata.requires_credentials == ()
    for check in (ServiceExposureDrift, CertificateSurprise, BreachExposure):
        assert check.metadata.enabled_by_default is False
        assert check.metadata.type == "passive"


def test_censys_auth_is_basic_base64() -> None:
    from arachne.modules.m1.intel import _basic_auth

    header = _basic_auth(f"{CENSYS_ID}:{CENSYS_SECRET}")["authorization"]
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    assert decoded == f"{CENSYS_ID}:{CENSYS_SECRET}"


def test_the_new_checks_target_kinds_are_bounded() -> None:
    assert set(ServiceExposureDrift.metadata.target_kinds) == {TargetKind.IP, TargetKind.CIDR}
    assert set(CertificateSurprise.metadata.target_kinds) == {
        TargetKind.DOMAIN,
        TargetKind.DOMAIN_PATTERN,
    }
    assert PROVIDER_HOSTS["censys"] == "search.censys.io"
