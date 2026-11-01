"""The OSINT provider layer: scope agreement, parsing, budgets and the replay transport.

The provider layer is a second HTTP client, which makes it the most likely place for a scope
hole to appear. These tests assert the properties that keep it closed:

* every provider's declared host is exactly what the deployment allowlist says (so "which
  third parties may be contacted" has one answer in the codebase);
* an unconfigured, unselected or credential-less provider produces a reason, never a request;
* a request that fails degrades to :class:`OsintError` (data), and the budget stops a runaway
  check rather than letting it spend without limit;
* recorded-fixture replay is exact, and refuses to guess when a recording is ambiguous.
"""

from __future__ import annotations

import httpx
import pytest
from tests.helpers.checks import make_osint

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import OSINT_PROVIDER_HOSTS, OsintSettings
from arachne.core.errors import ConfigurationError, OsintError
from arachne.core.http import RecordedResponse, fixture_transport
from arachne.modules.providers import (
    PROVIDER_HOSTS,
    SPECS,
    build_osint_access,
    provider_scope,
)
from arachne.modules.providers.sources import (
    circl_url,
    commoncrawl_url,
    crtsh_url,
    github_code_search_url,
    internetdb_url,
    parse_circl,
    parse_commoncrawl_jsonl,
    parse_crtsh,
    parse_github_code_search,
    parse_internetdb,
    parse_search_results,
    parse_wayback_cdx,
    search_url_for,
    urls_from_rows,
    wayback_cdx_url,
)


# ------------------------------------------------------------------ scope agreement
def test_provider_hosts_match_the_deployment_allowlist() -> None:
    """The provider table and `core.config` must describe the same allowlist."""
    assert PROVIDER_HOSTS == OSINT_PROVIDER_HOSTS
    for name, spec in SPECS.items():
        assert spec.host == PROVIDER_HOSTS[name]


def test_provider_scope_is_deny_by_default() -> None:
    assert provider_scope(()).is_empty
    scope = provider_scope(("crt.sh",))
    assert scope.check("crt.sh").allowed
    assert not scope.check("evil.example").allowed


def test_osint_settings_reject_an_unknown_provider() -> None:
    with pytest.raises(ConfigurationError, match="unknown OSINT provider"):
        OsintSettings(providers=("shodan-pro",))


def test_osint_settings_hosts_follow_the_enabled_providers() -> None:
    settings = OsintSettings(providers=("crtsh", "internetdb"))
    assert settings.provider_hosts() == ("crt.sh", "internetdb.shodan.io")
    assert OsintSettings(
        providers=("crtsh",), search_url="https://x.example/search"
    ).provider_hosts() == (
        "crt.sh",
        "x.example",
    )
    # GitHub's host is only allowlisted when a token exists to authenticate with.
    assert "api.github.com" not in OsintSettings(providers=("github",)).provider_hosts()
    assert (
        "api.github.com"
        in OsintSettings(
            providers=("github",),
            github_token="t",  # type: ignore[arg-type]
        ).provider_hosts()
    )


# ------------------------------------------------------------------ construction
def test_disabled_osint_builds_nothing() -> None:
    assert build_osint_access(enabled=False, providers=("crtsh",)) is None
    assert build_osint_access(enabled=True, providers=()) is None


def test_enabling_a_search_url_enables_the_search_provider() -> None:
    access = build_osint_access(
        enabled=True, providers=("crtsh",), search_url="https://search.example.net/search"
    )
    assert access is not None
    assert access.available("search")
    assert access.client.scope.check("search.example.net").allowed


def test_an_unavailable_provider_explains_itself() -> None:
    access = make_osint(providers=("crtsh",), search_url=None)
    assert access.available("crtsh")
    assert not access.available("search")
    assert "ARACHNE_OSINT_SEARCH_URL" in access.unavailable_reason("search")
    assert not access.available("github")
    assert "ARACHNE_OSINT_PROVIDERS" in access.unavailable_reason("github")


def test_an_unknown_provider_is_an_error_not_a_request() -> None:
    access = make_osint()
    with pytest.raises(OsintError, match="unknown OSINT provider"):
        access.spec("nonexistent")


async def test_fetch_refuses_a_provider_it_may_not_use() -> None:
    access = make_osint(providers=("crtsh",))
    with pytest.raises(OsintError, match="refusing to query"):
        await access.fetch("internetdb", internetdb_url("93.184.216.34"))


# ------------------------------------------------------------------ budget and audit
async def test_the_budget_stops_the_checks_and_is_audited() -> None:
    sink = MemoryAuditSink()
    access = make_osint(budget=1, auditor=Auditor(sink, actor="pytest"))
    first = await access.fetch("crtsh", crtsh_url("example.com"))
    assert first.ok
    assert access.remaining == 0
    with pytest.raises(OsintError, match="budget of 1 is spent"):
        await access.fetch("circl", circl_url("example.com"))
    assert AuditAction.BUDGET_EXHAUSTED.value in sink.actions()


async def test_every_query_is_audited_with_its_provider() -> None:
    sink = MemoryAuditSink()
    access = make_osint(auditor=Auditor(sink, actor="pytest"))
    await access.fetch("crtsh", crtsh_url("example.com"))
    events = sink.of_action(AuditAction.OSINT_QUERY)
    assert len(events) == 1
    assert events[0].meta["provider"] == "crtsh"
    assert events[0].meta["host"] == "crt.sh"


async def test_repeated_queries_are_cached_so_merging_sources_is_cheap() -> None:
    access = make_osint()
    first = await access.fetch("crtsh", crtsh_url("example.com"))
    second = await access.fetch("crtsh", crtsh_url("example.com"))
    assert not first.cached
    assert second.cached
    assert access.used == 1


async def test_a_refused_request_becomes_osint_error_with_the_reason() -> None:
    """A host outside the provider allowlist is refused by the client, then reported as data.

    The scope is the whole point of the second client: a check cannot reach a source the
    deployment did not name, and the failure surfaces as an ``OsintError`` the check turns
    into a recorded result rather than an exception that ends the scan.
    """
    access = make_osint()
    with pytest.raises(OsintError, match="OSINT query to 'internetdb' failed"):
        await access.fetch("internetdb", "https://not-a-provider.example/1")


async def test_a_fixture_gap_is_a_loud_non_200_not_a_silent_empty_body() -> None:
    access = make_osint()
    response = await access.fetch("internetdb", internetdb_url("203.0.113.9"))
    assert response.status == 501
    assert "fixture-missing" in response.text
    assert response.ok is False


async def test_evidence_payload_is_bounded_and_hashed() -> None:
    access = make_osint()
    response = await access.fetch("crtsh", crtsh_url("example.com"))
    payload = response.evidence_payload(limit=40)
    assert payload["provider"] == "crtsh"
    assert payload["status"] == 200
    assert payload["body_truncated"] is True
    assert len(payload["body_preview"]) == 40
    assert payload["sha256"]


# ------------------------------------------------------------------ replay transport
async def test_replay_is_exact_and_loud_about_a_fixture_gap() -> None:
    import httpx as _httpx

    from arachne.core.http import ScopedHttpClient
    from arachne.core.safety import Scope, StaticResolver

    routes = (
        RecordedResponse("GET", "https://crt.sh/?q=a", body='["one"]'),
        RecordedResponse("GET", "https://crt.sh/?q=b", body='["two"]'),
    )
    client = ScopedHttpClient(
        scope=Scope(allowed_hosts=("crt.sh",)),
        resolver=StaticResolver(("93.184.216.34",)),
        transport=fixture_transport(routes),
    )
    assert (await client.get("https://crt.sh/?q=a")).body == '["one"]'
    assert (await client.get("https://crt.sh/?q=b")).body == '["two"]'
    # Two recordings share host+path, so the path fallback is ambiguous and must not guess.
    missing = await client.get("https://crt.sh/?q=c")
    assert missing.status_code == 501
    assert "fixture-missing" in missing.body
    await client.aclose()
    assert _httpx is not None


def test_replay_falls_back_to_host_and_path_only_when_unique() -> None:
    routes = (RecordedResponse("GET", "https://x.example/a?token=1", body="hello"),)
    transport = fixture_transport(routes)
    request = httpx.Request("GET", "https://x.example/a?token=2")
    response = _call(transport, request)
    assert response.status_code == 200
    assert response.text == "hello"


def _call(transport: httpx.AsyncBaseTransport, request: httpx.Request) -> httpx.Response:
    import asyncio

    return asyncio.run(_run(transport, request))


async def _run(transport: httpx.AsyncBaseTransport, request: httpx.Request) -> httpx.Response:
    async with httpx.AsyncClient(transport=transport, base_url="https://x.example") as client:
        return await client.request(request.method, str(request.url))


# ------------------------------------------------------------------ parsers
def test_crtsh_url_and_parser() -> None:
    assert crtsh_url("Example.COM") == "https://crt.sh/?q=%25.example.com&output=json"
    payload = [
        {"name_value": "example.com\n*.example.com", "issuer_name": "CA", "not_after": "2025"},
        {"common_name": "other.example.org", "issuer_name": "CA2"},
        {"nothing": True},
    ]
    parsed = parse_crtsh(payload)
    assert parsed.hosts == ("example.com", "other.example.org")
    assert parsed.issuers == ("CA", "CA2")
    # Scoped to the queried domain, a fixture cannot smuggle in unrelated names.
    scoped = parse_crtsh(payload, domain="example.com")
    assert scoped.hosts == ("example.com",)
    assert parse_crtsh("nonsense").hosts == ()


def test_wayback_cdx_url_and_parser() -> None:
    url = wayback_cdx_url("example.com", limit=5)
    assert url.startswith("https://web.archive.org/cdx/search/cdx?")
    assert "limit=5" in url and "collapse=urlkey" in url
    rows = parse_wayback_cdx(
        [
            ["original", "timestamp"],
            ["https://example.com/a", "20240101"],
            ["https://example.com/b", "20240102"],
        ]
    )
    assert urls_from_rows(rows) == ("https://example.com/a", "https://example.com/b")
    assert parse_wayback_cdx([]) == ()
    assert parse_wayback_cdx([[]]) == ()


def test_commoncrawl_url_and_jsonl_parser() -> None:
    url = commoncrawl_url("example.com", index="CC-MAIN-2024-51", limit=3)
    assert "CC-MAIN-2024-51-index" in url and "output=json" in url
    rows = parse_commoncrawl_jsonl(
        '{"url": "https://example.com/a", "status": "200"}\n'
        "not json at all\n"
        '{"url": "https://example.com/b"}\n'
    )
    assert urls_from_rows(rows) == ("https://example.com/a", "https://example.com/b")


def test_internetdb_url_and_parser() -> None:
    assert internetdb_url("93.184.216.34") == "https://internetdb.shodan.io/93.184.216.34"
    record = parse_internetdb(
        {
            "ports": [80, "443"],
            "hostnames": ["a"],
            "cpes": ["cpe:/a:x"],
            "tags": [],
            "vulns": ["CVE-1"],
        },
        address="1.2.3.4",
    )
    assert record.ports == (80, 443)
    assert record.vulns == ("CVE-1",)
    assert not record.is_empty
    # "No information available" is a result, not an error.
    empty = parse_internetdb({"detail": "No information available"}, address="1.2.3.4")
    assert empty.found is False and empty.is_empty
    assert parse_internetdb("junk", address="1.2.3.4").found is False


def test_circl_url_and_parser_strips_mx_preference() -> None:
    assert circl_url("Example.com") == "https://www.circl.lu/pdns/query/example.com"
    records = parse_circl(
        '{"rrtype": "A", "rdata": "93.184.216.34", "rrname": "example.com",'
        ' "time_first": 1, "time_last": 2}\n'
        '{"rrtype": "MX", "rdata": "10 mail.example.com", "rrname": "example.com"}\n'
        '{"rrtype": "NS", "rdata": "ns1.example.net", "rrname": "example.com"}\n'
        '{"rrtype": "CNAME", "rdata": "cdn.example.net", "rrname": "www.example.com"}\n'
    )
    assert records.addresses == ("93.184.216.34",)
    assert records.mail_servers == ("mail.example.com",)
    assert records.name_servers == ("ns1.example.net",)
    assert records.hostnames == ("cdn.example.net",)
    assert records.first_seen == "1" and records.last_seen == "2"
    assert not records.is_empty
    assert parse_circl("").is_empty


def test_search_url_builder_and_parser() -> None:
    assert search_url_for("https://s.example/search?q={query}&limit={limit}", "a b") == (
        "https://s.example/search?q=a%20b&limit=20"
    )
    assert search_url_for("https://s.example/search", "a b") == (
        "https://s.example/search?q=a+b&limit=20&format=json"
    )
    hits = parse_search_results(
        {
            "results": [
                {"url": "https://x/1", "title": "T", "content": "Snippet"},
                {"link": "https://x/2"},
            ]
        }
    )
    assert hits[0].url == "https://x/1" and hits[0].snippet == "Snippet"
    assert hits[1].url == "https://x/2"
    assert parse_search_results({"results": "nope"}) == ()
    assert parse_search_results(None) == ()


def test_github_url_and_parser() -> None:
    url = github_code_search_url('"example.com" filename:.env', per_page=500)
    assert url.startswith("https://api.github.com/search/code?q=")
    assert "per_page=100" in url  # clamped to the API's maximum
    matches = parse_github_code_search(
        {"items": [{"html_url": "u", "path": "p/.env", "repository": {"full_name": "o/r"}}]}
    )
    assert matches[0]["repository"] == "o/r"
    assert parse_github_code_search({"items": []}) == ()
    assert parse_github_code_search(None) == ()


def test_osint_access_can_be_closed() -> None:
    import asyncio

    access = make_osint()
    asyncio.run(access.aclose())


def test_a_provider_response_reports_its_own_shape() -> None:
    from arachne.modules.providers import ProviderResponse

    exchange = _exchange()
    response = ProviderResponse(
        provider="crtsh", url="https://crt.sh/x", status=200, exchange=exchange
    )
    assert response.ok
    assert response.json() == {"a": 1}
    assert ProviderResponse("p", "u", 500, exchange).ok is False


def _exchange():  # type: ignore[no-untyped-def]
    from arachne.core.http import HttpExchange

    return HttpExchange(method="GET", url="https://crt.sh/x", status_code=200, body='{"a": 1}')
