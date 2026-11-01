"""The nine M1 checks, one section each (docs/spec/05- M1, research ch. 01).

Every check is run the way the pipeline runs it — through :class:`CheckContext` with recorded
OSINT responses — so what these tests assert is the *contract each check owes the framework*:

* it reports "not run" (with a reason) rather than failing when its source is unavailable,
  which is what makes OSINT-off the safe default (F-02-09);
* it records what it discovers as scoped assets (F-01-02) and raises candidates only for
  exposures (ADR-02: no severity, no prose-only findings);
* it never lets a hostile or unexpected body turn into an exception or unbounded work.
"""

from __future__ import annotations

import pytest
from tests.helpers.checks import FIXTURES, asset_for, make_osint, make_target_client, run_check

from arachne.core.audit import AuditAction
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError, OsintError
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.safety import Scope, StaticResolver
from arachne.core.target import TargetKind
from arachne.modules.base import Asset
from arachne.modules.context import ModuleConfig
from arachne.modules.extract import match_sensitive_paths
from arachne.modules.m1 import (
    BucketHunt,
    CodeSecretMining,
    CtLookup,
    DnsTxtMining,
    DocMetadata,
    DorkSweep,
    EmailHarvest,
    FaviconHash,
    InternetDbTriage,
    JsAssetScan,
    PassiveDns,
    SubdomainPassive,
    WebArchiveHarvest,
)
from arachne.modules.m1.exposure import _infer_pattern, load_dork_corpus
from arachne.modules.m1.hardening import _bucket_names, _image_exif, _pdf_info
from arachne.modules.m1.inventory import _hosts_from_cdx
from arachne.modules.providers.sources import github_code_search_url

DOMAIN = asset_for("domain", "example.com")
URL_ASSET = asset_for("url", "https://example.com/")
NETWORK = asset_for("network", "93.184.216.32/30")


def module_config(**overrides: object) -> ModuleConfig:
    """The effective module configuration, with the field under test overridden."""
    import dataclasses

    base = ModuleConfig.from_settings(
        Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


# ------------------------------------------------------------------ unavailability
@pytest.mark.parametrize(
    ("check", "asset"),
    [
        (CtLookup, DOMAIN),
        (PassiveDns, DOMAIN),
        (SubdomainPassive, DOMAIN),
        (WebArchiveHarvest, DOMAIN),
        (DorkSweep, DOMAIN),
        (EmailHarvest, DOMAIN),
        (InternetDbTriage, NETWORK),
        (CodeSecretMining, DOMAIN),
    ],
)
async def test_a_check_without_osint_reports_a_skip_not_a_failure(check, asset) -> None:  # type: ignore[no-untyped-def]
    results, _memory = await run_check(check, asset, osint=None)
    assert len(results) == 1
    assert results[0].status == "info"
    assert "not run" in results[0].title
    assert any(item.payload.get("skipped") for item in results[0].evidence)


async def test_a_check_waits_for_its_own_provider() -> None:
    """Enabled OSINT that lacks *this* provider still yields a skip with the reason."""
    results, _ = await run_check(CtLookup, DOMAIN, osint=make_osint(providers=("internetdb",)))
    assert results[0].status == "info"
    assert any(item.payload.get("skipped") for item in results[0].evidence)


# ------------------------------------------------------------------ m1.ct-lookup
async def test_ct_lookup_records_hosts_from_certificate_transparency() -> None:
    results, memory = await run_check(CtLookup, DOMAIN, osint=make_osint())
    assert [r.status for r in results] == ["info"]
    # The apex plus the four subdomains: www, staging, jira and mail.
    assert "5 hostname(s)" in results[0].title
    hosts = {
        record.value for record in memory.store.list_assets(memory.scan_id) if record.kind == "host"
    }
    assert {
        "www.example.com",
        "staging.example.com",
        "jira.example.com",
        "mail.example.com",
    } <= hosts
    evidence = results[0].evidence[0].payload
    # Non-production names are called out for the exposure ledger, not raised as findings.
    assert "staging.example.com" in evidence["non_production_hosts"]


async def test_ct_lookup_handles_an_answer_with_no_certificates() -> None:
    routes = {
        "GET x": {
            "method": "GET",
            "url": "https://crt.sh/?q=%25.example.com&output=json",
            "body": "[]",
        }
    }
    results, _ = await run_check(CtLookup, DOMAIN, osint=make_osint(routes=routes))
    assert results[0].status == "not_vulnerable"


# ------------------------------------------------------------------ m1.passive-dns
async def test_passive_dns_reports_history_and_discards_out_of_scope_cnames() -> None:
    results, memory = await run_check(PassiveDns, DOMAIN, osint=make_osint())
    assert results[0].status == "info"
    assert "2 address(es)" in results[0].title
    payload = results[0].evidence[0].payload
    # The historical A record of a decommissioned host is part of the answer, and exactly the
    # kind of thing a takeover check (M3, S6) wants to see.
    assert payload["addresses"] == ["93.184.216.34", "203.0.113.10"]
    assert payload["cname_targets"] == ["example-net.example-cdn.net"]
    # A CNAME pointing at someone else's infrastructure is discovery, not inventory.
    values = {record.value for record in memory.store.list_assets(memory.scan_id)}
    assert "example-net.example-cdn.net" not in values
    assert any(event.action is AuditAction.SCOPE_DISCARDED for event in memory.sink.events)


# ------------------------------------------------------------------ m1.subdomain-passive
async def test_subdomain_passive_merges_sources_and_marks_agreement() -> None:
    results, _memory = await run_check(SubdomainPassive, DOMAIN, osint=make_osint())
    assert results[0].status == "info"
    assert "5 subdomain(s)" in results[0].title
    artifact = results[0].evidence[-1].payload
    assert "crtsh" in artifact["sources"]["staging.example.com"]
    assert artifact["multi_source"], "hosts seen by two sources should be flagged"
    assert "legacy.example.com" in artifact["subdomains"]


async def test_subdomain_passive_needs_at_least_one_answering_source() -> None:
    routes = {
        "GET x": {
            "method": "GET",
            "url": "https://crt.sh/?q=%25.example.com&output=json",
            "body": "junk",
        },
        "GET y": {
            "method": "GET",
            "url": "https://www.circl.lu/pdns/query/example.com",
            "body": "",
        },
        "GET z": {
            "method": "GET",
            "url": "https://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=original%2Ctimestamp%2Cstatuscode%2Cmimetype&collapse=urlkey&limit=100",
            "body": "[]",
        },
    }
    results, _ = await run_check(
        SubdomainPassive,
        DOMAIN,
        osint=make_osint(routes=routes),
        config=module_config(max_results=100),
    )
    # Each source answered, so the check reports zero findings rather than a skip.
    assert results[0].status in {"not_vulnerable", "info"}


# ------------------------------------------------------------------ m1.webarchive-harvest
async def test_webarchive_harvest_records_urls_and_flags_sensitive_paths() -> None:
    results, memory = await run_check(WebArchiveHarvest, DOMAIN, osint=make_osint())
    statuses = [r.status for r in results]
    assert statuses == ["info", "vulnerable"]
    assert "URL(s)" in results[0].title
    values = {record.value for record in memory.store.list_assets(memory.scan_id)}
    assert "https://example.com/.env" in values
    assert "https://legacy.example.com/backup.zip" in values
    candidate = results[1]
    assert candidate.confidence < 0.5  # archived ≠ live: the analyzer decides
    matches = candidate.evidence[-1].payload["matches"]
    assert any(item["pattern"] == ".env" for item in matches)


def test_sensitive_path_matching_is_about_paths_not_substrings() -> None:
    assert match_sensitive_paths("https://example.com/.git/config")
    assert match_sensitive_paths("https://example.com/admin/login")
    assert not match_sensitive_paths("https://example.com/about")
    assert not match_sensitive_paths("https://example.com/assets/app.js")


# ------------------------------------------------------------------ m1.dork-sweep
SEARCH_CONFIG = module_config(
    search_url="https://search.example.net/search?q={query}&limit={limit}&format=json"
)


async def test_dork_sweep_runs_the_corpus_and_raises_exposures() -> None:
    results, memory = await run_check(DorkSweep, DOMAIN, osint=make_osint(), config=SEARCH_CONFIG)
    statuses = [r.status for r in results]
    assert statuses[0] == "info"
    assert "dork(s)" in results[0].title
    candidates = [r for r in results if r.status == "vulnerable"]
    # The fixture answers four exposure dorks (env file, backup, admin panel, non-production
    # host) and two non-exposure ones (API docs, documents); only the exposures are
    # candidates, because "a document is indexed" is not yet an exposure.
    assert len(candidates) == 4
    assert all("search index exposes" in r.title for r in candidates)
    assert all("example.com" in r.title for r in candidates)
    corpus = results[0].evidence[0].payload
    assert corpus["corpus_version"] == "1.0"
    values = {record.value for record in memory.store.list_assets(memory.scan_id)}
    assert "https://example.com/.env" in values


def test_the_dork_corpus_is_validated() -> None:
    version, entries = load_dork_corpus()
    assert version == "1.0"
    assert len(entries) >= 10
    assert all("{domain}" in entry.query for entry in entries)
    assert any(entry.exposure for entry in entries)
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_dork_corpus("/nonexistent/corpus.yaml")


# ------------------------------------------------------------------ m1.email-harvest
async def test_email_harvest_reports_addresses_and_infers_the_pattern() -> None:
    results, _ = await run_check(EmailHarvest, DOMAIN, osint=make_osint(), config=SEARCH_CONFIG)
    assert results[0].status == "info"
    assert "3 address(es)" in results[0].title
    artifact = results[0].evidence[0].payload
    assert "jane.doe@example.com" in artifact["addresses"]
    assert artifact["inferred_pattern"] == "first.last"
    # A personal address found in the same results is not attributed to the organization.
    assert "personal.jane@gmail.com" in artifact["third_party_addresses"]
    assert results[1].status == "vulnerable"


def test_pattern_inference_needs_two_samples() -> None:
    assert _infer_pattern(["a.b@x.com"]) is None
    assert _infer_pattern(["a.b@x.com", "c.d@x.com"]) == "first.last"
    assert _infer_pattern(["jsmith@x.com", "jdoe@x.com"]) == "firstname"
    # A digit suffix is its own shape (``name.sequence``), and it is still named.
    assert _infer_pattern(["j.smith2@x.com", "a.b2@x.com", "c@x.com"]) == "name.sequence"


# ------------------------------------------------------------------ m1.internetdb-triage
async def test_internetdb_triage_reports_services_and_cves() -> None:
    results, memory = await run_check(
        InternetDbTriage, asset_for("host", "93.184.216.34"), osint=make_osint()
    )
    assert [r.status for r in results] == ["info", "vulnerable"]
    assert "2 known CVE(s) indexed" in results[1].title
    artifact = results[1].evidence[-1].payload
    assert artifact["cpes"] == ["cpe:/a:igor_sysoev:nginx:1.18.0", "cpe:/a:openbsd:openssh:8.2"]
    hosts = {
        record.value: record.meta
        for record in memory.store.list_assets(memory.scan_id)
        if record.kind == "host"
    }
    assert hosts["93.184.216.34"]["ports"] == [22, 80, 443]


async def test_internetdb_triage_handles_an_address_with_no_index_entry() -> None:
    results, _ = await run_check(
        InternetDbTriage, asset_for("host", "93.184.216.35"), osint=make_osint()
    )
    assert [r.status for r in results] == ["not_vulnerable"]


async def test_internetdb_triage_walks_a_network_within_its_cap() -> None:
    """A CIDR is expanded arithmetically, and the cap keeps the lookup count bounded."""
    results, _ = await run_check(
        InternetDbTriage,
        asset_for("network", "93.184.216.32/30"),
        osint=make_osint(),
        config=module_config(max_hosts_per_network=256),
    )
    # .33 and .34 are the usable addresses of a /30; .32/.35 are network/broadcast. Only .34
    # has an indexed service in the recordings: one info result and one candidate.
    assert [r.status for r in results] == ["info", "vulnerable"]
    assert "2 lookup(s)" in results[0].detail


def test_network_enumeration_never_expands_a_default_route() -> None:
    from arachne.modules.m1.assets import _addresses_of

    assert _addresses_of("93.184.216.34", 5) == ("93.184.216.34",)
    assert _addresses_of("not-an-address", 5) == ()
    assert len(_addresses_of("10.0.0.0/8", 10)) == 10


# ------------------------------------------------------------------ m1.js-asset-scan
async def test_js_asset_scan_extracts_endpoints_and_reports_secrets_by_kind() -> None:
    from arachne.core.safety import Scope

    scope = Scope(allowed_domains=("example.com",))
    results, memory = await run_check(JsAssetScan, URL_ASSET, http=make_target_client(scope))
    statuses = [r.status for r in results]
    assert statuses == ["info", "vulnerable"]
    artifact = results[1].evidence[-1].payload
    assert "aws-access-key-id" in artifact["matched_patterns"]
    # The raw key never reaches a result: the bundle is redacted at capture time.
    assert "AKIAIOSFODNN7EXAMPLE" not in repr([r.to_dict() for r in results])
    values = {record.value for record in memory.store.list_assets(memory.scan_id)}
    assert "https://example.com/api/v1/admin/users" in values


async def test_js_asset_scan_without_a_client_skips() -> None:
    results, _ = await run_check(JsAssetScan, URL_ASSET, http=None)
    assert results[0].status == "info"
    assert "dry run" in results[0].detail


async def test_js_asset_scan_never_fetches_out_of_scope_scripts() -> None:
    """The recorded page references a CDN bundle; the scope guard refuses it (F-01-02)."""
    from arachne.core.safety import Scope

    scope = Scope(allowed_domains=("example.com",))
    results, _ = await run_check(JsAssetScan, URL_ASSET, http=make_target_client(scope))
    artifact = results[0].evidence[-1].payload
    assert any("cdn.example.net" in failure for failure in artifact["script_failures"])


# ------------------------------------------------------------------ m1.code-secret-mining
async def test_code_secret_mining_needs_a_token() -> None:
    results, _ = await run_check(CodeSecretMining, DOMAIN, osint=make_osint())
    assert results[0].status == "info"
    assert "ARACHNE_GITHUB_TOKEN" in results[0].detail


async def test_code_secret_mining_raises_candidates_per_query_class() -> None:
    routes = {}
    for _label, query in CodeSecretMining.QUERY_TEMPLATES:
        url = github_code_search_url(query.format(domain="example.com"), per_page=100)
        routes[f"GET {url}"] = {
            "method": "GET",
            "url": url,
            "body": (
                '{"items": [{"html_url": "https://github.com/o/r/blob/main/.env", '
                '"path": ".env", "repository": {"full_name": "o/r"}}]}'
            ),
        }
    from pydantic import SecretStr

    results, _ = await run_check(
        CodeSecretMining,
        DOMAIN,
        osint=make_osint(providers=("github",), routes=routes),
        config=module_config(github_token=SecretStr("token-value")),
    )
    assert all(r.status == "vulnerable" for r in results)
    assert len(results) == len(CodeSecretMining.QUERY_TEMPLATES)
    assert "o/r" in results[0].detail


# ------------------------------------------------------------------ module config
def test_module_config_projects_settings() -> None:
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
    )
    config = ModuleConfig.from_settings(settings)
    assert config.osint_enabled is False
    assert config.max_hosts_per_network == settings.planner.max_hosts_per_network


def test_every_m1_check_declares_a_bounded_estimate() -> None:
    for check in (
        CtLookup,
        PassiveDns,
        SubdomainPassive,
        WebArchiveHarvest,
        DorkSweep,
        EmailHarvest,
        InternetDbTriage,
        JsAssetScan,
        CodeSecretMining,
        DnsTxtMining,
        FaviconHash,
        BucketHunt,
        DocMetadata,
    ):
        metadata = check.metadata
        assert metadata.estimated_requests >= 1, metadata.id
        assert metadata.target_kinds
        # Every M1 check is scoped to a target kind a real scan can declare.
        assert set(metadata.target_kinds) & {
            TargetKind.DOMAIN,
            TargetKind.DOMAIN_PATTERN,
            TargetKind.URL,
            TargetKind.IP,
            TargetKind.CIDR,
            TargetKind.GIT,
        }


def test_cdx_host_extraction_ignores_junk_urls() -> None:
    from arachne.modules.providers import ProviderResponse

    class FakeExchange:
        body = '{"a": 1}'

        def json_body(self):  # type: ignore[no-untyped-def]
            return [["original"], ["not a url at all", "1"]]

    class FakeResponse(ProviderResponse):  # type: ignore[misc]
        pass

    fake = FakeResponse("wayback", "u", 200, FakeExchange())  # type: ignore[arg-type]
    assert _hosts_from_cdx(fake) == set()


def test_asset_kind_guard_for_buckets() -> None:
    from arachne.modules.m1 import CtLookup as _CtLookup

    # A cloud/bucket asset is not a target kind any M1 check declares, so nothing matches it.
    bucket = Asset.from_meta("bucket", "s3://example-bucket")
    assert not _CtLookup().supports(bucket)


# ------------------------------------------------------------------ corpus and failure paths
def test_a_custom_dork_corpus_is_loaded_and_validated(tmp_path) -> None:  # type: ignore[no-untyped-def]
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text(
        'corpus_version: "2.0"\ndorks:\n'
        "  - id: custom\n    category: sensitive-file\n"
        '    query: "site:{domain} filetype:log"\n    exposure: true\n',
        encoding="utf-8",
    )
    version, entries = load_dork_corpus(corpus)
    assert version == "2.0"
    assert [entry.id for entry in entries] == ["custom"]
    assert entries[0].exposure is True


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("just a string\n", "expected a mapping"),
        ("corpus_version: '1.0'\n", "'dorks' must be a non-empty list"),
        ("dorks:\n  - a string\n", "is not a mapping"),
        ("dorks:\n  - {id: x}\n", "is missing 'category'"),
        ("dorks:\n  - {id: Bad_Id, category: c, query: 'site:{domain}'}\n", "kebab-case"),
        ("dorks:\n  - {id: ok, category: c, query: 'no placeholder'}\n", "{domain}"),
        (
            "dorks:\n  - {id: dup, category: c, query: 'site:{domain}'}\n"
            "  - {id: dup, category: c, query: 'site:{domain}'}\n",
            "duplicate dork id",
        ),
    ],
)
def test_a_malformed_dork_corpus_is_refused(tmp_path, document: str, message: str) -> None:  # type: ignore[no-untyped-def]
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text(document, encoding="utf-8")
    with pytest.raises(ConfigurationError, match=message):
        load_dork_corpus(corpus)


def test_a_corpus_that_is_not_yaml_is_reported(tmp_path) -> None:  # type: ignore[no-untyped-def]
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text("dorks: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_dork_corpus(corpus)


async def test_dork_sweep_skips_without_a_search_endpoint() -> None:
    """A client that has no search endpoint configured yields a skip, never a crash."""
    results, _ = await run_check(
        DorkSweep, DOMAIN, osint=make_osint(), config=module_config(search_url=None)
    )
    assert results[0].status == "info"
    assert "ARACHNE_OSINT_SEARCH_URL" in results[0].detail


async def test_dork_sweep_reports_a_search_failure_as_data() -> None:
    routes = {
        "GET x": {"method": "GET", "url": "https://search.example.net/search?q=zzz", "status": 500}
    }
    results, _ = await run_check(
        DorkSweep, DOMAIN, osint=make_osint(routes=routes), config=SEARCH_CONFIG
    )
    # The one recording stands in for every search query (a unique host+path), and it fails:
    # the sweep reports "nothing found" with the reasons rather than raising.
    assert results[0].status == "not_vulnerable"
    assert "HTTP 500" in results[0].detail


async def test_a_check_reports_an_error_when_the_provider_refuses() -> None:
    """A provider that is enabled but unreachable produces an error result, not a crash."""
    from arachne.modules.providers import OsintAccess

    class Refusing(OsintAccess):
        async def fetch(self, provider, url, headers=None):  # type: ignore[no-untyped-def]
            raise OsintError("index is down")

    access = make_osint()
    refusing = Refusing(
        client=access.client,
        enabled=frozenset({"crtsh", "circl", "wayback", "commoncrawl", "internetdb"}),
        budget=access.budget,
    )
    results, _ = await run_check(CtLookup, DOMAIN, osint=refusing)
    assert results[0].status == "error"
    assert "index is down" in (results[0].detail or "")
    await refusing.aclose()


async def test_ct_lookup_reports_a_non_200_answer() -> None:
    routes = {
        "GET x": {
            "method": "GET",
            "url": "https://crt.sh/?q=%25.example.com&output=json",
            "status": 503,
            "body": "service unavailable",
        }
    }
    results, _ = await run_check(CtLookup, DOMAIN, osint=make_osint(routes=routes))
    assert results[0].status == "info"
    assert "HTTP 503" in results[0].title


async def test_email_harvest_reports_nothing_found() -> None:
    routes = {
        "GET x": {
            "method": "GET",
            "url": "https://search.example.net/search?q=%22example.com%22%20email&limit=100&format=json",
            "body": '{"results": []}',
        },
        "GET y": {
            "method": "GET",
            "url": "https://search.example.net/search?q=%22%40example.com%22&limit=100&format=json",
            "body": '{"results": []}',
        },
        "GET z": {
            "method": "GET",
            "url": "https://search.example.net/search?q=site%3Apastebin.com%20%22example.com%22&limit=100&format=json",
            "body": "{}",
        },
    }
    results, _ = await run_check(
        EmailHarvest, DOMAIN, osint=make_osint(routes=routes), config=SEARCH_CONFIG
    )
    assert [r.status for r in results] == ["not_vulnerable"]


async def test_webarchive_harvest_skips_when_no_archive_answers() -> None:
    results, _ = await run_check(
        WebArchiveHarvest,
        DOMAIN,
        osint=make_osint(providers=("crtsh",)),
    )
    assert results[0].status == "info"
    assert any(item.payload.get("skipped") for item in results[0].evidence)


# ------------------------------------------------------------------ hardening helpers
HARDENING_HTTP = FIXTURES / "http" / "hardening-replay.json"
PROVIDER_HOSTS = ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net")


def hardening_client(*domains: str) -> ScopedHttpClient:
    """A target-scoped client replaying the hardening fixture responses."""
    from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes

    replay = FixtureReplay(load_fixture_routes(HARDENING_HTTP))
    return ScopedHttpClient(
        scope=Scope(allowed_domains=domains),
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


def jpeg_with_exif(*, software: str, artist: str) -> bytes:
    """A minimal JPEG carrying one APP1/EXIF segment with two ASCII tags (stdlib only)."""
    import struct

    entries: list[tuple[int, bytes]] = []
    for tag, text in ((0x0131, software), (0x013B, artist)):
        entries.append((tag, text.encode("latin-1") + b"\x00"))
    data_area = b""
    value_offsets = 8 + 2 + 12 * len(entries) + 4  # tiff header + count + entries + next-IFD
    ifd = struct.pack("<H", len(entries))
    for tag, raw in entries:
        if len(raw) <= 4:
            value = raw + b"\x00" * (4 - len(raw))
        else:
            value = struct.pack("<I", value_offsets + len(data_area))
            data_area += raw
        ifd += struct.pack("<HHI", tag, 2, len(raw)) + value
    ifd += struct.pack("<I", 0)
    tiff = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8) + ifd + data_area
    payload = b"Exif\x00\x00" + tiff
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload


# ------------------------------------------------------------------ m1.dns-txt-mining
async def test_dns_txt_mining_flags_unenforced_dmarc() -> None:
    results, _ = await run_check(DnsTxtMining, DOMAIN, osint=make_osint(providers=("dns",)))
    assert [r.status for r in results] == ["info", "vulnerable"]
    artifact = results[0].evidence[0].payload
    assert artifact["spf_present"] is True
    assert artifact["spf_qualifier"] == "-all"
    assert artifact["dmarc_policy"] == "none"
    assert "dmarc-not-enforced" in artifact["issues"]
    assert artifact["dkim_selectors"] == ["default"]
    assert artifact["queries"] == 6


async def test_dns_txt_mining_accepts_an_enforced_policy() -> None:
    results, _ = await run_check(
        DnsTxtMining, asset_for("domain", "clean.example.com"), osint=make_osint(providers=("dns",))
    )
    assert [r.status for r in results] == ["info"]
    artifact = results[0].evidence[0].payload
    assert artifact["dmarc_policy"] == "reject"
    assert artifact["issues"] == []


# ------------------------------------------------------------------ m1.favicon-hash
async def test_favicon_hash_matches_a_vendor_default() -> None:
    results, _ = await run_check(FaviconHash, DOMAIN, http=hardening_client("example.com"))
    # Recon identification is an observation, not a finding: M1 yields info only (ADR-02).
    assert [r.status for r in results] == ["info"]
    artifact = results[0].evidence[0].payload
    assert len(str(artifact["sha256"])) == 64
    assert artifact["vendor"] == "vendor-default"
    assert "vendor-default" in (results[0].detail or "")


async def test_favicon_hash_reports_an_unknown_icon() -> None:
    results, _ = await run_check(
        FaviconHash,
        asset_for("domain", "unlisted.example.com"),
        http=hardening_client("unlisted.example.com"),
    )
    assert [r.status for r in results] == ["info"]
    assert results[0].evidence[0].payload["vendor"] is None


# ------------------------------------------------------------------ m1.bucket-hunt
async def test_bucket_hunt_flags_anonymous_listings() -> None:
    results, _ = await run_check(
        BucketHunt, DOMAIN, http=hardening_client("example.com", *PROVIDER_HOSTS)
    )
    assert results[0].status == "info"
    findings = results[0].evidence[0].payload["findings"]
    assert {finding["provider"] for finding in findings} == {"s3", "gcs", "azure"}
    assert "example-backup" in {finding["bucket"] for finding in findings}
    assert [r.status for r in results[1:]] == ["vulnerable"] * len(findings)
    assert _bucket_names("example.com")[0] == "example"


async def test_bucket_hunt_reports_no_listing() -> None:
    results, _ = await run_check(
        BucketHunt,
        asset_for("domain", "no-buckets.com"),
        http=hardening_client("no-buckets.com", *PROVIDER_HOSTS),
    )
    assert [r.status for r in results] == ["not_vulnerable"]


# ------------------------------------------------------------------ m1.doc-metadata
async def test_doc_metadata_extracts_pdf_info() -> None:
    results, _ = await run_check(
        DocMetadata,
        asset_for("url", "https://example.com/reports/2024-q1.pdf"),
        http=hardening_client("example.com"),
    )
    assert [r.status for r in results] == ["info", "vulnerable"]
    fields = results[0].evidence[0].payload["fields"]
    assert fields["Producer"] == "Microsoft Word 2016"
    assert fields["Author"] == "internal\\jdoe"
    assert "software-version:Producer" in results[1].title


async def test_doc_metadata_skips_a_non_document() -> None:
    results, _ = await run_check(
        DocMetadata,
        asset_for("url", "https://example.com/index.html"),
        http=hardening_client("example.com"),
    )
    assert [r.status for r in results] == ["info"]
    assert any(item.payload.get("skipped") for item in results[0].evidence)


def test_document_parsers_read_ascii_metadata_only() -> None:
    assert _pdf_info(b"trailer << /Info << /Author (a b) /Producer (x) >> >>") == {
        "Author": "a b",
        "Producer": "x",
    }
    fields = _image_exif(jpeg_with_exif(software="Adobe Photoshop 24.0", artist="internal\\jdoe"))
    assert fields == {"Software": "Adobe Photoshop 24.0", "Artist": "internal\\jdoe"}
    assert _image_exif(b"\xff\xd8\xff\xe0not-an-exif-jpeg") == {}
