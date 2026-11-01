"""Every M4 check against the stdlib web lab: it detects the planted mistake, not its control.

The lab (``tests/lab/web_lab.py``) serves a vulnerable *and* a hardened answer for most
families, so a check that reports both has been tested for sensitivity but not for
specificity. Each test below states both halves: the planted route is reported with the
evidence that proves it, and the hardened counterpart is not.

The tests run against real loopback sockets through the shared scoped client — a path probe
whose whole job is to read the server's answer cannot be meaningfully tested against a
mock. Rate limits are raised because a check makes tens of requests; production limits have
their own suite (``tests/test_safety.py``).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator

import pytest
from tests.helpers.checks import make_osint, settings_for_checks
from tests.helpers.checks import run_check as run_check_ctx
from tests.helpers.m4 import M4Harness, make_m4_harness
from tests.lab.web_lab import start_web_lab

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import M4Settings, RateLimitSettings, SafetySettings
from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
from arachne.core.results import CheckResult
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.modules.base import Asset
from arachne.modules.m4 import M4_CHECKS
from arachne.modules.m4.hardening import (
    ActuatorExposure,
    AliasTraversal,
    DatastoreSurface,
    RobotsSitemap,
    VerboseErrors,
    WordpressSurface,
    datastore_signal,
    robots_entries,
    sensitive_hits,
    sitemap_locations,
    verbose_error_signals,
)
from arachne.modules.m4.transport import EmailAuthReview


@pytest.fixture(scope="module")
def lab() -> Iterator[object]:
    with start_web_lab() as running:
        yield running


@pytest.fixture
async def harness(lab: object) -> Iterator[M4Harness]:
    running = make_m4_harness(
        lab,
        seed=(("cloud", f"endpoint:{lab.base_url}storage/backup"),),
    )
    await running.prepare()
    try:
        yield running
    finally:
        await running.aclose()


def _check(check_id: str) -> type:
    return next(check for check in M4_CHECKS if check.metadata.id == check_id)


def _artifact(result: CheckResult) -> dict:
    for item in result.evidence:
        if item.kind == "artifact":
            return dict(item.payload)
    return {}


async def run_check(
    harness: M4Harness, check_id: str, *, asset: Asset | None = None, m4: M4Settings | None = None
) -> list[CheckResult]:
    ctx = harness.context(_check(check_id)(), asset=asset)
    if m4 is not None:
        ctx.config = dataclasses.replace(ctx.config, m4=m4)
    return [result async for result in ctx.module.run(ctx)]


def _candidates(results: list[CheckResult]) -> list[CheckResult]:
    return [result for result in results if result.status == "vulnerable"]


def _skipped(results: list[CheckResult]) -> bool:
    return all(any(item.payload.get("skipped") for item in result.evidence) for result in results)


def _blob(result: CheckResult) -> str:
    return json.dumps([item.payload for item in result.evidence], default=str)


# --------------------------------------------------------------------------- file families
async def test_env_files_are_found_and_denied_paths_are_not(harness: M4Harness) -> None:
    results = await run_check(harness, "m4.env-file-probe")
    candidates = _candidates(results)
    assert len(candidates) == 1, [result.title for result in results]
    artifact = _artifact(candidates[0])
    assert artifact["path"] == "/.env"
    assert artifact["assignment_count"] >= 4
    assert "aws-access-key-id" in artifact["detectors"]
    assert "DB_PASSWORD" in artifact["assignment_keys"]
    # The two denied variants (403) must not be reported.
    assert not any("/.env.local" in _blob(candidate) for candidate in candidates)


async def test_vcs_metadata_is_found_with_markers(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.vcs-exposure"))
    paths = {_artifact(result)["path"] for result in candidates}
    assert paths == {"/.git/HEAD", "/.git/config", "/.git/packed-refs"}
    assert all(_artifact(result)["marker"] for result in candidates)
    assert all(_artifact(result)["family"] == "git" for result in candidates)


async def test_backup_artifacts_are_found_with_content_signatures(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.backup-file-hunt"))
    by_path = {_artifact(result)["path"]: _artifact(result) for result in candidates}
    assert "/backup/db.sql" in by_path
    assert by_path["/backup/db.sql"]["content_family"] == "sql"
    assert by_path["/index.php.bak"]["content_family"] == "source"
    assert by_path["/backup/site.zip"]["binary"] is True
    assert "backup/safe.sql" not in by_path


async def test_key_material_is_detected_by_the_redactor(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.key-exposure"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["path"] == "/id_rsa"
    # The value was redacted before the check saw it; the detector name is the proof.
    assert "private-key" in artifact["detectors"]
    assert "MIIEow" not in _blob(candidates[0])


async def test_source_map_and_client_secrets(harness: M4Harness) -> None:
    maps = _candidates(await run_check(harness, "m4.sourcemap-exposure"))
    assert len(maps) == 1
    assert _artifact(maps[0])["map_url"].endswith("/app.js.map")
    assert _artifact(maps[0])["sources_content"] is True

    secrets = _candidates(await run_check(harness, "m4.client-secrets"))
    assert len(secrets) == 1
    assert _artifact(secrets[0])["page"].endswith("/app.js")
    assert "aws-access-key-id" in _artifact(secrets[0])["detectors"]
    assert "AKIAIOSFODNN7EXAMPLE" not in _blob(secrets[0])


# --------------------------------------------------------------------------- surfaces
async def test_api_document_is_parsed_and_feeds_the_shared_inventory(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.api-doc-exposure"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["path"] == "/swagger.json"
    assert artifact["endpoint_count"] == 3
    assert any("/api/internal/users" in url for url in artifact["internal_endpoints"])
    # The hand-off: the routes are now in the shared crawl as api-doc endpoints.
    documented = {url for url, source in harness.inventory.endpoints.items() if source == "api-doc"}
    assert any(url.endswith("/api/internal/users") for url in documented)
    # …and recorded as assets for the rest of the run (scope-guarded).
    recorded = {record.value for record in harness.memory.store.list_assets(harness.memory.scan_id)}
    assert any(value.endswith("/api/internal/users") for value in recorded)


async def test_debug_surfaces_are_found(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.debug-endpoints"))
    families = {_artifact(result)["family"] for result in candidates}
    assert families == {"phpinfo", "actuator-env"}
    assert not any(_artifact(result)["path"] == "/health" for result in candidates)


async def test_directory_listing_is_classified(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.directory-listing"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["path"] == "/files/"
    assert "dump.sql" in artifact["entries"]
    # /files-hardened answers 200 with a normal page: not a listing.
    assert not any("files-hardened" in _blob(result) for result in candidates)


async def test_dashboards_are_fingerprinted(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.dashboard-exposure"))
    products = {_artifact(result)["product"] for result in candidates}
    assert products == {"Jenkins", "Grafana", "phpMyAdmin"}
    jenkins = next(result for result in candidates if _artifact(result)["product"] == "Jenkins")
    grafana = next(result for result in candidates if _artifact(result)["product"] == "Grafana")
    assert _artifact(jenkins)["anonymous"] is True
    assert _artifact(grafana)["auth_challenge"] is True
    assert products != {"Kibana"}


async def test_hidden_paths_are_deduplicated_and_classified(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.hidden-endpoint-hunt"))
    paths = {_artifact(result)["path"] for result in candidates}
    # ``/admin`` and ``/admin/`` are one handler; the response identity dedupes them.
    assert "admin" in paths and "admin/" not in paths
    assert "staging" in paths
    # A 200 HTML page that is neither sensitive by name nor a file is not reported.
    assert "files" not in paths


async def test_staging_paths_are_reported_once(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.staging-exposure"))
    assert len(candidates) == 1
    assert _artifact(candidates[0])["path"] == "/staging/"


async def test_unauth_api_uses_documented_routes(harness: M4Harness) -> None:
    # In a scan the checks step orders the API-document producer first; a unit test does
    # the same explicitly rather than depending on another test having run.
    assert _candidates(await run_check(harness, "m4.api-doc-exposure"))
    candidates = _candidates(await run_check(harness, "m4.unauth-api-audit"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["endpoint"].endswith("/api/internal/users")
    assert artifact["documented"] is True
    assert artifact["records"] >= 1
    # The protected route answers 401: the control works and must not be reported.
    assert not any("/api/orders" in _blob(result) for result in candidates)


async def test_bucket_listing_and_acl_on_the_declared_endpoint(harness: M4Harness) -> None:
    cloud = next(
        record
        for record in harness.memory.store.list_assets(harness.memory.scan_id)
        if record.kind == "cloud"
    )
    asset = Asset.from_meta("cloud", cloud.value, {"declared": True})
    candidates = _candidates(await run_check(harness, "m4.bucket-exposure", asset=asset))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["bucket"] == "backup"
    assert artifact["public_listing"] is True
    assert artifact["public_acl"] is True
    assert "dump.sql" in artifact["object_keys"]
    # The denied bucket is a control, not an exposure.
    assert not any(_artifact(result)["bucket"] == "private" for result in candidates)


# --------------------------------------------------------------------------- transport
async def test_headers_cookies_and_cors(harness: M4Harness) -> None:
    headers = _candidates(await run_check(harness, "m4.security-header-review"))
    assert len(headers) == 1
    assert "content-security-policy" in _artifact(headers[0])["missing"]

    cookies = _candidates(await run_check(harness, "m4.cookie-flag-audit"))
    assert len(cookies) == 1
    assert set(_artifact(cookies[0])["missing"]) >= {"secure", "httponly", "samesite"}

    cors = _candidates(await run_check(harness, "m4.cors-config-review"))
    # One finding per endpoint, not one per probe origin.
    assert len(cors) == 1
    artifact = _artifact(cors[0])
    assert artifact["endpoint"].endswith("/api/config")
    assert artifact["reflected"] is True and artifact["allows_auth"] is True
    assert artifact["null_origin"] is True
    assert "_fixed" not in _blob(cors[0])


async def test_user_enumeration_reports_the_differential(harness: M4Harness, lab: object) -> None:
    before = len(lab.requests)
    candidates = _candidates(await run_check(harness, "m4.user-enumeration"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["endpoint"].endswith("/login")
    assert artifact["differential"] is True
    # Bounded: two candidate names plus one random baseline.
    assert artifact["names_probed"] == 3
    assert len(lab.requests) == before + 3, "one paced POST per name, nothing more"


async def test_email_authentication_reads_dns_over_https(harness: M4Harness) -> None:
    """SPF/DMARC are read through the OSINT layer, which is deny-by-default."""
    domain = Asset.from_meta("domain", "example.com")
    off = await run_check(harness, "m4.email-auth-review", asset=domain)
    assert _skipped(off), [result.title for result in off]

    def doh(name: str, *records: str) -> dict:
        body = json.dumps(
            {"Status": 0, "Answer": [{"type": 16, "data": record} for record in records]}
        )
        url = f"https://dns.google/resolve?name={name}&type=TXT"
        return {
            "method": "GET",
            "url": url,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": body,
        }

    routes = {
        doh("example.com", '"v=spf1 +all"')["url"]: doh("example.com", '"v=spf1 +all"'),
        doh("_dmarc.example.com", '"v=DMARC1; p=none"')["url"]: doh(
            "_dmarc.example.com", '"v=DMARC1; p=none"'
        ),
    }
    access = make_osint(providers=("dns",), routes=routes)
    ctx = harness.context(EmailAuthReview(), asset=Asset.from_meta("domain", "example.com"))
    ctx.osint = access
    results = [result async for result in ctx.module.run(ctx)]
    candidates = _candidates(results)
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["domain"] == "example.com"
    assert artifact["spf_all"] == "+all"
    assert artifact["dmarc_policy"] == "none"
    assert "no-dkim-selector" in artifact["issues"]
    await access.aclose()


# --------------------------------------------------------------------------- opt-in gates
async def test_metadata_ssrf_is_inert_until_the_switch_is_on(
    harness: M4Harness, lab: object
) -> None:
    before = len(lab.requests)
    results = await run_check(harness, "m4.metadata-ssrf")
    assert _skipped(results)
    assert len(lab.requests) == before, "a disabled check must send nothing"

    enabled = await run_check(harness, "m4.metadata-ssrf", m4=M4Settings(metadata_ssrf_probe=True))
    candidates = _candidates(enabled)
    assert candidates
    # The lab's fetch sink answers the AWS metadata path with ami-data (it also serves the
    # Azure/GCP documents the M5 checks use, so more than one provider can match).
    aws = [item for item in candidates if _artifact(item)["provider"] == "aws"]
    assert aws, [_artifact(item)["provider"] for item in candidates]
    artifact = _artifact(aws[0])
    assert artifact["sink"] == "url"
    assert artifact["posture"] == "imdsv1-served"


async def test_default_credentials_make_one_paced_attempt_only_when_enabled(
    harness: M4Harness, lab: object
) -> None:
    def jenkins_posts() -> list[str]:
        return [entry for entry in lab.requests if entry.startswith("POST /jenkins")]

    before = len(jenkins_posts())
    results = await run_check(harness, "m4.default-credentials")
    assert _skipped(results)
    assert len(jenkins_posts()) == before, "a disabled check must not attempt a credential"

    enabled = await run_check(
        harness,
        "m4.default-credentials",
        m4=M4Settings(default_credentials=True, default_credentials_pacing_s=0.0),
    )
    candidates = _candidates(enabled)
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["product"] == "Jenkins"
    assert artifact["attempts"] == 1
    assert artifact["vendor_default"] is True
    # Exactly one attempt: no retry, no second pair.
    assert len(jenkins_posts()) == before + 1


async def test_webdav_verbs_never_send_a_write_verb(harness: M4Harness) -> None:
    candidates = _candidates(await run_check(harness, "m4.webdav-verbs"))
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["endpoint"].endswith("/dav/")
    assert "PROPFIND" in artifact["allow"]
    assert "PUT" in artifact["write_verbs"]  # advertised…
    assert artifact["safe_sent"] == ["OPTIONS", "PROPFIND", "TRACE"]  # …never sent
    assert artifact["trace_echo"] is True
    assert artifact["webdav"] is True
    # The hardened collection advertises no write verb and refuses PROPFIND/TRACE.
    assert not any("dav-hardened" in _blob(result) for result in candidates)


async def test_a_dry_run_turns_every_probe_into_a_skip(lab: object) -> None:
    """F-01-10: no client, no request, and every check says so rather than pretending."""
    harness = make_m4_harness(lab)
    harness.step.http = None
    try:
        for check_id in (
            "m4.env-file-probe",
            "m4.directory-listing",
            "m4.bucket-exposure",
            "m4.security-header-review",
        ):
            results = await run_check(harness, check_id)
            assert _skipped(results), check_id
    finally:
        await harness.aclose()


# --------------------------------------------------------------------------- hardening checks
# The six ch04 hardening checks (``m4.hardening``). They probe a fixed set of paths and
# classify the answer against the application's not-found page; each test below drives a real
# check run over a recorded-response client (``core.http.fixture_transport``), so the
# assertion is about the classifier, not about a mock's opinion of the lab.
_FIXTURE_HOST = "lab.test"
_FIXTURE_ORIGIN = f"https://{_FIXTURE_HOST}"
_FIXTURE_IP = "93.184.216.34"


def _fixture_client(routes: dict[str, dict]) -> ScopedHttpClient:
    """A scoped client that replays one recorded response per ``path -> spec`` entry.

    An unmatched request answers 501 (``fixture_transport``'s deliberate "fixture gap"), which
    is what the check's random not-found probe always gets — and what makes the not-found
    comparison meaningful without a live server.
    """
    responses = [
        RecordedResponse(
            method="GET",
            url=f"{_FIXTURE_ORIGIN}{path}",
            status=int(route.get("status", 200)),
            headers={
                "content-type": "text/html",
                **{str(k): str(v) for k, v in (route.get("headers") or {}).items()},
            },
            body=str(route.get("body", "")),
        )
        for path, route in routes.items()
    ]
    settings = settings_for_checks(
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        rate_limit=RateLimitSettings(
            per_host_rate=1_000_000.0,
            per_host_burst=100_000,
            global_rate=1_000_000.0,
            global_burst=100_000,
        ),
    )
    return ScopedHttpClient(
        settings=settings,
        scope=Scope(allowed_hosts=(_FIXTURE_HOST,)),
        policy=UrlSafetyPolicy(allow_private_ips=True, allow_loopback=True),
        resolver=StaticResolver({_FIXTURE_HOST: (_FIXTURE_IP,)}),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=fixture_transport(responses),
    )


async def _run_fixture(check: type, routes: dict[str, dict]) -> list[CheckResult]:
    client = _fixture_client(routes)
    try:
        results, _ = await run_check_ctx(
            check,
            Asset.from_meta("url", _FIXTURE_ORIGIN),
            http=client,
            seed=[("url", _FIXTURE_ORIGIN)],
        )
    finally:
        await client.aclose()
    return results


# --------------------------------------------------------------------------- helpers (pure)
def test_robots_and_sitemap_parsers_and_sensitive_hits() -> None:
    body = "User-agent: *\nDisallow: /admin/\nAllow: /public\n# comment\nDisallow:\n"
    assert robots_entries(body) == ("/admin/", "/public")
    assert sitemap_locations("<urlset><url><loc> https://x/.env </loc></url></urlset>") == (
        "https://x/.env",
    )
    assert sensitive_hits(("/admin/", "/shop")) == (("/admin/", "admin"),)


def test_verbose_error_signal_helper_requires_the_real_markers() -> None:
    assert verbose_error_signals("Traceback (most recent call last):") == ("python-traceback",)
    assert verbose_error_signals("Warning: undefined index on line 3") == ("php-warning",)
    assert verbose_error_signals("<html><body>nothing to see</body></html>") == ()


def test_datastore_signal_rejects_a_generic_json_page() -> None:
    assert datastore_signal("/_cluster/health", '{"cluster_name":"lab"}') == "elasticsearch"
    assert datastore_signal("/_cluster/health", '{"message":"welcome"}') is None


# --------------------------------------------------------------------------- verbose errors
async def test_verbose_errors_flags_a_python_traceback() -> None:
    traceback_body = (
        "<html><body><h1>Internal Server Error</h1>"
        '<pre>Traceback (most recent call last):\n  File "app.py", line 1\n'
        "ValueError: boom</pre></body></html>"
    )
    candidates = _candidates(
        await _run_fixture(VerboseErrors, {"/api/%00": {"status": 500, "body": traceback_body}})
    )
    assert len(candidates) == 1
    artifact = _artifact(candidates[0])
    assert artifact["path"] == "/api/%00"
    assert "python-traceback" in artifact["markers"]


async def test_verbose_errors_ignores_the_ordinary_not_found_page() -> None:
    results = await _run_fixture(VerboseErrors, {"/": {"status": 200, "body": "<html>ok</html>"}})
    assert _candidates(results) == []
    assert results and results[0].status == "not_vulnerable"


# --------------------------------------------------------------------------- actuator
async def test_actuator_endpoints_are_fingerprinted() -> None:
    results = await _run_fixture(
        ActuatorExposure,
        {
            "/actuator": {"status": 200, "body": '{"_links":{"self":{"href":"/actuator"}}}'},
            "/actuator/env": {
                "status": 200,
                "body": '{"activeProfiles":["prod"],"propertySources":[]}',
            },
            "/actuator/health": {"status": 200, "body": '{"status":"UP"}'},
        },
    )
    candidates = _candidates(results)
    families = {_artifact(result)["family"] for result in candidates}
    assert families == {"actuator-index", "actuator-env", "actuator-health"}
    index = next(result for result in candidates if _artifact(result)["family"] == "actuator-index")
    assert index.confidence > 0.9  # a reachable Actuator index is the high-confidence case


async def test_actuator_absent_is_clean() -> None:
    results = await _run_fixture(
        ActuatorExposure, {"/": {"status": 200, "body": "<html>ok</html>"}}
    )
    assert _candidates(results) == []


# --------------------------------------------------------------------------- datastores
async def test_datastore_surfaces_are_fingerprinted() -> None:
    results = await _run_fixture(
        DatastoreSurface,
        {
            "/_cluster/health": {
                "status": 200,
                "body": '{"cluster_name":"lab","status":"yellow"}',
            },
            "/_all_dbs": {"status": 200, "body": '["_users","orders"]'},
        },
    )
    products = {_artifact(result)["product"] for result in _candidates(results)}
    assert products == {"elasticsearch", "couchdb"}


async def test_datastore_generic_json_is_not_flagged() -> None:
    results = await _run_fixture(
        DatastoreSurface,
        {"/_cluster/health": {"status": 200, "body": '{"message":"welcome","items":[1,2]}'}},
    )
    assert _candidates(results) == []


# --------------------------------------------------------------------------- robots/sitemap
async def test_robots_and_sitemap_sensitive_entries_are_reported() -> None:
    results = await _run_fixture(
        RobotsSitemap,
        {
            "/robots.txt": {
                "status": 200,
                "body": "User-agent: *\nDisallow: /admin/\nDisallow: /.git/\nDisallow: /shop/\n",
            },
            "/sitemap.xml": {
                "status": 200,
                "body": (
                    "<urlset><url><loc>https://lab.test/backup/db.sql</loc></url>"
                    "<url><loc>https://lab.test/about</loc></url></urlset>"
                ),
            },
        },
    )
    candidates = _candidates(results)
    assert {_artifact(result)["source"] for result in candidates} == {"robots.txt", "sitemap.xml"}
    robots = next(result for result in candidates if _artifact(result)["source"] == "robots.txt")
    assert "/admin/" in _artifact(robots)["sensitive_entries"]
    sitemap = next(result for result in candidates if _artifact(result)["source"] == "sitemap.xml")
    assert any("db.sql" in entry for entry in _artifact(sitemap)["sensitive_entries"])


async def test_robots_with_only_ordinary_paths_is_information() -> None:
    results = await _run_fixture(
        RobotsSitemap,
        {
            "/robots.txt": {
                "status": 200,
                "body": "User-agent: *\nDisallow: /shop/\nDisallow: /about\n",
            }
        },
    )
    assert _candidates(results) == []
    assert any(
        result.status == "info" and "ordinary" in (result.detail or "") for result in results
    )


# --------------------------------------------------------------------------- WordPress
async def test_wordpress_user_enumeration_and_xmlrpc_are_reported() -> None:
    results = await _run_fixture(
        WordpressSurface,
        {
            "/wp-json/wp/v2/users": {
                "status": 200,
                "body": '[{"id":1,"name":"admin","slug":"admin"}]',
            },
            "/xmlrpc.php": {
                "status": 405,
                "body": "XML-RPC server accepts POST requests only.",
            },
        },
    )
    signals = {signal for result in _candidates(results) for signal in _artifact(result)["signals"]}
    assert "user-enumeration" in signals
    assert "xmlrpc-enabled" in signals


async def test_wordpress_author_redirect_leaks_a_login_name() -> None:
    results = await _run_fixture(
        WordpressSurface,
        {
            "/?author=1": {
                "status": 302,
                "headers": {"location": "https://lab.test/author/admin/"},
            }
        },
    )
    candidates = _candidates(results)
    assert any("author-enumeration" in _artifact(result)["signals"] for result in candidates)


async def test_wordpress_login_page_alone_is_clean() -> None:
    results = await _run_fixture(
        WordpressSurface,
        {"/wp-login.php": {"status": 200, "body": "<html><body>Log in</body></html>"}},
    )
    assert _candidates(results) == []


# --------------------------------------------------------------------------- alias traversal
async def test_alias_traversal_is_reported_only_when_the_canary_leaks() -> None:
    candidates = _candidates(
        await _run_fixture(
            AliasTraversal,
            {
                "/static/..%2f..%2f..%2fetc/passwd": {
                    "status": 200,
                    "body": "root:x:0:0:root:/root:/bin/bash\n",
                }
            },
        )
    )
    assert len(candidates) == 1
    assert _artifact(candidates[0])["canary"] == "root:x:0:0:"


async def test_alias_traversal_named_but_refused_is_clean() -> None:
    results = await _run_fixture(
        AliasTraversal,
        {"/static/..%2f..%2f..%2fetc/passwd": {"status": 403, "body": "Forbidden"}},
    )
    assert _candidates(results) == []
