"""Per-check tests for M3, driven against the live lab.

Each check is exercised where it matters: it reports the *planted* behaviour of the lab route
it targets, and stays quiet on the hardened counterpart of that route (the false-positive
trap). The transport is real loopback HTTP, because an oracle's whole value is the differential
it reads out of a real response — a mocked transport would only confirm the test author's
beliefs about the server.

The dry-run case is asserted once per check family through the harness: with no HTTP client a
check must report itself *skipped* (F-01-10), never clean.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.helpers.checks import run_check
from tests.helpers.web import WebHarness, close_harness, make_web_harness
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.core.http import HttpExchange
from arachne.modules.base import Asset
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3.client import XssOracle
from arachne.modules.m3.exposure import ApiSurface, SecurityHeaders
from arachne.modules.m3.files import TraversalOracle, UploadAudit
from arachne.modules.m3.hardening import (
    CrlfInjection,
    DirectoryTraversal,
    FileInclusion,
    NosqlOracle,
)
from arachne.modules.m3.identity import AuthSessionAudit, CsrfAudit, IdorOracle
from arachne.modules.m3.injection import SqliOracle
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.transport import CorsAudit, OpenRedirect, RateLimitAudit


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


@pytest.fixture
async def harness(lab: WebLab) -> Iterator[WebHarness]:
    built = make_web_harness(lab, upload_probe=True)
    await built.prepare()
    try:
        yield built
    finally:
        await close_harness(built)


def titles(results: list[object]) -> str:
    return " | ".join(getattr(item, "title", "") for item in results)


def artifacts(results: list[object]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for result in results:
        for item in getattr(result, "evidence", ()):
            if getattr(item, "kind", "") == "artifact":
                found.append(dict(item.payload))
    return found


# ------------------------------------------------------------------ the registry shape
def test_the_module_exposes_the_core_and_extended_checks() -> None:
    ids = [check.metadata.id for check in M3_CHECKS]
    # The S6 core set is all still present; S10 appended the extended families.
    core = {
        "m3.security-headers",
        "m3.api-surface",
        "m3.csrf-audit",
        "m3.sqli-oracle",
        "m3.xss-oracle",
        "m3.traversal-oracle",
        "m3.open-redirect",
        "m3.cors-audit",
        "m3.idor-oracle",
        "m3.auth-session-audit",
        "m3.rate-limit-audit",
        "m3.upload-audit",
    }
    assert core <= set(ids)
    # S15 appended the six proof-ladder checks (4x L2 out-of-band variants + the attested
    # L3/L4 proofs) — 34 + 6 = 40; S19 appended the two credentialed checks — 42; S29 appended
    # the depth-expansion family: two GraphQL probes, two WebSocket probes and the L2
    # client-secret check — 47. WP-08 adds the four CWE Top 25 emitters and the five
    # injection families (REQ-DET-004/009) — 56. WP-11 adds the DOM-sink browser check
    # (REQ-DET-015) — 57. WP-25 adds the WordPress ecosystem family (REQ-DET-018) — 83.
    # WP-26 adds the CMS family B (REQ-DET-019): Joomla, Drupal, Moodle, PrestaShop and
    # Magento — 113. WP-27 adds the application-server and framework family (REQ-DET-020):
    # Spring Boot, Django, Rails, Laravel, Tomcat, JBoss, WebLogic, ColdFusion and IIS — 138.
    assert len(ids) == 138, ids
    assert len(set(ids)) == len(ids)
    # The proof ladder's declarations are part of the module's contract: the L2+ rows are
    # all opt-in, and only rce-echo/state-marker demand the state-change attestation.
    ladder = [check for check in M3_CHECKS if check.metadata.proof.is_opt_in]
    # m3.ssrf-probe (S10) stays L1: its in-band confirmation works alone and REQ-PROOF-002
    # annotated every pre-S15 check L1; the six S15 rows carry the L2+ declarations, and S29
    # adds the seventh: m3.client-secret-verify, whose out-of-band token is its L2 proof.
    assert {check.metadata.id for check in ladder} == {
        "m3.sqli-oob",
        "m3.xxe-oob",
        "m3.cmdi-oob",
        "m3.ssti-oob",
        "m3.rce-echo",
        "m3.state-marker",
        "m3.client-secret-verify",
    }
    assert all(not check.metadata.enabled_by_default for check in ladder)
    assert {c.metadata.id for c in M3_CHECKS if c.metadata.requires_state_attestation} == {
        "m3.rce-echo",
        "m3.state-marker",
    }
    # The S10 families each appear exactly once.
    for extended in (
        "m3.ssrf-probe",
        "m3.ssti-oracle",
        "m3.xxe-oracle",
        "m3.cmdi-oracle",
        "m3.deser-audit",
        "m3.smuggling-oracle",
        "m3.cache-poison-audit",
        "m3.jwt-audit",
        "m3.oauth-flow-audit",
        "m3.saml-audit",
        "m3.hpp-oracle",
        "m3.mass-assign-audit",
        "m3.proto-pollution",
        "m3.race-oracle",
        "m3.business-logic-audit",
        "m3.graphql-audit",
        "m3.websocket-audit",
        "m3.subdomain-takeover",
        # S10 hardening family (ch03#2/#12/#13/#15).
        "m3.nosql-oracle",
        "m3.directory-traversal",
        "m3.file-inclusion",
        "m3.crlf-injection",
        # S15 proof ladder.
        "m3.sqli-oob",
        "m3.xxe-oob",
        "m3.cmdi-oob",
        "m3.ssti-oob",
        "m3.rce-echo",
        "m3.state-marker",
    ):
        assert extended in ids, extended
    # An active check must demand the opt-in (F-01-09), and a read-only one must not.
    for check in M3_CHECKS:
        metadata = check.metadata
        if metadata.type == "active":
            assert metadata.requires_active_checks, metadata.id
        assert metadata.safe, metadata.id
        assert metadata.cwe, metadata.id
        assert metadata.research_ref.startswith("ch03#"), metadata.id


# ------------------------------------------------------------------ injection
async def test_sqli_reports_the_error_oracle_in_a_query_parameter(harness: WebHarness) -> None:
    results, _ = await run_check(
        SqliOracle,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert [item for item in payloads if item.get("technique") == "error-based"]
    assert any(item.get("db_family") == "mysql" for item in payloads)
    assert any(item.get("parameter") == "category" for item in payloads)
    # The escaped control page and the JSON API must not be reported.
    assert "/safe-search" not in titles(results)
    assert not [item for item in payloads if "user-fixed" in str(item.get("endpoint", ""))]


async def test_sqli_skips_in_a_dry_run(harness: WebHarness) -> None:
    results, _ = await run_check(SqliOracle, harness.asset, http=None, config=harness.config)
    assert len(results) == 1
    assert any(item.payload.get("skipped") for item in results[0].evidence)


# ------------------------------------------------------------------ cross-site scripting
async def test_xss_classifies_the_html_and_attribute_reflections(harness: WebHarness) -> None:
    results, _ = await run_check(
        XssOracle,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    contexts = {
        (str(item.get("endpoint", "")).split("?")[0], item.get("context")) for item in payloads
    }
    assert any(endpoint.endswith("/search") and context == "html" for endpoint, context in contexts)
    attribute = [item for item in contexts if item[0].endswith("/profile")]
    assert attribute and attribute[0][1] == "attribute"
    # The escaped echo is the trap: it must not be a finding.
    assert not any("/safe-search" in str(item.get("endpoint", "")) for item in payloads)


# ------------------------------------------------------------------ files
async def test_traversal_confirms_by_content_marker(harness: WebHarness) -> None:
    results, _ = await run_check(
        TraversalOracle,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert any(item.get("marker_file") == "/etc/passwd" for item in payloads)
    assert any(item.get("parameter") == "file" for item in payloads)
    assert not any("/hardened-download" in str(item.get("endpoint", "")) for item in payloads)


async def test_upload_audit_needs_the_opt_in_and_then_finds_the_extension_gap(lab: WebLab) -> None:
    default = make_web_harness(lab, upload_probe=False)
    await default.prepare()
    try:
        results, _ = await run_check(
            UploadAudit,
            default.asset,
            http=default.client,
            config=default.config,
            web=default.inventory,
        )
        assert results and all(item.status == "info" for item in results)
        assert any(item.payload.get("skipped") for item in results[0].evidence)
    finally:
        await close_harness(default)

    enabled = make_web_harness(lab, upload_probe=True)
    await enabled.prepare()
    try:
        results, _ = await run_check(
            UploadAudit,
            enabled.asset,
            http=enabled.client,
            config=enabled.config,
            web=enabled.inventory,
        )
        payloads = artifacts(results)
        assert any(item.get("extension") == "php" for item in payloads)
        # The extension-allowlisted control form must not be reported.
        assert not any("upload-hardened" in str(item.get("endpoint", "")) for item in payloads)
    finally:
        await close_harness(enabled)


# ------------------------------------------------------------------ identity
async def test_csrf_flags_the_token_less_form_only(harness: WebHarness) -> None:
    results, _ = await run_check(
        CsrfAudit,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    endpoints = {str(item.get("endpoint", "")) for item in payloads}
    assert any(item.endswith("/account/settings") for item in endpoints)
    assert not any(item.endswith("/notes-fixed") for item in endpoints)


async def test_idor_enumerates_object_identifiers(harness: WebHarness) -> None:
    results, _ = await run_check(
        IdorOracle,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert payloads
    assert any(item.get("parameter") == "id" for item in payloads)
    assert any(item.get("distinct_records") for item in payloads)
    assert not any("user-fixed" in str(item.get("endpoint", "")) for item in payloads)


async def test_auth_session_audit_reports_transport_enumeration_and_cookie_flags(
    harness: WebHarness,
) -> None:
    results, _ = await run_check(
        AuthSessionAudit,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    signals = {str(item.get("signal")) for item in artifacts(results)}
    assert "session-cookie-hardening" in signals
    assert "insecure-login-transport" in signals
    assert "user-enumeration" in signals


# ------------------------------------------------------------------ transport
async def test_open_redirect_reads_a_reflected_location(harness: WebHarness) -> None:
    results, _ = await run_check(
        OpenRedirect,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert payloads
    assert all(item.get("location_host") == "arachne-redirect.invalid" for item in payloads)
    assert any("/redirect" in str(item.get("endpoint", "")) for item in payloads)
    assert not any("/api/safe-redirect" in str(item.get("endpoint", "")) for item in payloads)


async def test_cors_reports_the_reflected_origin_with_credentials(harness: WebHarness) -> None:
    results, _ = await run_check(
        CorsAudit,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert payloads
    # ``allows_auth``, not ``allow_credentials``: the evidence redactor blanks any key
    # containing "credential" (ADR-120.7), so the flag is named for what it means.
    assert any(item.get("reflected") and item.get("allows_auth") for item in payloads)
    assert any("/api/config" in str(item.get("endpoint", "")) for item in payloads)
    assert not any("/api/config-fixed" in str(item.get("endpoint", "")) for item in payloads)


async def test_rate_limit_audit_profiles_the_unthrottled_login(harness: WebHarness) -> None:
    results, _ = await run_check(
        RateLimitAudit,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert any(item.get("signal") == "no-rate-limit" for item in payloads)
    assert not any("/login-fast" in str(item.get("endpoint", "")) for item in payloads)


# ------------------------------------------------------------------ exposure
async def test_security_headers_reports_the_missing_baseline_and_weak_cookies(
    harness: WebHarness,
) -> None:
    results, _ = await run_check(
        SecurityHeaders,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    missing = next(item for item in payloads if item.get("signal") == "missing-headers")
    assert "content-security-policy" in missing["missing"]
    assert any(item.get("signal") == "weak-cookie-flags" for item in payloads)


async def test_api_surface_finds_the_hidden_endpoint_and_ignores_the_catch_all(
    harness: WebHarness,
) -> None:
    results, _ = await run_check(
        ApiSurface,
        harness.asset,
        http=harness.client,
        config=harness.config,
        web=harness.inventory,
        memory=harness.memory,
    )
    payloads = artifacts(results)
    assert any(str(item.get("path", "")).rstrip("/") == "/admin" for item in payloads)
    assert not any(str(item.get("path", "")).startswith("/api/v1") for item in payloads)
    assets = harness.memory.store.list_assets(harness.memory.scan_id)
    recorded = {record.value for record in assets}
    assert any(value.endswith(("/admin", "/admin/")) for value in recorded)


# ------------------------------------------------------------------ hardening (ch03#2/#12/#13/#15)
# The four hardening oracles are exercised against a *scripted* transport rather than the live
# lab: their contract is the differential they read out of a response, so the test states the
# response each probe must receive. ``_ScriptedClient`` is the narrow ``ctx.http`` seam
# (``request``), so no HTTP library is imported and nothing leaves the process.


def _exchange(
    url: str, body: str, *, status: int = 200, headers: dict[str, str] | None = None
) -> HttpExchange:
    return HttpExchange(
        method="GET",
        url=url,
        status_code=status,
        response_headers=dict(headers) if headers is not None else {"content-type": "text/html"},
        body=body,
    )


class _ScriptedClient:
    """A ``ctx.http`` that answers each URL from a responder and records what it was asked."""

    def __init__(self, responder: Callable[[str], HttpExchange]) -> None:
        self._responder = responder
        self.requests: list[str] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: object = None,
        content: object = None,
        follow_redirects: object = None,
    ) -> HttpExchange:
        self.requests.append(url)
        return self._responder(url)


def _inventory(url: str) -> WebInventory:
    """A one-page crawl so the check has an endpoint with the parameter under test."""
    inventory = WebInventory(origin=origin_of(url), roots=(url,))
    inventory.add_page(
        Page(
            url=url,
            status=200,
            headers={"content-type": "text/html"},
            body="<html><body>index</body></html>",
            content_type="text/html",
            elapsed_ms=1.0,
        )
    )
    return inventory


def _asset(url: str) -> Asset:
    return Asset.from_meta("url", url, {"declared": True})


# ------------------------------------------------------------------ NoSQL (ch03#2)
async def test_nosql_reports_a_query_altered_by_an_operator_payload() -> None:
    url = "http://items.example/api/items?id=1"

    def responder(request_url: str) -> HttpExchange:
        value = parse_qs(urlsplit(request_url).query).get("id", [""])[0]
        if value == "1":
            return _exchange(request_url, "items: apple, banana, cherry, date")
        return _exchange(request_url, "no matching items")

    client = _ScriptedClient(responder)
    results, _ = await run_check(NosqlOracle, _asset(url), http=client, web=_inventory(url))
    payloads = artifacts(results)
    assert any(item.get("signal") == "nosql-injection" for item in payloads)
    assert any(item.get("parameter") == "id" for item in payloads)
    assert len(client.requests) >= 2


async def test_nosql_stays_quiet_on_a_parameter_that_ignores_input() -> None:
    url = "http://safe.example/api/items?id=1"

    def responder(request_url: str) -> HttpExchange:
        return _exchange(request_url, "items: apple, banana, cherry, date")

    client = _ScriptedClient(responder)
    results, _ = await run_check(NosqlOracle, _asset(url), http=client, web=_inventory(url))
    assert not artifacts(results)
    assert any(item.status == "not_vulnerable" for item in results)


# ------------------------------------------------------------------ directory traversal (ch03#12)
async def test_directory_traversal_confirms_by_a_file_canary() -> None:
    url = "http://files.example/download?file=report.txt"

    def responder(request_url: str) -> HttpExchange:
        value = parse_qs(urlsplit(request_url).query).get("file", [""])[0]
        if "passwd" in value or "win.ini" in value:
            return _exchange(request_url, "root:x:0:0:root:/root:/bin/bash\n")
        return _exchange(request_url, "report not found")

    client = _ScriptedClient(responder)
    results, _ = await run_check(DirectoryTraversal, _asset(url), http=client, web=_inventory(url))
    payloads = artifacts(results)
    assert any(item.get("signal") == "directory-traversal" for item in payloads)
    assert any(item.get("parameter") == "file" for item in payloads)
    assert any(item.get("canary") for item in payloads)


async def test_directory_traversal_ignores_a_sanitised_download() -> None:
    url = "http://files.example/hardened-download?file=report.txt"

    def responder(request_url: str) -> HttpExchange:
        return _exchange(request_url, "requested file is not available")

    client = _ScriptedClient(responder)
    results, _ = await run_check(DirectoryTraversal, _asset(url), http=client, web=_inventory(url))
    assert not artifacts(results)
    assert any(item.status == "not_vulnerable" for item in results)


# ------------------------------------------------------------------ file inclusion (ch03#13)
async def test_file_inclusion_confirms_a_local_file_disclosure() -> None:
    url = "http://files.example/view?page=home"

    def responder(request_url: str) -> HttpExchange:
        value = parse_qs(urlsplit(request_url).query).get("page", [""])[0]
        if value.endswith("/etc/passwd"):
            return _exchange(request_url, "root:x:0:0:root:/root:/bin/bash\n")
        return _exchange(request_url, "page not found")

    client = _ScriptedClient(responder)
    results, _ = await run_check(FileInclusion, _asset(url), http=client, web=_inventory(url))
    payloads = artifacts(results)
    assert any(item.get("technique") == "lfi" for item in payloads)
    assert any(item.get("parameter") == "page" for item in payloads)


async def test_file_inclusion_stays_quiet_without_a_canary_or_wrapper_error() -> None:
    url = "http://files.example/view?page=home"

    def responder(request_url: str) -> HttpExchange:
        return _exchange(request_url, "page not found")

    client = _ScriptedClient(responder)
    results, _ = await run_check(FileInclusion, _asset(url), http=client, web=_inventory(url))
    assert not artifacts(results)
    assert any(item.status == "not_vulnerable" for item in results)


# -------------------------------------------------------- CRLF / header injection (ch03#15)
async def test_crlf_injection_reports_an_echoed_header() -> None:
    url = "http://app.example/r?next=home"

    def responder(request_url: str) -> HttpExchange:
        value = parse_qs(urlsplit(request_url).query).get("next", [""])[0]
        if "X-Injected:" in value:
            marker = value.split("X-Injected:", 1)[1].strip().split()[0]
            return _exchange(request_url, "ok", headers={"X-Injected": marker})
        if "Set-Cookie:" in value:
            marker = value.split("Set-Cookie:", 1)[1].strip().split("=")[0]
            return _exchange(request_url, "ok", headers={"Set-Cookie": f"{marker}=1"})
        return _exchange(request_url, "ok")

    client = _ScriptedClient(responder)
    results, _ = await run_check(CrlfInjection, _asset(url), http=client, web=_inventory(url))
    payloads = artifacts(results)
    assert any(item.get("signal") == "crlf-injection" for item in payloads)
    assert any(item.get("technique") == "injected-header" for item in payloads)


async def test_crlf_injection_stays_quiet_when_headers_are_encoded() -> None:
    url = "http://app.example/safe?next=home"

    def responder(request_url: str) -> HttpExchange:
        return _exchange(request_url, "ok")

    client = _ScriptedClient(responder)
    results, _ = await run_check(CrlfInjection, _asset(url), http=client, web=_inventory(url))
    assert not artifacts(results)
    assert any(item.status == "not_vulnerable" for item in results)
