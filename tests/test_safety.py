"""Safety suite : the properties that must never regress.

1. **Redaction is applied at capture time** (F-08-01, F-08-04) — a secret a target returns
   in a body, a header, or a redirect URL is already gone from the evidence object, the
   audit record, and the log line, so no later stage can leak it.
2. **Rate limits hold** (F-01-07) — per-host and global token buckets, including across
   retries, which must not be a way to bypass the budget .
3. **Private-IP URLs are blocked** (F-08-03) — a literal private address, a DNS name that
   resolves to one, and a redirect pointing at one are all refused before any request is
   sent, and the refusal is audited (F-01-08).
4. **A scan cannot leave its declared and authorized scope** (F-01-02, F-01-09, F-08-05) —
   an out-of-scope target is refused before the scan is created, a live scan without an
   authorization attestation is refused before the process can send anything, and a check
   that tries to reach outside the scan's scope is blocked per request and audited. Each
   refusal is recorded with its reason.

The tests are async: with ``asyncio_mode = "auto"`` (pyproject.toml) pytest-asyncio runs
them directly, so each scenario reads like the code it exercises.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import HttpSettings, SafetySettings, Settings
from arachne.core.errors import AuthorizationError, OutOfScopeError, UnsafeUrlError
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, StepContext
from arachne.core.logging import configure_logging
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.ratelimit import RateLimitSettings, TokenBucket
from arachne.core.redaction import redact_text, redact_url
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy, classify_ip
from arachne.core.vault import CredentialScope
from arachne.creds.broker import CredentialBroker
from arachne.modules.registry import ModuleRegistry
from tests.conftest import PUBLIC_IP, TARGET_HOST, build_scan_request
from tests.helpers.checks import make_step_context
from tests.helpers.vault import make_vault

# --------------------------------------------------------------------------- secrets
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "sup3rs3cr3t-db-password"
BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"

SECRET_BODY = json.dumps(
    {
        "aws_access_key_id": AWS_ACCESS_KEY,
        "aws_secret_access_key": AWS_SECRET_KEY,
        "database": {"password": DB_PASSWORD, "host": "db.internal.example"},
        "authorization": BEARER,
    }
)


async def test_redaction_applied_to_captured_evidence(make_client) -> None:
    """Secrets in a response body and headers never survive into the exchange."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=SECRET_BODY,
            headers={
                "Content-Type": "application/json",
                "Set-Cookie": f"session={DB_PASSWORD}; Path=/",
                "X-Api-Key": AWS_ACCESS_KEY,
            },
        )

    client = make_client(handler)
    exchange = await client.get(f"https://{TARGET_HOST}/config.json")

    assert AWS_ACCESS_KEY not in exchange.body
    assert AWS_SECRET_KEY not in exchange.body
    assert DB_PASSWORD not in exchange.body
    assert "eyJhbGciOiJIUzI1NiJ9" not in exchange.body
    assert "[REDACTED" in exchange.body

    # Header values are cleared too (lookup is case-insensitive: transports normalise).
    assert AWS_ACCESS_KEY not in (exchange.header("x-api-key") or "")
    assert DB_PASSWORD not in (exchange.header("set-cookie") or "")

    # Evidence built from the exchange inherits the redaction (F-08-04).
    request_evidence, response_evidence = exchange.to_evidence()
    dumped = json.dumps([request_evidence.to_dict(), response_evidence.to_dict()])
    assert AWS_SECRET_KEY not in dumped
    assert DB_PASSWORD not in dumped


async def test_redaction_applied_to_audit_trail(make_client, audit_sink: MemoryAuditSink) -> None:
    """Audit records carry a redacted URL and redacted metadata (F-08-01)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=SECRET_BODY, headers={"X-Api-Key": AWS_ACCESS_KEY})

    client = make_client(handler)
    await client.get(f"https://{TARGET_HOST}/secrets?token={AWS_ACCESS_KEY}")

    audit_dump = json.dumps([event.to_dict() for event in audit_sink.events])
    assert AWS_ACCESS_KEY not in audit_dump
    assert "query-param" in audit_dump
    assert audit_sink.of_action(AuditAction.HTTP_REQUEST)


def test_redaction_applied_to_log_output() -> None:
    """Secrets in a log message or an ``extra`` field never reach the stream (F-08-01).

    Redaction is pattern-based, so what this pins is the *wiring*: every identifiable
    secret form (prefixed keys, assignments, JWTs, credentialed URLs, PEM blocks) is
    scrubbed on both the message and the extra fields. A bare high-entropy string with no
    recognisable form is not detectable — which is why the rule is "never log secrets in
    the first place" (the S1 gotchas).
    """
    stream = StringIO()
    configure_logging("INFO", json_output=True, stream=stream)
    try:
        logging.getLogger("arachne.test").warning(
            "target leaked credential token=%s for %s",
            AWS_SECRET_KEY,
            f"AKIAIOSFODNN7EXAMPLE at postgres://admin:{DB_PASSWORD}@db.internal/app",
            extra={"body": SECRET_BODY, "x_api_key": AWS_ACCESS_KEY},
        )
    finally:
        configure_logging("INFO", json_output=True)

    emitted = stream.getvalue()
    assert AWS_ACCESS_KEY not in emitted
    assert DB_PASSWORD not in emitted
    assert "[REDACTED" in emitted
    assert "target leaked credential" in emitted  # the useful part of the line survives


def test_redaction_helpers_cover_urls_text_and_keys() -> None:
    assert (
        redact_url(f"https://user:pw@example.com/path?api_key={AWS_ACCESS_KEY}&q=1")
        == "https://user:[REDACTED:url-password]@example.com/path"
        "?api_key=[REDACTED:query-param]&q=1"
    )
    assert AWS_ACCESS_KEY not in redact_text(f"key={AWS_ACCESS_KEY}")
    assert "MIIEow" not in redact_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    )


# ----------------------------------------------------------------------- rate limits
async def test_rate_limit_respected_per_host(make_client, fake_clock) -> None:
    """Three requests through a burst-1 bucket must be spread over the clock."""
    client = make_client(
        rate_limit=RateLimitSettings(
            per_host_rate=10.0, per_host_burst=1, global_rate=1000.0, global_burst=1000
        )
    )
    for _ in range(3):
        await client.get(f"https://{TARGET_HOST}/")

    # The first request spends the token; the next two wait one token interval each.
    assert fake_clock.sleep_calls >= 2
    assert fake_clock.now == pytest.approx(0.2, abs=0.01)


async def test_global_rate_limit_spreads_requests_across_hosts(make_client, fake_clock) -> None:
    """The global budget throttles even when each host has budget left (F-01-06/07)."""
    client = make_client(
        scope=Scope(allowed_hosts=("a.example.com", "b.example.com", "c.example.com")),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=10.0, global_burst=1
        ),
    )
    for host in ("a.example.com", "b.example.com", "c.example.com"):
        await client.get(f"https://{host}/")

    assert fake_clock.now == pytest.approx(0.2, abs=0.01)


async def test_retries_do_not_bypass_rate_limits(make_client, fake_clock) -> None:
    """Each retry re-acquires tokens ."""
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(200, text="ok")

    client = make_client(
        flaky,
        rate_limit=RateLimitSettings(
            per_host_rate=10.0, per_host_burst=1, global_rate=1000.0, global_burst=1000
        ),
        http=HttpSettings(retries=2),
    )
    exchange = await client.get(f"https://{TARGET_HOST}/")

    assert exchange.attempts == 2
    assert calls["n"] == 2
    # One wait for the retry: the retry could not skip the throttle.
    assert fake_clock.sleep_calls >= 1
    assert fake_clock.now >= 0.1


async def test_rate_limiter_rejects_burst_above_capacity() -> None:
    bucket = TokenBucket(rate=1.0, burst=2)
    with pytest.raises(ValueError, match="capacity"):
        await bucket.acquire(3)


# ------------------------------------------------------------------- private IP URLs
BLOCKED_URLS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/admin",
    "http://localhost/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.4.4/",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[fd00::1]/",
    "http://2130706433/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
async def test_private_ip_and_dangerous_urls_blocked(make_client, audit_sink, url: str) -> None:
    """Every dangerous URL is refused, audited, and never reaches the transport."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="should not happen")

    client = make_client(handler, scope=Scope(allowed_hosts=(TARGET_HOST,)))
    with pytest.raises((UnsafeUrlError, OutOfScopeError)):
        await client.get(url)

    assert seen == [], "a blocked URL must never produce a network request"
    blocked = [event for event in audit_sink.events if event.outcome.value == "blocked"]
    assert blocked, "a refusal must be audited (F-01-08)"
    assert blocked[0].action in {AuditAction.SAFETY_BLOCKED, AuditAction.SCOPE_REJECTED}


async def test_dns_name_resolving_to_private_ip_is_blocked(make_client) -> None:
    """A public-looking name pointing at internal space is still refused."""
    client = make_client(addresses=("10.13.37.9",))
    with pytest.raises(UnsafeUrlError, match="private-address"):
        await client.get(f"https://{TARGET_HOST}/")


async def test_redirect_to_private_ip_is_blocked(make_client, audit_sink) -> None:
    """A target cannot redirect the scanner into the internal network."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/"})

    client = make_client(handler)
    with pytest.raises(UnsafeUrlError, match="link-local-address"):
        await client.get(f"https://{TARGET_HOST}/")

    assert requested == [f"https://{TARGET_HOST}/"], "only the first hop may be sent"
    assert any(event.outcome.value == "blocked" for event in audit_sink.events)


async def test_out_of_scope_host_is_blocked_and_audited(make_client, audit_sink) -> None:
    """The allowlist is enforced before the request leaves the process (F-01-02)."""
    client = make_client(scope=Scope(allowed_hosts=(TARGET_HOST,)))
    with pytest.raises(OutOfScopeError):
        await client.get("https://not-declared.example.net/")

    assert audit_sink.of_action(AuditAction.SCOPE_REJECTED)


async def test_empty_scope_denies_everything(make_client) -> None:
    """Deny-by-default: an undeclared scope contacts nothing (F-01-09)."""
    client = make_client(scope=Scope.deny_all())
    with pytest.raises(OutOfScopeError, match="deny by default"):
        await client.get(f"https://{TARGET_HOST}/")


async def test_loopback_allowed_only_when_policy_permits_it(make_client) -> None:
    """Lab work is possible, but only through an explicit opt-in (F-08-03)."""
    client = make_client(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
    exchange = await client.get("http://127.0.0.1:8080/health")

    assert exchange.status_code == 200
    assert exchange.resolved_addresses == ("127.0.0.1",)


def test_safety_helpers_used_by_the_client_agree_with_policy() -> None:
    assert classify_ip(PUBLIC_IP) is None
    assert classify_ip("127.0.0.1") == "loopback-address"
    assert classify_ip("169.254.169.254") == "link-local-address"
    assert classify_ip("10.0.0.1") == "private-address"
    # Opting into private ranges does not silently open the metadata endpoint.
    permissive = UrlSafetyPolicy(allow_private_ips=True, allow_loopback=True)
    assert classify_ip("169.254.169.254", permissive) == "link-local-address"


# ---------------------------------------------------- scope & authorization gates (S2)
def _scan_stack(
    *, sink: MemoryAuditSink | None = None, **settings_overrides: object
) -> tuple[Orchestrator, MemoryAuditSink, list[str]]:
    """An orchestrator wired to a memory audit sink and a transport that records calls."""
    audit_sink = sink or MemoryAuditSink()
    auditor = Auditor(audit_sink, actor="pytest")
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(**settings_overrides),  # type: ignore[arg-type]
        log_level="CRITICAL",
    )
    requests: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, text="ok")

    def client_factory(scope: Scope) -> httpx.AsyncClient:  # pragma: no cover - adapter
        raise AssertionError("unused")

    def factory(scope: Scope):  # type: ignore[no-untyped-def]
        from arachne.core.http import ScopedHttpClient

        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            resolver=StaticResolver((PUBLIC_IP,)),
            auditor=auditor,
            transport=httpx.MockTransport(transport_handler),
        )

    orchestrator = Orchestrator(
        settings=settings,
        auditor=auditor,
        bus=EventBus(),
        store=MemoryScanStateStore(),
        client_factory=factory,
        handlers={},
    )
    del client_factory
    return orchestrator, audit_sink, requests


def test_an_out_of_scope_target_is_blocked_and_the_block_is_audited() -> None:
    """F-01-02 + F-01-08: the refusal happens before anything is created or sent."""
    orchestrator, sink, requests = _scan_stack(scope=Scope(allowed_hosts=("in-scope.example",)))

    with pytest.raises(OutOfScopeError) as excinfo:
        orchestrator.plan(build_scan_request(), dry_run=True)

    assert "out of scope" in str(excinfo.value)
    assert "deployment scope" in excinfo.value.reason
    blocked = [event for event in sink.events if event.outcome.value == "blocked"]
    assert blocked, "a blocked target must be recorded in the audit log (F-01-08)"
    assert blocked[0].action is AuditAction.SCOPE_REJECTED
    assert blocked[0].reason
    assert blocked[0].meta["kind"] == "url"
    assert orchestrator.store.list_scans() == ()
    assert requests == []


def test_a_target_excluded_by_its_own_definition_is_blocked_and_audited() -> None:
    orchestrator, sink, requests = _scan_stack()
    request = build_scan_request(
        targets=[{"kind": "domain", "value": "example.com"}],
        exclusions=[{"kind": "domain", "value": "example.com"}],
    )

    with pytest.raises(OutOfScopeError, match="excluded"):
        orchestrator.plan(request, dry_run=True)

    assert sink.of_action(AuditAction.SCOPE_REJECTED)
    assert "excluded" in (sink.of_action(AuditAction.SCOPE_REJECTED)[0].reason or "")
    assert requests == []


async def test_a_live_scan_without_an_attestation_never_leaves_the_process() -> None:
    """F-01-09 + F-08-05: no attestation, no request — the gate runs first."""
    orchestrator, sink, requests = _scan_stack()

    with pytest.raises(AuthorizationError, match="no authorization attestation"):
        await orchestrator.scan(build_scan_request(attestation=None))

    rejected = sink.of_action(AuditAction.AUTH_REJECTED)
    assert rejected and rejected[0].outcome.value == "blocked"
    assert orchestrator.store.list_scans() == ()
    assert requests == []


async def test_a_check_cannot_reach_a_host_outside_the_scan_scope() -> None:
    """Every request goes through the shared client, scoped to the definition (ADR-05)."""
    reachable: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        reachable.append(str(request.url))
        return httpx.Response(200, text="ok")

    request = build_scan_request(targets=[{"kind": "domain", "value": "example.com"}])
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(),
        log_level="CRITICAL",
    )

    async def poking_handler(context: StepContext) -> object:
        from arachne.core.lifecycle import StepOutcome

        # A module that tries to wander: the client refuses before any packet is sent.
        with pytest.raises(OutOfScopeError):
            await context.http.get("https://elsewhere.example.net/admin")
        good = await context.http.get("https://example.com/")
        assert good.status_code == 200
        return StepOutcome()

    def factory(scope: Scope):  # type: ignore[no-untyped-def]
        from arachne.core.http import ScopedHttpClient

        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            resolver=StaticResolver((PUBLIC_IP,)),
            auditor=auditor,
            transport=httpx.MockTransport(transport_handler),
        )

    orchestrator = Orchestrator(
        settings=settings,
        auditor=auditor,
        bus=EventBus(),
        store=MemoryScanStateStore(),
        client_factory=factory,
        handlers={ScanStep.RECON: poking_handler},
    )

    session = await orchestrator.scan(request)

    assert session.scan_id is not None
    assert reachable == ["https://example.com/"], "only the in-scope URL may be requested"
    assert sink.of_action(AuditAction.SCOPE_REJECTED)
    assert sink.of_action(AuditAction.HTTP_REQUEST)


def test_an_attestation_is_recorded_in_the_audit_log() -> None:
    """F-08-05: who authorized what scope, and when, is part of the audit trail."""
    orchestrator, sink, _ = _scan_stack()

    orchestrator.plan(build_scan_request(), dry_run=False)

    recorded = sink.of_action(AuditAction.ATTESTATION_RECORDED)
    assert recorded
    assert recorded[0].meta["attested_by"].startswith("Jane Operator")
    assert recorded[0].meta["allowed_targets"] == ["example.com"]


# ------------------------------------------------------------------ S3: OSINT and secrets
# The module framework added a second HTTP client (third-party OSINT sources) and a second
# way for target data to reach a finding (extracted secrets). Both are safety-critical, so
# the properties below are asserted here rather than only in the unit suite.


async def test_the_osint_client_cannot_reach_anything_but_its_providers() -> None:
    """F-01-02 applied to the second client: an unnamed third party is out of scope.

    The OSINT client exists because crt.sh is not the target; that is exactly why its scope
    has to be its own allowlist and not a copy of the scan's.
    """
    from arachne.modules.providers import build_osint_access

    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    access = build_osint_access(
        enabled=True, providers=("crtsh",), auditor=auditor, search_url=None
    )
    assert access is not None
    assert access.client.scope.check("crt.sh").allowed
    assert not access.client.scope.check("example.com").allowed
    assert not access.client.scope.check("internetdb.shodan.io").allowed
    await access.aclose()


async def test_an_osint_request_outside_the_allowlist_is_refused_and_audited() -> None:
    from arachne.core.errors import OsintError
    from arachne.modules.providers import build_osint_access

    sink = MemoryAuditSink()
    access = build_osint_access(
        enabled=True, providers=("crtsh",), auditor=Auditor(sink, actor="pytest")
    )
    assert access is not None
    with pytest.raises(OsintError):
        await access.fetch("crtsh", "https://attacker.example/steal")
    assert sink.of_action(AuditAction.SAFETY_BLOCKED) or sink.of_action(AuditAction.SCOPE_REJECTED)
    await access.aclose()


async def test_a_tls_certificate_secret_in_a_body_never_reaches_a_finding() -> None:
    """A credential a target serves is redacted before a check can even see it (F-08-04).

    The js-asset-scan check reports *which detectors fired*, never a value; this asserts the
    property end to end, from the response body to the persisted candidate.
    """
    from arachne.core.config import Settings as S3Settings
    from arachne.core.safety import Scope as S3Scope
    from arachne.data.finding_store import MemoryFindingStore
    from arachne.modules.handlers import build_handlers
    from arachne.modules.registry import ModuleRegistry

    secret = "AKIAIOSFODNN7EXAMPLE"
    body = f"const cfg = {{aws_access_key_id: '{secret}', admin: '/api/v1/admin/users'}};"

    def transport_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".js"):
            return httpx.Response(
                200, text=body, headers={"content-type": "application/javascript"}
            )
        return httpx.Response(
            200,
            text='<html><script src="/app.js"></script></html>',
            headers={"content-type": "text/html"},
        )

    settings = S3Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        http=HttpSettings(retries=0, follow_redirects=False),
    )
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    findings = MemoryFindingStore()
    registry = ModuleRegistry.discover()
    handlers = build_handlers(
        settings=settings, registry=registry, findings=findings, auditor=auditor
    )

    def factory(scope: S3Scope):  # type: ignore[no-untyped-def]
        from arachne.core.http import ScopedHttpClient

        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            resolver=StaticResolver((PUBLIC_IP,)),
            auditor=auditor,
            transport=httpx.MockTransport(transport_handler),
        )

    orchestrator = Orchestrator(
        settings=settings,
        auditor=auditor,
        bus=EventBus(),
        store=MemoryScanStateStore(),
        handlers=handlers,
        registry=registry,
        client_factory=factory,
    )
    session = await orchestrator.scan(build_scan_request())

    candidates = findings.list_candidates(session.scan_id or 0)
    assert candidates, "the JavaScript scan should have flagged the hardcoded key"
    blob = json.dumps([record.to_dict() for record in candidates])
    assert secret not in blob
    assert "aws-access-key-id" in blob
    # The audit trail and the events are equally clean.
    assert secret not in json.dumps([event.to_dict() for event in sink.events])
    events = json.dumps([event.to_dict() for event in orchestrator.bus.history()])
    assert secret not in events


async def test_a_scan_with_osint_disabled_queries_no_third_party() -> None:
    """The default posture (F-02-09): nothing leaves the process for OSINT unless asked."""
    from arachne.core.config import Settings as S3Settings
    from arachne.modules.handlers import build_handlers
    from arachne.modules.registry import ModuleRegistry

    class Sentinel(httpx.AsyncBaseTransport):
        """Records where a request went, so "did this touch a third party?" is answerable."""

        urls: list[str] = []

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            Sentinel.urls.append(str(request.url))
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    settings = S3Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    registry = ModuleRegistry.discover()
    handlers = build_handlers(settings=settings, registry=registry)
    sink = MemoryAuditSink()
    orchestrator = Orchestrator(
        settings=settings,
        auditor=Auditor(sink, actor="pytest"),
        bus=EventBus(),
        store=MemoryScanStateStore(),
        handlers=handlers,
        registry=registry,
        client_factory=lambda scope: ScopedHttpClient(
            settings=settings,
            scope=scope,
            resolver=StaticResolver((PUBLIC_IP,)),
            transport=Sentinel(),
        ),
    )
    await orchestrator.scan(build_scan_request())
    # Only the declared target is read; no third-party source is involved.
    assert Sentinel.urls, "the scan should still do its target-scoped work"
    assert all(url.startswith("https://example.com/") for url in Sentinel.urls), Sentinel.urls
    assert not sink.of_action(AuditAction.OSINT_QUERY)


# --------------------------------------------------------------------------- S4: M2 network probes
async def test_no_network_probe_is_ever_sent_out_of_scope() -> None:
    """F-01-02 for the TCP/UDP/TLS path: the scope gate runs before any packet.

    The transport is a recording fake, so "nothing was dialled" is provable: an out-of-scope
    target yields a refusal and an empty call log, whatever protocol is used.
    """
    from arachne.core.config import NetSettings
    from arachne.core.config import Settings as S4Settings
    from arachne.core.errors import OutOfScopeError
    from arachne.core.net import ScopedNetClient, ScriptedNetTransport
    from arachne.core.safety import Scope, UrlSafetyPolicy

    transport = ScriptedNetTransport()
    client = ScopedNetClient(
        settings=S4Settings(net=NetSettings()),
        scope=Scope(allowed_hosts=("only.example",)),
        policy=UrlSafetyPolicy(allow_private_ips=True, allow_loopback=True),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=transport,
    )
    for probe in (
        client.tcp("elsewhere.example", 22),
        client.udp("elsewhere.example", 161, b"\x30\x00"),
        client.tls("elsewhere.example", 443),
        client.icmp("elsewhere.example"),
    ):
        with pytest.raises(OutOfScopeError):
            await probe
    assert transport.calls == [], "an out-of-scope probe must not reach the transport"


async def test_a_private_address_needs_an_explicit_policy_permission() -> None:
    """F-08-03: the address policy applies to raw probes exactly as it does to HTTP."""
    from arachne.core.config import NetSettings
    from arachne.core.config import Settings as S4Settings
    from arachne.core.errors import SafetyError
    from arachne.core.net import ScopedNetClient, ScriptedNetTransport
    from arachne.core.safety import Scope

    transport = ScriptedNetTransport()
    client = ScopedNetClient(
        settings=S4Settings(net=NetSettings()),
        scope=Scope(allowed_hosts=("10.1.2.3", "169.254.169.254")),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=transport,
    )
    with pytest.raises(SafetyError):
        await client.tcp("10.1.2.3", 445)  # RFC1918 is private by default
    with pytest.raises(SafetyError):
        await client.tcp("169.254.169.254", 80)  # the cloud metadata address
    assert transport.calls == []


async def test_active_m2_checks_never_run_without_the_opt_in_and_the_attestation() -> None:
    """F-01-09 for M2: no active probe without ``--active-checks`` *and* an attestation."""
    from arachne.core.planner import MODULE_STEP, ScanStep
    from arachne.modules.registry import ModuleRegistry

    registry = ModuleRegistry.builtin()
    m2_active = [
        check
        for check in registry.checks()
        if MODULE_STEP[check.metadata.module] is ScanStep.DISCOVERY
        and check.metadata.requires_active_checks
    ]
    assert m2_active, "M2 ships active checks; the gate must have something to withhold"
    from arachne.core.target import ModuleSelection

    for allowed in (False,):
        selected = registry.select(ModuleSelection(), active_checks_allowed=allowed)
        assert not {check.metadata.id for check in selected} & {
            check.metadata.id for check in m2_active
        }


async def test_a_dry_run_run_builds_no_network_client() -> None:
    """F-01-10: a dry run has no client at all, so M2's checks cannot probe anything."""
    from arachne.core.config import Settings as S4Settings
    from arachne.core.planner import ScanStep
    from arachne.modules.handlers import build_handlers

    settings = S4Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    handlers = build_handlers(settings=settings)
    assert ScanStep.DISCOVERY in handlers
    # The handler is the module-backed one, and it reports "no client" rather than probing.
    from arachne.core.events import EventBus
    from arachne.core.lifecycle import MemoryScanStateStore, StepContext
    from arachne.core.safety import Scope

    request = build_scan_request()
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    context = StepContext(
        scan_id=record.id,
        step=ScanStep.DISCOVERY,
        definition=request.target,
        options=request.options,
        scope=Scope.deny_all() if False else request.target.compile_scope(),
        store=store,
        bus=EventBus(),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        http=None,
        net=None,
    )
    outcome = await handlers[ScanStep.DISCOVERY](context)
    assert outcome.stats.get("net_checks_skipped") is True
    assert outcome.stats.get("checks_run", 0) == 0


async def test_udp_probing_is_off_unless_the_deployment_allows_it() -> None:
    """F-01-09: UDP is a deployment-level opt-in *on top of* the per-check opt-in."""
    from arachne.core.results import CheckResult
    from arachne.modules.context import ModuleConfig
    from arachne.modules.m2.netinfra import SnmpEnum
    from tests.helpers.checks import make_m2_harness

    harness = make_m2_harness(seed_services=[(161, "snmp")])
    context = harness.context(SnmpEnum, config=ModuleConfig(net_allow_udp=False))
    results: list[CheckResult] = [result async for result in context.module.run(context)]
    assert harness.transport.calls == [], "no datagram may be sent while UDP is disabled"
    assert all(any(item.payload.get("skipped") for item in result.evidence) for result in results)


# ---------------------------------------------------------------------- S7: M4 exposure
# M4 is the module that *collects* other people's secrets, so its safety properties are the
# most load-bearing of the build: a served credential must never reach evidence, only the
# redactor's detector names may; the operator's ledger is masked and encrypted; and the two
# checks that touch authentication or cloud metadata stay inert until explicitly enabled.
M4_ENV_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sup3rs3cr3t-db-password",
)
M4_MANIFEST_PASSPHRASE = "s7-safety-passphrase"


def test_a_served_credential_never_reaches_evidence_or_the_ledger_plaintext(
    make_client, tmp_path
) -> None:
    """F-08-04 end to end: redaction at capture, and an encrypted, masked manifest."""
    from arachne.core.secrets import SecretsManifest, load_manifest

    body = (
        "APP_KEY=base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
        "DB_PASSWORD=sup3rs3cr3t-db-password\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})

    manifest_path = tmp_path / "secrets.enc"
    manifest = SecretsManifest(manifest_path, passphrase=M4_MANIFEST_PASSPHRASE)
    client = ScopedHttpClient(
        settings=Settings(database_url="sqlite:///:memory:", log_level="CRITICAL"),
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        transport=httpx.MockTransport(handler),
        secrets_manifest=manifest,
    )

    import asyncio

    exchange = asyncio.run(client.get(f"https://{TARGET_HOST}/.env"))
    asyncio.run(client.aclose())

    request_evidence, response_evidence = exchange.to_evidence()
    evidenced = json.dumps([request_evidence.to_dict(), response_evidence.to_dict()])
    for secret in M4_ENV_SECRETS:
        assert secret not in evidenced, secret
    assert "[REDACTED" in exchange.body
    # The detectors fired, which is what a check may report.
    assert "aws-access-key-id" in exchange.secret_kinds

    raw = manifest_path.read_bytes()
    assert raw.startswith(b"ARACHNE-SM-1")
    for secret in M4_ENV_SECRETS:
        assert secret.encode() not in raw, secret
    records = load_manifest(manifest_path, M4_MANIFEST_PASSPHRASE)
    assert records and all(item["masked"] for item in records)
    assert "aws-access-key-id" in {item["kind"] for item in records}


def test_cors_policy_headers_are_not_over_redacted(make_client) -> None:
    """A policy flag is not a secret: ``Access-Control-Allow-Credentials: true`` is evidence.

    The key-aware redactor blanks values under names containing "credential"; the CORS
    finding *is* that header, so those specific names are exempt while ``X-Api-Key`` and
    ``Authorization`` stay blanked (ADR-120.8).
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="{}",
            headers={
                "content-type": "application/json",
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
                "X-Api-Key": AWS_ACCESS_KEY,
                "Authorization": BEARER,
            },
        )

    client = make_client(handler)
    import asyncio

    exchange = asyncio.run(client.get(f"https://{TARGET_HOST}/api/config"))
    assert exchange.header("access-control-allow-credentials") == "true"
    assert exchange.header("access-control-allow-origin") == "https://evil.example"
    assert AWS_ACCESS_KEY not in (exchange.header("x-api-key") or "")
    assert "eyJhbGciOiJIUzI1NiJ9" not in (exchange.header("authorization") or "")


def test_m4_opt_in_checks_are_withheld_unless_named_and_authorized() -> None:
    """F-01-09 + F-02-09: two independent switches, plus an explicit check id."""
    from arachne.core.target import ModuleSelection
    from arachne.modules.registry import ModuleRegistry

    opt_in = {"m4.default-credentials", "m4.metadata-ssrf"}
    registry = ModuleRegistry.builtin()

    default = {check.metadata.id for check in registry.select(ModuleSelection())}
    assert not (opt_in & default), "an opt-in M4 check must not be in the default set"

    named_selection = ModuleSelection(checks=tuple(sorted(opt_in)))
    # ``select`` receives the named checks the way the scan handler passes them
    # (``options.modules.checks`` -> ``enabled_check_ids``).
    unauthorized = {
        check.metadata.id
        for check in registry.select(
            named_selection,
            active_checks_allowed=False,
            enabled_check_ids=named_selection.checks,
        )
    }
    assert not (opt_in & unauthorized), "naming a check never bypasses the active-checks gate"

    authorized = {
        check.metadata.id
        for check in registry.select(
            named_selection,
            active_checks_allowed=True,
            enabled_check_ids=named_selection.checks,
        )
    }
    assert opt_in <= authorized


async def test_a_named_m4_opt_in_check_still_sends_nothing_with_its_switch_off(
    make_client,
) -> None:
    """The config switch is the third gate: off means no request at all."""
    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m4.cloud import MetadataSsrf
    from tests.helpers.checks import make_step_context

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"a disabled check sent a request to {request.url}")

    client = make_client(handler)
    step, _memory = make_step_context(http=client, seed=[("url", f"https://{TARGET_HOST}/")])
    context = CheckContext(
        step=step,
        module=MetadataSsrf(),
        asset=Asset.from_meta("url", f"https://{TARGET_HOST}/", {"declared": True}),
        config=ModuleConfig(),
    )
    assert context.config.m4.metadata_ssrf_probe is False

    results = [result async for result in MetadataSsrf().run(context)]
    assert results
    assert all(any(item.payload.get("skipped") for item in result.evidence) for result in results)


def test_s10_opt_in_checks_are_withheld_unless_named_and_authorized() -> None:
    """F-01-09 + F-02-09 for the S10 opt-in families (M3 SSRF, M5 metadata)."""
    from arachne.core.target import ModuleSelection
    from arachne.modules.registry import ModuleRegistry

    opt_in = {"m3.ssrf-probe", "m5.imds-ssrf", "m5.azure-mi-audit"}
    registry = ModuleRegistry.builtin()

    default = {check.metadata.id for check in registry.select(ModuleSelection())}
    assert not (opt_in & default), "an S10 opt-in check must not be in the default set"

    named = ModuleSelection(checks=tuple(sorted(opt_in)))
    unauthorized = {
        check.metadata.id
        for check in registry.select(
            named, active_checks_allowed=False, enabled_check_ids=named.checks
        )
    }
    assert not (opt_in & unauthorized), "naming a check never bypasses the active-checks gate"

    authorized = {
        check.metadata.id
        for check in registry.select(
            named, active_checks_allowed=True, enabled_check_ids=named.checks
        )
    }
    assert opt_in <= authorized


async def test_a_named_m3_ssrf_check_sends_nothing_with_its_switch_off(make_client) -> None:
    """The SSRF callback switch is the third gate: off means no request at all."""
    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m3.advanced_protocol import SsrfProbe
    from tests.helpers.checks import make_step_context

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"a disabled check sent a request to {request.url}")

    client = make_client(handler)
    step, _memory = make_step_context(http=client, seed=[("url", f"https://{TARGET_HOST}/")])
    context = CheckContext(
        step=step,
        module=SsrfProbe(),
        asset=Asset.from_meta("url", f"https://{TARGET_HOST}/", {"declared": True}),
        config=ModuleConfig(),
    )
    assert context.config.web.ssrf_probe is False

    results = [result async for result in SsrfProbe().run(context)]
    assert results
    assert all(any(item.payload.get("skipped") for item in result.evidence) for result in results)


async def test_a_named_m5_imds_check_sends_nothing_with_its_switch_off(make_client) -> None:
    """The IMDS switch is the third gate: off means no metadata request at all."""
    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m5.cloud import ImdsSsrf
    from tests.helpers.checks import make_step_context

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"a disabled check sent a request to {request.url}")

    client = make_client(handler)
    step, _memory = make_step_context(http=client, seed=[("url", f"https://{TARGET_HOST}/")])
    context = CheckContext(
        step=step,
        module=ImdsSsrf(),
        asset=Asset.from_meta("url", f"https://{TARGET_HOST}/", {"declared": True}),
        config=ModuleConfig(),
    )
    assert context.config.m5.imds_probe is False

    results = [result async for result in ImdsSsrf().run(context)]
    assert results
    assert all(any(item.payload.get("skipped") for item in result.evidence) for result in results)


def test_s11_opt_in_checks_are_withheld_unless_named() -> None:
    """F-02-09 for the S11 opt-in families (M6 deception and AD path analysis).

    Neither is an *active* check (both only read local files), so the safety gate they carry
    is "off by default and inert until named", not the active-checks opt-in.
    """
    from arachne.core.target import ModuleSelection
    from arachne.modules.registry import ModuleRegistry

    opt_in = {"m6.deception-listeners", "m6.ad-attack-path"}
    registry = ModuleRegistry.builtin()

    for check in registry.select(ModuleSelection()):
        assert check.metadata.id not in opt_in, "an S11 opt-in check must not be in the default set"

    named = ModuleSelection(checks=tuple(sorted(opt_in)))
    selected = {
        check.metadata.id for check in registry.select(named, enabled_check_ids=named.checks)
    }
    assert opt_in <= selected
    # And they never demand the active-checks attestation (they send nothing).
    assert all(registry.get(check).metadata.requires_active_checks is False for check in opt_in)  # type: ignore[union-attr]


async def test_a_named_m6_sigma_check_reads_no_telemetry_without_the_grant(make_client) -> None:
    """The log-access grant is the gate: without it, nothing is ingested and nothing is sent."""
    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m6.hunting import SigmaHuntRules
    from tests.helpers.checks import make_step_context

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"the Sigma check sent a request to {request.url}")

    client = make_client(handler)
    step, _memory = make_step_context(http=client, seed=[("cloud", "repo:/tmp/does-not-exist")])
    context = CheckContext(
        step=step,
        module=SigmaHuntRules(),
        asset=Asset.from_meta("cloud", "repo:/tmp/does-not-exist", {"declared": True}),
        config=ModuleConfig(),
    )
    assert context.config.m6.log_access is False

    results = [result async for result in SigmaHuntRules().run(context)]
    assert results
    assert not [result for result in results if result.status == "vulnerable"]
    assert any(item.payload.get("skipped") for result in results for item in result.evidence)


# ------------------------------------------------------- distributed gates (S16, area SCALE)
#
# Distribution must not move a gate off the executing node (REQ-SCALE-008): a scan
# admitted on one node is re-checked on the node that actually touches the network,
# against *that* node's deployment allowlist and the authorization state as it stands at
# execution time — not as it stood when the scan was enqueued. And no scan may execute on
# two nodes at once (the queue grants exactly one lease per scan).


async def _enqueue_on_node(tmp_path: Any, request: Any, *, name: str) -> tuple[Any, int]:
    """Admit a scan on one node of a distributed fixture and enqueue it (S16)."""
    from arachne.data.services import build_orchestrator
    from tests.helpers.distributed import build_stack

    producer = build_stack(tmp_path / name)
    orchestrator = build_orchestrator(producer.services, pipeline=(ScanStep.RECON,))
    session = await orchestrator.launch(request)
    assert session.scan_id is not None
    producer.services.queue.enqueue(session.scan_id, requested_by="safety-test")
    return producer, session.scan_id


def _with_overrides(settings: Any, **overrides: Any) -> Any:
    """Rebuild a frozen Settings with replaced sub-settings (the helpers/api.py pattern)."""
    from dataclasses import fields

    return settings.__class__(
        **{
            **{field.name: getattr(settings, field.name) for field in fields(settings)},
            **overrides,
        }
    )


async def test_a_revoked_attestation_stops_the_scan_on_the_executing_node(
    tmp_path: Any,
) -> None:
    """The authorization gate runs at execution time, not only at enqueue time."""
    from arachne.agent.control import AgentLease
    from arachne.agent.runner import build_executor
    from arachne.core.audit import AuditAction, AuditOutcome
    from arachne.data.models import Target

    request = build_scan_request()
    node, scan_id = await _enqueue_on_node(tmp_path, request, name="revoked.db")
    try:
        executor = build_executor(node.services, name="agent-x", pipeline=(ScanStep.RECON,))

        # Revoke the attestation *after* admission, *before* execution.
        record = node.services.store.get_scan(scan_id)
        assert record is not None and record.target_id is not None
        with node.services.session_factory() as db_session:
            target = db_session.get(Target, record.target_id)
            assert target is not None
            target.auth_attestation = None
            db_session.commit()

        result = await executor(AgentLease(scan_id=scan_id))

        assert result.status == "failed"
        refusals = node.events_of(AuditAction.AUTH_REJECTED)
        assert refusals and refusals[-1].outcome is AuditOutcome.BLOCKED
        failed = node.events_of(AuditAction.SCAN_FAILED)
        assert any(event.scan_id == scan_id for event in failed)
        finished = node.services.store.get_scan(scan_id)
        assert finished is not None and finished.status.value == "failed"
        # Nothing ran: the recon step has no state to resume from.
        assert finished.step_state(ScanStep.RECON) is None
    finally:
        node.close()


async def test_a_scan_outside_the_executing_node_scope_is_refused_there(
    tmp_path: Any,
) -> None:
    """The deployment allowlist is evaluated on the node that would send the requests."""
    from arachne.agent.control import AgentLease
    from arachne.agent.runner import build_executor
    from arachne.core.audit import AuditAction, AuditOutcome
    from arachne.core.safety import Scope
    from tests.helpers.distributed import build_stack, distributed_settings

    request = build_scan_request()  # targets example.com
    producer, scan_id = await _enqueue_on_node(tmp_path, request, name="scope.db")
    try:
        # The executing node is more restricted than the producer was.
        settings = distributed_settings(tmp_path / "scope.db")
        restricted = _with_overrides(
            settings,
            safety=settings.safety.__class__(
                policy=settings.safety.policy,
                scope=Scope(allowed_domains=("elsewhere.example",)),
                redaction_enabled=True,
            ),
        )
        node = build_stack(tmp_path / "scope.db", settings=restricted)
        try:
            executor = build_executor(node.services, name="agent-y", pipeline=(ScanStep.RECON,))
            result = await executor(AgentLease(scan_id=scan_id))

            assert result.status == "failed"
            refusals = node.events_of(AuditAction.SCOPE_REJECTED)
            assert refusals and refusals[-1].outcome is AuditOutcome.BLOCKED
            assert "deployment scope" in (refusals[-1].reason or "")
            finished = node.services.store.get_scan(scan_id)
            assert finished is not None and finished.status.value == "failed"
        finally:
            node.close()
    finally:
        producer.close()


def test_one_queued_scan_yields_exactly_one_lease_across_nodes(tmp_path: Any) -> None:
    """No scan may execute on two nodes at once — the queue is the arbiter."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    from arachne.agent.service import AgentService
    from arachne.data.services import build_orchestrator
    from tests.helpers.distributed import build_stack

    stack = build_stack(tmp_path / "race.db")
    try:
        request = build_scan_request()
        orchestrator = build_orchestrator(stack.services, pipeline=(ScanStep.RECON,))
        session = asyncio.run(orchestrator.launch(request))
        assert session.scan_id is not None
        stack.services.queue.enqueue(session.scan_id)

        service_a = AgentService(stack.services, settings=stack.settings)
        service_b = AgentService(stack.services, settings=stack.settings)
        service_a.register("agent-a", principal="safety")
        service_b.register("agent-b", principal="safety")

        with ThreadPoolExecutor(max_workers=2) as pool:
            lease_a = pool.submit(
                service_a.lease, "agent-a", principal="safety", cap=1, ttl_s=60
            )
            lease_b = pool.submit(
                service_b.lease, "agent-b", principal="safety", cap=1, ttl_s=60
            )
            first, second = lease_a.result(), lease_b.result()

        claimed = [entry.scan_id for entry in (*first, *second)]
        assert claimed == [session.scan_id]  # granted once, to exactly one of them
        assert stack.services.queue.stats() == {"leased": 1}
    finally:
        stack.close()


# --------------------------------------------------------------------------- S18: intel
# The intel providers are the newest way target data leaves the process, and the feed sync is
# the newest way data comes *in*. Both are held to the same three rules as everything else:
# nothing is contacted without an explicit declaration, a refusal is recorded, and a
# credential never reaches a log line, an audit record or a finding.


async def test_the_opt_in_providers_are_unreachable_until_named_and_keyed() -> None:
    """REQ-INTEL-003/005: twice-opt-in, then keyed — the scope enforces all three.

    Enabling OSINT with the default provider list does not reach Shodan/Censys/HIBP at all;
    naming one without its key still does not reach it (its host leaves the scope), so a
    half-configured provider produces a refusal rather than an unauthenticated request.
    """
    from arachne.core.config import OsintSettings
    from arachne.modules.providers import build_osint_access, provider_scope

    default = OsintSettings(enabled=True)
    for host in ("api.shodan.io", "search.censys.io", "haveibeenpwned.com"):
        assert host not in default.provider_hosts()

    # Named but unkeyed: the builder drops them, so they are out of the scope *and* disabled.
    access = build_osint_access(
        enabled=True,
        providers=("shodan", "censys", "hibp"),
        usable=OsintSettings(enabled=True).usable_provider,
    )
    for host in ("api.shodan.io", "search.censys.io", "haveibeenpwned.com"):
        assert access is None or not access.client.scope.check(host).allowed
    if access is not None:
        assert access.enabled == frozenset()
        assert access.unavailable_reason("shodan").startswith("provider 'shodan' needs")
        await access.aclose()

    # And a provider that is not in the list cannot be fetched even by asking directly.
    from arachne.core.errors import OsintError

    allowed = build_osint_access(enabled=True, providers=("crtsh",))
    assert allowed is not None
    with pytest.raises(OsintError):
        await allowed.fetch("shodan", "https://api.shodan.io/shodan/host/192.0.2.1")
    await allowed.aclose()
    assert provider_scope(()).is_empty


async def test_a_named_intel_check_without_opt_in_sends_nothing_and_is_audited() -> None:
    """The socket is armed; a provider that was not opted into produces zero requests."""
    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m1.intel import BreachExposure, ServiceExposureDrift
    from arachne.modules.providers import OsintAccess, provider_scope
    from tests.helpers.checks import make_step_context

    class Sentinel(httpx.AsyncBaseTransport):
        urls: list[str] = []

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            Sentinel.urls.append(str(request.url))
            return httpx.Response(200, text="{}", headers={"content-type": "application/json"})

    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    armed = OsintAccess(
        client=ScopedHttpClient(
            scope=provider_scope(("crt.sh",)),
            auditor=auditor,
            resolver=StaticResolver((PUBLIC_IP,)),
            transport=Sentinel(),
        ),
        enabled=frozenset({"crtsh"}),
        budget=10,
        auditor=auditor,
    )
    step, _memory = make_step_context(seed=[("host", "192.0.2.10"), ("domain", "example.com")])
    for module, asset in (
        (BreachExposure, Asset(kind="domain", value="example.com")),
        (ServiceExposureDrift, Asset(kind="host", value="192.0.2.10")),
    ):
        context = CheckContext(
            step=step,
            module=module(),
            asset=asset,
            config=ModuleConfig(),
            osint=armed,
        )
        async for result in context.module.run(context):
            assert result.status == "info"
            assert "not run" in result.title
    assert Sentinel.urls == [], "an opt-in provider must send nothing when it was not opted into"
    assert {
        event.meta.get("provider") for event in sink.of_action(AuditAction.INTEL_PROVIDER_BLOCKED)
    } >= {"shodan", "censys", "hibp"}
    await armed.aclose()


async def test_a_provider_key_never_reaches_a_log_line_a_record_or_a_finding() -> None:
    """REQ-INTEL-005's log-scan: Shodan's key travels *in the request URL*, so every record
    of the exchange — the log line, the audit event, the provider response and the finding's
    evidence — must carry the redacted form instead (F-08-01, F-08-04)."""
    from pydantic import SecretStr

    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m1.intel import BreachExposure, ServiceExposureDrift
    from tests.helpers.checks import make_osint, make_step_context

    shodan_key = "SHODAN-SAFETY-KEY-0123456789"
    hibp_key = "HIBP-SAFETY-KEY-0123456789"
    stream = StringIO()
    configure_logging("DEBUG", json_output=True, stream=stream)
    collected: list[Any] = []
    try:
        step, memory = make_step_context(
            seed=[("host", "203.0.113.9"), ("domain", "example.com")]
        )
        osint = make_osint(
            providers=("shodan", "hibp", "censys", "certspotter", "whois"),
            auditor=memory.auditor,
            whois_url="https://rdap.org/domain/{query}",
        )
        config = ModuleConfig(
            shodan_api_key=SecretStr(shodan_key),
            hibp_api_key=SecretStr(hibp_key),
            osint_ct_window_days=36500,
        )
        for module, asset in (
            (ServiceExposureDrift, Asset(kind="host", value="203.0.113.9")),
            (BreachExposure, Asset(kind="domain", value="example.com")),
        ):
            context = CheckContext(
                step=step, module=module(), asset=asset, config=config, osint=osint
            )
            async for result in module().run(context):
                collected.append(result)
    finally:
        configure_logging("INFO", json_output=True)

    # The run was real: both checks produced results that name their provider.
    blob_parts = [
        stream.getvalue(),
        json.dumps([event.to_dict() for event in memory.sink.events]),
        json.dumps([event.payload for event in memory.bus.history()]),
        json.dumps(
            [
                {"title": result.title, "detail": result.detail, "evidence": [
                    evidence.payload for evidence in result.evidence
                ]}
                for result in collected
            ],
            default=str,
        ),
    ]
    blob = "\n".join(blob_parts)
    assert collected, "the checks must have run for this test to mean anything"
    assert shodan_key not in blob
    assert hibp_key not in blob
    assert "[REDACTED" in blob, "the Shodan URL's key parameter should be visibly redacted"


# ------------------------------------------------- S19: the credential path (area CREDS)
async def test_a_credential_outside_its_scope_is_refused_before_a_request(
    make_client: Callable[..., ScopedHttpClient], tmp_path: Path
) -> None:
    """REQ-CREDS-005: scope confinement happens before the socket, not after.

    The credential is stored for ``app.internal`` and offered for ``TARGET_HOST``: the broker
    refuses it and *no request is sent at all* (the transport raises if one is), which is the
    credential half of the scope invariant the rest of this file tests for targets.
    """
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        msg = "a credential outside its scope must never produce a request"
        raise AssertionError(msg)

    vault = make_vault(
        tmp_path,
        entries={
            "elsewhere": {
                "kind": "web-form",
                "username": "operator",
                "secret": "an-out-of-scope-secret-value",
                "scope": CredentialScope(hosts=("app.internal",)),
            }
        },
    )
    step, memory = make_step_context(seed=[("url", f"http://{TARGET_HOST}/")])
    client = make_client(handler, scope=Scope(allowed_hosts=(TARGET_HOST,)))
    broker = CredentialBroker(
        store=vault,
        labels=("elsewhere",),
        auditor=memory.auditor,
        scan_id=memory.scan_id,
        targets=(f"http://{TARGET_HOST}/",),
        hosts=(TARGET_HOST,),
    )
    broker.validate_selection()
    session = await broker.login(
        client=client, inventory=None, url=f"http://{TARGET_HOST}/login"
    )
    await client.aclose()

    assert session is None
    assert calls == []
    assert memory.sink.of_action(AuditAction.CREDENTIAL_SCOPE_REJECTED)
    assert memory.sink.of_action(AuditAction.CREDENTIAL_RELEASED) == []
    del step


def test_an_authenticated_scan_still_needs_the_active_checks_attestation() -> None:
    """Authentication is not an authorization: the proof/active gate is unchanged (G3 item 3).

    A scan that names a credential *and* a credentialed check is planned exactly as a scan
    without one: the opt-in check is withheld unless the attestation authorized active checks.
    """
    from arachne.core.target import parse_scan_request

    document = {
        "target": {
            "name": "credentialed-gate",
            "targets": [{"kind": "url", "value": f"http://{TARGET_HOST}/"}],
        },
        "options": {
            "active_checks": False,
            "modules": {"enabled": ["M3"], "checks": ["m3.authenticated-surface"]},
            "credentials": ["portal"],
        },
    }
    request = parse_scan_request(document)
    assert request.options.credentials == ("portal",)
    assert request.target.attestation is None
    registry = ModuleRegistry.discover()
    selected = registry.select(
        request.options.modules,
        active_checks_allowed=request.options.active_checks,
        enabled_check_ids=request.options.modules.checks or None,
    )
    # The credentialed check is active, so it is withheld: a credential does not authorize it.
    assert all(check.metadata.id != "m3.authenticated-surface" for check in selected)
    # And with the opt-in *and* an authorizing attestation it is planned, which is what makes
    # the refusal above about authorization rather than about the check being unreachable.
    authorized = parse_scan_request(
        {
            **document,
            "target": {
                **document["target"],
                "attestation": {
                    "attested_by": "Operator <op@example.com>",
                    "attested_at": "2026-10-01T00:00:00Z",
                    "scope_statement": "Authorized assessment",
                    "allowed_targets": [TARGET_HOST],
                    "active_checks_authorized": True,
                },
            },
            "options": {**document["options"], "active_checks": True},
        }
    )
    authorized.target.assert_authorized(active_checks=True)
    selected = registry.select(
        authorized.options.modules,
        active_checks_allowed=authorized.options.active_checks,
        enabled_check_ids=authorized.options.modules.checks or None,
    )
    assert any(check.metadata.id == "m3.authenticated-surface" for check in selected)
