"""Shared HTTP client tests (ADR-05, F-01-07/08, F-02-08, F-08-03/04)."""

from __future__ import annotations

import httpx
import pytest
from tests.conftest import PUBLIC_IP, TARGET_HOST, TARGET_URL

from arachne.core.audit import AuditAction, MemoryAuditSink
from arachne.core.config import HttpSettings
from arachne.core.errors import RequestError, UnsafeUrlError
from arachne.core.ratelimit import RateLimitSettings
from arachne.core.safety import Scope


async def test_successful_get_is_captured_and_audited(
    make_client, audit_sink: MemoryAuditSink
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"].startswith("ARACHNE/")
        return httpx.Response(200, text="hello", headers={"Server": "nginx"})

    client = make_client(handler)
    exchange = await client.get(TARGET_URL)

    assert exchange.status_code == 200
    assert exchange.body == "hello"
    assert exchange.header("server") == "nginx"
    assert exchange.attempts == 1
    assert exchange.resolved_addresses == (PUBLIC_IP,)
    assert exchange.elapsed_ms >= 0
    assert exchange.ok

    events = audit_sink.of_action(AuditAction.HTTP_REQUEST)
    assert len(events) == 1
    assert events[0].meta["status"] == 200
    assert events[0].meta["method"] == "GET"
    assert events[0].meta["host"] == TARGET_HOST
    assert events[0].outcome.value == "allowed"


async def test_request_headers_are_sent_and_redacted_in_evidence(make_client) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(request.headers))
        return httpx.Response(200, text="ok")

    client = make_client(handler)
    exchange = await client.get(TARGET_URL, headers={"Authorization": "Bearer abcdefghijklmnop"})

    assert seen["authorization"] == "Bearer abcdefghijklmnop"  # the target does get it
    assert exchange.request_headers["Authorization"].startswith("[REDACTED")  # evidence does not


async def test_response_json_helper_parses_redacted_body(make_client) -> None:
    client = make_client(lambda request: httpx.Response(200, json={"a": 1, "token": "s3cretvalue"}))
    exchange = await client.get(TARGET_URL)

    parsed = exchange.json_body()
    assert parsed["a"] == 1
    assert parsed["token"] == "[REDACTED:value]"


async def test_non_json_body_returns_none(make_client) -> None:
    client = make_client(lambda request: httpx.Response(200, text="<html>hi</html>"))
    exchange = await client.get(TARGET_URL)
    assert exchange.json_body() is None


async def test_redirects_are_followed_hop_by_hop(make_client, audit_sink) -> None:
    hops: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(301, headers={"Location": "/next"})
        if request.url.path == "/next":
            return httpx.Response(302, headers={"Location": f"https://{TARGET_HOST}/final"})
        return httpx.Response(200, text="arrived")

    client = make_client(handler)
    exchange = await client.get(TARGET_URL)

    assert hops == [TARGET_URL, f"https://{TARGET_HOST}/next", f"https://{TARGET_HOST}/final"]
    assert exchange.body == "arrived"
    assert len(exchange.redirect_chain) == 2
    assert len(audit_sink.of_action(AuditAction.HTTP_REQUEST)) == 1


async def test_redirect_limit_is_respected(make_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/loop"})

    client = make_client(handler, http=HttpSettings(max_redirects=2))
    exchange = await client.get(TARGET_URL)

    assert exchange.status_code == 302
    assert len(exchange.redirect_chain) == 2


async def test_cross_host_redirect_is_validated_against_scope(make_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example.net/steal"})

    client = make_client(handler, scope=Scope(allowed_hosts=(TARGET_HOST,)))
    with pytest.raises(Exception, match="not in scope"):
        await client.get(TARGET_URL)


async def test_post_redirect_303_switches_to_get(make_client) -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.method == "POST":
            return httpx.Response(303, headers={"Location": "/done"})
        return httpx.Response(200, text="done")

    client = make_client(handler)
    exchange = await client.post(TARGET_URL, content="a=1")

    assert methods == ["POST", "GET"]
    assert exchange.method == "GET"
    assert exchange.status_code == 200


async def test_transport_errors_are_retried_then_wrapped(make_client) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("refused", request=request)

    client = make_client(handler, http=HttpSettings(retries=2))
    with pytest.raises(RequestError, match="failed after 3 attempt"):
        await client.get(TARGET_URL)
    assert calls["n"] == 3


async def test_timeouts_surface_as_request_error(make_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client = make_client(handler, http=HttpSettings(retries=0))
    with pytest.raises(RequestError):
        await client.get(TARGET_URL)


async def test_retryable_status_codes_are_retried(make_client) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, text="recovered")

    client = make_client(handler, http=HttpSettings(retries=1))
    exchange = await client.get(TARGET_URL)

    assert exchange.status_code == 200
    assert exchange.attempts == 2


async def test_body_is_truncated_to_the_configured_limit(make_client) -> None:
    client = make_client(
        lambda request: httpx.Response(200, text="A" * 5000),
        http=HttpSettings(max_body_bytes=100),
    )
    exchange = await client.get(TARGET_URL)

    assert len(exchange.body) == 100
    assert exchange.body_truncated


async def test_binary_bodies_are_not_stored(make_client) -> None:
    client = make_client(lambda request: httpx.Response(200, content=b"\x00\x01\x02binary"))
    exchange = await client.get(TARGET_URL)

    assert exchange.body_is_binary
    assert exchange.body.startswith("[binary payload:")


async def test_request_body_is_redacted_in_evidence(make_client) -> None:
    client = make_client(lambda request: httpx.Response(200, text="ok"))
    exchange = await client.post(TARGET_URL, content="password=hunter2&user=alice")

    assert "hunter2" not in (exchange.request_body or "")
    assert "user=alice" in (exchange.request_body or "")


async def test_evidence_objects_carry_hashes(make_client) -> None:
    client = make_client(lambda request: httpx.Response(200, text="ok"))
    exchange = await client.get(TARGET_URL)
    request_evidence, response_evidence = exchange.to_evidence()

    assert request_evidence.kind == "http_request"
    assert response_evidence.kind == "http_response"
    assert request_evidence.sha256 and len(request_evidence.sha256) == 64
    assert response_evidence.sha256 and len(response_evidence.sha256) == 64


async def test_client_can_be_used_as_a_context_manager(make_client) -> None:
    client = make_client()
    async with client as entered:
        assert entered is client


async def test_no_request_when_url_is_unsafe(make_client) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    client = make_client(handler)
    with pytest.raises(UnsafeUrlError):
        await client.get("http://127.0.0.1/")
    assert not called


async def test_rate_limit_is_applied_on_every_request(make_client, fake_clock) -> None:
    client = make_client(
        rate_limit=RateLimitSettings(
            per_host_rate=4.0, per_host_burst=1, global_rate=1000.0, global_burst=1000
        )
    )
    for _ in range(4):
        await client.get(TARGET_URL)

    assert fake_clock.sleep_calls >= 3
    assert fake_clock.now == pytest.approx(0.75, abs=0.02)


async def test_last_exchange_is_recorded_for_inspection(make_client) -> None:
    client = make_client(lambda request: httpx.Response(204))
    assert client.last_exchange is None
    await client.get(TARGET_URL)
    assert client.last_exchange is not None
    assert client.last_exchange.status_code == 204


async def test_redirect_location_with_dangerous_scheme_is_blocked(make_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "file:///etc/passwd"})

    client = make_client(handler)
    with pytest.raises(UnsafeUrlError):
        await client.get(TARGET_URL)
