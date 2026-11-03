"""The scope-bound browser proxy (REQ-DET-015, INV-2): the browser's only way out.

The proxy is the reason a headless browser can be trusted with an invalidation-free scope
gate. These tests drive it the way the browser would — over a real loopback socket, speaking
CONNECT and absolute-form HTTP — against a real listening origin, and assert the two things
that matter:

* an **in-scope** request is forwarded to the address the gate *resolved and checked*, and the
  request reaches the origin unchanged;
* an **out-of-scope** or **policy-refused** request is answered 403, audited with the same
  action the HTTP client uses, and **never dialled** — asserted by arming
  :func:`arachne.browser.proxy.open_upstream`, the single function that opens an upstream
  socket. A test that counted bytes would be weaker than one that can observe that no socket
  was opened at all.

The armed fixture is deliberately narrow: the test's own client connection to the proxy is
*not* armed (it is the harness, not the target). ``test_browser_safety.py`` carries the
product-level version of the same claim.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator

import pytest
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.browser import proxy as proxy_module
from arachne.browser.proxy import ScopeProxy, refusal_summary
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy

TARGET_HOST = "target.example"
PUBLIC_IP = "93.184.216.34"


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _proxy(
    sink: MemoryAuditSink,
    *,
    allowed_hosts: tuple[str, ...] = (TARGET_HOST, "127.0.0.1"),
    policy: UrlSafetyPolicy | None = None,
) -> ScopeProxy:
    return ScopeProxy(
        scope=Scope(allowed_hosts=allowed_hosts),
        auditor=Auditor(sink, actor="pytest"),
        policy=policy or UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver((PUBLIC_IP,)),
    )


async def _speak(port: int, request: bytes) -> bytes:
    """Send a raw request to the proxy and read whatever it answers (bounded)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(65536), 10.0)
        except TimeoutError:  # pragma: no cover - a refused request answers immediately
            return b""
    finally:
        with contextlib.suppress(Exception):
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.fixture
def armed_dial(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """Arm ``open_upstream``: record every dial, and fail the test if one happens."""
    dialed: list[tuple[str, int]] = []

    async def forbidden(address: str, port: int, **kwargs: object) -> object:
        dialed.append((address, port))
        raise AssertionError(f"the proxy dialled {address}:{port} when it should not have")

    monkeypatch.setattr(proxy_module, "open_upstream", forbidden)
    return dialed


# ------------------------------------------------------------------ the refusal path
async def test_an_out_of_scope_host_is_refused_audited_and_never_dialled(
    armed_dial: list[tuple[str, int]],
) -> None:
    sink = MemoryAuditSink()
    proxy = _proxy(sink, allowed_hosts=("in-scope.example",))
    await proxy.start()
    try:
        response = await _speak(
            proxy.port,
            b"CONNECT out-of-scope.example:443 HTTP/1.1\r\nHost: out-of-scope.example:443\r\n\r\n",
        )
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 403")
    assert armed_dial == [], "an out-of-scope navigation must not open a socket"
    assert proxy.blocked == 1
    refusals = sink.of_action(AuditAction.SCOPE_REJECTED)
    assert refusals, "a blocked navigation must be audited (REQ-DET-015)"
    assert refusals[0].outcome.value == "blocked"
    assert "browser-proxy" in str(refusals[0].meta)


async def test_a_policy_refused_address_is_refused_before_the_dial(
    armed_dial: list[tuple[str, int]],
) -> None:
    """A host that *is* in scope but resolves into private space is still refused.

    This is the address half of the gate: declaring ``metadata.example`` in scope must not make
    it reachable when it resolves to link-local space, and the refusal is a ``safety.blocked``
    (an address policy) rather than a ``scope.rejected`` (a declaration).
    """
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=("metadata.example",)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=False),
        resolver=StaticResolver(("169.254.169.254",)),
    )
    await proxy.start()
    try:
        response = await _speak(
            proxy.port, b"GET http://metadata.example/ HTTP/1.1\r\nHost: metadata.example\r\n\r\n"
        )
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 403")
    assert armed_dial == []
    assert sink.of_action(AuditAction.SAFETY_BLOCKED)


@pytest.mark.parametrize(
    "request_line",
    [
        b"GET file:///etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET ftp://in-scope.example/x HTTP/1.1\r\nHost: in-scope.example\r\n\r\n",
        b"GET /relative-path HTTP/1.1\r\n\r\n",  # no Host to name the request with
    ],
)
async def test_a_request_that_cannot_be_named_is_refused(
    armed_dial: list[tuple[str, int]], request_line: bytes
) -> None:
    """A non-HTTP scheme or a nameless request is refused rather than guessed at."""
    sink = MemoryAuditSink()
    proxy = _proxy(sink)
    await proxy.start()
    try:
        response = await _speak(proxy.port, request_line)
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 403")
    assert armed_dial == []
    assert proxy.blocked == 1


async def test_a_path_only_request_with_a_host_is_named_and_checked(
    armed_dial: list[tuple[str, int]],
) -> None:
    """A path-only line is completed from ``Host`` — and then gated like anything else."""
    sink = MemoryAuditSink()
    proxy = _proxy(sink, allowed_hosts=("in-scope.example",))
    await proxy.start()
    try:
        response = await _speak(
            proxy.port,
            b"GET /admin HTTP/1.1\r\nHost: out-of-scope.example\r\nConnection: close\r\n\r\n",
        )
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 403")
    assert armed_dial == []
    assert proxy.blocked == 1
    assert sink.of_action(AuditAction.SCOPE_REJECTED)


# ------------------------------------------------------------------ the allow path
async def test_an_in_scope_absolute_request_is_forwarded_to_the_origin(
    lab: WebLab,
) -> None:
    """An allowed plain-HTTP request reaches the origin, and the client gets its response."""
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
    await proxy.start()
    request = (
        f"GET {lab.base_url} HTTP/1.1\r\nHost: {lab.host}\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        response = await _speak(proxy.port, request)
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 200")
    assert proxy.allowed == 1
    assert proxy.dialed == [f"127.0.0.1:{lab.port}"]
    # The forwarded request is the request the application saw: the lab records every one.
    assert any("GET /" in line for line in lab.requests), lab.requests


async def test_the_dialled_address_is_the_one_the_gate_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name is resolved once, by the gate, and the literal it returned is what is dialled.

    Re-resolving at connect time is the DNS-rebinding hole this closes: the address the policy
    checked must be the address that is connected to.
    """
    dialed: list[tuple[str, int]] = []

    class _Writer:
        def close(self) -> None: ...
        async def wait_closed(self) -> None: ...

    class _Reader:
        async def read(self, _size: int) -> bytes:
            return b""

    async def recorder(address: str, port: int, **kwargs: object) -> object:
        dialed.append((address, port))
        return _Reader(), _Writer()

    monkeypatch.setattr(proxy_module, "open_upstream", recorder)
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(),
        resolver=StaticResolver((PUBLIC_IP,)),
    )
    await proxy.start()
    try:
        await _speak(proxy.port, f"CONNECT {TARGET_HOST}:443 HTTP/1.1\r\n\r\n".encode())
    finally:
        await proxy.aclose()
    assert dialed == [(PUBLIC_IP, 443)], "the validated literal must be what is dialled"


async def test_a_connect_tunnel_establishes_and_says_so(lab: WebLab) -> None:
    """``CONNECT`` answers ``200 Connection Established`` and then pipes bytes (TLS passthrough)."""
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        try:
            writer.write(f"CONNECT 127.0.0.1:{lab.port} HTTP/1.1\r\n\r\n".encode())
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10.0)
            assert head.startswith(b"HTTP/1.1 200")
            # Inside the tunnel is plain HTTP: a request reaches the lab and comes back.
            writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            await writer.drain()
            body = await asyncio.wait_for(reader.read(4096), 10.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await proxy.aclose()
    assert b"200" in body.split(b"\r\n", 1)[0]
    assert proxy.dialed == [f"127.0.0.1:{lab.port}"]


# ------------------------------------------------------------------ the evidence shape
async def test_the_summary_is_json_safe_and_counts_what_happened() -> None:
    sink = MemoryAuditSink()
    proxy = _proxy(sink, allowed_hosts=("in-scope.example",))
    await proxy.start()
    try:
        await _speak(proxy.port, b"CONNECT out.example:443 HTTP/1.1\r\n\r\n")
    finally:
        await proxy.aclose()
    summary = refusal_summary(proxy)
    assert summary["requests"] == 1
    assert summary["blocked"] == 1
    assert summary["allowed"] == 0
    assert isinstance(summary["refusals"], list)
    assert summary["refusals"][0]["reason"]
    import json

    json.dumps(summary)  # the evidence a finding carries must serialize
