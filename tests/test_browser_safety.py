"""Safety acceptance for the headless browser (REQ-DET-015, INV-1/INV-2/INV-3, R-16).

The work package treats a browser inside the scanner as a new attack surface *inside* the
scanner, and its safety criteria as gate conditions rather than aspirations. This module is
where those criteria are proven, and it follows the repository's existing idiom for "no
request leaves": arm the socket entry points and assert the list of attempts is empty, rather
than count bytes on the wire (``tests/test_depth_safety.py`` is the model).

The six claims proven here, one per exit criterion:

1. **Every navigation passes the scope gate before the request.** A combined event log records
   the order of gate calls and navigator calls; every navigation's URL must have been
   validated *earlier* in that log.
2. **An out-of-scope navigation is blocked, audited, and produces no request.** Armed sockets;
   zero attempts; a ``scope.rejected`` audit line with the reason.
3. **The gate is deny-by-default and per-hop.** An empty scope refuses every root; a refusal
   happens before resolution (so an out-of-scope host generates no DNS query); and the proxy
   re-runs the gate for *every* request, not once per connection.
4. **No downloaded file is executed and no non-HTTP scheme is navigated.** The launch argv and
   the navigation guard are asserted, and the recorder shows a hostile page's download and
   ``file:`` attempt staying data.
5. **Each of the six capabilities is off**, asserted from the hardening report (the
   unconditional half of the pair whose other half is the optional integration module).
6. **The browser is optional**: with the extra absent, the crawl reports itself skipped and
   opens no socket and no browser.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from arachne.browser import crawl as crawl_module
from arachne.browser import proxy as proxy_module
from arachne.browser.crawl import BrowserCrawl, CrawlBudget
from arachne.browser.hardening import (
    DISABLED_CAPABILITIES,
    NON_HTTP_SCHEMES,
    capability_report,
    context_kwargs,
    launch_args,
    scheme_allowed,
)
from arachne.browser.proxy import ScopeProxy
from arachne.core.airgap import AirgapPolicy
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import WebSettings
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3 import dom_xss as dom_xss_module
from arachne.modules.m3.dom_xss import DomSinkCheck
from tests.helpers.browser import ScriptedNavigator, ScriptedPage
from tests.helpers.checks import asset_for, make_step_context
from tests.lab.web_lab import WebLab, start_web_lab

TARGET_HOST = "target.example"
PUBLIC_IP = "93.184.216.34"
OFF_SCOPE = "http://out-of-scope.example/steal"


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


@pytest.fixture
def armed_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Arm every socket entry point a request could leave through.

    ``socket.socket`` itself is left alone (the event loop's self-pipe needs it); the *entry
    points* are what a scanner actually calls, exactly as ``tests/test_depth_safety.py`` does.
    """
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> object:
        attempts.append(str(args[:1]))
        raise AssertionError("an armed socket was reached")

    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    yield attempts
    assert attempts == [], f"the browser crawl touched a target socket: {attempts}"


def _crawl(
    sink: MemoryAuditSink,
    navigator: Any,
    *,
    scope: Scope | None = None,
    resolver: Any = None,
    budget: CrawlBudget | None = None,
) -> BrowserCrawl:
    return BrowserCrawl(
        navigator=navigator,
        scope=scope if scope is not None else Scope(allowed_hosts=("127.0.0.1",)),
        auditor=Auditor(sink, actor="pytest"),
        budget=budget or CrawlBudget(max_pages=20, max_seconds=10.0),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=resolver,
    )


class _RecordingResolver:
    def __init__(self) -> None:
        self.asked: list[str] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del port
        self.asked.append(host)
        return (PUBLIC_IP,)


# ------------------------------------------------------- 1. validation before the request
async def test_every_navigation_is_validated_before_the_browser_is_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordering claim: gate first, navigation second, for every frame opened."""
    events: list[tuple[str, str]] = []
    real_validate = crawl_module.validate_url

    async def recorded_validate(url: str, *args: Any, **kwargs: Any) -> Any:
        events.append(("validate", url))
        return await real_validate(url, *args, **kwargs)

    class _Recording(ScriptedNavigator):
        async def navigate(self, url: str) -> Any:  # type: ignore[override]
            events.append(("navigate", url))
            return await super().navigate(url)

    monkeypatch.setattr(crawl_module, "validate_url", recorded_validate)
    navigator = _Recording(
        pages={
            "/": ScriptedPage(raw_body="<div/>", links=("/next",)),
            "/next": ScriptedPage(raw_body="<div/>"),
        }
    )
    sink = MemoryAuditSink()
    await _crawl(sink, navigator).run(["http://127.0.0.1:8080/"])
    navigations = [url for kind, url in events if kind == "navigate"]
    assert navigations, "the crawl navigated at least once"
    for url in navigations:
        base = url.split("#", 1)[0].split("?", 1)[0]
        validated = [u for kind, u in events if kind == "validate"]
        index = events.index(("navigate", url))
        assert any(u.split("#", 1)[0].split("?", 1)[0] == base for u in validated[:index]), (
            f"{url} was navigated before it was validated"
        )
        assert events.index(("validate", next(u for u in validated if base in u))) < index


# ------------------------------------------------------- 2. blocked, audited, no request
async def test_an_out_of_scope_navigation_produces_no_request(
    armed_sockets: list[str],
) -> None:
    """The armed-socket proof: the gate refuses, and nothing is dialled."""
    del armed_sockets  # asserted by the fixture's teardown
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/": ScriptedPage(raw_body="<div/>")})
    result = await _crawl(sink, navigator).run([OFF_SCOPE])
    assert navigator.navigations == []
    assert result.blocked_navigations == (OFF_SCOPE,)
    blocked = sink.of_action(AuditAction.SCOPE_REJECTED)
    assert blocked and blocked[0].outcome.value == "blocked"
    assert blocked[0].reason


async def test_the_proxy_refuses_an_out_of_scope_connect_without_dialling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same proof at the transport layer: a browser CONNECT to an off-scope origin.

    This is the case that matters most in production, because a *page* — not the crawl — is
    what asks for it: a hostile page that navigates its own frame, opens an image or fetches a
    CDN origin goes through the proxy, and the proxy refuses before it dials.
    """
    dialed: list[tuple[str, int]] = []

    async def forbidden(address: str, port: int, **kwargs: object) -> object:
        dialed.append((address, port))
        raise AssertionError("the proxy dialled an out-of-scope origin")

    monkeypatch.setattr(proxy_module, "open_upstream", forbidden)
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(),
    )
    await proxy.start()
    try:
        response = await _speak(
            proxy.port,
            b"CONNECT out-of-scope.example:443 HTTP/1.1\r\nHost: out-of-scope.example:443\r\n\r\n",
        )
    finally:
        await proxy.aclose()
    assert response.startswith(b"HTTP/1.1 403")
    assert dialed == []
    refused = sink.of_action(AuditAction.SCOPE_REJECTED)
    assert refused and refused[0].outcome.value == "blocked"
    assert "out-of-scope.example" in str(refused[0].target)


async def test_a_hostile_page_that_reaches_off_scope_is_data_not_an_escape() -> None:
    """A page whose sub-resources were refused still renders; the refusal is recorded."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/hostile": ScriptedPage(
                raw_body="<div/>",
                refused_requests=("http://cdn.example/tracker.js", "https://evil.example/x"),
                downloads=("installer.exe",),
                links=("https://evil.example/next", "/local"),
            )
        }
    )
    result = await _crawl(sink, navigator).run(["http://127.0.0.1:8080/hostile"])
    assert all("evil.example" not in url for url in navigator.navigations)
    assert all("evil.example" not in route.url for route in result.routes)
    assert "installer.exe" in result.downloads
    assert len(result.refused_requests) == 2


# ------------------------------------------------------- 3. deny-by-default and per-hop
async def test_an_empty_scope_refuses_everything(armed_sockets: list[str]) -> None:
    """INV-1: the same deny-by-default as every other request path in the product."""
    del armed_sockets
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/": ScriptedPage(raw_body="<div/>")})
    result = await _crawl(sink, navigator, scope=Scope.deny_all()).run(
        ["http://127.0.0.1:8080/", "https://anything.example/"]
    )
    assert result.navigations == 0
    assert len(result.blocked_navigations) == 2
    assert navigator.navigations == []


async def test_an_out_of_scope_host_is_never_resolved() -> None:
    """INV-2: the refusal happens before resolution, so no DNS query is generated."""
    resolver = _RecordingResolver()
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/": ScriptedPage(raw_body="<div/>")})
    await _crawl(sink, navigator, resolver=resolver).run(["http://not-declared.example/"])
    assert resolver.asked == []


async def test_the_gate_runs_per_request_not_once_per_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INV-3: every hop is re-validated. Two requests on the proxy are two gate runs."""
    seen: list[str] = []
    real_validate = proxy_module.validate_url

    async def counted(url: str, *args: Any, **kwargs: Any) -> Any:
        seen.append(url)
        return await real_validate(url, *args, **kwargs)

    monkeypatch.setattr(proxy_module, "validate_url", counted)
    monkeypatch.setattr(proxy_module, "open_upstream", _unreachable)
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=(TARGET_HOST, "other.example")),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(),
    )
    await proxy.start()
    try:
        for host in (TARGET_HOST, "other.example", TARGET_HOST):
            await _speak(proxy.port, f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
    finally:
        await proxy.aclose()
    assert [url.split("//")[1].split(":")[0] for url in seen] == [
        TARGET_HOST,
        "other.example",
        TARGET_HOST,
    ], seen


async def _unreachable(address: str, port: int, **kwargs: object) -> object:
    raise OSError("no route to host")


async def test_an_air_gapped_estate_refuses_an_in_scope_host_the_allowlist_does_not_cover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REQ-RESIL-001 applied to the new transport: air-gapped mode is not bypassable.

    A host can be inside the scan's *declared scope* and outside the air-gapped estate's
    allowlist, and the shared HTTP client and the raw-network client both refuse it. The
    browser's proxy must too — otherwise the browser would be a way *around* a control the
    product already enforces, which is the whole class of defect R-16 warns about.
    """
    dialed: list[tuple[str, int]] = []

    async def forbidden(address: str, port: int, **kwargs: object) -> object:
        dialed.append((address, port))
        raise AssertionError("an air-gapped refusal dialled the host")

    monkeypatch.setattr(proxy_module, "open_upstream", forbidden)
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=(TARGET_HOST, "extra.example")),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(),
        resolver=StaticResolver((PUBLIC_IP,)),
        airgap=AirgapPolicy(enabled=True),
    )
    await proxy.start()
    try:
        in_scope = await _speak(proxy.port, f"CONNECT {TARGET_HOST}:443 HTTP/1.1\r\n\r\n".encode())
    finally:
        await proxy.aclose()
    assert in_scope.startswith(b"HTTP/1.1 403")
    assert dialed == [], "an air-gapped refusal must not dial"
    refusals = sink.of_action(AuditAction.AIRGAP_BLOCKED)
    assert refusals, "the air-gapped refusal must be audited"
    assert refusals[0].outcome.value == "blocked"
    assert TARGET_HOST in str(refusals[0].target)


async def test_an_air_gapped_estate_still_allows_the_scan_own_target(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other direction: the deployment's scan targets stay reachable while air-gapped."""
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        airgap=AirgapPolicy(enabled=True, allowed_hosts=("127.0.0.1",)),
        airgap_scope_hosts=("127.0.0.1",),
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
    assert proxy.dialed == [f"127.0.0.1:{lab.port}"]
    assert sink.of_action(AuditAction.AIRGAP_BLOCKED) == []


# ------------------------------------------------------- 4. no execution, no odd schemes
@pytest.mark.parametrize("scheme", NON_HTTP_SCHEMES)
def test_no_non_http_scheme_is_navigable(scheme: str) -> None:
    assert scheme_allowed(f"{scheme}://example.com/") is False
    assert scheme_allowed(f"{scheme}:/etc/passwd") is False


def test_the_browser_is_configured_never_to_write_or_hand_over_a_file() -> None:
    kwargs = context_kwargs()
    args = launch_args("http://127.0.0.1:1")
    assert kwargs["accept_downloads"] is False, "nothing may be written to disk"
    assert "--disable-file-system" in args
    assert kwargs["permissions"] == []


def test_the_browser_code_has_no_process_and_no_execution_primitive() -> None:
    """Nothing in the subsystem can run a downloaded file: there is no such call to reach."""
    root = Path(__file__).resolve().parents[1] / "src" / "arachne" / "browser"
    banned_modules = {"subprocess", "ctypes", "marshal", "shutil"}
    banned_calls = {"os.system", "os.popen", "os.execv", "os.execve", "os.spawnv"}
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in banned_modules, (path, alias.name)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in banned_modules, (path, node.module)
            if isinstance(node, ast.Attribute):
                assert _dotted(node) not in banned_calls, (path, _dotted(node))


def _dotted(node: ast.Attribute) -> str:
    parts: list[str] = [node.attr]
    value: Any = node.value
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def test_a_downloaded_file_is_never_executed_because_it_is_never_written() -> None:
    """The download guard records and cancels; the file chooser is dismissed with no path."""
    driver = Path(crawl_module.__file__).with_name("driver.py")
    text = driver.read_text(encoding="utf-8")
    assert context_kwargs()["accept_downloads"] is False
    assert "cancel" in text, "the download event is cancelled, not saved"
    assert "set_files([])" in text, "the file chooser is dismissed with no path"
    assert "--disable-file-system" in launch_args("http://127.0.0.1:1")


# ------------------------------------------------------- 5. the six capabilities
def test_each_of_the_six_capabilities_is_asserted_off() -> None:
    report = capability_report("http://127.0.0.1:1")
    assert set(report) == set(DISABLED_CAPABILITIES)
    for capability in DISABLED_CAPABILITIES:
        assert report[capability]["disabled"] is True, capability
        assert report[capability]["mechanisms"]


# ------------------------------------------------------- 6. the optional extra
async def test_without_the_extra_the_check_skips_and_nothing_is_opened(
    armed_sockets: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The air-gapped/default install: the crawl reports itself skipped and opens nothing.

    The context carries a non-``None`` HTTP client (so the check is past the dry-run gate) but
    the check returns at the availability gate, before it touches the client, the crawl or the
    browser — which the armed sockets prove.
    """
    del armed_sockets
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: False)
    results = await _run_check(asset_for("url", "http://127.0.0.1:8080/"), web=_browser_web())
    assert results
    assert _skipped(results), [result.title for result in results]
    assert all(result.status != "vulnerable" for result in results)


async def test_without_the_switch_nothing_is_opened_even_with_the_extra(
    armed_sockets: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second gate: an installed browser is still not used unless the operator opts in."""
    del armed_sockets
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: True)

    async def forbidden(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("a browser was opened with the crawl switched off")

    monkeypatch.setattr(dom_xss_module, "open_navigator", forbidden)
    results = await _run_check(
        asset_for("url", "http://127.0.0.1:8080/"),
        web=replace(_browser_web(), browser_crawl=False),
    )
    assert all(result.status != "vulnerable" for result in results)
    assert _skipped(results)
    assert any("ARACHNE_WEB_BROWSER_CRAWL" in (result.detail or "") for result in results)


async def _run_check(asset: Any, *, web: WebSettings) -> list[Any]:
    """Run the check with a step context that has a client but performs no request."""
    step, _memory = make_step_context(http=_NO_HTTP)
    context = CheckContext(
        step=step, module=DomSinkCheck(), asset=asset, config=ModuleConfig(web=web)
    )
    return [result async for result in DomSinkCheck().run(context)]


class _NoHttp:
    """A stand-in for the scoped client: the checks under test never reach it."""

    policy = UrlSafetyPolicy()
    resolver = None


_NO_HTTP = _NoHttp()


def _skipped(results: list[Any]) -> bool:
    return any(
        evidence.payload.get("skipped") for result in results for evidence in result.evidence
    )


def _browser_web() -> WebSettings:
    return replace(WebSettings(), browser_crawl=True, browser_max_pages=4)


async def _speak(port: int, request: bytes) -> bytes:
    """Send a raw request to the harness proxy and read its answer (bounded)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(65536), 10.0)
        except TimeoutError:  # pragma: no cover
            return b""
    finally:
        with contextlib.suppress(Exception):
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
