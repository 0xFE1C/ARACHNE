"""Peak body memory is an allocation bound, not a processing bound (REQ-SCALE-013, G6 clause 3).

Before WP-17 the client assigned ``response.content`` — the **whole** body — and then sliced
it to ``body_limit``. The limit therefore bounded what was decoded and redacted, never what
was allocated, and one hostile endpoint could exhaust the scanner's memory before the cap
applied anywhere.

The fixture here is a real loopback HTTP server that declares and would send a 500 MiB body.
The client is configured with a 1 MiB limit and must stop reading at the cap: the request
completes, the captured body is exactly the limit, ``body_truncated`` is true, and Python's
allocation peak stays a small constant above the limit — nowhere near 500 MiB.
"""

from __future__ import annotations

import threading
import tracemalloc
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import HttpSettings, SafetySettings, Settings
from arachne.core.http import ScopedHttpClient
from arachne.core.ratelimit import RateLimitSettings
from arachne.core.safety import Scope, UrlSafetyPolicy

#: What the fixture server says (and would send, if anyone kept reading).
HUGE_BODY_BYTES = 500 * 1024 * 1024
#: The configured cap the client must enforce while streaming.
BODY_LIMIT = 1024 * 1024
#: The documented allocation ceiling for one request: the cap plus a fixed constant. The
#: constant covers the 64 KiB read chunk, the decoded text and the redaction pass's copies.
#: Measured well under this; it is stated in ``docs/performance.md`` as the envelope's
#: per-request body bound.
MEMORY_BOUND_BYTES = 16 * 1024 * 1024

_CHUNK = b"A" * (64 * 1024)


class _HugeHandler(BaseHTTPRequestHandler):
    """``/huge`` declares 500 MiB; ``/small`` returns a body under the cap."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path == "/small":
            payload = b"small body under the cap"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(HUGE_BODY_BYTES))
        self.end_headers()
        remaining = HUGE_BODY_BYTES
        try:
            while remaining > 0:
                self.wfile.write(_CHUNK)
                remaining -= len(_CHUNK)
        except (BrokenPipeError, ConnectionResetError):
            # The client stopped at its cap and closed the connection: the intended outcome.
            pass

    def log_message(self, *_args: object) -> None:  # keep the test output clean
        pass


@pytest.fixture
def huge_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HugeHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _client(url: str) -> ScopedHttpClient:
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            # The fixture is a loopback socket on purpose: it is the only way to prove the
            # cap at the socket layer without contacting anything outside this process.
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=("127.0.0.1",)),
        ),
        http=HttpSettings(max_body_bytes=BODY_LIMIT, timeout_s=30.0),
        rate_limit=RateLimitSettings(
            per_host_rate=100_000.0,
            per_host_burst=100_000,
            global_rate=100_000.0,
            global_burst=100_000,
        ),
    )
    return ScopedHttpClient(
        settings=settings,
        scope=settings.safety.scope,
        policy=settings.safety.policy,
        auditor=Auditor(MemoryAuditSink(), actor="perf"),
    )


@pytest.mark.perf
@pytest.mark.timeout(120)
async def test_a_500mb_body_with_a_1mb_limit_completes_within_the_memory_bound(
    huge_server: str,
) -> None:
    client = _client(huge_server)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        exchange = await client.get(f"{huge_server}/huge")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        await client.aclose()

    assert exchange.status_code == 200
    assert exchange.body_truncated is True
    # The captured body is exactly the limit — the old code also produced the first
    # ``limit`` bytes, so the *bytes* are unchanged; only the allocation is bounded now.
    assert len(exchange.body) == BODY_LIMIT
    assert set(exchange.body) == {"A"}
    bound_mib = MEMORY_BOUND_BYTES // 1024 // 1024
    body_mib = HUGE_BODY_BYTES // 1024 // 1024
    limit_kib = BODY_LIMIT // 1024
    assert peak < MEMORY_BOUND_BYTES, (
        f"peak allocation {peak / 1024 / 1024:.1f} MiB exceeded the "
        f"{bound_mib} MiB bound for a {body_mib} MiB body with a {limit_kib} KiB limit"
    )
    print(
        f"\nPERF body cap: {body_mib} MiB body, {limit_kib} KiB limit -> "
        f"peak {peak / 1024:.0f} KiB traced allocation"
    )


@pytest.mark.perf
@pytest.mark.timeout(120)
async def test_a_body_under_the_limit_is_captured_whole_and_not_flagged(
    huge_server: str,
) -> None:
    """The truncation flag and captured bytes are unchanged for a body under the limit."""
    client = _client(huge_server)
    try:
        exchange = await client.get(f"{huge_server}/small")
        raw = await client.request_bytes("GET", f"{huge_server}/small")
    finally:
        await client.aclose()
    assert exchange.body_truncated is False
    assert exchange.body == "small body under the cap"
    assert raw.truncated is False
    assert raw.content == b"small body under the cap"
    assert raw.body_bytes == len(b"small body under the cap")
