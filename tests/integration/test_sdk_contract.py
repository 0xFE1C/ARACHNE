"""Integration: the **generated** clients against the live API — auth, shape, rate limit.

REQ-ECOS-002's acceptance criterion is "generated clients pass contract tests against the
API test fixture", and the hard rule is "generated clients must not bypass API auth or rate
limits". Both are properties of the *wire*, not of a unit, so every assertion here drives the
committed client against the real assembled app (``make_api_harness`` — middleware, auth
dependencies, exception handlers and the real stores) served by a real ``uvicorn`` socket:

* the Python client is the generated synchronous client and its own transport;
* the TypeScript client is the generated ``client.ts``, executed by ``node`` (Node 22+
  strips the types natively), talking to the same server with the global ``fetch``.

``httpx.ASGITransport`` would be tempting for the Python half, but it is an *async* transport
and the generated Python client is synchronous; driving a real socket is both simpler and a
stronger contract test (the header really crosses TCP and every middleware really runs).

What "not bypassing" means, concretely:

* a blank key never leaves the process (the constructor refuses it);
* a wrong key reaches the server and comes back as the server's 401 — the refusal is in the
  audit trail, which only the auth dependency writes;
* a ``429`` reaches the caller as ``ArachneRateLimitError`` with the server's ``Retry-After``,
  proving the client is an ordinary rate-limited consumer rather than something that loops
  past the limit.
"""

from __future__ import annotations

import importlib
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from tests.helpers.api import (
    ADMIN_KEY,
    SCANNER_KEY,
    VIEWER_KEY,
    ApiHarness,
    build_api_settings,
    make_api_harness,
)

pytestmark = pytest.mark.integration

CLIENTS = Path(__file__).resolve().parents[2] / "clients"
TYPESCRIPT_CLIENT = CLIENTS / "typescript" / "src" / "client.ts"

#: A rate limit small enough to hit on the second request, and legal for the settings model
#: (``per_minute`` and ``burst`` must both be >= 1).
TINY_LIMIT: dict[str, int] = {"rate_limit_per_minute": 1, "rate_limit_burst": 1}

#: The server's own refusal text, which the client must pass through verbatim.
RATE_LIMIT_MESSAGE = "rate limit exceeded"


@dataclass(frozen=True)
class LiveApi:
    """The fixture app behind a real socket, plus the harness that built it."""

    base_url: str
    harness: ApiHarness


@pytest.fixture(scope="module")
def sdk() -> Iterator[ModuleType]:
    """The generated Python package, imported from the committed tree."""
    root = str(CLIENTS / "python")
    sys.path.insert(0, root)
    try:
        yield importlib.import_module("arachne_client")
    finally:
        sys.path.remove(root)


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[ApiHarness]:
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_serving(base_url: str, *, timeout: float = 20.0) -> None:
    """Poll a keyed endpoint so readiness never consumes the keyless bucket.

    The probe uses the admin key (which the tests below never use) because a one-token
    bucket is spent by a single successful request.
    """
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"{base_url}/api/v1/health",
                headers={"X-API-Key": ADMIN_KEY},
                timeout=2.0,
            )
        except httpx.HTTPError as exc:  # not listening yet
            last = exc
        else:
            if response.status_code == 200:
                return
            last = f"health answered {response.status_code}: {response.text}"
        time.sleep(0.05)
    raise AssertionError(f"the API did not start: {last}")


def _serve(built: ApiHarness) -> Iterator[LiveApi]:
    """Run ``built.app`` on a real port in a background thread, and stop it afterwards."""
    uvicorn = pytest.importorskip("uvicorn")
    port = _free_port()
    config = uvicorn.Config(
        built.app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        # The lifespan owns the runner/scheduler and the harness owns the services; the
        # routes under test need neither, so the ASGI lifespan stays off.
        lifespan="off",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_serving(base_url)
        yield LiveApi(base_url=base_url, harness=built)
    finally:
        server.should_exit = True
        thread.join(timeout=15)


@pytest.fixture
def api(harness: ApiHarness) -> Iterator[LiveApi]:
    """The fixture app on a real port, with the harness's generous rate limits."""
    yield from _serve(harness)


@pytest.fixture
def throttled_api(tmp_path: Path) -> Iterator[LiveApi]:
    """The same app with a one-request bucket, so the rate limit is provable."""
    built = make_api_harness(tmp_path, settings=build_api_settings(tmp_path, api=dict(TINY_LIMIT)))
    try:
        yield from _serve(built)
    finally:
        built.close()


# --------------------------------------------------------------------------- (a) the key
def test_a_blank_key_is_refused_before_any_request(sdk: ModuleType) -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    for blank in ("", "   "):
        with pytest.raises(sdk.ArachneConfigError):
            sdk.Client(
                base_url="http://127.0.0.1:1",
                api_key=blank,
                transport=httpx.MockTransport(handler),
            )
    assert sent == [], "an unauthenticated request was attempted"


# --------------------------------------------------------------------------- (b) the 401
def test_a_wrong_key_reaches_the_server_and_is_refused(sdk: ModuleType, api: LiveApi) -> None:
    with sdk.Client(base_url=api.base_url, api_key="not-a-real-key") as client:
        with pytest.raises(sdk.ArachneAuthError) as info:
            client.list_scans()
    assert info.value.status_code == 401
    # The 401 is the *server's*: only the auth dependency writes this audit row.
    assert "api.denied" in api.harness.actions(), "the refusal did not come from the server"
    assert info.value.response_headers.get("www-authenticate") == "ApiKey"


def test_a_key_without_the_role_is_refused(sdk: ModuleType, api: LiveApi) -> None:
    """403 is the auth path too (the client must not paper over it)."""
    with sdk.Client(base_url=api.base_url, api_key=VIEWER_KEY) as client:
        with pytest.raises(sdk.ArachneAuthError) as info:
            client.list_service_accounts()
    assert info.value.status_code == 403


# --------------------------------------------------------------------------- (c) happy path
def test_the_generated_client_reads_the_live_api(sdk: ModuleType, api: LiveApi) -> None:
    api.harness.seed_scan()
    with sdk.Client(base_url=api.base_url, api_key=ADMIN_KEY) as client:
        health = client.health()
        assert health["status"] == "ok"
        assert isinstance(health["api_keys"], int)
        scans = client.list_scans()
        # REQ-UIX-001: a collection method returns a page, so pagination is exposed by the
        # generated client itself — the cursors come from the response headers.
        assert isinstance(scans, dict) and set(scans) >= {
            "items",
            "next_cursor",
            "prev_cursor",
            "has_more",
        }
        items = scans["items"]
        assert isinstance(items, list) and len(items) == 1
        assert set(items[0]) >= {"id", "status", "engine", "counts"}
        assert isinstance(items[0]["counts"], dict)
        # The models the client declares really are the shapes the server sends.
        detail = client.get_scan(items[0]["id"])
        assert detail["id"] == items[0]["id"]


def test_the_project_header_is_sent_and_acted_on(sdk: ModuleType, api: LiveApi) -> None:
    """A bogus tenant is the *server's* 404: the ``x-project`` header crossed the wire."""
    with sdk.Client(base_url=api.base_url, api_key=ADMIN_KEY) as client:
        assert client.list_scans()["items"] == []
        with pytest.raises(sdk.ArachneAPIError) as info:
            client.list_scans(project="no-such-tenant")
        assert info.value.status_code == 404
        assert "no-such-tenant" in str(info.value)
    with sdk.Client(base_url=api.base_url, api_key=ADMIN_KEY, project="no-such-tenant") as scoped:
        with pytest.raises(sdk.ArachneAPIError):
            scoped.list_scans()


def test_an_unknown_path_parameter_is_a_plain_404(sdk: ModuleType, api: LiveApi) -> None:
    with sdk.Client(base_url=api.base_url, api_key=ADMIN_KEY) as client:
        with pytest.raises(sdk.ArachneAPIError) as info:
            client.get_project("no-such-project")
    assert info.value.status_code == 404


# --------------------------------------------------------------------------- (d) rate limit
def test_the_python_client_is_a_rate_limited_consumer(
    sdk: ModuleType, throttled_api: LiveApi
) -> None:
    with sdk.Client(base_url=throttled_api.base_url, api_key=VIEWER_KEY) as client:
        assert client.health()["status"] == "ok"  # the bucket's only token
        with pytest.raises(sdk.ArachneRateLimitError) as info:
            client.health()
    assert RATE_LIMIT_MESSAGE in str(info.value)
    assert info.value.status_code == 429
    assert info.value.retry_after is not None and info.value.retry_after > 0
    assert info.value.limit == 1
    # The refusal was the server's, and it was audited as such.
    assert "api.denied" in throttled_api.harness.actions()


def test_a_rate_limited_request_is_not_retried(sdk: ModuleType, throttled_api: LiveApi) -> None:
    """After a 429 the client keeps failing immediately: it never waits the limit out."""
    with sdk.Client(base_url=throttled_api.base_url, api_key=SCANNER_KEY) as client:
        assert client.health()["status"] == "ok"  # the bucket's only token
        with pytest.raises(sdk.ArachneRateLimitError):
            client.health()
        with pytest.raises(sdk.ArachneRateLimitError):
            client.health()


# --------------------------------------------------------------------------- (e) TypeScript
#: The driver the node test runs. It imports the *generated* client and reports what it saw;
#: the assertions live in Python so a failure reads as a pytest failure.
_NODE_DRIVER = """\
const baseUrl = process.argv[2];
const clientUrl = process.argv[3];
const goodKey = process.argv[4];

const { ArachneClient, ArachneAuthError, ArachneConfigError, ArachneRateLimitError } =
  await import(clientUrl);

const observed = {};

// (a) no key at all: the server itself must refuse the request.
const bare = await fetch(new URL("/api/v1/scans", baseUrl));
observed.noKeyStatus = bare.status;

// (b) a blank key never becomes a request.
try {
  new ArachneClient({ baseUrl, apiKey: "" });
  observed.emptyKey = "no-error";
} catch (error) {
  observed.emptyKey = error instanceof ArachneConfigError ? "config-error" : "other";
}

// (c) a wrong key is the server's 401, surfaced as a typed error.
const wrong = new ArachneClient({ baseUrl, apiKey: "not-a-real-key" });
try {
  await wrong.listScans();
  observed.wrongKey = "no-error";
} catch (error) {
  observed.wrongKey = error instanceof ArachneAuthError ? error.statusCode : "other";
  observed.authHeader =
    error instanceof ArachneAuthError ? error.responseHeaders["www-authenticate"] ?? null : null;
}

// (d) the happy path.
const client = new ArachneClient({ baseUrl, apiKey: goodKey });
const health = await client.health();
observed.healthStatus = health.status;
observed.healthHasApiKeys = typeof health.api_keys === "number";

// (e) the rate limit still applies to this client.
try {
  await client.health();
  observed.secondCall = "no-error";
} catch (error) {
  observed.secondCall = error instanceof ArachneRateLimitError ? error.retryAfter : "other";
}

console.log(JSON.stringify(observed));
"""


def _node_binary() -> str:
    """``node``, or a clean skip: a bare environment must still be green."""
    found = shutil.which("node")
    if found is None:
        pytest.skip("node is not on PATH; the TypeScript contract test needs it")
    return found


def test_the_typescript_test_skips_cleanly_when_node_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skip is asserted, not assumed (pytest's ``Skipped`` is a ``BaseException``)."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(BaseException, match="node is not on PATH"):
        _node_binary()


def test_the_generated_typescript_client_contract(tmp_path: Path, throttled_api: LiveApi) -> None:
    """One server, four distinct rate-limit identities, so each concern gets its own token."""
    node = _node_binary()
    driver = tmp_path / "contract.mjs"
    driver.write_text(_NODE_DRIVER, encoding="utf-8")
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, node from PATH
        [node, str(driver), throttled_api.base_url, TYPESCRIPT_CLIENT.as_uri(), VIEWER_KEY],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    observed: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])

    # (a) the server, not the client, refuses a keyless request.
    assert observed["noKeyStatus"] == 401
    # (b) a blank key is refused by the client before any request.
    assert observed["emptyKey"] == "config-error"
    # (c) a wrong key is the server's 401, as a typed error carrying its headers.
    assert observed["wrongKey"] == 401
    assert observed["authHeader"] == "ApiKey"
    # (d) the happy path returns the server's shape.
    assert observed["healthStatus"] == "ok"
    assert observed["healthHasApiKeys"] is True
    # (e) the rate limit applies to the generated client too.
    assert isinstance(observed["secondCall"], int | float)
    assert observed["secondCall"] > 0
