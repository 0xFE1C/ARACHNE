"""Blocking I/O does not run on the event loop (REQ-SCALE-013, WP-17).

Three UI handlers and the local evidence backend call synchronous stores, the credential
store, the auditor and the filesystem. In an ``async def`` handler or an ``async`` backend
method, that work used to run *on* the loop: every other request, scan task and audit write
waited for it.

These tests make the blocking deterministic rather than timing-dependent. The synchronous
call is replaced by one that parks on a :class:`threading.Event` for up to five seconds, and
the parked call is started *from inside* the probe, so the probe's own ``await
asyncio.sleep(0.15)`` is what gets delayed when the call runs on the loop. Run off the loop,
the sleep completes in milliseconds and an independent ticker keeps ticking. The assertion
is therefore a real detector: with the fix reverted, ``elapsed`` is the park.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request

from arachne.api.auth import API_KEY_COOKIE, Principal, Role
from arachne.api.routes_ui import delete_feed_ui, import_feed_ui, login
from arachne.data.evidence_backend import LocalEvidenceBackend

__all__ = []  # a test module, not part of the package API

#: How long a fake blocking call parks when the code under test does not move it off the
#: loop. Long enough to dominate the probe's 0.15 s; short enough that a regression fails
#: the test in seconds rather than hanging the suite.
PARK_S = 5.0
#: How long the probe sleeps. Off the loop this is all it costs; on the loop the measured
#: time is the park instead.
PROBE_S = 0.15


class _BlockingCall:
    """A synchronous callable that parks its thread until released."""

    def __init__(self, result: Any = None) -> None:
        self.entered = threading.Event()
        self.released = threading.Event()
        self.result = result

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        self.entered.set()
        self.released.wait(PARK_S)
        return self.result


async def _probe(
    blocker: _BlockingCall,
    call: Callable[[], Coroutine[Any, Any, Any]],
    *,
    what: str,
) -> Any:
    """Start ``call`` on the loop and measure how long the probe's sleep took.

    Returns the call's result. Fails if the sleep took a meaningful fraction of the park
    (the call held the loop) or if an independent ticker never ran at all.
    """
    ticks = 0
    stop = False

    async def ticker() -> None:
        nonlocal ticks
        while not stop:
            ticks += 1
            await asyncio.sleep(0.01)

    tick_task = asyncio.create_task(ticker())
    pending = asyncio.create_task(call())
    started = time.monotonic()
    await asyncio.sleep(PROBE_S)
    elapsed = time.monotonic() - started
    ticks_seen = ticks
    # Release before asserting: a failure must not leave the parked thread waiting out its
    # full timeout while the test reports.
    blocker.released.set()
    stop = True
    results = await asyncio.gather(tick_task, pending, return_exceptions=True)
    assert ticks_seen >= 3, "the ticker never ran: the event loop made no progress"
    assert elapsed < 1.0, (
        f"{what} held the event loop for {elapsed:.2f}s — the synchronous call must run "
        f"via asyncio.to_thread"
    )
    return results[1]


def _principal() -> Principal:
    return Principal(label="perf", role=Role.ADMIN, user="perf@arachne.test")


class _Credentials:
    def __init__(self, principal: Principal, blocker: _BlockingCall | None = None) -> None:
        self._principal = principal
        self.blocker = blocker

    def verify_key(self, _key: str | None) -> Principal | None:
        if self.blocker is not None:
            return self.blocker()
        return self._principal

    def resolve_session(self, _token: str | None) -> Principal | None:
        return None


class _Auditor:
    def __init__(self, blocker: _BlockingCall | None = None) -> None:
        self.blocker = blocker
        self.records: list[tuple[Any, dict[str, Any]]] = []

    def record(self, action: Any, **meta: Any) -> None:
        if self.blocker is not None:
            self.blocker()
        self.records.append((action, meta))


def _request(body: bytes = b"", *, headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"cookie", f"{API_KEY_COOKIE}=perf-key".encode())]
    for key, value in (headers or {}).items():
        raw_headers.append((key.encode(), value.encode()))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/ui/feeds/1/delete",
        "raw_path": b"/ui/feeds/1/delete",
        "root_path": "",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _ui_context(*, credentials: Any, auditor: Any, feeds: Any = None) -> Any:
    return SimpleNamespace(
        credentials=credentials,
        auditor=auditor,
        services=SimpleNamespace(feeds=feeds),
        settings=SimpleNamespace(
            api=SimpleNamespace(session_max_age_s=60, tls_configured=False),
            feeds=SimpleNamespace(max_entries=10),
        ),
        oidc=None,
    )


# ------------------------------------------------------------------ evidence backend
async def test_the_local_evidence_read_runs_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LocalEvidenceBackend(tmp_path)
    stored = await backend.put(b"payload for the blocking-read test")

    blocker = _BlockingCall()
    original = Path.read_bytes

    def slow_read(self: Path) -> bytes:
        blocker()
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", slow_read)

    read = await _probe(blocker, lambda: backend.get(stored.key), what="a blocking evidence read")
    assert read == b"payload for the blocking-read test"


async def test_the_local_evidence_write_runs_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LocalEvidenceBackend(tmp_path)

    blocker = _BlockingCall()
    original = Path.open

    def slow_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        blocker()
        return original(self, *args, **kwargs)

    # ``_put_stream`` opens a temp file to write the container.
    monkeypatch.setattr(Path, "open", slow_open)

    stored = await _probe(
        blocker, lambda: backend.put(b"written payload"), what="a blocking evidence write"
    )
    assert stored.size == len(b"written payload")


# ------------------------------------------------------------------ UI handlers
async def test_feed_delete_does_not_block_the_event_loop() -> None:
    blocker = _BlockingCall(True)
    context = _ui_context(
        credentials=_Credentials(_principal()),
        auditor=_Auditor(),
        feeds=SimpleNamespace(delete=blocker),
    )
    request = _request(headers={"hx-request": "true"})

    response = await _probe(
        blocker, lambda: delete_feed_ui(request, 1, context), what="the feed delete"
    )
    assert response.status_code == 303


async def test_feed_import_does_not_block_the_event_loop() -> None:
    blocker = _BlockingCall(None)
    context = _ui_context(
        credentials=_Credentials(_principal()),
        auditor=_Auditor(),
        feeds=SimpleNamespace(import_text=blocker),
    )
    request = _request(
        body=b"kind=kev&name=kev&content=%5B%5D",
        headers={"hx-request": "true", "content-type": "application/x-www-form-urlencoded"},
    )

    response = await _probe(
        blocker, lambda: import_feed_ui(request, context), what="the feed import"
    )
    assert response.status_code == 303


async def test_login_does_not_block_the_event_loop() -> None:
    blocker = _BlockingCall(_principal())
    context = _ui_context(credentials=_Credentials(_principal(), blocker), auditor=_Auditor())
    request = _request(
        body=b"key=perf-key&next=%2Fui%2F",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    response = await _probe(blocker, lambda: login(request, context), what="the credential check")
    assert response.status_code == 303
