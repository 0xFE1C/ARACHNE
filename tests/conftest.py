"""Shared test fixtures.

Two ideas carry most of the weight here:

* :class:`FakeClock` — the rate limiter's clock and sleep function are injectable, so
  rate-limit tests are exact and instant instead of slow and flaky.
* ``make_client`` — builds a :class:`~arachne.core.http.ScopedHttpClient` whose transport
  is an ``httpx.MockTransport`` and whose DNS resolver is a stub, so the safety pipeline
  (scope, URL policy, rate limit, audit, redaction) is exercised end to end without a
  single packet leaving the process.

Stage S2 adds ``make_request`` / ``build_scan_request``, which keep the exhaustive target
definition of F-01-01 out of every individual test: a test states only the part it cares
about.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import HttpSettings, RateLimitSettings, SafetySettings, Settings
from arachne.core.http import ScopedHttpClient
from arachne.core.ratelimit import HostRateLimiter
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.core.target import ScanOptions, ScanRequest
from arachne.tools.skip_gate import (
    ALLOWLIST_PATH,
    QUARANTINE_PATH,
    check_quarantine,
    is_skip_allowed,
    load_allowlist,
    load_quarantine,
)

# The CLI renders its help to the terminal's width, so on a narrow terminal an option name is
# wrapped or dropped and a test asserting the name is present fails for a reason that has
# nothing to do with the code. It is a real failure mode: the CI runner reports a narrower
# width than a developer's terminal, and four help tests failed there while passing locally.
# Pinning the width makes the rendered help identical in both places. Nothing in the suite
# renders to a terminal except these help assertions, so no other test can observe it.
os.environ["COLUMNS"] = "200"

#: A documentation-range address (RFC 5737) that is never private.
PUBLIC_IP = "93.184.216.34"
#: A second public address, for multi-address resolution cases.
PUBLIC_IP_2 = "93.184.216.35"
#: Test target host used across the suite.
TARGET_HOST = "example.com"
TARGET_URL = f"https://{TARGET_HOST}/"

#: Path of the shipped example fixture (the one the CLI documentation points at).
EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples" / "targets"
#: Path of the test target fixtures.
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "targets"

Handler = Callable[[httpx.Request], httpx.Response]

#: A complete, valid attestation for the default test target. Tests override the fields
#: they are exercising (an uncovered target, an expiry, a withheld active-checks flag).
DEFAULT_ATTESTATION: dict[str, Any] = {
    "attested_by": "Jane Operator <jane.operator@example.com>",
    "attested_at": "2026-10-01T00:00:00Z",
    "scope_statement": "Unit-test authorization covering the documentation domain",
    "authorization_ref": "TEST-1",
    "allowed_targets": ["example.com"],
}


def build_scan_request(
    *,
    name: str = "unit-fixture",
    targets: Iterable[Mapping[str, str]] | None = None,
    exclusions: Iterable[Mapping[str, str]] | None = None,
    attestation: Mapping[str, Any] | str | None = "default",
    options: Mapping[str, Any] | None = None,
) -> ScanRequest:
    """Build a :class:`ScanRequest` from the parts a test cares about.

    ``attestation="default"`` uses :data:`DEFAULT_ATTESTATION`; ``None`` omits it (the
    "not authorized" case); a mapping is merged onto the default, so a test overrides only
    the field it is exercising (``allowed_targets``, ``expires_at``, ...).
    """
    document: dict[str, Any] = {
        "target": {
            "name": name,
            "targets": list(targets or [{"kind": "url", "value": "https://example.com/"}]),
            "exclusions": list(exclusions or []),
        },
        "options": dict(options or {}),
    }
    if attestation == "default":
        document["target"]["attestation"] = dict(DEFAULT_ATTESTATION)
    elif attestation is not None:
        document["target"]["attestation"] = dict(DEFAULT_ATTESTATION) | dict(attestation)
    return ScanRequest.model_validate(document)


@pytest.fixture
def make_request() -> Callable[..., ScanRequest]:
    """Fixture form of :func:`build_scan_request`."""
    return build_scan_request


def build_options(**overrides: Any) -> ScanOptions:
    """Build :class:`ScanOptions` with test-friendly defaults."""
    return ScanOptions(**overrides)


class FakeClock:
    """Deterministic replacement for ``time.monotonic`` + ``asyncio.sleep``."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.sleep_calls = 0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleep_calls += 1
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(autouse=True)
def _reset_arachne_logging() -> Iterator[None]:
    """Restore the ARACHNE logger to its default after every test.

    ``configure_logging`` installs a process-global handler and sets
    ``propagate = False`` (so the CLI does not double-log). Any test that exercises the
    CLI therefore leaves global state behind, and a later test that relies on ``caplog``
    would see nothing. Resetting to the documented default (no handler, NOTSET,
    propagate) keeps the suite order-independent.
    """
    logger = logging.getLogger("arachne")
    yield
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def audit_sink() -> MemoryAuditSink:
    return MemoryAuditSink()


@pytest.fixture
def auditor(audit_sink: MemoryAuditSink) -> Auditor:
    return Auditor(audit_sink, actor="pytest")


def build_settings(
    *,
    scope: Scope | None = None,
    policy: UrlSafetyPolicy | None = None,
    rate_limit: RateLimitSettings | None = None,
    http: HttpSettings | None = None,
    redaction_enabled: bool = True,
    **http_overrides: Any,
) -> Settings:
    """Build settings for a test.

    Defaults are deliberately fast (high rate limits, no redirects surprises) and the
    scope allows exactly one host — the scanner's deny-by-default posture is the
    production default, but tests need a target to talk to.
    """
    effective_http = http or HttpSettings(**http_overrides)
    return Settings(
        database_url="sqlite:///:memory:",
        http=effective_http,
        rate_limit=rate_limit
        or RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
        safety=SafetySettings(
            policy=policy or UrlSafetyPolicy(),
            scope=scope if scope is not None else Scope(allowed_hosts=(TARGET_HOST,)),
            redaction_enabled=redaction_enabled,
        ),
        log_level="WARNING",
        actor="pytest",
    )


def default_handler(
    *,
    status: int = 200,
    body: str = "ok",
    headers: Mapping[str, str] | None = None,
) -> Handler:
    """A transport handler returning a fixed response."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body, headers=dict(headers or {}))

    return handler


@pytest.fixture
async def make_client(
    fake_clock: FakeClock, auditor: Auditor
) -> AsyncIterator[Callable[..., ScopedHttpClient]]:
    """Factory for clients wired to a mock transport, stub DNS and fake clock."""
    created: list[ScopedHttpClient] = []

    def _make(
        handler: Handler | None = None,
        *,
        scope: Scope | None = None,
        policy: UrlSafetyPolicy | None = None,
        addresses: Iterable[str] = (PUBLIC_IP,),
        settings: Settings | None = None,
        rate_limit: RateLimitSettings | None = None,
        resolver: Any = None,
        limiter: HostRateLimiter | None = None,
        **http_overrides: Any,
    ) -> ScopedHttpClient:
        effective_settings = settings or build_settings(
            scope=scope,
            policy=policy,
            rate_limit=rate_limit,
            **http_overrides,
        )
        effective_limiter = limiter or HostRateLimiter(
            effective_settings.rate_limit,
            clock=fake_clock.monotonic,
            sleep=fake_clock.sleep,
        )
        client = ScopedHttpClient(
            settings=effective_settings,
            scope=scope if scope is not None else effective_settings.safety.scope,
            policy=policy if policy is not None else effective_settings.safety.policy,
            resolver=resolver or StaticResolver(tuple(addresses)),
            limiter=effective_limiter,
            auditor=auditor,
            transport=httpx.MockTransport(handler or default_handler()),
        )
        created.append(client)
        return client

    try:
        yield _make
    finally:
        for client in created:
            await client.aclose()


@pytest.fixture
def repo_root() -> Path:
    """``code/`` — the directory holding alembic.ini and migrations/."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def synthetic_report() -> object:
    """A small, fully-formed report (confirmed + low-confidence + dropped findings)."""
    from tests.helpers.report import synthetic_report as build

    return build()


# --------------------------------------------------------------- quality gates
# REQ-QUAL-010 (quarantine), REQ-QUAL-011 (skip allowlist) and REQ-QUAL-007's wall-clock
# budget. Enforcement lives here so it applies to whatever subset is run, not only to the
# full-suite job. The rules themselves are in the shipped tool (arachne.tools.skip_gate), so
# the gate and the file format cannot drift.

_REPO_ROOT = Path(__file__).resolve().parents[1]
_BUDGET_ENV = "ARACHNE_SUITE_BUDGET"
_SKIPPED: list[tuple[str, str]] = []
_LAYER_SECONDS: dict[str, float] = {}
_SESSION_START = 0.0


def _skip_reason(report: pytest.TestReport | pytest.CollectReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr)


def pytest_configure(config: pytest.Config) -> None:
    """Fail fast on a quarantined test past its deadline, or a retry plugin."""
    global _SESSION_START
    _SESSION_START = time.monotonic()
    if config.pluginmanager.hasplugin("rerunfailures"):
        raise pytest.UsageError(
            "pytest-rerunfailures is installed: retries are disabled (REQ-QUAL-010); a flake "
            "is recorded in tests/quarantine.json, not papered over with a retry"
        )
    if config.getoption("--reruns", None) is not None:
        raise pytest.UsageError("--reruns is set: retries are disabled (REQ-QUAL-010)")
    try:
        quarantine = load_quarantine(_REPO_ROOT)
    except ValueError as exc:
        raise pytest.UsageError(f"{QUARANTINE_PATH}: {exc}") from exc
    expired = check_quarantine(quarantine, today=datetime.now(UTC).date())
    if expired:
        raise pytest.UsageError(
            "quarantine deadline passed (REQ-QUAL-010): "
            + "; ".join(violation.render() for violation in expired)
        )


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record skips and per-layer durations (REQ-QUAL-011, REQ-QUAL-007)."""
    layer = "/".join(report.nodeid.split("/")[:2])
    _LAYER_SECONDS[layer] = _LAYER_SECONDS.get(layer, 0.0) + report.duration
    if report.skipped and report.when in {"setup", "call"}:
        _SKIPPED.append((report.nodeid, _skip_reason(report)))


def pytest_collectreport(report: pytest.CollectReport) -> None:
    """A module-level ``skipif`` is reported here, not as a per-test skip."""
    if report.skipped:
        _SKIPPED.append((str(report.nodeid), _skip_reason(report)))


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """Report per-layer durations (REQ-QUAL-007)."""
    if not _LAYER_SECONDS:
        return
    terminalreporter.write_sep("-", "per-layer durations")
    for layer, seconds in sorted(_LAYER_SECONDS.items(), key=lambda item: -item[1]):
        terminalreporter.write_line(f"{seconds:8.1f}s  {layer}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the run on an unlisted skip, or on a wall clock over the budget (REQ-QUAL-007/011)."""
    problems: list[str] = []
    try:
        allowlist = load_allowlist(_REPO_ROOT)
    except ValueError as exc:
        problems.append(f"{ALLOWLIST_PATH}: {exc}")
        allowlist = []
    for node_id, reason in _SKIPPED:
        if not is_skip_allowed(node_id, allowlist):
            problems.append(
                f"unlisted skip: {node_id} — {reason} (add it to {ALLOWLIST_PATH} with a reason, "
                "or remove the skip)"
            )
    budget = os.environ.get(_BUDGET_ENV)
    if budget:
        elapsed = time.monotonic() - _SESSION_START
        if elapsed > float(budget):
            problems.append(
                f"suite wall clock {elapsed:.0f}s exceeds the {budget}s budget (REQ-QUAL-007)"
            )
    if problems:
        print("\n".join(f"[quality gate] {problem}" for problem in problems))
        session.exitstatus = 1
