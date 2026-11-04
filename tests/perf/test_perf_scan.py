"""G-06 performance benchmark: a synthetic 50-host / 200-endpoint heuristic scan.

**What this measures.** The wall-clock time ``Orchestrator.scan()`` takes to run a full
*heuristic* scan (analysis engine = heuristic, i.e. no AI provider) over a synthetic estate
of 50 hosts and 200 crawl endpoints, from the scope/authorization gates through the
discovery seed, the M3/M4 web crawl and checks, the heuristic analysis step and the
correlation step. The G-06 budget is "under 60 min" (Performance row);
the assertion below pins that budget (``< 3600`` s) so a regression that is orders of
magnitude slower than today fails while CI stays meaningful, and the measured number is
printed for the record.

**What this deliberately excludes, so the recorded number is honest.**

* *Network latency and real target I/O.* The 50 hosts and their endpoints are served by an
  in-process :class:`httpx.MockTransport` handler that answers every request deterministically
  from a canned synthetic page (HTTP 200 HTML with a couple of planted markers). No socket is
  opened and DNS is a :class:`~arachne.core.safety.StaticResolver`; nothing leaves the
  process. The number therefore measures ARACHNE's own pipeline and analysis throughput, not
  how fast the scanned estate is.
* *M1 / M2.* OSINT (M1) and the raw-network modules (M2) are out of scope: their cost is
  dominated by unreachable-host and closed-port *timeouts* on a synthetic estate and would
  measure the (scripted) network, not the scanner. The scan is scoped to the web-facing
  modules (M3/M4), which are the realistic per-endpoint cost.
* *Rate-limit pacing.* The rate limits are raised to generous values (as the M4 lab
  acceptance test does) so the benchmark measures pipeline/analysis throughput rather than
  the deliberate pacing a polite production scan performs. The shared client still enforces
  every safety gate — scope, URL policy, redaction, audit — for every request.

The endpoint count is asserted so the fixture cannot silently shrink and quietly turn a
regression benchmark into a coverage-free green tick.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry

#: The synthetic estate: 50 hosts, 4 endpoints each (root + 3 linked paths) = 200 endpoints.
HOST_COUNT = 50
ENDPOINTS_PER_HOST = 4
ENDPOINT_TOTAL = HOST_COUNT * ENDPOINTS_PER_HOST

#: The G-06 budget : a heuristic scan of this estate must finish well under
#: 60 minutes. We assert against the full budget so a catastrophic regression fails, while a
#: machine- and load-independent margin keeps CI green.
G06_BUDGET_SECONDS = 3600.0

#: A public (RFC 5737 documentation-range) address: the StaticResolver answers every host
#: with it, so the safety policy's per-address classification passes with the shipped policy.
TARGET_ADDRESS = "93.184.216.34"

#: The synthetic page every endpoint serves. It links three same-origin paths (so the crawl
#: discovers exactly four endpoints per host) and carries two planted markers: a benign HTML
#: comment and an obviously-fake cloud key (so the redaction path runs with real input).
_PLANTED_MARKER = "ARACHNE-PERF-FIXTURE-MARKER"
_PLANTED_FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"
_CANNED_PAGE = (
    "<!doctype html><html lang='en'><head><title>Arachne perf fixture</title>"
    f"<meta name='generator' content='{_PLANTED_MARKER}'>"
    "</head><body><h1>Perf fixture</h1>"
    "<a href='/p1'>p1</a> <a href='/p2'>p2</a> <a href='/p3'>p3</a>"
    f"<!-- planted marker: {_PLANTED_MARKER} -->"
    f"<script>var aws_access_key_id = '{_PLANTED_FAKE_KEY}';</script>"
    "</body></html>"
)


def _hosts() -> tuple[str, ...]:
    return tuple(f"perf-{index:03d}.arachne.test" for index in range(HOST_COUNT))


def _canned_transport() -> httpx.AsyncBaseTransport:
    """A transport that answers any request with the canned synthetic page.

    Deterministic and offline: the same URL always yields the same 200 HTML response, and no
    socket, DNS lookup or clock is involved. The ``Set-Cookie`` without hardening flags is a
    third planted marker, so the cookie-audit checks have something to read.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=_CANNED_PAGE,
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "PERFSESS=abc123; path=/",
            },
        )

    return httpx.MockTransport(handler)


@pytest.fixture(scope="module")
def scan_fixture() -> Iterator[dict[str, Any]]:
    """A 50-host / 200-endpoint estate and everything needed to scan it offline."""
    hosts = _hosts()
    definition = TargetDefinition(
        name="perf-50-host-200-endpoint",
        targets=tuple(TargetSelector(kind="url", value=f"http://{host}/") for host in hosts),
        attestation={
            "attested_by": "G-06 benchmark <perf@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": (
                "Synthetic, fully offline 50-host heuristic-mode performance fixture owned "
                "by the test suite; no real host is ever contacted."
            ),
            # One domain entry covers every declared URL target (subdomain match).
            "allowed_targets": ["arachne.test"],
            "authorization_ref": "TEST-G06",
            "active_checks_authorized": True,
        },
    )
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        # The scope gate is the target definition's own scope; the deployment allowlist stays
        # empty (the default), so nothing extra is declared. The fixture resolves to a public
        # address, so the shipped URL policy is satisfied without widening it.
        safety=SafetySettings(
            policy=UrlSafetyPolicy(),
            scope=Scope.deny_all(),
        ),
        # Generous limits: measure pipeline/analysis throughput, not rate-limit pacing.
        rate_limit=RateLimitSettings(
            per_host_rate=100_000.0,
            per_host_burst=100_000,
            global_rate=100_000.0,
            global_burst=100_000,
        ),
        # The crawl must be wide enough to walk all 200 endpoints (defaults are far smaller).
        web=WebSettings(max_pages=2000, max_depth=2, max_endpoints=2000),
    )
    yield {"definition": definition, "settings": settings, "hosts": hosts}


@pytest.mark.perf
# An explicit, reviewed timeout (REQ-QUAL-012's mechanism). The measured run is 30-37 s, so
# the global 60 s cap left only a 1.7x margin against a busy machine — and a benchmark should
# fail on its *assertion* (the 3,600 s G-06 budget), not on a wall-clock cap it legitimately
# approaches. The timeout here is a hang guard, not the performance gate.
@pytest.mark.timeout(300)
async def test_g06_scan_50_hosts_200_endpoints_under_budget(
    scan_fixture: dict[str, Any],
) -> None:
    """The G-06 benchmark: a 50-host/200-endpoint heuristic scan, timed end to end."""
    definition: TargetDefinition = scan_fixture["definition"]
    settings: Settings = scan_fixture["settings"]

    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    auditor = Auditor(MemoryAuditSink(), actor="perf")

    def client_factory(scope: Scope) -> ScopedHttpClient:
        """A real ScopedHttpClient whose transport is the deterministic offline fixture."""
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=settings.safety.policy,
            resolver=StaticResolver((TARGET_ADDRESS,)),
            auditor=auditor,
            transport=_canned_transport(),
        )

    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=registry,
            findings=findings,
            analyses=analyses,
            auditor=auditor,
        ),
        registry=registry,
        client_factory=client_factory,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            # Heuristic mode (the default engine): no AI provider is configured or contacted.
            modules=ModuleSelection(enabled=("M3", "M4")),
        ),
    )

    started = time.perf_counter()
    session = await orchestrator.scan(request)
    elapsed = time.perf_counter() - started

    assert session.status is ScanStatus.COMPLETED, session
    assert session.record is not None

    # The fixture must not silently shrink: 50 declared hosts and 200 crawled endpoints.
    assert len(definition.targets) == HOST_COUNT
    checks_state = session.record.step_state(ScanStep.CHECKS)
    web = dict(checks_state.stats.get("web", {})) if checks_state else {}
    endpoints = int(web.get("endpoints", 0))
    assert endpoints == ENDPOINT_TOTAL, (
        f"fixture shrank: expected {ENDPOINT_TOTAL} endpoints, crawled {endpoints}"
    )

    print(
        f"\nPERF G-06: {HOST_COUNT} hosts / {endpoints} endpoints in {elapsed:.1f}s "
        f"(heuristic mode; offline fixture, no network latency or rate-limit pacing)"
    )
    assert elapsed < G06_BUDGET_SECONDS, (
        f"G-06 regression: {HOST_COUNT} hosts / {ENDPOINT_TOTAL} endpoints took "
        f"{elapsed:.1f}s, over the {G06_BUDGET_SECONDS:.0f}s budget"
    )
