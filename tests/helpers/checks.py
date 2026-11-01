"""Harness for check-level tests: build a context, run a check, collect its results.

A check is a small async generator over one asset, so its tests should read like a
specification of that: give it an asset, give it (recorded) OSINT access, and look at the
results. Everything else — the store, the bus, the auditor, the scope — is real machinery
from the framework, because the point of these tests is the *contract*, not a mock.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings
from arachne.core.events import EventBus
from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import MemoryScanStateStore, StepContext
from arachne.core.net import ScopedNetClient, ScriptedNetTransport
from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult
from arachne.core.safety import Scope, StaticResolver
from arachne.core.steps import seed_asset
from arachne.core.target import ScanOptions, TargetDefinition, TargetSelector, load_scan_request
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.base import Asset, Module
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m2.inventory import NetworkInventory
from arachne.modules.providers import OsintAccess, build_osint_access_for_fixtures
from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes

__all__ = [
    "FIXTURES",
    "M2Harness",
    "MemoryContext",
    "build_asset",
    "make_osint",
    "make_step_context",
    "run_check",
]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
OSINT_FIXTURES = FIXTURES / "osint"
HTTP_FIXTURES = FIXTURES / "http"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"

DEFAULT_DEFINITION = FIXTURES / "targets" / "m1-fixture.yaml"


class MemoryContext:
    """The pieces of a scan a check touches, wired to memory implementations."""

    def __init__(
        self,
        *,
        scope: Scope,
        definition: TargetDefinition,
        options: ScanOptions,
        store: MemoryScanStateStore,
        bus: EventBus,
        sink: MemoryAuditSink,
        auditor: Auditor,
        scan_id: int,
    ) -> None:
        self.scope = scope
        self.definition = definition
        self.options = options
        self.store = store
        self.bus = bus
        self.sink = sink
        self.auditor = auditor
        self.scan_id = scan_id

    def step_context(
        self, *, http: Any = None, step: ScanStep = ScanStep.RECON, web: Any = None
    ) -> StepContext:
        return StepContext(
            scan_id=self.scan_id,
            step=step,
            definition=self.definition,
            options=self.options,
            scope=self.scope,
            store=self.store,
            bus=self.bus,
            auditor=self.auditor,
            http=http,
            web=web,
        )

    def actions(self) -> list[str]:
        return self.sink.actions()


def make_step_context(
    *,
    definition: TargetDefinition | None = None,
    scope: Scope | None = None,
    http: Any = None,
    options: ScanOptions | None = None,
    seed: Iterable[tuple[str, str]] = (),
    web: Any = None,
) -> tuple[StepContext, MemoryContext]:
    """A step context over in-memory state, optionally pre-seeded with assets."""
    if definition is None:
        request = load_scan_request(DEFAULT_DEFINITION)
        definition = request.target
        options = options or request.options
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    sink = MemoryAuditSink()
    bus = EventBus()
    memory = MemoryContext(
        scope=scope if scope is not None else definition.compile_scope(),
        definition=definition,
        options=options or ScanOptions(),
        store=store,
        bus=bus,
        sink=sink,
        auditor=Auditor(sink, actor="pytest"),
        scan_id=record.id,
    )
    for kind, value in seed:
        store.add_asset(record.id, kind=kind, value=value, meta={"declared": True})
    return memory.step_context(http=http, web=web), memory


def build_asset(selector: TargetSelector) -> Asset:
    """The asset a check would be handed for a declared target selector."""
    kind, value, meta = seed_asset(selector)
    return Asset.from_meta(kind, value, meta)


def make_osint(
    *,
    providers: Sequence[str] = ("crtsh", "circl", "wayback", "commoncrawl", "internetdb"),
    budget: int = 50,
    auditor: Auditor | None = None,
    fixtures: Path | None = OSINT_FIXTURES,
    search_url: str | None = SEARCH_URL,
    whois_url: str | None = None,
    rate_limits: Mapping[str, float] | None = None,
    routes: Mapping[str, Any] | None = None,
) -> OsintAccess:
    """An OSINT access object backed by recorded responses.

    ``rate_limits`` is empty by default: pacing is a production property, and a test that
    wanted to observe it passes a fake clock and the rates explicitly.
    """
    loaded = dict(routes) if routes is not None else load_fixture_routes(fixtures or OSINT_FIXTURES)
    return build_osint_access_for_fixtures(
        loaded,
        providers=tuple(providers),
        budget=budget,
        auditor=auditor,
        search_url=search_url,
        whois_url=whois_url,
        rate_limits=rate_limits,
    )


def make_target_client(scope: Scope, *, auditor: Auditor | None = None) -> ScopedHttpClient:
    """A target-scoped client replaying the recorded lab page and its bundle."""
    replay = FixtureReplay(load_fixture_routes(HTTP_FIXTURES))
    return ScopedHttpClient(
        scope=scope,
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


async def run_check(
    module: type[Module],
    asset: Asset,
    *,
    osint: OsintAccess | None = None,
    config: ModuleConfig | None = None,
    definition: TargetDefinition | None = None,
    options: ScanOptions | None = None,
    http: Any = None,
    web: Any = None,
    seed: Iterable[tuple[str, str]] = (),
    memory: MemoryContext | None = None,
) -> tuple[list[CheckResult], MemoryContext]:
    """Run one check over one asset and return ``(results, memory)``.

    The store is seeded with the asset itself when the caller did not seed anything, because
    every M1 check records what it discovers relative to the asset it was handed. ``web``
    injects the M3 crawl into the step context (S6), so an M3 check sees the same inventory the
    checks step would have built.
    """
    if memory is None:
        seed_values = list(seed) or [(asset.kind, asset.value)]
        step, memory = make_step_context(
            definition=definition, options=options, http=http, seed=seed_values, web=web
        )
    else:
        step = memory.step_context(http=http, web=web)
    context = CheckContext(
        step=step,
        module=module(),
        asset=asset,
        config=config or ModuleConfig(),
        osint=osint,
    )
    results: list[CheckResult] = []
    async for result in context.module.run(context):
        results.append(result)
    return results, memory


@dataclass
class M2Harness:
    """Everything an M2 check needs: a scripted network client and a shared inventory.

    M2's checks are a pipeline over real sockets, so their unit tests drive them with a
    :class:`~arachne.core.net.ScriptedNetTransport` (deterministic replies, no packet
    anywhere) plus an inventory the test fills in — which is exactly the state the checks
    find in a scan after the earlier stages ran.
    """

    asset: Asset
    inventory: NetworkInventory
    client: ScopedNetClient
    step: StepContext
    memory: MemoryContext
    transport: ScriptedNetTransport
    #: Set when the harness was given an HTTP client (the JSON-API datastores need one).
    http_transport: Any = None
    #: Recorded HTTP responses the client answers from (see :meth:`http_route`).
    #: Recorded HTTP responses the client answers from (see ``http_routes``).
    http_responses: list[Any] = dataclasses.field(default_factory=list)

    def context(self, module: type[Module], *, config: ModuleConfig | None = None) -> CheckContext:
        return CheckContext(
            step=self.step,
            module=module(),
            asset=self.asset,
            config=config or ModuleConfig(),
        )

    #: The address the client dials (a name asset is resolved before the transport sees it).
    resolved: str = ""

    def add_service(self, port: int, *, protocol: str = "tcp", **kwargs: Any) -> Any:
        return self.inventory.add_service(self.asset.value, port, protocol=protocol, **kwargs)

    def route(self, protocol: str, port: int, value: Any, *, host: str | None = None) -> None:
        """Script a transport reply, keyed by what the transport will actually receive.

        The client resolves a name and dials the address (resolve-and-pin), so routes for a
        hostname asset are keyed by the resolved address; this method does that translation so
        a test never has to remember which of the two the transport sees.
        """
        self.transport.routes[(protocol, host or self.resolved, port)] = value


def make_m2_harness(
    *,
    host: str = "93.184.216.34",
    kind: str = "host",
    routes: dict[tuple[str, str, int], Any] | None = None,
    seed_services: Iterable[tuple[int, str]] = (),
    config: ModuleConfig | None = None,
    settings: Settings | None = None,
    alive: bool = True,
    resolvable: bool = True,
    with_http: bool = False,
    http_routes: Iterable[Mapping[str, Any]] = (),
) -> M2Harness:
    """Build a scripted M2 harness for one asset.

    The harness stands for the state a scan is in when a check runs: the asset is seeded,
    liveness has (or has not, with ``alive=False``) established that the host answers, the
    earlier checks have already recorded some services, and the transport answers from
    ``routes``. A hostname asset resolves to the fixture address unless ``resolvable=False``,
    which is how the "this name does not exist" path is exercised.

    ``http_routes`` scripts the *shared HTTP client* (``ctx.http``), which the JSON-API
    datastore checks use: each entry is ``{"url": ..., "body": ..., "status": ..., "headers":
    ...}``. They are declared up front because a recorded-response transport is built from a
    complete set of recordings (an unmatched request answers 501 rather than guessing).
    """
    from arachne.core.net import ScopedNetClient, ScriptedNetTransport
    from arachne.core.planner import ScanStep
    from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
    from arachne.modules.m2.inventory import NetworkInventory

    effective_settings = settings or settings_for_checks(
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        # Checks make tens of probes per run; the production 5/s per host would turn a unit
        # test into a coffee break. Rate limiting has its own tests.
        rate_limit=RateLimitSettings(
            per_host_rate=1_000_000.0,
            per_host_burst=100_000,
            global_rate=1_000_000.0,
            global_burst=100_000,
        ),
    )
    resolved = host if _is_ip(host) else "93.184.216.34"
    transport = ScriptedNetTransport(_rekey(routes or {}, host, resolved))
    http_responses = [
        RecordedResponse(
            method=str(route.get("method", "GET")),
            url=str(route["url"]),
            status=int(route.get("status", 200)),
            headers=dict(route.get("headers") or {}),
            body=str(route.get("body", "")),
        )
        for route in http_routes
    ]
    http_client = None
    if with_http or http_responses:
        from arachne.core.http import fixture_transport

        http_client = ScopedHttpClient(
            settings=effective_settings,
            scope=Scope(allowed_hosts=(host, resolved)),
            policy=UrlSafetyPolicy(allow_private_ips=True, allow_loopback=True),
            resolver=StaticResolver((resolved,)),
            auditor=Auditor(MemoryAuditSink(), actor="pytest"),
            transport=fixture_transport(http_responses),
        )
    client = ScopedNetClient(
        settings=effective_settings,
        scope=Scope(allowed_hosts=(host,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=(
            StaticResolver({host: (host if _is_ip(host) else "93.184.216.34",)})
            if resolvable
            else StaticResolver({})
        ),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=transport,
    )
    inventory = NetworkInventory(max_hosts=8, max_ports=40)
    record = inventory.host(host, declared=True)
    if alive:
        record.alive = True
        record.discovery.append("tcp:80")
    for port, service in seed_services:
        inventory.add_service(host, port, service=service)
    step, memory = make_step_context(http=http_client, seed=[(kind, host)])
    step.net = client
    step.inventory = inventory
    step.step = ScanStep.DISCOVERY
    return M2Harness(
        http_transport=http_client,
        http_responses=http_responses,
        resolved=resolved,
        asset=asset_for(kind, host),
        inventory=inventory,
        client=client,
        step=step,
        memory=memory,
        transport=transport,
    )


def _rekey(
    routes: dict[tuple[str, str, int], Any], host: str, resolved: str
) -> dict[tuple[str, str, int], Any]:
    """Let a test key its scripted routes by the *asset* while the transport sees the address.

    The network client resolves a name before it dials (resolve-and-pin), so
    the transport is always called with an address. Rewriting the keys here keeps the tests
    readable — ``("tcp", "lab.test", 53)`` — without pretending the client dials names.
    """
    if host == resolved:
        return routes
    return {
        (protocol, resolved if key == host else key, port): value
        for (protocol, key, port), value in routes.items()
    }


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def asset_for(kind: str, value: str, **meta: Any) -> Asset:
    """Build an asset directly (``kind`` in the asset vocabulary)."""
    return Asset.from_meta(kind, value, {"declared": True, **meta})


def settings_for_checks(**overrides: Any) -> Settings:
    """Settings a check-level test can read a :class:`ModuleConfig` from."""
    return Settings(database_url="sqlite:///:memory:", log_level="CRITICAL", **overrides)


__all__ = [
    *__all__,
    "AuditAction",
    "MemoryFindingStore",
    "asset_for",
    "settings_for_checks",
]
