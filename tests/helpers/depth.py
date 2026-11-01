"""Harness for the S29 depth-expansion checks: a crawl *and* a live network client.

The depth family straddles two transports. The GraphQL and client-side checks speak HTTP and
need the shared crawl (``ctx.web``); the WebSocket frame probe and the OT protocol checks speak
raw TCP and need the scoped network client (``ctx.net``); the mobile-artifact check reads a
local file and needs neither. A harness that provided only one of the two would force those
checks to be tested through a stand-in context, and a stand-in context is precisely where a
safety gate can go missing.

So this harness wires the *real* collaborators the checks step provides — the scoped HTTP
client over loopback, the scoped network client over loopback, a real crawl and a real step
store — and nothing else. Everything a check is allowed to do it does through them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import (
    NetSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
    WebSettings,
)
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import StepContext
from arachne.core.net import ScopedNetClient, SocketTransport
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3.inventory import WebInventory
from arachne.modules.m3.support import crawl
from tests.helpers.checks import MemoryContext, asset_for, make_step_context

__all__ = ["DepthHarness", "make_depth_harness"]


@dataclass
class DepthHarness:
    """A live loopback HTTP client, a live loopback network client and a shared crawl."""

    http_client: ScopedHttpClient
    net_client: ScopedNetClient
    config: ModuleConfig
    step: StepContext
    memory: MemoryContext
    settings: Settings
    asset: Asset
    inventory: WebInventory | None = None

    async def prepare(self, roots: list[str]) -> WebInventory:
        """Crawl ``roots`` and hand the inventory to every check through ``ctx.web``."""
        ctx = self.context(None)
        self.inventory = await crawl(ctx, roots)
        self.step.web = self.inventory
        return self.inventory

    def context(self, module: Any, *, asset: Asset | None = None) -> CheckContext:
        return CheckContext(
            step=self.step,
            module=module or _stand_in(),
            asset=asset or self.asset,
            config=self.config,
        )

    async def aclose(self) -> None:
        await self.http_client.aclose()


def _stand_in() -> Any:
    from arachne.core.target import TargetKind
    from arachne.modules.base import CheckMetadata, Module

    class _StandIn(Module):
        metadata = CheckMetadata(
            id="m3.stand-in",
            module="M3",
            name="stand-in",
            version="1.0",
            title="Stand-in check",
            description="A check that only exists so the harness can build a crawl context.",
            research_ref="ch03#1",
            target_kinds=(TargetKind.URL,),
        )

        async def run(self, ctx: CheckContext) -> Any:  # pragma: no cover - never called
            yield ctx.info("stand-in")

    return _StandIn()


def make_depth_harness(
    *,
    asset: Asset | None = None,
    web: WebSettings | None = None,
    net: NetSettings | None = None,
    extra_hosts: tuple[str, ...] = (),
    seed_services: tuple[tuple[int, str], ...] = (),
) -> DepthHarness:
    """Build a harness over loopback with the real HTTP and network clients.

    The network client uses the real :class:`~arachne.core.net.SocketTransport` — this harness
    exists precisely to exercise byte-level protocols against the lab — while the scope still
    allows nothing but the loopback hosts named here, so a check that tried to reach anywhere
    else would be refused and audited.

    ``seed_services`` fills the network inventory the way the discovery step would (the host is
    alive and these ports are open), which the M2 protocol checks read through ``ctx.inventory``.
    """
    host = "127.0.0.1"
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=(host, *extra_hosts)),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=100_000.0,
            per_host_burst=100_000,
            global_rate=100_000.0,
            global_burst=100_000,
        ),
        web=web or WebSettings(),
        net=net or NetSettings(),
    )
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    http_client = ScopedHttpClient(
        settings=settings,
        scope=settings.safety.scope,
        policy=settings.safety.policy,
        auditor=auditor,
    )
    net_client = ScopedNetClient(
        settings=settings,
        scope=Scope(allowed_hosts=(host, *extra_hosts)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        auditor=auditor,
        transport=SocketTransport(),
    )
    chosen = asset or asset_for("url", "http://127.0.0.1:1/")
    step, memory = make_step_context(
        http=http_client, seed=[(chosen.kind, chosen.value)], scope=settings.safety.scope
    )
    step.net = net_client
    step.step = ScanStep.CHECKS
    if seed_services:
        from arachne.modules.m2.inventory import NetworkInventory

        inventory = NetworkInventory(max_hosts=8, max_ports=64)
        record = inventory.host(host, declared=True)
        record.alive = True
        for port, service in seed_services:
            inventory.add_service(host, port, service=service)
        step.inventory = inventory
    return DepthHarness(
        http_client=http_client,
        net_client=net_client,
        config=ModuleConfig.from_settings(settings),
        step=step,
        memory=memory,
        settings=settings,
        asset=chosen,
    )
