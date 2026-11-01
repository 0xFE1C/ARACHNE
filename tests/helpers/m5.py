"""Harness for M5 check-level tests: a live loopback client, a shared crawl, local artifacts.

M5 checks come in two shapes. Endpoint checks need a real HTTP client scoped to the cloud lab;
artifact checks read a local directory and need no client at all. This harness provides both:
a :class:`~arachne.core.http.ScopedHttpClient` over loopback (rate limits raised, because a
check makes tens of probes) and a step context the caller seeds with whatever assets the check
under test consumes (a ``cloud`` endpoint, a ``bucket`` or a ``repo:`` reference).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import (
    M5Settings,
    M6Settings,
    RateLimitSettings,
    SafetySettings,
    Settings,
    WebSettings,
)
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import StepContext
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3.inventory import WebInventory
from arachne.modules.m3.support import crawl
from tests.helpers.checks import MemoryContext, asset_for, make_step_context

__all__ = ["M5Harness", "make_m5_harness"]


@dataclass
class M5Harness:
    """A live loopback client and a step context seeded with the assets under test."""

    client: ScopedHttpClient
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
        await self.client.aclose()


def _stand_in() -> Any:
    from arachne.core.target import TargetKind
    from arachne.modules.base import CheckMetadata, Module

    class _StandIn(Module):
        metadata = CheckMetadata(
            id="m5.stand-in",
            module="M5",
            name="stand-in",
            version="1.0",
            title="Stand-in check",
            description="A check that only exists so the harness can build a crawl context.",
            research_ref="ch05#1",
            target_kinds=(TargetKind.CLOUD,),
        )

        async def run(self, ctx: CheckContext) -> Any:  # pragma: no cover - never called
            yield ctx.info("stand-in")

    return _StandIn()


def make_m5_harness(
    *,
    asset: Asset | None = None,
    m5: M5Settings | None = None,
    m6: M6Settings | None = None,
    web: WebSettings | None = None,
    allowed_hosts: tuple[str, ...] = ("127.0.0.1",),
) -> M5Harness:
    """Build a harness with a loopback-scoped client and one seeded asset (default: loopback)."""
    host = "127.0.0.1"
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=(host, *allowed_hosts)),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=100_000.0,
            per_host_burst=100_000,
            global_rate=100_000.0,
            global_burst=100_000,
        ),
        m5=m5 or M5Settings(),
        m6=m6 or M6Settings(),
        web=web or WebSettings(),
    )
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    client = ScopedHttpClient(
        settings=settings,
        scope=settings.safety.scope,
        policy=settings.safety.policy,
        auditor=auditor,
    )
    chosen = asset or asset_for("cloud", "endpoint:http://127.0.0.1:1/")
    step, memory = make_step_context(
        http=client, seed=[(chosen.kind, chosen.value)], scope=settings.safety.scope
    )
    step.step = ScanStep.CHECKS
    return M5Harness(
        client=client,
        config=ModuleConfig.from_settings(settings),
        step=step,
        memory=memory,
        settings=settings,
        asset=chosen,
    )
