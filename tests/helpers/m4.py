"""Harness for M4 check-level tests: a live lab, a real client, the shared crawl.

M4's checks read the same per-step crawl M3's do (``ctx.web``) and issue their own bounded
probes through the shared scoped client, so the harness is the M3 one plus the two things
M4 needs on top: the M4 configuration (bounds and the two opt-in switches) and the ability
to seed a declared *cloud* asset, which is what ``m4.bucket-exposure`` probes.

The transport is real (loopback sockets into ``tests/lab/web_lab.py``). A mock would answer
with whatever the test author believed the lab serves, which is exactly the assumption a
path-probe check must not make.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import M4Settings, RateLimitSettings, SafetySettings, Settings
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import StepContext
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3.inventory import WebInventory
from arachne.modules.m3.support import crawl
from tests.helpers.checks import MemoryContext, asset_for, make_step_context

__all__ = ["M4Harness", "make_m4_harness"]


@dataclass
class M4Harness:
    """One origin's crawl, a live client and the audit trail, ready for an M4 check."""

    asset: Asset
    client: ScopedHttpClient
    config: ModuleConfig
    step: StepContext
    memory: MemoryContext
    settings: Settings
    inventory: WebInventory = field(default_factory=WebInventory)

    async def prepare(self, *, roots: list[str] | None = None) -> WebInventory:
        """Run the shared crawl (once) and store it for the check under test."""
        ctx = self.context()
        self.inventory = await crawl(ctx, roots or [self.asset.value])
        self.step.web = self.inventory
        return self.inventory

    def context(self, module: Any = None, *, asset: Asset | None = None) -> CheckContext:
        return CheckContext(
            step=self.step,
            module=module or _stand_in(),
            asset=asset or self.asset,
            config=self.config,
        )

    async def aclose(self) -> None:
        await self.client.aclose()


def _stand_in() -> Any:
    """A check instance that exists only so the harness can build a context."""
    from arachne.core.target import TargetKind
    from arachne.modules.base import CheckMetadata, Module

    class _StandIn(Module):
        metadata = CheckMetadata(
            id="m4.stand-in",
            module="M4",
            name="stand-in",
            version="1.0",
            title="Stand-in check",
            description="A check that only exists so the harness can build a crawl context.",
            research_ref="ch04#1",
            target_kinds=(TargetKind.URL,),
        )

        async def run(self, ctx: CheckContext) -> Any:  # pragma: no cover - never called
            yield ctx.info("stand-in")

    return _StandIn()


def make_m4_harness(
    lab: Any,
    *,
    m4: M4Settings | None = None,
    seed: tuple[tuple[str, str], ...] = (),
    host: str | None = None,
) -> M4Harness:
    """Build a harness against a running :class:`~tests.lab.web_lab.WebLab`."""
    host = host or f"127.0.0.1:{lab.port}"
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=(host, "127.0.0.1")),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        m4=m4 or M4Settings(),
    )
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    client = ScopedHttpClient(
        settings=settings,
        scope=settings.safety.scope,
        policy=settings.safety.policy,
        auditor=auditor,
    )
    seeded = [("url", lab.base_url), *seed]
    step, memory = make_step_context(http=client, seed=seeded, scope=settings.safety.scope)
    step.step = ScanStep.CHECKS
    return M4Harness(
        asset=asset_for("url", lab.base_url),
        client=client,
        config=ModuleConfig.from_settings(settings),
        step=step,
        memory=memory,
        settings=settings,
    )
