"""Harness for M3 check-level tests: a live lab, a real client, a shared crawl.

An M3 check is an oracle over the crawl, so its test needs the state a scan is in when the
check runs: a scoped client that can reach the lab, the single crawl the checks step builds
(:class:`~arachne.modules.m3.inventory.WebInventory`), and the audit/store machinery. This
module assembles exactly that, so an individual check's test reads as a statement about the
check rather than about wiring.

The transport is real (loopback sockets into ``tests/lab/web_lab.py``), not a mock: an oracle's
whole job is to read a differential out of real HTTP, and a mock would answer with whatever the
test author believed the server does. Rate limits are raised because one check makes tens of
probes; the production limits have their own suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import StepContext
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3.inventory import WebInventory, build_web_inventory
from arachne.modules.m3.support import crawl
from tests.helpers.checks import MemoryContext, asset_for, make_step_context

__all__ = ["WebHarness", "make_web_harness"]


@dataclass
class WebHarness:
    """One origin's crawl, a live client and the audit trail, ready for a check to run."""

    asset: Asset
    client: ScopedHttpClient
    config: ModuleConfig
    step: StepContext
    memory: MemoryContext
    inventory: WebInventory = field(default_factory=WebInventory)
    settings: Settings | None = None

    async def prepare(self, *, roots: list[str] | None = None) -> WebInventory:
        """Run the shared crawl (once) and store it for the checks under test."""
        ctx = self.context()
        self.inventory = await crawl(ctx, roots or [self.asset.value])
        self.step.web = self.inventory
        return self.inventory

    def context(self, module: Any = None) -> CheckContext:
        """A check context over the harness' step (``module`` defaults to a stand-in)."""
        from arachne.modules.base import Module

        class _StandIn(Module):
            metadata = _stand_in_metadata()

            async def run(self, ctx: CheckContext) -> Any:  # pragma: no cover - never called
                yield ctx.info("stand-in")

        return CheckContext(
            step=self.step,
            module=module or _StandIn(),
            asset=self.asset,
            config=self.config,
        )


def _stand_in_metadata() -> Any:
    from arachne.core.target import TargetKind
    from arachne.modules.base import CheckMetadata

    return CheckMetadata(
        id="m3.stand-in",
        module="M3",
        name="stand-in",
        version="1.0",
        title="Stand-in check",
        description="A check that only exists so the harness can build a crawl context.",
        research_ref="ch03#1",
        target_kinds=(TargetKind.URL,),
    )


def make_web_harness(
    lab: Any,
    *,
    upload_probe: bool = False,
    max_pages: int = 20,
    max_depth: int = 2,
    host: str | None = None,
) -> WebHarness:
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
        web=WebSettings(upload_probe=upload_probe, max_pages=max_pages, max_depth=max_depth),
    )
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    client = ScopedHttpClient(
        settings=settings,
        scope=settings.safety.scope,
        policy=settings.safety.policy,
        auditor=auditor,
    )
    # The *definition* scope for the harness is the lab host, not the shared unit-test fixture:
    # a check's ``record_asset`` goes through the step's scope, so a mismatch here would make
    # every discovery look out-of-scope and silently discard it (F-01-02).
    step, memory = make_step_context(
        http=client, seed=[("url", lab.base_url)], scope=settings.safety.scope
    )
    step.step = _checks_step()
    return WebHarness(
        asset=asset_for("url", lab.base_url),
        client=client,
        config=ModuleConfig.from_settings(settings),
        step=step,
        memory=memory,
        settings=settings,
    )


def _checks_step() -> Any:
    from arachne.core.planner import ScanStep

    return ScanStep.CHECKS


async def close_harness(harness: WebHarness) -> None:
    await harness.client.aclose()


def build_inventory(roots: list[str], fetch: Any, **kwargs: Any) -> Any:
    """Re-export of the crawl builder (kept here so a test imports one module)."""
    return build_web_inventory(roots, fetch, **kwargs)
