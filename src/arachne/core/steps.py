"""Built-in pipeline step handlers that need no detection module (S2).

S3+ supplies module-backed handlers for the ``checks`` step and later for analysis,
correlation and reporting. Until then the scanner still has to be a *scanner*: these two
handlers turn the declared target definition into the scan's asset inventory — the input
every future check consumes — using nothing but local computation. No socket is opened.

* ``recon`` seeds one asset per declared target and announces each host it can name
  (``host_discovered`` with ``source="target-definition"``, so a consumer can tell a
  declared host from a discovered one).
* ``discovery`` derives web endpoint candidates (``scheme://host/``) from the seeded
  hosts so that the web modules of S6/S7 have endpoints to attach to.

Everything is routed through :meth:`StepContext.record_asset`, so the scope guard and the
"discovery outside scope is discarded and logged" rule (F-01-02) apply here exactly as
they will to a module's discoveries.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from arachne.core.events import Event
from arachne.core.lifecycle import StepContext, StepHandler, StepOutcome
from arachne.core.planner import ScanStep
from arachne.core.target import TargetKind, TargetSelector

__all__ = [
    "default_handlers",
    "discovery_step",
    "recon_step",
    "seed_asset",
]

#: Upper bound on the host count recorded for a network asset (report readability, and
#: it keeps an IPv6 range from producing a 39-digit number in the plan).
MAX_NETWORK_HOSTS = 65536


def seed_asset(selector: TargetSelector) -> tuple[str, str, dict[str, Any]]:
    """Map a target selector onto the asset row it seeds (``assets.kind`` vocabulary)."""
    meta: dict[str, Any] = {"declared": True}
    if selector.kind is TargetKind.DOMAIN:
        return "domain", selector.value, meta
    if selector.kind is TargetKind.DOMAIN_PATTERN:
        meta["glob"] = selector.value.startswith("*.")
        return "domain_pattern", selector.value, meta
    if selector.kind is TargetKind.URL:
        return "url", selector.value, meta
    if selector.kind is TargetKind.IP:
        meta["address"] = True
        return "host", selector.value, meta
    if selector.kind is TargetKind.CIDR:
        network = ipaddress.ip_network(selector.value, strict=False)
        meta.update(
            {
                "prefixlen": network.prefixlen,
                "hosts": min(network.num_addresses, MAX_NETWORK_HOSTS),
            }
        )
        return "network", selector.value, meta
    if selector.kind is TargetKind.GIT:
        meta["host"] = selector.host
        return "git", selector.value, meta
    if selector.kind is TargetKind.ARTIFACT:
        # An offline artifact (S29, REQ-DEPTH-005): the value *is* the local path, and the
        # scope gate decides whether any check may read it.
        meta["path"] = selector.value
        return "artifact", selector.value, meta
    return "cloud", selector.value, meta


async def recon_step(ctx: StepContext) -> StepOutcome:
    """Seed the asset inventory from the declared targets (offline, F-01-02)."""
    seeded = 0
    hosts: list[str] = []
    for selector in ctx.definition.targets:
        kind, value, meta = seed_asset(selector)
        asset = await ctx.record_asset(kind, value, meta=meta, source="target-definition")
        if asset is None:  # discarded as out of scope; already logged
            continue
        seeded += 1
        host = selector.host
        if host:
            hosts.append(host)
            await ctx.emit(
                Event.host_discovered(
                    scan_id=ctx.scan_id,
                    host=host,
                    kind=kind,
                    source="target-definition",
                    addresses=(value,) if kind == "host" else (),
                )
            )
    return StepOutcome(
        stats={
            "selectors": len(ctx.definition.targets),
            "seeded_assets": seeded,
            "hosts_named": len(set(hosts)),
        }
    )


async def discovery_step(ctx: StepContext) -> StepOutcome:
    """Derive web endpoint candidates from the seeded hosts (offline).

    A host discovered only as an address gets both schemes (a service probe decides the
    real one in M2/S4); a host that came from a URL keeps that URL's scheme, so the
    inventory is not padded with endpoints the operator never declared.
    """
    existing = ctx.store.list_assets(ctx.scan_id)
    known_urls = {asset.value for asset in existing if asset.kind == "url"}
    candidates: dict[str, tuple[str, str]] = {}  # url -> (host, source)

    for asset in existing:
        if asset.kind == "url":
            host = _host_of(asset.value)
            if host:
                candidates.setdefault(asset.value, (host, "declared-url"))
        elif asset.kind in {"host", "ip", "domain", "domain_pattern"}:
            for scheme in ("https", "http"):
                candidates.setdefault(f"{scheme}://{asset.value}/", (asset.value, "host-expansion"))

    recorded = 0
    discarded = 0
    for url, (host, source) in candidates.items():
        if url in known_urls:
            continue
        derived = await ctx.record_asset("url", url, meta={"host": host}, source=source)
        if derived is None:
            discarded += 1
        else:
            recorded += 1
    return StepOutcome(
        stats={
            "endpoint_candidates": len(candidates),
            "recorded": recorded,
            "discarded": discarded,
        }
    )


def _host_of(url: str) -> str | None:
    return urlsplit(url).hostname or None


#: Handlers this build can execute. Steps without a handler are recorded as ``skipped`` by
#: the machine, which is why a plan says "no step handler is registered in this build".
_HANDLERS: Mapping[ScanStep, StepHandler] = {
    ScanStep.RECON: recon_step,
    ScanStep.DISCOVERY: discovery_step,
}


def default_handlers() -> dict[ScanStep, StepHandler]:
    """The built-in handler set, as a fresh mapping the caller may extend or replace."""
    return dict(_HANDLERS)
