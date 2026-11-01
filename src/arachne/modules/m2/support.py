"""Shared M2 check plumbing: catalogue access, wordlists, preconditions and evidence.

Every M2 check starts with the same few questions — "do I have a network client at all?",
"what has the inventory established so far?", "which hosts does this asset cover?" — and
ends with the same few answers — a ``skipped`` result with a reason, or evidence describing
what was probed. This module holds those, so the checks themselves read as protocol logic.

The rule the helpers exist to enforce: **a check that cannot do its work says so, and costs
nothing.** In dry-run mode there is no client (``ctx.net is None``) and every check reports
itself skipped; a check whose precondition is missing from the inventory (no open port, no
TLS service, no fingerprinted version) reports skipped with the reason, without a packet
leaving the process. That is what keeps ``--dry-run`` honest and what keeps the M2 checks
compositional: each can run alone.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from arachne.core.errors import ConfigurationError
from arachne.core.net import ScopedNetClient
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext
from arachne.modules.m2.catalog import CveIndex, PortCatalog, load_cve_index, load_port_catalog
from arachne.modules.m2.inventory import NetworkInventory, ServiceRecord

__all__ = [
    "MAX_WORDLIST_ENTRIES",
    "NetworkCheck",
    "addresses_for_asset",
    "catalog_ports_for_probe",
    "cve_index_for",
    "inventory_or_skip",
    "load_wordlist",
    "net_or_skip",
    "port_catalog_for",
    "services_of",
    "skip_result",
]

#: Hard cap on how many wordlist entries a check will use, so a project-supplied wordlist
#: cannot turn one check into an unbounded scan.
MAX_WORDLIST_ENTRIES = 200

#: The shipped wordlists (F-09-04: wordlists are managed data).
WORDLIST_RESOURCES: dict[str, tuple[str, ...]] = {
    "smtp-users": ("m2", "wordlists", "smtp-users.txt"),
    "kerberos-users": ("m2", "wordlists", "kerberos-users.txt"),
    "dns-subdomains": ("m2", "wordlists", "dns-subdomains.txt"),
    "common-communities": ("m2", "wordlists", "snmp-communities.txt"),
}


#: The discovery step's endpoint derivation (``core.steps.discovery_step``) marks the URLs it
#: invents with this source, which is how an M2 check tells "the operator declared this
#: endpoint" from "we guessed http://host/ ourselves".
DERIVED_URL_SOURCES: frozenset[str] = frozenset({"host-expansion"})


class NetworkCheck:
    """Base class for M2's checks: one host, one scan, whatever assets describe it.

    A scan of ``ip 127.0.0.1`` also seeds ``https://127.0.0.1/`` and ``http://127.0.0.1/``
    (S2's discovery step derives endpoints for the web modules). Without a rule, every M2
    check would run three times over the same host and raise three copies of every finding —
    and the request estimate in the plan would be wrong by the same factor. A *derived* URL
    asset is therefore skipped: the declared host it was derived from is already being
    scanned. A URL the operator declared outright is kept, because then it *is* the target.
    """

    def supports(self, asset: Asset) -> bool:
        """True when this check should run for ``asset`` (see the class docstring).

        ``super()`` here resolves to :class:`~arachne.modules.base.Module` — every M2 check
        mixes this class in *before* the ABC (``class PortScan(NetworkCheck, Module)``), which
        is what lets the mixin narrow applicability without duplicating the metadata rule.
        """
        if not super().supports(asset):  # type: ignore[misc]
            return False
        if asset.kind != "url":
            return True
        source = str(asset.meta.get("source") or "")
        return source not in DERIVED_URL_SOURCES


@lru_cache(maxsize=8)
def _catalog(path: str | None) -> PortCatalog:
    return load_port_catalog(path)


@lru_cache(maxsize=8)
def _index(path: str | None, baseline: str | None) -> CveIndex:
    return load_cve_index(path, baseline=baseline)


def port_catalog_for(ctx: CheckContext) -> PortCatalog:
    """The port catalogue (cached per path: parsing YAML per check would be wasteful)."""
    return _catalog(ctx.config.port_catalog)


def cve_index_for(ctx: CheckContext) -> CveIndex:
    """The offline CVE/EPSS index: generated baseline + curated overlay (cached per path)."""
    return _index(ctx.config.cve_index, ctx.config.cve_index_baseline)


def net_or_skip(ctx: CheckContext) -> tuple[ScopedNetClient | None, CheckResult | None]:
    """``(client, None)`` when a live client exists, else ``(None, skipped result)``."""
    client = ctx.net
    if client is None:
        return None, skip_result(
            ctx,
            "no network client in this run: M2 probes need a live scan "
            "(a dry run sends nothing — F-01-10)",
        )
    assert isinstance(client, ScopedNetClient)
    return client, None


def inventory_or_skip(ctx: CheckContext) -> tuple[NetworkInventory | None, CheckResult | None]:
    """``(inventory, None)`` when this step built one, else ``(None, skipped result)``."""
    inventory = ctx.inventory
    if inventory is None:
        return None, skip_result(
            ctx,
            "no network inventory for this step: the discovery step builds it (S4/M2)",
        )
    assert isinstance(inventory, NetworkInventory)
    return inventory, None


def skip_result(ctx: CheckContext, reason: str) -> CheckResult:
    """A skipped result carrying a machine-readable reason (never prose matching)."""
    return ctx.skipped(reason)


def services_of(
    inventory: NetworkInventory,
    asset: Asset,
) -> tuple[ServiceRecord, ...]:
    """Every inventory service belonging to ``asset`` (by name, address or network)."""
    addresses = set(addresses_for_asset(asset))
    results: list[ServiceRecord] = []
    for key in inventory.order:
        if key in addresses:
            results.extend(inventory.hosts[key].service_list)
    return tuple(results)


def addresses_for_asset(asset: Asset, *, max_hosts: int = 256) -> tuple[str, ...]:
    """The host keys an asset contributes to the inventory (no network access).

    * an ``ip``/``domain``/``domain_pattern`` asset → itself (the name *is* the key: the net
      client resolves per probe, so the inventory never has to guess which address a name
      meant);
    * a ``network`` asset → its addresses, network/broadcast excluded on IPv4 and capped at
      ``max_hosts``;
    * a ``url`` asset → its hostname;
    * anything else (git, cloud) → nothing: M2 has no probe for a repository reference.
    """
    if asset.kind in {"host", "domain", "domain_pattern"}:
        return (asset.value,)
    if asset.kind == "url":
        host = asset.host
        return (host,) if host else ()
    if asset.kind == "network":
        try:
            network = ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return ()
        hosts: list[str] = []
        for index, address in enumerate(network.hosts() if network.num_addresses > 2 else network):
            if index >= max_hosts:
                break
            hosts.append(str(address))
        return tuple(hosts)
    return ()


def load_wordlist(
    ctx: CheckContext,
    name: str,
    *,
    limit: int = MAX_WORDLIST_ENTRIES,
) -> tuple[str, ...]:
    """Load a wordlist: the operator's directory when configured, else the shipped one."""
    cap = min(limit, MAX_WORDLIST_ENTRIES)
    extra = ctx.config.wordlists_dir
    entries: list[str] = []
    if extra:
        candidate = Path(extra) / f"{name}.txt"
        if candidate.is_file():
            entries.extend(_read_lines(candidate.read_text(encoding="utf-8")))
    if not entries:
        resource = WORDLIST_RESOURCES.get(name)
        if resource is None:
            msg = f"unknown wordlist {name!r}; known wordlists are {sorted(WORDLIST_RESOURCES)}"
            raise ConfigurationError(msg)
        node = files("arachne.templates")
        for part in resource:
            node = node.joinpath(part)
        try:
            entries.extend(_read_lines(node.read_text(encoding="utf-8")))
        except (FileNotFoundError, OSError):  # pragma: no cover - packaging failure
            return ()
    return tuple(dict.fromkeys(entries))[:cap]


def _read_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def tls_capable_services(
    services: Sequence[ServiceRecord],
    catalog: PortCatalog,
) -> tuple[ServiceRecord, ...]:
    """Services a TLS scan should look at: identified as TLS, or on a TLS-ish catalogue port."""
    from arachne.modules.m2.catalog import PortEntry

    tls_ports = {
        entry.port
        for entry in (*catalog.tcp,)
        if isinstance(entry, PortEntry) and entry.probe == "tls"
    }
    identified = {"tls", "https", "ldaps", "smtps", "imaps", "pop3s", "ftps", "docker-tls"}
    results: list[ServiceRecord] = []
    for service in services:
        if service.effective_service.lower() in identified:
            results.append(service)
            continue
        if service.port in tls_ports:
            results.append(service)
            continue
        extra = service.identity.extra if service.identity else {}
        if extra.get("tls_available") or service.tls is not None:
            results.append(service)
    return tuple(results)


def catalog_ports_for_probe(
    ctx: CheckContext, probe: str, *, protocol: str = "tcp", limit: int = 4
) -> tuple[int, ...]:
    """The ports the port catalogue associates with a probe family.

    A protocol check needs to know *where* to look before the inventory has anything to say
    (SNMP's datagrams are never discovered by a connect scan), and the catalogue is exactly
    the managed declaration for that. Inventory-derived ports take precedence at the call
    site; this is the fallback, and it is bounded so a hand-written catalogue cannot turn one
    check into a sweep.
    """
    catalog = port_catalog_for(ctx)
    ports = catalog.ports_for_probe(probe, protocol=protocol)
    return tuple(ports[:limit])


def common_ports_of(asset: Asset, catalog: PortCatalog, *, limit: int) -> tuple[int, ...]:
    """The top-N TCP ports for an asset (the "top-ports policy" of research ch02#7)."""
    del asset
    return catalog.top_tcp(limit)


def target_kinds_for_network_probes() -> tuple[TargetKind, ...]:
    """The target kinds every host/port/service check applies to."""
    return (
        TargetKind.IP,
        TargetKind.CIDR,
        TargetKind.DOMAIN,
        TargetKind.DOMAIN_PATTERN,
    )
