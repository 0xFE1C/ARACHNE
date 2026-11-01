"""M2 discovery checks: liveness, open ports, OS hints, service identity (ch02#1-11).

These four checks are the front of M2's pipeline and the only ones that talk about *hosts*
rather than services. Read together with :mod:`arachne.modules.m2.support`, they implement
research methods 1-11 of chapter 2 in the order the table lists them:

===========================  ==========  =========================================
check                        ref         what it establishes
===========================  ==========  =========================================
``m2.host-discovery``        ch02#1-4     which addresses answer ICMP or TCP at all
``m2.port-scan``             ch02#4-7     which ports are open, over a top-ports policy
``m2.os-fingerprint``        ch02#8       a best-effort OS family from TTL and banners
``m2.service-fingerprint``   ch02#9-10    the product and version behind each open port
===========================  ==========  =========================================

Every one of them is **active** by construction — they are the acts of contact that
F-01-09 gates behind an explicit opt-in and an authorizing attestation — and every probe
goes through :class:`~arachne.core.net.ScopedNetClient`, so the per-host rate limit and the
audit trail apply to a fifty-port sweep exactly as they do to a single banner read.

The coverage-matrix note from M1 applies here too: the ``research_ref`` values are the
canonical method numbers in ``docs/research/02-active-scanning-and-enumeration.md``
(whose numbering drifted from the earlier table), recorded in ADR-080.3.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping

from arachne.core.errors import NetProbeError
from arachne.core.net import IcmpExchange
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.fingerprint import identify, product_from_banner
from arachne.modules.m2.inventory import (
    HostRecord,
    NetworkInventory,
    ServiceIdentity,
    ServiceRecord,
)
from arachne.modules.m2.scanners import PortFinding, ScanBackend, pick_backend
from arachne.modules.m2.support import (
    NetworkCheck,
    addresses_for_asset,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = [
    "HostDiscovery",
    "OsFingerprint",
    "PortScan",
    "ServiceFingerprint",
    "os_family_from_banner",
    "os_family_from_ttl",
]

#: The ports a liveness sweep probes (research ch02#1: TCP probes rescue hosts that drop
#: ICMP). Deliberately tiny — liveness is a yes/no question, and the real port scan follows.
LIVENESS_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389, 8080, 8443)

#: OS families by initial TTL bucket (research ch02#8; a heuristic, never a claim).
DEFAULT_TTL: Mapping[str, tuple[int, str]] = {
    "linux": (64, "Linux/Unix (default TTL 64)"),
    "windows": (128, "Windows (default TTL 128)"),
    "network-device": (255, "network device/BSD (default TTL 255)"),
    "embedded": (32, "embedded/legacy (default TTL 32)"),
}

_BANNER_OS_HINTS: tuple[tuple[str, str], ...] = (
    ("debian", "linux"),
    ("ubuntu", "linux"),
    ("centos", "linux"),
    ("red hat", "linux"),
    ("amazon linux", "linux"),
    ("fedora", "linux"),
    ("suse", "linux"),
    ("linux", "linux"),
    ("freebsd", "bsd"),
    ("openbsd", "bsd"),
    ("netbsd", "bsd"),
    ("windows", "windows"),
    ("microsoft", "windows"),
    ("iis", "windows"),
    ("cisco", "network-device"),
    ("juniper", "network-device"),
    ("mikrotik", "network-device"),
    ("routeros", "network-device"),
    ("synology", "embedded"),
    ("multicast", "embedded"),
    ("embedded", "embedded"),
)


def os_family_from_ttl(ttl: int | None, *, hops: int = 0) -> tuple[str | None, str]:
    """``(family, explanation)`` from an observed TTL (best-effort, research ch02#8).

    A TTL only bounds the *initial* TTL, so the smallest default at or above the observed
    value is chosen — a host seen with TTL 57 behind 7 hops is a 64 host, not a 32 one.
    """
    if ttl is None:
        return None, "no TTL observed (ICMP unavailable or filtered)"
    observed = ttl + hops
    for family, (default, description) in sorted(DEFAULT_TTL.items(), key=lambda item: item[1][0]):
        if observed <= default:
            return family, f"observed TTL {ttl} → {description}"
    return "network-device", f"observed TTL {ttl} is above every known default"


def os_family_from_banner(*banners: str) -> tuple[str | None, str]:
    """``(family, explanation)`` from service banners (the passive half of ch02#8)."""
    for banner in banners:
        lowered = (banner or "").lower()
        for needle, family in _BANNER_OS_HINTS:
            if needle in lowered:
                return family, f"service banner names {needle!r}"
    return None, "no OS hint in any service banner"


class HostDiscovery(NetworkCheck, Module):
    """``m2.host-discovery`` — which addresses are alive (research ch02#1-4)."""

    metadata = CheckMetadata(
        id="m2.host-discovery",
        module="M2",
        name="host-discovery",
        version="1.0",
        title="Host discovery",
        description=(
            "Determines which addresses in the declared ranges are alive, combining an ICMP "
            "echo probe with a TCP connect sweep over a few common ports (a host that drops "
            "ICMP still answers TCP), and records every live host in the asset inventory."
        ),
        research_ref="ch02#1-4",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="info",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        requires_active_checks=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        addresses = addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts)
        if not addresses:
            yield ctx.skipped(f"asset {ctx.asset.key} contributes no address to probe")
            return

        liveness_ports = list(LIVENESS_PORTS)
        declared_port = _port_of_asset(ctx.asset.value)
        if declared_port is not None and declared_port not in liveness_ports:
            liveness_ports.append(declared_port)

        live: list[str] = []
        icmp_notes: dict[str, str] = {}
        truncated = False
        for address in addresses:
            if not inventory.can_add_host():
                truncated = bool(inventory.host(address).declared) or True
                inventory.truncated_hosts = True
                break
            record = inventory.host(address, declared=ctx.asset.declared)
            record.probes += 1
            try:
                echo = await client.icmp(address)
            except NetProbeError as exc:
                # A name that does not resolve is data about that asset, not a failed check:
                # the other addresses (and the other checks) carry on.
                icmp_notes[address] = str(exc)
                continue
            _apply_icmp(record, echo)
            if echo.unavailable:
                icmp_notes[address] = echo.error or "ICMP unavailable"
            outcomes = await client.probe_ports(address, liveness_ports)
            for outcome in outcomes:
                if not outcome.open:
                    continue
                live.append(address)
                inventory.mark_alive(address, method=f"tcp:{outcome.port}")
                service = inventory.add_service(
                    address,
                    outcome.port,
                    discovered_by="liveness",
                )
                if not service.banner and outcome.banner:
                    service.identity = _identity_from_banner(outcome.banner)
            if echo.replied:
                live.append(address)
                inventory.mark_alive(address, method="icmp", ttl=echo.ttl)

        discovered = sorted(set(live))
        recorded = 0
        # A host discovered inside a range or under a name becomes an asset in its own right
        # (F-01-02 applies: an address outside the scope is discarded and audited).
        if ctx.asset.kind in {"network", "domain", "domain_pattern"}:
            for address in discovered:
                if await ctx.record_host(address, source="host-discovery"):
                    recorded += 1

        evidence = [
            ctx.evidence(
                "note",
                {
                    "asset": ctx.asset.key,
                    "probed": len(addresses),
                    "live": discovered,
                    "liveness_ports": liveness_ports,
                    "icmp": {
                        address: {
                            "state": (record.ttl is not None and "reply") or "no-reply",
                            "ttl": record.ttl,
                            "note": icmp_notes.get(address),
                        }
                        for address, record in (
                            (address, inventory.host(address)) for address in addresses[:64]
                        )
                    },
                },
                source=ctx.asset.key,
            )
        ]
        if not discovered:
            yield ctx.clean(
                f"no live host among {len(addresses)} probed address(es) for {ctx.asset.value}",
                detail=(
                    "Neither ICMP nor a TCP connect to "
                    f"{', '.join(str(port) for port in liveness_ports)} answered. Hosts that "
                    "drop ICMP *and* filter these ports are indistinguishable from dead space "
                    "with this method (research ch02#1)."
                ),
                evidence=evidence,
                confidence=0.6,
            )
        else:
            yield ctx.info(
                f"{len(discovered)} live host(s) found for {ctx.asset.value}",
                detail=(
                    f"probed {len(addresses)} address(es); {recorded} host asset(s) recorded"
                    + ("; address cap reached" if truncated else "")
                    + (
                        f"; ICMP unavailable for {len(icmp_notes)} address(es)"
                        if icmp_notes
                        else ""
                    )
                ),
                evidence=evidence,
                confidence=0.9,
            )


class PortScan(NetworkCheck, Module):
    """``m2.port-scan`` — open TCP ports over a top-ports policy (research ch02#4-7)."""

    metadata = CheckMetadata(
        id="m2.port-scan",
        module="M2",
        name="port-scan",
        version="1.0",
        title="TCP port scan",
        description=(
            "Probes the top-ports policy (ARACHNE_NET_MAX_PORTS, default 100) on every live "
            "host with a TCP connect scan, using python-nmap when it is installed and "
            "permitted and the pure-Python connect scanner otherwise."
        ),
        research_ref="ch02#4-7",
        target_kinds=(*target_kinds_for_network_probes(), TargetKind.URL),
        severity_hint="info",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        ports = catalog.top_tcp(ctx.config.max_ports)
        if not ports:
            yield ctx.skipped("the port catalogue is empty; nothing to scan")
            return

        targets = _scan_targets(ctx, inventory)
        if not targets:
            yield ctx.skipped(f"no probed host is associated with asset {ctx.asset.key}")
            return

        hints = {entry.port: entry.service for entry in catalog.tcp}
        backend: ScanBackend = pick_backend(
            client, settings=client.settings, hints=hints, prefer_nmap=ctx.config.nmap_enabled
        )
        results: dict[str, list[int]] = {}
        banners: dict[str, dict[int, str]] = {}
        for host in targets:
            findings = await backend.probe_ports(host, ports)
            open_ports: list[int] = []
            for finding in findings:
                if not finding.open:
                    continue
                open_ports.append(finding.port)
                service = inventory.add_service(
                    host,
                    finding.port,
                    protocol=finding.protocol,
                    service=finding.service_hint,
                    discovered_by=finding.source,
                )
                if finding.banner and not service.banner:
                    service.identity = _identity_from_finding(finding)
                if finding.banner:
                    banners.setdefault(host, {})[finding.port] = finding.banner
            results[host] = sorted(open_ports)
            if ctx.config.net_allow_udp and backend.name == "nmap":
                udp = await backend.probe_ports(
                    host, [entry.port for entry in catalog.udp], protocol="udp"
                )
                for finding in udp:
                    if finding.open:
                        inventory.add_service(
                            host,
                            finding.port,
                            protocol="udp",
                            service=finding.service_hint,
                            discovered_by=finding.source,
                        )

        total_open = sum(len(value) for value in results.values())
        evidence = [
            ctx.evidence(
                "note",
                {
                    "backend": backend.name,
                    "port_policy": f"top {len(ports)} TCP",
                    "hosts": results,
                    "banners": banners,
                    "udp": (
                        [entry.port for entry in catalog.udp]
                        if ctx.config.net_allow_udp and backend.name == "nmap"
                        else "not probed (UDP is opt-in: F-01-09)"
                    ),
                },
                source=ctx.asset.key,
            )
        ]
        if total_open == 0:
            yield ctx.clean(
                f"no open TCP port in the top-{len(ports)} policy on {len(targets)} host(s)",
                detail=(
                    "A filtered host answers nothing; a closed port answers with a reset. "
                    "Neither is a finding, and a non-standard port outside the policy would "
                    "be missed by design (research ch02#7)."
                ),
                evidence=evidence,
                confidence=0.7,
            )
            return
        yield ctx.info(
            f"{total_open} open TCP port(s) across {len(targets)} host(s)",
            detail=(
                f"backend: {backend.name}; policy: top {len(ports)} TCP ports; "
                + "; ".join(
                    f"{host}: {len(value)} open" for host, value in list(results.items())[:8]
                )
            ),
            evidence=evidence,
            confidence=0.95,
        )


class OsFingerprint(NetworkCheck, Module):
    """``m2.os-fingerprint`` — best-effort OS family from TTL and banners (research ch02#8)."""

    metadata = CheckMetadata(
        id="m2.os-fingerprint",
        module="M2",
        name="os-fingerprint",
        version="1.0",
        title="OS fingerprinting",
        description=(
            "Infers an operating-system family for each live host from the ICMP reply TTL "
            "and from service banners, each with the observation that produced it. "
            "Best-effort by design: no probe battery and no raw-socket spoofing."
        ),
        research_ref="ch02#8",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="info",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=1,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        hosts = _hosts_of(ctx, inventory)
        if not hosts:
            yield ctx.skipped(f"asset {ctx.asset.key} has no probed host in the inventory")
            return

        guesses: dict[str, dict[str, object]] = {}
        for record in hosts:
            if record.ttl is None:
                try:
                    echo = await client.icmp(record.address)
                except NetProbeError:
                    echo = None
                if echo is not None:
                    _apply_icmp(record, echo)
            ttl_family, ttl_reason = os_family_from_ttl(record.ttl)
            banner_family, banner_reason = os_family_from_banner(
                *(service.banner for service in record.service_list)
            )
            family = banner_family or ttl_family
            reason = f"{banner_reason}; {ttl_reason}" if banner_family else ttl_reason
            record.os_family = family
            for service in record.service_list:
                service.os_family = family
            guesses[record.address] = {
                "family": family,
                "reason": reason,
                "ttl": record.ttl,
                "confidence": 0.6 if banner_family else (0.4 if ttl_family else 0.0),
            }

        evidence: list[Evidence] = [ctx.evidence("note", {"hosts": guesses}, source=ctx.asset.key)]
        identified = {key: value for key, value in guesses.items() if value["family"]}
        if not identified:
            yield ctx.clean(
                f"no OS hint for {len(hosts)} host(s)",
                detail=(
                    "No TTL was observed (ICMP silent or unavailable) and no banner named a "
                    "platform. A service-silent, ICMP-filtered host is exactly the case this "
                    "method cannot resolve (research ch02#8)."
                ),
                evidence=evidence,
                confidence=0.3,
            )
            return
        yield ctx.info(
            f"OS family inferred for {len(identified)}/{len(hosts)} host(s)",
            detail="; ".join(
                f"{address}: {value['family']} ({value['reason']})"
                for address, value in list(identified.items())[:8]
            ),
            evidence=evidence,
            confidence=0.6,
        )


class ServiceFingerprint(NetworkCheck, Module):
    """``m2.service-fingerprint`` — product and version per open port (ch02#9-10)."""

    metadata = CheckMetadata(
        id="m2.service-fingerprint",
        module="M2",
        name="service-fingerprint",
        version="1.0",
        title="Service version detection",
        description=(
            "Identifies the protocol, product and version behind every open port, using the "
            "banner the port already sent and a bounded probe suite (HTTP, TLS, Redis, "
            "memcached, MongoDB, SMTP, ...) when it did not. The result is what the CVE "
            "correlation consumes."
        ),
        research_ref="ch02#9-10",
        target_kinds=(*target_kinds_for_network_probes(), TargetKind.URL),
        severity_hint="info",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        services = [item for item in services_of(inventory, ctx.asset) if item.protocol == "tcp"]
        if not services:
            yield ctx.skipped(
                f"no open port recorded for asset {ctx.asset.key}: nothing to fingerprint "
                "(m2.port-scan establishes them first)"
            )
            return

        pending = [item for item in services if _needs_identification(item)]
        server_name = None if _is_address(ctx.asset.value) else ctx.asset.value
        identified: list[dict[str, object]] = []
        unidentified: list[str] = []
        banners: list[Evidence] = []
        for service in pending:
            hint = catalog.hint_service(service.port) or service.service
            result = await identify(
                client,
                host=service.host,
                port=service.port,
                probe_hint=hint,
                banner=service.banner,
                server_name=server_name,
            )
            service.probes += len(result.probes)
            if result.identity is not None:
                service.identity = result.identity
                identified.append(
                    {
                        **result.identity.to_dict(),
                        "host": service.host,
                        "port": service.port,
                        "probes": result.probes,
                    }
                )
                if result.identity.banner:
                    banners.append(
                        ctx.evidence(
                            "banner",
                            {
                                "host": service.host,
                                "port": service.port,
                                "protocol": result.identity.protocol,
                                "product": result.identity.product,
                                "version": result.identity.version,
                                "banner": result.identity.banner,
                            },
                            source=service.key,
                        )
                    )
            else:
                unidentified.append(service.key)

        versioned = [item for item in services if item.identity and item.identity.versioned]
        detail = (
            f"{len(services)} open service(s); {len(identified)} newly identified; "
            f"{len(versioned)} with a product and version"
            + (f"; unidentified: {', '.join(unidentified[:6])}" if unidentified else "")
        )
        if not identified and not pending:
            yield ctx.info(
                f"all {len(services)} service(s) were already identified",
                detail=f"{len(versioned)} with a product and version",
                evidence=banners,
                confidence=0.8,
            )
            return
        if not identified:
            yield ctx.clean(
                f"no service on {ctx.asset.value} could be identified",
                detail=(
                    f"{len(unidentified)} port(s) answered no probe in the identification suite "
                    "and sent no banner. An unidentified service is left unidentified: guessing "
                    "a product would produce a guessed CVE (research ch02#9)."
                ),
                evidence=[
                    ctx.evidence(
                        "note",
                        {"unidentified": unidentified, "attempted": len(pending)},
                        source=ctx.asset.key,
                    ),
                    *banners,
                ],
                confidence=0.4,
            )
            return
        yield ctx.info(
            f"identified {len(identified)} service(s) on {ctx.asset.value}",
            detail=detail,
            evidence=[
                ctx.evidence(
                    "note",
                    {"identified": identified, "unidentified": unidentified},
                    source=ctx.asset.key,
                ),
                *banners,
            ],
            confidence=0.9,
        )


# --------------------------------------------------------------------------- helpers
def _apply_icmp(record: HostRecord, echo: IcmpExchange) -> None:
    if echo.replied:
        record.ttl = echo.ttl
        if "icmp" not in record.discovery:
            record.discovery.append("icmp")


def _identity_from_banner(banner: str) -> ServiceIdentity:
    """The identity a bare banner supports: the protocol it names, or "unknown"."""
    classified = product_from_banner(banner)
    if classified is not None:
        return classified
    return ServiceIdentity(protocol="unknown", banner=banner, confidence=0.2)


def _identity_from_finding(finding: PortFinding) -> ServiceIdentity:
    """An identity from a scanner backend's own verdict (nmap's ``-sV``), or its banner.

    A backend that named the product is trusted for it; otherwise the banner is classified
    like any other, so a port-scan banner that clearly says ``SSH-2.0-...`` is *identifying*,
    not merely "unknown with a note attached".
    """
    if finding.product:
        return ServiceIdentity(
            protocol=product_from_banner(finding.banner).protocol  # type: ignore[union-attr]
            if product_from_banner(finding.banner)
            else "unknown",
            product=finding.product,
            version=finding.version,
            banner=finding.banner,
            confidence=0.6,
        )
    return _identity_from_banner(finding.banner)


def _needs_identification(service: ServiceRecord) -> bool:
    """True when the service has no usable identity yet (a versioned one is left alone)."""
    if service.identity is None:
        return True
    if service.identity.versioned:
        return False
    # An "unknown" placeholder from a bare banner still deserves the probe suite.
    return service.identity.protocol == "unknown"


def _is_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _port_of_asset(value: str) -> int | None:
    """The port an explicit ``host:port`` or URL asset names, if any."""
    from urllib.parse import urlsplit

    if "://" in value:
        try:
            return urlsplit(value).port
        except ValueError:
            return None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if host and port.isdigit():
            return int(port)
    return None


def _hosts_of(ctx: CheckContext, inventory: NetworkInventory) -> tuple[HostRecord, ...]:
    """The inventory hosts belonging to this asset (declared or discovered)."""
    addresses = set(addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts))
    return tuple(record for record in inventory.iter_hosts() if record.address in addresses)


def _scan_targets(ctx: CheckContext, inventory: NetworkInventory) -> tuple[str, ...]:
    """Hosts to port-scan for this asset: inventory hosts when known, else the asset itself."""
    addresses = addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts)
    wanted = set(addresses)
    known = [record for record in inventory.iter_hosts() if record.address in wanted]
    if not known:
        return addresses
    alive = [record.address for record in known if record.alive]
    if alive:
        return tuple(alive)
    # Liveness was probed and nothing answered: scanning anyway would contradict what the
    # liveness check just established, so the port scan reports an empty result honestly.
    return ()
