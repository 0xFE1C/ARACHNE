"""Infrastructure and OT checks: SNMP, active DNS, ICS/SCADA (research ch02#15, #27, #28).

Three checks that reach past TCP services:

``m2.snmp-enum`` (ch02#15) — UDP, therefore **two** opt-ins: the check is not in the default
    set and :data:`~arachne.core.config.NetSettings.allow_udp` must be true. It tries a small
    community-string catalogue (``public``/``private`` plus the shipped vendor defaults) with
    a read-only GET on the MIB-2 system group, and reports a writable community as its own
    finding.
``m2.dns-active`` (ch02#28) — an AXFR attempt against the zone's nameserver followed by
    dictionary resolution, both over **TCP** (a transfer is TCP-only, and using TCP for the
    lookups keeps the UDP switch meaningful). A successful AXFR is a high-confidence exposure.
``m2.ics-probe`` (ch02#27) — opt-in, and read-only: a Modbus "Read Device Identification"
    (function 0x2B) over TCP and, when UDP is enabled, a BACnet/IP Who-Is. Any device that
    answers is reported as critical in *framing* terms (the protocols have no authentication)
    with the severity left to the analyzer.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import (
    HostRecord,
    NetworkInventory,
    ServiceIdentity,
    ServiceRecord,
)
from arachne.modules.m2.support import (
    NetworkCheck,
    catalog_ports_for_probe,
    inventory_or_skip,
    load_wordlist,
    net_or_skip,
    target_kinds_for_network_probes,
)

__all__ = ["DnsActive", "IcsProbe", "SnmpEnum", "dns_zone_of"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)

#: How many dictionary names an active DNS check resolves (bounded, F-01-07).
MAX_DNS_NAMES = 60


def dns_zone_of(ctx: CheckContext) -> str | None:
    """The zone a DNS check works on: the asset's name, or the first declared domain."""
    value = ctx.asset.value
    if not _is_address(value) and "." in value:
        return value
    for selector in ctx.definition.targets:
        if (
            selector.kind in {TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN}
            and "." in selector.value
        ):
            return selector.value
    return None


class SnmpEnum(NetworkCheck, Module):
    """``m2.snmp-enum`` — community-string probe of the MIB-2 system group (ch02#15)."""

    metadata = CheckMetadata(
        id="m2.snmp-enum",
        module="M2",
        name="snmp-enum",
        version="1.0",
        title="SNMP enumeration",
        description=(
            "Probes 161/udp with a community-string catalogue (public/private plus vendor "
            "defaults) and a read-only GET on the system group, reporting readable and "
            "writable communities together with the system description, name and contacts "
            "they expose. UDP probing requires ARACHNE_NET_ALLOW_UDP in addition to this "
            "check's opt-in."
        ),
        research_ref="ch02#15",
        framework=("WSTG-CONF-01", "CWE-306"),
        cwe="CWE-306",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not ctx.config.net_allow_udp:
            yield ctx.skipped(
                "UDP probing is disabled: set ARACHNE_NET_ALLOW_UDP=true to let the SNMP check "
                "send datagrams (F-01-09 makes UDP an explicit deployment-level opt-in)"
            )
            return
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

        hosts = _hosts_for(ctx)
        if not hosts:
            yield ctx.skipped(f"no probed host for asset {ctx.asset.key}")
            return

        communities = _communities(ctx)
        oids = tuple(wire.SNMP_OIDS.values())
        for host in hosts:
            reachable = False
            for community in communities:
                exchange = await client.udp(
                    host,
                    _snmp_port(ctx, host),
                    wire.build_snmp_get(community, oids),
                )
                if exchange.state != "open" or not exchange.payload:
                    continue
                parsed = wire.parse_snmp_response(exchange.payload)
                if parsed is None:
                    continue
                error_status, varbinds = parsed
                if error_status not in {0, 2}:  # noError, or noSuchName for one OID
                    continue
                reachable = True
                values = dict(wire.parse_snmp_varbinds(varbinds))
                facts = {
                    "host": host,
                    "community": community,
                    "error_status": wire.SNMP_ERRORS.get(error_status, str(error_status)),
                    "values": values,
                }
                evidence = [
                    ctx.evidence("note", facts, source=f"{host}:161/udp"),
                ]
                default = community in {"public", "private"}
                yield ctx.candidate(
                    f"SNMP agent answers community {community!r} on {host}",
                    detail=(
                        f"The agent returned the system group for the community string "
                        f"{community!r}"
                        + (" — a well-known default." if default else ".")
                        + (
                            " It is the writable community, so the device can be reconfigured "
                            "remotely."
                            if community == "private"
                            else ""
                        )
                        + " System description: "
                        + values.get("1.3.6.1.2.1.1.1.0", "unreadable")
                    ),
                    confidence=0.95 if default else 0.85,
                    evidence=evidence,
                )
                if community == "private":
                    yield ctx.candidate(
                        f"SNMP write community is the default on {host}",
                        detail=(
                            "The agent accepted 'private', the default read-write community. Any "
                            "client that can reach 161/udp can reconfigure the device "
                            "(research ch02#15)."
                        ),
                        confidence=0.9,
                        evidence=evidence,
                    )
                break
            if not reachable:
                yield ctx.clean(
                    f"no SNMP agent answered on {host}",
                    detail=(
                        f"{len(communities)} community string(s) tried with a read-only GET; "
                        "silence on UDP is ambiguous (an agent may be filtered or may require "
                        "SNMPv3), so this is not evidence that SNMP is absent."
                    ),
                    evidence=[
                        ctx.evidence(
                            "note",
                            {"host": host, "communities_tried": list(communities)},
                            source=host,
                        )
                    ],
                    confidence=0.4,
                )


class DnsActive(NetworkCheck, Module):
    """``m2.dns-active`` — zone transfer attempt and dictionary resolution (ch02#28)."""

    metadata = CheckMetadata(
        id="m2.dns-active",
        module="M2",
        name="dns-active",
        version="1.0",
        title="Active DNS enumeration",
        description=(
            "Attempts a zone transfer (AXFR) against the zone's nameserver and then resolves a "
            "bounded dictionary of candidate subdomains over TCP, recording every name that "
            "resolves as a discovered host. A successful transfer is reported as the exposure "
            "it is."
        ),
        research_ref="ch02#28",
        framework=("WSTG-INFO-10", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=3,
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

        zone = dns_zone_of(ctx)
        if zone is None:
            yield ctx.skipped(
                "active DNS enumeration needs a zone name: declare the domain as a target"
            )
            return
        servers = _dns_servers(ctx, inventory, zone)
        if not servers:
            yield ctx.skipped(
                f"no nameserver address recorded for {zone}: m2.port-scan must find an open "
                "DNS port (53) first, or the domain must resolve to the scanned host"
            )
            return

        for host in servers:
            port = _dns_port(ctx, host)
            transfer = await client.tcp(
                host,
                port,
                payload=wire.dns_tcp_payload(wire.dns_axfr_query(zone)),
                reads=1,
            )
            service = inventory.service(host, port) or inventory.add_service(
                host, port, service="dns", discovered_by="dns-active"
            )
            service.probes += 1
            message = wire.parse_dns_message(
                transfer.banner[2:] if len(transfer.banner) > 2 else transfer.banner
            )
            facts: dict[str, Any] = {
                "zone": zone,
                "server": host,
                "port": port,
                "axfr_rcode": message.rcode if message else None,
                "axfr_records": len(message.records) if message else 0,
                "axfr_sample": list(message.records[:20]) if message else [],
            }
            evidence = [ctx.evidence("note", facts, source=f"{host}:{port}/tcp")]
            if message is not None and message.rcode == "NOERROR" and message.records:
                recorded = 0
                for record in message.records[:200]:
                    name = record.split(" ")[0].rstrip(".")
                    if (
                        name
                        and name != zone
                        and not _is_address(name)
                        and await ctx.record_host(name, source="dns-active")
                    ):
                        recorded += 1
                yield ctx.candidate(
                    f"DNS zone transfer succeeded for {zone} on {host}",
                    detail=(
                        f"The nameserver returned {len(message.records)} record(s) for an AXFR, "
                        f"which discloses the complete zone — including staging, VPN and internal "
                        f"names that are never linked from the public site ({recorded} host "
                        "asset(s) recorded). Restrict AXFR to authorised secondaries "
                        "(research ch02#28)."
                    ),
                    confidence=0.95,
                    evidence=evidence,
                )
            else:
                yield ctx.info(
                    f"AXFR for {zone} refused by {host} ({facts['axfr_rcode'] or 'no answer'})",
                    detail=(
                        "The nameserver did not transfer the zone, which is the correct "
                        "configuration."
                    ),
                    evidence=evidence,
                    confidence=0.8,
                )

        # Dictionary resolution: the other half of research ch02#28.
        names = load_wordlist(ctx, "dns-subdomains")[:MAX_DNS_NAMES]
        resolved: dict[str, tuple[str, ...]] = {}
        for host in servers:
            port = _dns_port(ctx, host)
            for root in [zone]:
                for label in names:
                    candidate = f"{label}.{root}"
                    outcome = await _dns_resolve(client, host, port, candidate)
                    if outcome is None:
                        continue
                    resolved[candidate] = outcome
                    await ctx.record_host(candidate, source="dns-active")
        evidence = [
            ctx.evidence(
                "note",
                {
                    "zone": zone,
                    "names_tried": len(names),
                    "resolved": {
                        name: list(addresses) for name, addresses in list(resolved.items())[:60]
                    },
                },
                source=zone,
            )
        ]
        if not resolved:
            yield ctx.clean(
                f"no dictionary name resolved under {zone}",
                detail=f"{len(names)} candidate label(s) were queried over TCP without an answer.",
                evidence=evidence,
                confidence=0.6,
            )
            return
        yield ctx.info(
            f"active DNS enumeration resolved {len(resolved)} name(s) under {zone}",
            detail="; ".join(
                f"{name} → {', '.join(addresses)}"
                for name, addresses in list(resolved.items())[:10]
            ),
            evidence=evidence,
            confidence=0.9,
        )


class IcsProbe(NetworkCheck, Module):
    """``m2.ics-probe`` — Modbus/BACnet device discovery (research ch02#27). Opt-in."""

    metadata = CheckMetadata(
        id="m2.ics-probe",
        module="M2",
        name="ics-probe",
        version="1.0",
        title="ICS/SCADA protocol probing",
        description=(
            "Reads a Modbus device identification (function 0x2B) over TCP and, when UDP is "
            "enabled, sends a BACnet/IP Who-Is, reporting vendor, model and firmware of any "
            "controller that answers. Opt-in because OT protocols are unauthenticated by "
            "design and their endpoints are the most sensitive in an estate."
        ),
        research_ref="ch02#27",
        framework=("WSTG-CONF-01", "CWE-306"),
        cwe="CWE-306",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
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

        hosts = _hosts_for(ctx)
        if not hosts:
            yield ctx.skipped(f"no probed host for asset {ctx.asset.key}")
            return

        modbus_ports = catalog_ports_for_probe(ctx, "modbus") or (502,)
        found = False
        for host in hosts:
            for port in _candidate_ports(ctx, host, modbus_ports):
                exchange = await client.tcp(
                    host, port, payload=wire.modbus_read_device_id(), reads=1
                )
                service = inventory.service(host, port) or inventory.add_service(
                    host, port, service="modbus", discovered_by="ics-probe"
                )
                service.probes += 1
                device = wire.parse_modbus_device_id(exchange.banner)
                if device is None:
                    continue
                found = True
                service.identity = ServiceIdentity(
                    protocol="modbus",
                    product=device.product or "modbus device",
                    version=device.version,
                    banner=f"{device.vendor or 'Modbus'} {device.product or ''}".strip(),
                    confidence=0.9,
                    extra={str(key): value for key, value in device.objects.items()},
                )
                service.notes["ics"] = {
                    "vendor": device.vendor,
                    "product": device.product,
                    "version": device.version,
                    "objects": {str(key): value for key, value in device.objects.items()},
                }
                evidence = [
                    ctx.evidence(
                        "artifact",
                        {
                            "host": host,
                            "port": port,
                            "protocol": "modbus",
                            "vendor": device.vendor,
                            "product": device.product,
                            "version": device.version,
                            "objects": {str(key): value for key, value in device.objects.items()},
                        },
                        source=f"{host}:{port}/tcp",
                    )
                ]
                yield ctx.info(
                    f"Modbus device on {host}:{port}: {device.vendor or 'vendor unknown'} "
                    f"{device.product or ''}".strip(),
                    detail=f"firmware/version: {device.version or 'unknown'}",
                    evidence=evidence,
                    confidence=0.9,
                )
                yield ctx.candidate(
                    f"industrial control device reachable on {host}:{port}",
                    detail=(
                        f"The Modbus/TCP device identification reports "
                        f"{device.vendor or 'an unknown vendor'} "
                        f"{device.product or 'of unknown model'} "
                        f"firmware {device.version or 'unknown'}. Modbus predates "
                        "authentication entirely, so any client that can reach this port can read "
                        "and (with the write function codes) change controller state "
                        "(research ch02#27). Segment OT networks behind a unidirectional gateway."
                    ),
                    confidence=0.9,
                    evidence=evidence,
                )

            if ctx.config.net_allow_udp:
                bacnet_ports = catalog_ports_for_probe(ctx, "bacnet", protocol="udp") or (47808,)
                for port in bacnet_ports[:1]:
                    udp_exchange = await client.udp(host, port, wire.bacnet_who_is())
                    if udp_exchange.state != "open" or not udp_exchange.payload:
                        continue
                    bacnet = wire.parse_bacnet_i_am(udp_exchange.payload)
                    if bacnet is None:
                        continue
                    found = True
                    evidence = [
                        ctx.evidence(
                            "artifact",
                            {
                                "host": host,
                                "port": port,
                                "protocol": "bacnet",
                                "device_instance": bacnet.device_instance,
                                "vendor_id": bacnet.vendor_id,
                            },
                            source=f"{host}:{port}/udp",
                        )
                    ]
                    yield ctx.candidate(
                        f"BACnet device reachable on {host}:{port}/udp",
                        detail=(
                            f"A BACnet/IP device answered Who-Is with device instance "
                            f"{bacnet.device_instance} (vendor id {bacnet.vendor_id}). BACnet has "
                            "no authentication in its base standard, so the device's objects "
                            "are readable and writable by any client that reaches it "
                            "(research ch02#27)."
                        ),
                        confidence=0.85,
                        evidence=evidence,
                    )

        if not found:
            yield ctx.clean(
                f"no ICS device answered on {len(hosts)} host(s)",
                detail=(
                    "A Modbus device-identification request (and BACnet Who-Is when UDP is "
                    "enabled) drew no response. A controller that speaks only another OT protocol "
                    "would not be found by this check (research ch02#27)."
                ),
                evidence=[
                    ctx.evidence(
                        "note",
                        {"hosts": list(hosts), "modbus_ports": list(modbus_ports)},
                        source=ctx.asset.key,
                    )
                ],
                confidence=0.5,
            )


# --------------------------------------------------------------------------- helpers
def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _hosts_for(ctx: CheckContext) -> tuple[str, ...]:
    from arachne.modules.m2.support import addresses_for_asset

    addresses = addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts)
    inventory = ctx.inventory
    if inventory is None:
        return addresses
    known = [record.address for record in inventory.iter_hosts()]
    if not known:
        return addresses
    wanted = set(addresses)
    return tuple(address for address in known if address in wanted)


def _snmp_port(ctx: CheckContext, host: str) -> int:
    """The SNMP port to probe: the catalogue's UDP entry (161 in the shipped catalogue).

    A datagram probe is never discovered by a connect scan, so the catalogue is the only
    declaration of where SNMP lives — which is exactly what ``templates/m2/ports.yaml`` is for.
    """
    del host
    ports = catalog_ports_for_probe(ctx, "snmp", protocol="udp")
    return ports[0] if ports else 161


def _service_on_port(ctx: CheckContext, host: str, protocols: set[str]) -> ServiceRecord | None:
    """An open service of this host whose protocol identity matches (``None`` when absent)."""
    if ctx.inventory is None:
        return None
    inventory: NetworkInventory = ctx.inventory
    record: HostRecord | None = inventory.get(host)
    if record is None:
        return None
    for port in record.open_ports():
        service = record.service(port)
        if service is not None and service.effective_service.lower() in protocols:
            return service
    return None


def _dns_port(ctx: CheckContext, host: str) -> int:
    """The port the DNS service is on for this host (53 by default, the inventory otherwise)."""
    service = _service_on_port(ctx, host, {"dns", "domain"})
    if service is not None:
        return service.port
    ports = catalog_ports_for_probe(ctx, "dns")
    return ports[0] if ports else 53


def _dns_servers(ctx: CheckContext, inventory: NetworkInventory, zone: str) -> tuple[str, ...]:
    """Addresses to query: open DNS ports in the inventory, else the asset's own addresses."""
    from arachne.modules.m2.support import addresses_for_asset

    candidates: list[str] = []
    for record in inventory.iter_hosts():
        if _service_on_port(ctx, record.address, {"dns", "domain"}) is not None:
            candidates.append(record.address)
    if candidates:
        return tuple(dict.fromkeys(candidates))
    return addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts)[:1]


def _candidate_ports(ctx: CheckContext, host: str, ports: tuple[int, ...]) -> tuple[int, ...]:
    """Ports worth probing for a protocol: the inventory's open ports plus the canonical one."""
    inventory = ctx.inventory
    if inventory is None:
        return ports[:1]
    record = inventory.get(host)
    if record is None or not record.open_ports():
        return ports[:1]
    open_ports = record.open_ports()
    hints = [port for port in open_ports if port in ports]
    return tuple(dict.fromkeys([*hints, ports[0]]))[:3]


def _communities(ctx: CheckContext) -> tuple[str, ...]:
    """The community-string catalogue: the classics first, then any shipped vendor defaults."""
    from arachne.modules.m2.support import load_wordlist

    try:
        extra = load_wordlist(ctx, "common-communities", limit=12)
    except Exception:  # a missing custom list must not break the check
        extra = ()
    return tuple(dict.fromkeys([*extra, "public", "private", "community", "cisco"]))[:12]


async def _dns_resolve(client: Any, server: str, port: int, name: str) -> tuple[str, ...] | None:
    """One dictionary lookup over TCP; ``None`` when the name does not resolve."""
    exchange = await client.tcp(
        server,
        port,
        payload=wire.dns_tcp_payload(wire.dns_query(name, "A")),
        reads=1,
    )
    if not exchange.is_open:
        return None
    message = wire.parse_dns_message(
        exchange.banner[2:] if len(exchange.banner) > 2 else exchange.banner
    )
    if message is None or message.rcode != "NOERROR" or not message.records:
        return None
    addresses = tuple(
        record.split(" ")[-1] for record in message.records if " A " in record or " AAAA " in record
    )
    return addresses or None


def _service_evidence(ctx: CheckContext, service: ServiceRecord, facts: dict[str, Any]) -> Evidence:
    return ctx.evidence(
        "note", {"service": service.evidence_payload(), "facts": facts}, source=service.key
    )
