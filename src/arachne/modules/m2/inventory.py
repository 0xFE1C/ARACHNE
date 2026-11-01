"""The per-scan network inventory M2 builds and the rest of M2 reads (ADR-080.2).

M2's checks are separate registry entries (``m2.host-discovery``, ``m2.port-scan``,
``m2.service-fingerprint``, ...) but they form one pipeline: discoveries flow from liveness
to open ports to service identities to protocol enumeration to CVE correlation. The asset
table is the wrong place for that flow — a port or a banner is not a target-defined asset,
and writing one row per open port would flood the inventory with entries no later module
wants ('s ``assets`` table is the *inventory of things*, not of
observations).

So the hand-off lives here: a :class:`NetworkInventory` built once per discovery step,
attached to the step context, and read by every M2 check that needs "what have we learned so
far?". Two consequences worth stating:

* **A check with nothing in the inventory does nothing.** ``m2.tls-deep-scan`` only probes
  ports the port scan found open, so running it on an asset with no inventory entry costs
  zero packets and reports why. That keeps the plan's request estimate honest even though
  the checks are selected independently.
* **The inventory is bounded by construction.** ``max_hosts``/``max_ports`` come from
  :class:`~arachne.core.config.NetSettings`, so a stray ``/16`` cannot turn into a million
  probes no matter how the checks are ordered.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from arachne.core.net import TlsProfile

__all__ = [
    "HostRecord",
    "NetworkInventory",
    "ServiceIdentity",
    "ServiceRecord",
]


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    """What a service *is*, as far as the fingerprinter could establish (research ch02#9).

    ``product``/``version`` are the fields the CVE correlation keys on, so they are only set
    when a banner or a handshake actually named them: a guessed product would produce a
    guessed CVE. ``confidence`` expresses how the identity was reached (a version string in
    a banner is high; "the port answered a TLS ClientHello" is medium for the protocol and
    zero for the product).
    """

    protocol: str
    product: str | None = None
    version: str | None = None
    banner: str = ""
    confidence: float = 0.5
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def versioned(self) -> bool:
        return bool(self.product and self.version)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "protocol": self.protocol,
            "product": self.product,
            "version": self.version,
            "confidence": self.confidence,
        }
        if self.banner:
            payload["banner"] = self.banner[:512]
        if self.extra:
            payload["extra"] = {str(k): v for k, v in self.extra.items()}
        return payload


@dataclass
class ServiceRecord:
    """One reachable service: an open port plus everything M2 learned about it."""

    host: str
    port: int
    protocol: str = "tcp"
    #: The port catalogue's neutral name for this port (a hint, not a conclusion).
    service: str | None = None
    identity: ServiceIdentity | None = None
    tls: TlsProfile | None = None
    os_family: str | None = None
    #: How the port was found open, for evidence ("connect", "banner", "nmap").
    discovered_by: str = "connect"
    #: Free-form observations the protocol checks add (SMTP verbs, SMB dialects, ...).
    notes: dict[str, Any] = field(default_factory=dict)
    probes: int = 0

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    @property
    def effective_service(self) -> str:
        """The identified protocol when there is one, else the catalogue hint."""
        if self.identity is not None:
            return self.identity.protocol
        return self.service or "unknown"

    @property
    def product(self) -> str | None:
        return self.identity.product if self.identity else None

    @property
    def version(self) -> str | None:
        return self.identity.version if self.identity else None

    @property
    def banner(self) -> str:
        return self.identity.banner if self.identity else ""

    def evidence_payload(self) -> dict[str, Any]:
        """A bounded, report-ready description of the service."""
        payload: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.effective_service,
            "port_hint": self.service,
            "discovered_by": self.discovered_by,
            "probes": self.probes,
        }
        if self.identity is not None:
            payload["identity"] = self.identity.to_dict()
        if self.tls is not None:
            payload["tls"] = {
                "versions": [
                    {"version": item.version, "supported": item.supported}
                    for item in self.tls.versions
                ],
                "ciphers": list(self.tls.ciphers),
                "trust_error": self.tls.trust_error,
            }
        if self.os_family:
            payload["os_family"] = self.os_family
        if self.notes:
            payload["notes"] = {str(k): v for k, v in self.notes.items()}
        return payload


@dataclass
class HostRecord:
    """One host in the inventory: liveness, how we found it, and its services."""

    address: str
    alive: bool = False
    declared: bool = False
    ttl: int | None = None
    os_family: str | None = None
    #: Discovery methods that found it (``declared``, ``tcp:80``, ``icmp``, ...).
    discovery: list[str] = field(default_factory=list)
    services: dict[tuple[int, str], ServiceRecord] = field(default_factory=dict)
    probes: int = 0

    def open_ports(self, *, protocol: str = "tcp") -> tuple[int, ...]:
        return tuple(sorted(port for (port, proto) in self.services if proto == protocol))

    def service(self, port: int, *, protocol: str = "tcp") -> ServiceRecord | None:
        return self.services.get((port, protocol))

    def add(self, record: ServiceRecord) -> ServiceRecord:
        self.services[(record.port, record.protocol)] = record
        return record

    @property
    def service_list(self) -> tuple[ServiceRecord, ...]:
        ordered = sorted(self.services, key=lambda key: (key[1], key[0]))
        return tuple(self.services[key] for key in ordered)

    def summary(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "alive": self.alive,
            "declared": self.declared,
            "ttl": self.ttl,
            "os_family": self.os_family,
            "discovery": list(self.discovery),
            "services": [item.evidence_payload() for item in self.service_list],
        }


class NetworkInventory:
    """Per-step state shared by M2's checks (ADR-080.2)."""

    def __init__(self, *, max_hosts: int = 64, max_ports: int = 100) -> None:
        self.max_hosts = max_hosts
        self.max_ports = max_ports
        self.hosts: dict[str, HostRecord] = {}
        #: Addresses in discovery order, so evidence and reports are deterministic.
        self.order: list[str] = []
        self.probes = 0
        #: Set when the host cap was hit, so a check can say so instead of silently stopping.
        self.truncated_hosts = False

    # ------------------------------------------------------------------ hosts
    def host(self, address: str, *, declared: bool = False) -> HostRecord:
        record = self.hosts.get(address)
        if record is None:
            record = HostRecord(address=address, declared=declared)
            self.hosts[address] = record
            self.order.append(address)
        elif declared:
            record.declared = True
        return record

    def get(self, address: str) -> HostRecord | None:
        return self.hosts.get(address)

    def mark_alive(self, address: str, *, method: str, ttl: int | None = None) -> HostRecord:
        record = self.host(address)
        record.alive = True
        if method not in record.discovery:
            record.discovery.append(method)
        if ttl is not None:
            record.ttl = ttl
        return record

    def live_hosts(self) -> tuple[HostRecord, ...]:
        return tuple(record for record in self.iter_hosts() if record.alive)

    def iter_hosts(self) -> tuple[HostRecord, ...]:
        return tuple(self.hosts[address] for address in self.order)

    def can_add_host(self) -> bool:
        return len(self.order) < self.max_hosts

    # ------------------------------------------------------------------ services
    def add_service(
        self,
        host: str,
        port: int,
        *,
        protocol: str = "tcp",
        service: str | None = None,
        discovered_by: str = "connect",
    ) -> ServiceRecord:
        record = self.host(host)
        record.alive = True
        detection = f"{protocol}:{port}"
        if detection not in record.discovery:
            record.discovery.append(detection)
        existing = record.service(port, protocol=protocol)
        if existing is not None:
            return existing
        return record.add(
            ServiceRecord(
                host=host,
                port=port,
                protocol=protocol,
                service=service,
                discovered_by=discovered_by,
            )
        )

    def service(self, host: str, port: int, *, protocol: str = "tcp") -> ServiceRecord | None:
        record = self.hosts.get(host)
        return record.service(port, protocol=protocol) if record else None

    def services(self) -> tuple[ServiceRecord, ...]:
        return tuple(item for host in self.iter_hosts() for item in host.service_list)

    def services_on_ports(
        self, ports: Iterable[int], *, protocol: str = "tcp"
    ) -> tuple[ServiceRecord, ...]:
        wanted = set(ports)
        return tuple(
            item for item in self.services() if item.protocol == protocol and item.port in wanted
        )

    def services_with_protocol(self, *protocols: str) -> tuple[ServiceRecord, ...]:
        wanted = {item.lower() for item in protocols}
        return tuple(item for item in self.services() if item.effective_service.lower() in wanted)

    def versioned_services(self) -> tuple[ServiceRecord, ...]:
        """Services with a product *and* a version — the CVE correlation's input."""
        return tuple(item for item in self.services() if item.identity and item.identity.versioned)

    # ------------------------------------------------------------------ reporting
    @property
    def hosts_seen(self) -> int:
        return len(self.order)

    def summary(self, *, sample: int = 32) -> dict[str, Any]:
        """The step's inventory statistics, plus a bounded sample of what was identified.

        The sample is what the CLI (and a report appendix) shows an operator: which port ran
        which product and version. It is bounded so a large estate cannot turn a step's stats
        row into a second copy of the full inventory.
        """
        services = self.services()
        identified = [
            {
                "host": item.host,
                "port": item.port,
                "protocol": item.protocol,
                "service": item.effective_service,
                "product": item.product,
                "version": item.version,
                "tls": item.tls is not None,
            }
            for item in services
            if item.identity is not None and item.identity.product
        ]
        return {
            "hosts": self.hosts_seen,
            "live_hosts": len(self.live_hosts()),
            "services": len(services),
            "versioned_services": len(self.versioned_services()),
            "truncated_hosts": self.truncated_hosts,
            "probes": self.probes,
            "identified_sample": identified[:sample],
        }

    def evidence_payload(self, *, max_hosts: int = 32, max_services: int = 64) -> dict[str, Any]:
        """A bounded inventory snapshot for evidence (never the whole estate)."""
        hosts = self.iter_hosts()
        return {
            **self.summary(),
            "inventory": [item.summary() for item in hosts[:max_hosts]],
            "truncated": len(hosts) > max_hosts,
            "service_count": len(self.services()),
            "service_sample": [item.evidence_payload() for item in self.services()[:max_services]],
        }

    def ports_of(
        self, addresses: Sequence[str], *, protocol: str = "tcp"
    ) -> Mapping[str, tuple[int, ...]]:
        return {
            address: record.open_ports(protocol=protocol)
            for address in addresses
            if (record := self.hosts.get(address)) is not None
        }
