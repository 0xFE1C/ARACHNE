"""The declared-versus-implemented protocol matrix (REQ-DET-010).

A capability that appears to exist and does not is worse than an absent one. Before this
module, ``oracle`` sat in :data:`arachne.modules.m2.datastores.DATASTORE_PROTOCOLS` with no
dispatch branch, so an Oracle port fell through to a generic "database port reachable"
finding; SIP and OPC-UA sat in the port catalogue with ``probe: unknown`` and no check at
all. Nothing in the repository could answer "which protocols do we actually speak?", and
nothing failed when the two drifted apart.

This module is that single answer. It is a **table**, not a behaviour: one row per protocol
identity the product declares, saying

``implemented``
    a check speaks the protocol's read-only handshake. :attr:`ProtocolEntry.check_id` names
    it, and the id must be in the registry.
``fingerprint_only``
    the catalogue names the probe, but only the generic identification suite runs — a
    banner rule or a port identity, never a protocol-specific exchange. ``pop3``/``imap``
    are the shipped examples.
``not_supported``
    declared somewhere (a port-catalogue entry, a protocol set) and deliberately **not**
    probed. The ``reason`` is the recorded decision; that is the honest outcome for a
    protocol whose wire format this programme will not guess (``oracle``).

:func:`problems` is the cross-reference: it takes the port catalogue, the datastore
dispatcher's table and the registry, and returns every mismatch as a sentence. The test
suite calls it, so a protocol added to any of the three surfaces without a row here — or a
row whose owner does not exist — fails the build. That is the whole point of the module.

The vocabulary is deliberately *not* the probe vocabulary (``m2.catalog.ProbeName``): a
probe is a way to identify a service, while a protocol is a capability the product either
has or does not. ``oracle`` is in the former (the catalogue may hint it) and
``not_supported`` in the latter, and both statements are true at once.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

__all__ = [
    "MATRIX_VERSION",
    "PROTOCOL_MATRIX",
    "ProtocolEntry",
    "ProtocolState",
    "by_protocol",
    "matrix_states",
    "problems",
    "to_dict",
]

#: Bumped when a row changes state or owner: the coverage ledger records it.
MATRIX_VERSION = "1.0"

ProtocolState = Literal["implemented", "fingerprint_only", "not_supported"]

#: The surfaces a protocol can be declared in. A row records which of them name it, so a
#: reader can see where the claim came from — and ``problems`` can insist that each
#: declaration is covered by a row.
SURFACES: tuple[str, ...] = (
    "port_catalogue",
    "datastore_protocols",
    "probe_vocabulary",
    "http_datastore_ports",
)


@dataclass(frozen=True, slots=True)
class ProtocolEntry:
    """One row of the matrix: what the product claims about one protocol."""

    protocol: str
    state: ProtocolState
    check_id: str | None
    reason: str
    surfaces: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "state": self.state,
            "check_id": self.check_id,
            "surfaces": list(self.surfaces),
            "reason": self.reason,
        }


#: The generic identification check every ``fingerprint_only`` row is owned by.
_FINGERPRINT_CHECK = "m2.service-fingerprint"

#: Every protocol the product declares, and what it does about it.
#:
#: ``implemented`` rows are the reads this product actually performs; the cross-reference in
#: :func:`problems` proves each owner exists in the registry.
PROTOCOL_MATRIX: tuple[ProtocolEntry, ...] = (
    # ---------------------------------------------------------------- implemented
    ProtocolEntry(
        "ssh",
        "implemented",
        "m2.ssh-enum",
        "The banner and KEXINIT algorithm lists are read (research ch02#24).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "http",
        "implemented",
        "m2.http-fingerprint",
        "One read-only GET identifies the stack and its headers (research ch02#12).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "tls",
        "implemented",
        "m2.tls-deep-scan",
        "Version, cipher, certificate and trust posture are handshake observations "
        "(research ch02#14).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "ftp",
        "implemented",
        "m2.ftp-anonymous",
        "The greeting and an anonymous USER/PASS attempt establish exposure (ch02#21).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "telnet",
        "implemented",
        "m2.legacy-services",
        "The banner identifies the cleartext remote shell (research ch04#22).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "smtp",
        "implemented",
        "m2.smtp-enum",
        "EHLO/VRFY/EXPN/RCPT enumeration (research ch02#20); transport security and relay "
        "posture are the separate m2.smtp-transport check (REQ-DET-012).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "dns",
        "implemented",
        "m2.dns-active",
        "AXFR and dictionary resolution against the target's own nameserver (ch02#28).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "smb",
        "implemented",
        "m2.smb-enum",
        "A read-only SMB2 NEGOTIATE reads dialects and signing (research ch02#16).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "rpcbind",
        "implemented",
        "m2.nfs-enum",
        "An ONC RPC DUMP call lists the registered programs (research ch02#17).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "ldap",
        "implemented",
        "m2.ldap-enum",
        "An anonymous bind and a rootDSE read (research ch02#18).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "kerberos",
        "implemented",
        "m2.kerberos-enum",
        "A paced AS-REQ principal probe (research ch02#19).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "vnc",
        "implemented",
        "m2.rdp-vnc-detect",
        "The RFB security-type list is read (research ch02#25).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "rdp",
        "implemented",
        "m2.rdp-vnc-detect",
        "The X.224 negotiation establishes whether NLA is required (research ch02#25).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "mysql",
        "implemented",
        "m2.db-service-probe",
        "The server greeting is read; no credential is submitted (research ch02#22).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "postgres",
        "implemented",
        "m2.db-service-probe",
        "SSLRequest plus a startup message (research ch02#22).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "mssql",
        "implemented",
        "m2.db-service-probe",
        "A read-only TDS PRELOGIN reads the version and encryption token (ch02#22).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "redis",
        "implemented",
        "m2.db-service-probe",
        "PING and INFO establish an unauthenticated instance (research ch02#23).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "memcached",
        "implemented",
        "m2.db-service-probe",
        "An unauthenticated ``stats`` read (research ch02#23).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "mongodb",
        "implemented",
        "m2.db-service-probe",
        "The ``isMaster`` handshake establishes authentication state (ch02#23).",
        ("port_catalogue", "probe_vocabulary", "datastore_protocols"),
    ),
    ProtocolEntry(
        "elasticsearch",
        "implemented",
        "m2.db-service-probe",
        "The JSON root and ``_cat/indices`` are read over the scoped HTTP client "
        "(research ch02#23).",
        ("probe_vocabulary",),
    ),
    ProtocolEntry(
        "couchdb",
        "implemented",
        "m2.db-service-probe",
        "The JSON root and ``_all_dbs`` are read over the scoped HTTP client (ch02#23).",
        ("probe_vocabulary",),
    ),
    ProtocolEntry(
        "kibana",
        "implemented",
        "m2.db-service-probe",
        "The HTTP root of an Elasticsearch front end is read over the scoped HTTP client; the "
        "exposure (an unauthenticated dashboard API) is the finding (research ch02#23).",
        ("http_datastore_ports",),
    ),
    ProtocolEntry(
        "influxdb",
        "implemented",
        "m2.db-service-probe",
        "The HTTP root of a time-series API is read over the scoped HTTP client (ch02#23).",
        ("http_datastore_ports",),
    ),
    ProtocolEntry(
        "rabbitmq",
        "implemented",
        "m2.db-service-probe",
        "The HTTP management API root is read over the scoped HTTP client (ch02#23).",
        ("http_datastore_ports",),
    ),
    ProtocolEntry(
        "snmp",
        "implemented",
        "m2.snmp-enum",
        "Community strings and the system group over the opt-in UDP path (ch02#15).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "modbus",
        "implemented",
        "m2.ics-probe",
        "A read-only Modbus/TCP device-identification request (research ch02#27).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "bacnet",
        "implemented",
        "m2.ics-probe",
        "A read-only BACnet/IP who-is broadcast (research ch02#27).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "ssdp",
        "implemented",
        "m2.ssdp-discovery",
        "An SSDP M-SEARCH discovery of UPnP devices (research ch02#26).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "mdns",
        "implemented",
        "m2.ssdp-discovery",
        "Multicast DNS discovery shares the SSDP check's multicast path (ch02#26).",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "grpc",
        "implemented",
        "m2.grpc-plaintext",
        "gRPC/HTTP-2 posture: cleartext h2c, server reflection and request-metadata "
        "leakage (S29 depth family, REQ-DEPTH-003).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "s7",
        "implemented",
        "m2.ot-protocol-probe",
        "A read-only S7comm probe over ISO-TSAP (S29 depth family, REQ-DEPTH-006).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "dnp3",
        "implemented",
        "m2.ot-protocol-probe",
        "A read-only DNP3 link-status request (S29 depth family, REQ-DEPTH-006).",
        ("port_catalogue", "probe_vocabulary"),
    ),
    # ---------------------------------------------------------------- fingerprint only
    ProtocolEntry(
        "unknown",
        "fingerprint_only",
        _FINGERPRINT_CHECK,
        "The catalogue's explicit 'no protocol claimed' value. The port is still scanned, "
        "and the generic identification suite reads whatever banner the service offers; no "
        "protocol-specific exchange is attempted because none is claimed.",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "pop3",
        "fingerprint_only",
        _FINGERPRINT_CHECK,
        "Banner-only by design: a ``+OK`` greeting rule identifies the product and version "
        "(02-current-state.md §4.11). No check enumerates mailboxes over POP3.",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "imap",
        "fingerprint_only",
        _FINGERPRINT_CHECK,
        "Banner-only by design: a ``* OK`` greeting rule identifies the product and version "
        "(02-current-state.md §4.11). No check enumerates mailboxes over IMAP.",
        ("port_catalogue", "probe_vocabulary"),
    ),
    # ---------------------------------------------------------------- not supported
    ProtocolEntry(
        "oracle",
        "not_supported",
        None,
        "Recorded decision (REQ-DET-010 pitfall). Oracle's TNS listener has no public, "
        "normative wire specification that permits a documented read-only handshake, and "
        "this programme will not guess a proprietary binary protocol to make a scanner look "
        "broader than it is. Oracle is therefore removed from the datastore protocol set so "
        "an Oracle port can never be reported as 'database port reachable' on the strength "
        "of a claim the product does not implement; port/listener exposure is still reported "
        "by m2.port-scan and the CVE correlation. Implementing a TNS fingerprint from a "
        "published source remains a named gap.",
        ("datastore_protocols", "port_catalogue"),
    ),
    ProtocolEntry(
        "sip",
        "not_supported",
        None,
        "Recorded decision (REQ-DET-010, 02-current-state.md §4.11). The catalogue names "
        "port 5060 as SIP and declares no probe for it; no check in this product speaks SIP, "
        "and the generic suite has no SIP banner rule, so the port is scanned and fingerprinted "
        "generically. A SIP OPTIONS fingerprint (an application-layer request, not a read-only "
        "handshake) is left to the detection-breadth backlog rather than claimed here.",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "opcua",
        "not_supported",
        None,
        "Recorded decision (REQ-DET-010, 02-current-state.md §4.11). The catalogue names port "
        "4840 as OPC-UA and declares no probe for it; the S29 OT family covers S7comm and DNP3 "
        "only. A HEL/ACK endpoint-description fingerprint is a named gap, not a claim.",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "ntp",
        "not_supported",
        None,
        "The UDP catalogue labels port 123 as NTP, but nothing in this product sends an NTP "
        "probe: the UDP set is scanned by m2.port-scan when UDP probing is opted in, and no "
        "check interprets a mode-4 reply. Recorded as a gap so the catalogue's label is not "
        "read as coverage.",
        ("port_catalogue", "probe_vocabulary"),
    ),
    ProtocolEntry(
        "ipmi",
        "not_supported",
        None,
        "No IPMI/Redfish/BMC check exists (02-current-state.md §4.11). The UDP catalogue names "
        "port 623; the port is scanned and nothing more is claimed.",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "tftp",
        "not_supported",
        None,
        "No TFTP check exists. The UDP catalogue names port 69; the port is scanned and nothing "
        "more is claimed.",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "isakmp",
        "not_supported",
        None,
        "No IKE/IPsec check exists. The UDP catalogue names port 500; the port is scanned and "
        "nothing more is claimed.",
        ("port_catalogue",),
    ),
    ProtocolEntry(
        "netbios-ns",
        "not_supported",
        None,
        "No NetBIOS name-service check exists (SMB enumeration covers port 445/139 instead). "
        "The UDP catalogue names port 137; the port is scanned and nothing more is claimed.",
        ("port_catalogue",),
    ),
)


def by_protocol() -> dict[str, ProtocolEntry]:
    """The matrix keyed by protocol identity (constructed per call: it is tiny)."""
    return {entry.protocol: entry for entry in PROTOCOL_MATRIX}


def matrix_states() -> dict[str, tuple[str, ...]]:
    """``{state: (protocol, ...)}`` — the burn-down view a report or ledger prints."""
    grouped: dict[str, list[str]] = {}
    for entry in PROTOCOL_MATRIX:
        grouped.setdefault(entry.state, []).append(entry.protocol)
    return {state: tuple(sorted(names)) for state, names in sorted(grouped.items())}


def to_dict() -> dict[str, Any]:
    """The whole matrix as JSON-safe data (the ledger's ``protocols`` section)."""
    return {
        "matrix_version": MATRIX_VERSION,
        "surfaces": list(SURFACES),
        "totals": {state: len(names) for state, names in matrix_states().items()},
        "protocols": [entry.to_dict() for entry in PROTOCOL_MATRIX],
    }


def problems(
    *,
    catalogue: Any,
    datastore_protocols: Iterable[str],
    datastore_probes: Mapping[str, str],
    probe_vocabulary: Sequence[str],
    registry_check_ids: Iterable[str],
    http_datastore_ports: Mapping[int, str] | None = None,
) -> tuple[str, ...]:
    """Cross-reference the matrix against every surface that declares a protocol.

    Each argument is a *live* object read from the product (the loaded port catalogue, the
    datastore dispatcher's table, the probe vocabulary, the registry), never a second copy
    of the matrix. A non-empty result is a defect: the caller (a test, or the ledger's
    ``--check`` mode) reports it verbatim.
    """
    found: list[str] = []
    table = by_protocol()
    implemented = {name for name, entry in table.items() if entry.state == "implemented"}
    unprobed = {
        name
        for name, entry in table.items()
        if entry.state in {"fingerprint_only", "not_supported"}
    }
    registered = set(registry_check_ids)

    # 1. every probe the catalogue vocabulary can name has a row.
    for probe in probe_vocabulary:
        if probe not in table:
            found.append(
                f"probe vocabulary declares {probe!r}, which has no protocol-matrix row "
                "(add a row saying who implements it, or that it is fingerprint-only or "
                "not supported)"
            )

    # 2. a protocol in a datastore set must be implemented *and* have a dispatcher branch.
    for protocol in sorted(set(datastore_protocols)):
        entry = table.get(protocol)
        if entry is None:
            found.append(f"datastore protocol {protocol!r} has no protocol-matrix row")
            continue
        if entry.state != "implemented":
            found.append(
                f"datastore protocol {protocol!r} is declared {entry.state!r} in the matrix "
                "but the datastore check still claims it: remove it from the protocol set, or "
                "implement it"
            )
        if protocol not in datastore_probes:
            found.append(
                f"datastore protocol {protocol!r} has no entry in the datastore dispatch table "
                "(the dispatcher would fall through to the generic 'port reachable' path)"
            )

    # 3. the dispatcher must not speak a protocol the matrix does not call implemented.
    for protocol in sorted(datastore_probes):
        if protocol not in implemented:
            found.append(
                f"the datastore dispatch table implements {protocol!r}, which the matrix does "
                f"not record as implemented (state {table.get(protocol)!r})"
            )

    # 4. every implemented row names a check that exists.
    for name in sorted(implemented):
        check_id = table[name].check_id
        if not check_id:
            found.append(f"implemented protocol {name!r} names no owning check")
        elif check_id not in registered:
            found.append(
                f"implemented protocol {name!r} is owned by {check_id!r}, which is not a "
                "registered check"
            )

    # 5. a row that is not implemented must not be claimed in a protocol set.
    for name in sorted(unprobed & set(datastore_protocols)):
        found.append(
            f"protocol {name!r} is {table[name].state!r} in the matrix but is still named in "
            "the datastore protocol set"
        )

    # 6. the exit criterion: no protocol remains with an *unexplained* unknown probe.
    #    A catalogue entry that declares no probe is a claim about that protocol, so it must
    #    have a row — and a row the matrix calls ``implemented`` must not be declared probe-less.
    for protocol, entry in sorted(table.items()):
        if entry.state in {"fingerprint_only", "not_supported"} and not entry.reason.strip():
            found.append(
                f"protocol {protocol!r} is {entry.state!r} without a recorded reason: an "
                "unexplained declaration is what this matrix exists to prevent"
            )
        if entry.state == "implemented" and not entry.surfaces:
            found.append(
                f"protocol {protocol!r} is implemented but names no surface that declares it, "
                "so nothing ties the row to the product"
            )
    for section in ("tcp", "udp"):
        for port_entry in getattr(catalogue, section, ()):
            if port_entry.probe != "unknown":
                continue
            service = str(port_entry.service).lower()
            entry = table.get(service)
            if entry is not None and entry.state == "implemented":
                found.append(
                    f"port catalogue {section} port {port_entry.port} declares service "
                    f"{service!r} with probe 'unknown', but the matrix says that protocol is "
                    "implemented: give the entry its probe, or record it as not supported"
                )

    # 7. every HTTP-native datastore port the dispatcher special-cases is a matrix protocol
    #    the datastore check owns.
    for port, protocol in sorted((http_datastore_ports or {}).items()):
        name = protocol.removesuffix("-http")
        entry = table.get(name)
        if entry is None:
            found.append(
                f"HTTP datastore port {port} maps to {protocol!r}, which has no protocol-matrix row"
            )
            continue
        if entry.state != "implemented" or entry.check_id != "m2.db-service-probe":
            found.append(
                f"HTTP datastore port {port} maps to {protocol!r}, but the matrix records "
                f"{name!r} as {entry.state!r} owned by {entry.check_id!r}"
            )
    return tuple(found)
