"""The estate model: a queryable graph built from scan data only (REQ-SIM-001).

Area SIM's first requirement is that ARACHNE holds an *estate model* — verified assets,
findings, network reachability and identity relationships — as a graph an operator (or a
what-if run) can query, and that the model is **built from scan data only**. This module is
that model. It opens nothing, reads nothing and dials nothing: its inputs are plain values
the composition root already read out of the stores, and its accessors are pure.

Four node kinds and four edge kinds, each with one meaning:

``HOST``      an addressable asset a scan saw (an IP, a hostname, a URL's host).
``SERVICE``   one ``host:port/proto`` a scan observed **answering** — reachability, not a
              guess (:mod:`arachne.sim.reachability` is the only thing that creates these).
``IDENTITY``  a principal relationship a scan established: a credential label that
              authenticated to a host, a service account, a directory group.
``WEAKNESS``  a finding the estate carries, with the stage it reaches.

``EXPOSES``   host → service      the host exposes this service (an answering port).
``WEAKENS``   weakness → host     this weakness is on this host (so a query can walk from
                                  "what is exposed here" to "what does it get an attacker").
``AUTHENTICATES_TO`` identity → host  a *verified* identity relationship.
``PIVOTS_TO`` host → host         two hosts the same identity authenticates to — the
                                  lateral-movement edge, derived, never asserted by hand.

The graph also carries the composer's own inputs (``analyses`` and ``candidates``) so attack
paths are composed by :func:`arachne.analyzer.paths.build_attack_paths` — the **same**
function the verified report uses. A simulation that composed paths with its own rules
would answer a different question from the report it sits beside; sharing the composer is
what makes "the estate as scanned" and "the estate as hypothesised" comparable at all.

Nothing here mutates: :meth:`EstateGraph.add_host` and friends return a *new* graph, which is
what lets a what-if run inject a hypothetical state and leave the verified model intact.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final

from arachne.analyzer.model import Analysis, severity_rank
from arachne.analyzer.paths import (
    DEFAULT_MAX_PATHS,
    AttackPath,
    AttackStage,
    build_attack_paths,
    host_of,
    normalise_check_id,
    stage_for,
)
from arachne.sim.boundary import no_network
from arachne.sim.reachability import ServiceObservation, services_from_candidates

__all__ = [
    "ESTATE_MODEL_VERSION",
    "EdgeKind",
    "EstateEdge",
    "EstateGraph",
    "EstateNode",
    "EstateWeakness",
    "IdentityBinding",
    "NodeKind",
    "build_estate_graph",
]

#: The estate model's own format revision. Bumped when the node/edge vocabulary changes, so
#: a serialized model can be read for what it is.
ESTATE_MODEL_VERSION: Final = "1.0"

#: Asset kinds that name a host directly. ``url`` is handled separately (its host is
#: extracted), and anything else is not a host.
HOST_ASSET_KINDS: Final[frozenset[str]] = frozenset(
    {"host", "ip", "ipv4", "ipv6", "domain", "hostname", "fqdn", "netbios", "asn", "cloud"}
)

#: Asset kinds a scan records that describe an application rather than a host.
URL_ASSET_KINDS: Final[frozenset[str]] = frozenset({"url", "web", "endpoint"})


class NodeKind(StrEnum):
    HOST = "host"
    SERVICE = "service"
    IDENTITY = "identity"
    WEAKNESS = "weakness"


class EdgeKind(StrEnum):
    EXPOSES = "exposes"
    WEAKENS = "weakens"
    AUTHENTICATES_TO = "authenticates_to"
    PIVOTS_TO = "pivots_to"


@dataclass(frozen=True, slots=True)
class EstateNode:
    """One node of the estate model."""

    id: str
    kind: NodeKind
    label: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "label": self.label,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class EstateEdge:
    """One directed edge, with the scan fact it was derived from."""

    source: str
    target: str
    kind: EdgeKind
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class IdentityBinding:
    """A principal relationship a scan established between an identity and a host.

    ``kind`` is the relationship's nature — ``credential`` (a vault label that authenticated
    to this host), ``service-account``, ``directory`` (an SSO/LDAP group whose members can
    reach the host) or ``token``. It is recorded, never inferred: a binding is written by the
    composition root from what a scan or an operator import actually proved.
    """

    identity: str
    host: str
    kind: str = "credential"
    source: str = ""
    evidence_id: int | None = None


@dataclass(frozen=True, slots=True)
class EstateWeakness:
    """A finding the estate carries: what it is, where, and which stage it reaches.

    ``source`` is the analyzer's own :class:`~arachne.analyzer.model.Analysis` when the scan
    produced one, kept out of ``repr``/``eq`` because it is a large object that only the
    composer reads. A hypothetical weakness carries a synthetic analysis — which is the
    mechanism that lets a what-if run reuse the real composer instead of a parallel one.
    """

    node_id: str
    check_id: str
    title: str
    asset: str
    host: str
    severity: str
    confidence: int = 0
    cwe: str | None = None
    finding_id: int | None = None
    verdict: str = "analyzed"
    observed: bool = True
    #: Set on a weakness a hypothesis injected: the hypothesis's id.
    introduced_by: str | None = None
    remediation_id: str | None = None
    remediation_summary: str = ""
    remediation_steps: int = 0
    source: Analysis | None = field(default=None, compare=False, repr=False)

    @property
    def stage(self) -> AttackStage:
        return stage_for(self.cwe, self.severity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "check_id": self.check_id,
            "title": self.title,
            "asset": self.asset,
            "host": self.host,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "observed": self.observed,
            "introduced_by": self.introduced_by,
            "stage": self.stage.value,
        }


def host_node_id(host: str) -> str:
    return f"host:{host}"


def service_node_id(host: str, port: int, protocol: str) -> str:
    return f"service:{host}:{port}/{protocol}"


def identity_node_id(identity: str) -> str:
    return f"identity:{identity}"


def weakness_node_id(check_id: str, asset: str) -> str:
    return f"weakness:{check_id}@{asset}"


@dataclass(frozen=True, slots=True)
class EstateGraph:
    """The estate as a queryable graph (REQ-SIM-001). Frozen: every edit returns a new one."""

    estate_key: str
    nodes: tuple[EstateNode, ...] = ()
    edges: tuple[EstateEdge, ...] = ()
    weaknesses: tuple[EstateWeakness, ...] = ()
    candidates: tuple[Any, ...] = ()
    identity_bindings: tuple[IdentityBinding, ...] = ()
    built_from_scans: tuple[int, ...] = ()
    model_version: str = ESTATE_MODEL_VERSION
    #: CLOSED-OVER GAP: ``posture.cmdb.CriticalityIndex`` is a leaf value object, but area SIM
    #: may not import :mod:`arachne.posture` (it owns a re-scan path), so the index arrives
    #: as an opaque value and is handed straight to the composer, which knows its type.
    criticality: Any = field(default=None, compare=False, repr=False)

    # ------------------------------------------------------------------ queries
    def node(self, node_id: str) -> EstateNode | None:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def nodes_of_kind(self, kind: NodeKind) -> tuple[EstateNode, ...]:
        return tuple(node for node in self.nodes if node.kind == kind)

    def edges_of_kind(self, kind: EdgeKind) -> tuple[EstateEdge, ...]:
        return tuple(edge for edge in self.edges if edge.kind == kind)

    def edges_from(self, node_id: str, *, kind: EdgeKind | None = None) -> tuple[EstateEdge, ...]:
        return tuple(
            edge
            for edge in self.edges
            if edge.source == node_id and (kind is None or edge.kind == kind)
        )

    def edges_to(self, node_id: str, *, kind: EdgeKind | None = None) -> tuple[EstateEdge, ...]:
        return tuple(
            edge
            for edge in self.edges
            if edge.target == node_id and (kind is None or edge.kind == kind)
        )

    def neighbors(self, node_id: str, *, kind: EdgeKind | None = None) -> tuple[str, ...]:
        """Everything reachable in one hop, deterministically ordered."""
        out = {edge.target for edge in self.edges_from(node_id, kind=kind)}
        out |= {edge.source for edge in self.edges_to(node_id, kind=kind)}
        return tuple(sorted(out))

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(node.label for node in self.nodes_of_kind(NodeKind.HOST))

    @property
    def identities(self) -> tuple[str, ...]:
        return tuple(node.label for node in self.nodes_of_kind(NodeKind.IDENTITY))

    @property
    def services(self) -> tuple[ServiceObservation, ...]:
        """The observed services, rebuilt from the graph's own nodes (no second source)."""
        out: list[ServiceObservation] = []
        for node in self.nodes_of_kind(NodeKind.SERVICE):
            attributes = node.attributes
            out.append(
                ServiceObservation(
                    host=str(attributes.get("host") or ""),
                    port=int(attributes.get("port") or 0),
                    protocol=str(attributes.get("protocol") or "tcp"),
                    service=(str(attributes["service"]) if attributes.get("service") else None),
                    source_check=str(attributes.get("source_check") or ""),
                    evidence_id=attributes.get("evidence_id"),
                )
            )
        return tuple(out)

    def services_of(self, host: str) -> tuple[ServiceObservation, ...]:
        return tuple(item for item in self.services if item.host == host)

    def weaknesses_of(self, host: str) -> tuple[EstateWeakness, ...]:
        return tuple(item for item in self.weaknesses if item.host == host)

    def identities_of(self, host: str) -> tuple[str, ...]:
        """The identities a scan established for ``host`` (sorted, de-duplicated)."""
        edges = self.edges_to(host_node_id(host), kind=EdgeKind.AUTHENTICATES_TO)
        return tuple(sorted({edge.source.removeprefix("identity:") for edge in edges}))

    def hosts_of_identity(self, identity: str) -> tuple[str, ...]:
        """The hosts this identity authenticates to — its reach, in one query."""
        node_id = identity_node_id(identity)
        return tuple(
            sorted(
                edge.target.removeprefix("host:")
                for edge in self.edges_from(node_id, kind=EdgeKind.AUTHENTICATES_TO)
            )
        )

    def pivot_hosts(self, identity: str) -> tuple[str, ...]:
        """The hosts an identity reaches, when it reaches more than one (a lateral path)."""
        hosts = self.hosts_of_identity(identity)
        return hosts if len(hosts) > 1 else ()

    def reachable_hosts(self) -> tuple[str, ...]:
        """Hosts a scan observed answering — the model's notion of reachability."""
        out = {
            edge.source.removeprefix("host:")
            for edge in self.edges_of_kind(EdgeKind.EXPOSES)
        }
        return tuple(sorted(out))

    def observed_weaknesses(self) -> tuple[EstateWeakness, ...]:
        return tuple(item for item in self.weaknesses if item.observed)

    def hypothetical_weaknesses(self) -> tuple[EstateWeakness, ...]:
        return tuple(item for item in self.weaknesses if not item.observed)

    # ------------------------------------------------------------------ composition
    @property
    def analyses(self) -> tuple[Analysis, ...]:
        """The analyses the composer reads: the observed ones plus any injected ones."""
        return tuple(item.source for item in self.weaknesses if item.source is not None)

    def attack_paths(
        self,
        *,
        min_confidence: int = 55,
        max_paths: int = DEFAULT_MAX_PATHS,
        max_depth: int = 5,
    ) -> tuple[AttackPath, ...]:
        """Compose the estate's paths with the **verified report's own composer**.

        Pure and offline: it walks the model, and the model's inputs are already in memory.
        """
        with no_network():
            return build_attack_paths(
                self.analyses,
                self.candidates,
                min_confidence=min_confidence,
                max_depth=max_depth,
                max_paths=max_paths,
                criticality=self.criticality,
            )

    # ------------------------------------------------------------------ edits (pure)
    def add_node(self, node: EstateNode) -> EstateGraph:
        """Add ``node``, or replace the existing one (same id) — a new graph either way."""
        existing = [item for item in self.nodes if item.id != node.id]
        return replace(self, nodes=tuple(sorted([*existing, node], key=lambda item: item.id)))

    def add_edge(self, edge: EstateEdge) -> EstateGraph:
        if edge in self.edges:
            return self
        key = (edge.kind.value, edge.source, edge.target)
        existing = [
            item
            for item in self.edges
            if (item.kind.value, item.source, item.target) != key
        ]
        return replace(
            self,
            edges=tuple(
                sorted(
                    [*existing, edge],
                    key=lambda item: (item.kind.value, item.source, item.target),
                )
            ),
        )

    def add_weakness(self, weakness: EstateWeakness) -> EstateGraph:
        existing = [item for item in self.weaknesses if item.node_id != weakness.node_id]
        graph = replace(self, weaknesses=(*existing, weakness))
        graph = graph.add_node(
            EstateNode(
                id=weakness.node_id,
                kind=NodeKind.WEAKNESS,
                label=weakness.title,
                attributes={
                    "check_id": weakness.check_id,
                    "asset": weakness.asset,
                    "host": weakness.host,
                    "severity": weakness.severity,
                    "cwe": weakness.cwe,
                    "observed": weakness.observed,
                    "introduced_by": weakness.introduced_by,
                    "stage": weakness.stage.value,
                },
            )
        )
        return graph.add_edge(
            EstateEdge(
                source=weakness.node_id,
                target=host_node_id(weakness.host),
                kind=EdgeKind.WEAKENS,
                attributes={"check_id": weakness.check_id},
            )
        )

    def add_host(self, host: str, *, attributes: Mapping[str, Any] | None = None) -> EstateGraph:
        """Add a host node. An existing host is never overwritten with bare attributes.

        The model meets the same host from several directions (an asset row, a finding's
        asset, a service observation, an identity binding). The first writer is the one with
        something to say — the asset row carries the asset kinds — so a later, emptier
        sighting must not erase it.
        """
        if not host:
            return self
        if not attributes and self.node(host_node_id(host)) is not None:
            return self
        return self.add_node(
            EstateNode(
                id=host_node_id(host),
                kind=NodeKind.HOST,
                label=host,
                attributes=dict(attributes or {}),
            )
        )

    def add_service(self, observation: ServiceObservation) -> EstateGraph:
        if not observation.host:
            return self
        graph = self.add_host(observation.host)
        graph = graph.add_node(
            EstateNode(
                id=service_node_id(observation.host, observation.port, observation.protocol),
                kind=NodeKind.SERVICE,
                label=f"{observation.host}:{observation.port}/{observation.protocol}",
                attributes={
                    "host": observation.host,
                    "port": observation.port,
                    "protocol": observation.protocol,
                    "service": observation.service,
                    "source_check": observation.source_check,
                    "evidence_id": observation.evidence_id,
                },
            )
        )
        return graph.add_edge(
            EstateEdge(
                source=host_node_id(observation.host),
                target=service_node_id(observation.host, observation.port, observation.protocol),
                kind=EdgeKind.EXPOSES,
                attributes={"observed_by": observation.source_check},
            )
        )

    def bind_identity(self, binding: IdentityBinding) -> EstateGraph:
        """Add an identity relationship **and** the lateral edges it implies."""
        graph = self.add_node(
            EstateNode(
                id=identity_node_id(binding.identity),
                kind=NodeKind.IDENTITY,
                label=binding.identity,
                attributes={"kind": binding.kind},
            )
        )
        graph = graph.add_host(binding.host)
        graph = graph.add_edge(
            EstateEdge(
                source=identity_node_id(binding.identity),
                target=host_node_id(binding.host),
                kind=EdgeKind.AUTHENTICATES_TO,
                attributes={"kind": binding.kind, "source": binding.source},
            )
        )
        # Every host this identity already reaches becomes a lateral edge, in both
        # directions: an attacker holding the identity moves either way.
        for other in graph.hosts_of_identity(binding.identity):
            if other == binding.host:
                continue
            graph = graph.add_edge(
                EstateEdge(
                    source=host_node_id(binding.host),
                    target=host_node_id(other),
                    kind=EdgeKind.PIVOTS_TO,
                    attributes={"identity": binding.identity},
                )
            )
            graph = graph.add_edge(
                EstateEdge(
                    source=host_node_id(other),
                    target=host_node_id(binding.host),
                    kind=EdgeKind.PIVOTS_TO,
                    attributes={"identity": binding.identity},
                )
            )
        return graph

    # ------------------------------------------------------------------ reporting
    def summary(self) -> dict[str, int]:
        return {
            "hosts": len(self.nodes_of_kind(NodeKind.HOST)),
            "services": len(self.nodes_of_kind(NodeKind.SERVICE)),
            "identities": len(self.nodes_of_kind(NodeKind.IDENTITY)),
            "weaknesses": len(self.nodes_of_kind(NodeKind.WEAKNESS)),
            "weaknesses_observed": len(self.observed_weaknesses()),
            "weaknesses_hypothetical": len(self.hypothetical_weaknesses()),
            "edges": len(self.edges),
            "pivots": len(self.edges_of_kind(EdgeKind.PIVOTS_TO)) // 2,
            "scans": len(self.built_from_scans),
        }

    def to_dict(self) -> dict[str, Any]:
        """The whole model as plain data (JSON-ready), for ``arachne simulate model --json``."""
        return {
            "model_version": self.model_version,
            "estate_key": self.estate_key,
            "built_from_scans": list(self.built_from_scans),
            "summary": self.summary(),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "weaknesses": [item.to_dict() for item in self.weaknesses],
            "identity_bindings": [
                {
                    "identity": item.identity,
                    "host": item.host,
                    "kind": item.kind,
                    "source": item.source,
                }
                for item in self.identity_bindings
            ],
        }


def build_estate_graph(
    *,
    estate_key: str,
    assets: Sequence[Any] = (),
    candidates: Sequence[Any] = (),
    analyses: Sequence[Analysis] = (),
    identity_bindings: Sequence[IdentityBinding] = (),
    reachability: Sequence[ServiceObservation] | None = None,
    built_from_scans: Sequence[int] = (),
    criticality: Any = None,
) -> EstateGraph:
    """Build the estate model from scan data (REQ-SIM-001).

    Everything here is *received*: ``assets`` are the scan's asset rows, ``candidates`` its
    stored findings (with their evidence payloads, from which reachability is read), and
    ``analyses`` its analyzer output. ``identity_bindings`` are the principal relationships a
    scan or an import actually proved; they are never inferred here, because "which identity
    reaches which host" is a claim about authorization and a guess would be a false one.

    ``reachability`` overrides the evidence read when the caller already has observations
    (a lab fixture, or an imported inventory). Passing ``()`` means "no observed services",
    which is different from ``None`` ("read them from the evidence").

    Pure and offline by construction: the body runs inside
    :func:`arachne.sim.boundary.no_network`, so building a model in a process whose sockets
    are armed still sends nothing.
    """
    with no_network():
        graph = EstateGraph(estate_key=estate_key, criticality=criticality)

        hosts: dict[str, dict[str, Any]] = {}
        scans: list[int] = [int(item) for item in built_from_scans]

        def note_host(host: str, attributes: Mapping[str, Any]) -> None:
            if not host:
                return
            current = hosts.setdefault(host, {"asset_kinds": [], "scans": []})
            for kind in attributes.get("asset_kinds") or ():
                if kind not in current["asset_kinds"]:
                    current["asset_kinds"].append(kind)
            for scan_id in attributes.get("scans") or ():
                if scan_id is not None and int(scan_id) not in current["scans"]:
                    current["scans"].append(int(scan_id))

        for record in assets:
            kind = str(_get(record, "kind", "") or "").lower()
            value = str(_get(record, "value", "") or "").strip()
            if not value:
                continue
            scan_id = _get(record, "scan_id", None)
            if kind in URL_ASSET_KINDS:
                host = host_of(value)
                note_host(host, {"asset_kinds": ["url"], "scans": [scan_id]})
            elif kind in HOST_ASSET_KINDS or not kind:
                note_host(value, {"asset_kinds": [kind or "host"], "scans": [scan_id]})

        # A finding's asset is proof its host exists, whatever the asset table says.
        for record in candidates:
            asset = str(_get(record, "asset_value", "") or "").strip()
            if not asset:
                continue
            kind = str(_get(record, "asset_kind", "") or "").lower()
            scan_id = _get(record, "scan_id", None)
            note_host(
                host_of(asset),
                {"asset_kinds": [kind] if kind else ["host"], "scans": [scan_id]},
            )
            if scan_id is not None and int(scan_id) not in scans:
                scans.append(int(scan_id))

        for host in sorted(hosts):
            graph = graph.add_host(host, attributes=hosts[host])

        observations = (
            services_from_candidates(candidates)
            if reachability is None
            else tuple(reachability)
        )
        for observation in observations:
            graph = graph.add_service(observation)

        bindings = list(identity_bindings)
        for binding in bindings:
            graph = graph.bind_identity(binding)

        analysed_ids: set[int] = set()
        for analysis in analyses:
            weakness = _weakness_from_analysis(analysis)
            if weakness is None:
                continue
            if analysis.finding_id is not None:
                analysed_ids.add(int(analysis.finding_id))
            graph = graph.add_weakness(weakness)

        for record in candidates:
            finding_id = _get(record, "id", None)
            if finding_id is not None and int(finding_id) in analysed_ids:
                continue
            weakness = _weakness_from_candidate(record)
            if weakness is not None:
                graph = graph.add_weakness(weakness)

        return replace(
            graph,
            candidates=tuple(candidates),
            identity_bindings=tuple(bindings),
            built_from_scans=tuple(sorted(set(scans))),
        )


def _get(record: Any, name: str, default: Any) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _weakness_from_analysis(analysis: Analysis) -> EstateWeakness | None:
    """The weakness an analysis implies, or ``None`` when the analysis is not one.

    The rules mirror :mod:`arachne.analyzer.paths`: a dropped finding is the analyzer saying
    "no" and a merged one is represented by the finding that absorbed it, so neither is a
    weakness in the model.
    """
    check_id = normalise_check_id(analysis.check_id or "")
    asset = (analysis.asset or "").strip()
    if not check_id or not asset or analysis.verdict in ("dropped", "merged"):
        return None
    return EstateWeakness(
        node_id=weakness_node_id(check_id, asset),
        check_id=check_id,
        title=analysis.title,
        asset=asset,
        host=host_of(asset),
        severity=(analysis.severity or "info").lower(),
        confidence=int(analysis.confidence),
        cwe=analysis.cwe,
        finding_id=analysis.finding_id,
        verdict=analysis.verdict,
        observed=True,
        remediation_id=analysis.remediation.id,
        remediation_summary=analysis.remediation.summary,
        remediation_steps=len(analysis.remediation.steps),
        source=analysis,
    )


def _weakness_from_candidate(record: Any) -> EstateWeakness | None:
    """The weakness a stored candidate implies when no analysis covers it (S21's rule)."""
    check_id = normalise_check_id(str(_get(record, "check_key", "") or ""))
    asset = str(_get(record, "asset_value", "") or "").strip()
    if not check_id or not asset:
        return None
    severity = str(_get(record, "severity", "") or "info").lower()
    return EstateWeakness(
        node_id=weakness_node_id(check_id, asset),
        check_id=check_id,
        title=str(_get(record, "title", "") or check_id),
        asset=asset,
        host=host_of(asset),
        severity=severity,
        confidence=int(_get(record, "confidence", 0) or 0),
        finding_id=_get(record, "id", None),
        verdict="analyzed",
        observed=True,
    )


def ordered_by_severity(items: Iterable[EstateWeakness]) -> tuple[EstateWeakness, ...]:
    """Weaknesses worst-first, deterministic (a query helper the CLI and tests share)."""
    return tuple(
        sorted(
            items,
            key=lambda item: (-severity_rank(item.severity), item.check_id, item.asset),
        )
    )
