"""Network reachability read out of scan data (S28, REQ-SIM-001).

The estate model needs a reachability dimension, and the only honest source for it is what
a scan already observed. ARACHNE has exactly one such observation: the M2 network checks
probe ports and record which ones **answered**. An answering port is not an opinion — the
scanning host completed a TCP handshake — so it is the fact the model is allowed to use.
Nothing here opens anything: the input is a list of stored candidate rows with their
evidence payloads, and the output is a tuple of plain observations.

Two aggregate shapes and one per-service shape are recognised, and the reader is deliberately
literal about them:

``{"hosts": {"10.0.0.5": [22, 443]}}``
    the S2 port scan's evidence payload (``modules/m2/discovery.py``): a host → the ports that
    answered. The authority for a host being reachable at all.
``{"services": [{"host": …, "port": …, "protocol": …, "service": …}]}``
    a network inventory's per-host service list, as a fingerprinting check records it
    (``versioned_services`` from the CVE correlation is read the same way).
``{"host": …, "port": …}``
    **the per-service shape most checks write**: a probe that names the host it reached and
    the port it reached it on (``tls_certificate``, ``banner``, an M6 correlation artifact
    naming an ``asset``). Both keys must be present for this to count — a lone ``port`` in an
    unrelated payload means nothing about reachability — and ``asset`` is accepted as the host
    key because that is what the M6 payloads call it.

An unknown shape contributes nothing. That asymmetry is the point: a model that guessed
reachability from a finding's title would be inventing topology, and the requirement says the
model is built from scan data — so a payload nobody documented produces no edge, and the
reason is visible as a smaller graph rather than as a plausible-looking guess.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from arachne.analyzer.paths import host_of, normalise_check_id

__all__ = [
    "MAX_SERVICES",
    "ServiceObservation",
    "services_from_candidates",
    "services_from_payloads",
]

#: Upper bound on the services one model carries. A /16 scan with a permissive port policy
#: would otherwise turn the graph into a combinatorial object; the cap is reported in the
#: model summary rather than silently applied.
MAX_SERVICES: Final = 4096

#: The evidence payload keys a reachability observation is read from.
_HOST_PORT_KEY: Final = "hosts"
_SERVICE_LIST_KEYS: Final = ("services", "versioned_services")
#: The keys a payload may name its host under, in the order they are preferred. ``asset`` is
#: the M6 correlation payload's name for the same thing.
_HOST_KEYS: Final = ("host", "asset", "target", "address")
_PORT_KEY: Final = "port"


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    """One service a scan observed answering, with the evidence that says so."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    #: The check whose evidence carried the observation — the model's provenance for it.
    source_check: str = ""
    #: The evidence row's id, when the caller has it. ``None`` for a hand-written lab model.
    evidence_id: int | None = None

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "source_check": self.source_check,
            "evidence_id": self.evidence_id,
        }


def _as_int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 < number < 65536 else None


def services_from_payloads(
    payloads: Iterable[tuple[Any, str, int | None]],
) -> tuple[ServiceObservation, ...]:
    """Read observations from ``(payload, check_id, evidence_id)`` triples.

    Deterministic: the result is sorted by ``(host, port, protocol)`` and de-duplicated, so
    the same estate always yields the same graph regardless of row order.
    """
    found: list[ServiceObservation] = []
    for payload, check_id, evidence_id in payloads:
        if not isinstance(payload, Mapping):
            continue
        found.extend(_from_host_map(payload, check_id, evidence_id))
        found.extend(_from_service_list(payload, check_id, evidence_id))
        found.extend(_from_single_service(payload, check_id, evidence_id))
    return _dedupe(found)


def services_from_candidates(candidates: Sequence[Any]) -> tuple[ServiceObservation, ...]:
    """Read observations from stored candidate rows.

    A row is anything with the store's shape — ``id``, ``check_key`` and an ``evidence``
    sequence whose items carry a redacted ``payload``.
    """
    triples: list[tuple[Any, str, int | None]] = []
    for record in candidates:
        check_id = str(getattr(record, "check_key", "") or "")
        evidence = getattr(record, "evidence", ()) or ()
        for item in evidence:
            payload = getattr(item, "payload", None)
            if payload is None and isinstance(item, Mapping):
                payload = item
            evidence_id = getattr(item, "id", None) if not isinstance(item, Mapping) else None
            triples.append((payload, check_id, evidence_id))
    return services_from_payloads(triples)


def _from_host_map(
    payload: Mapping[str, Any], check_id: str, evidence_id: int | None
) -> list[ServiceObservation]:
    """``{"hosts": {host: [ports]}}`` — the port scan's answering-ports map."""
    hosts = payload.get(_HOST_PORT_KEY)
    if not isinstance(hosts, Mapping):
        return []
    out: list[ServiceObservation] = []
    for raw_host, raw_ports in hosts.items():
        host = str(raw_host).strip()
        if not host or not isinstance(raw_ports, Sequence) or isinstance(raw_ports, str):
            continue
        for raw_port in raw_ports:
            port = _as_int(raw_port)
            if port is None:
                continue
            out.append(
                ServiceObservation(
                    host=host,
                    port=port,
                    protocol="tcp",
                    source_check=normalise_check_id(check_id),
                    evidence_id=evidence_id,
                )
            )
    return out


def _from_service_list(
    payload: Mapping[str, Any], check_id: str, evidence_id: int | None
) -> list[ServiceObservation]:
    """``{"services": [{host, port, protocol, service}]}`` — an inventory's named services."""
    out: list[ServiceObservation] = []
    for key in _SERVICE_LIST_KEYS:
        services = payload.get(key)
        if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
            continue
        for entry in services:
            observation = _from_service_entry(entry, check_id, evidence_id)
            if observation is not None:
                out.append(observation)
    return out


def _from_single_service(
    payload: Mapping[str, Any], check_id: str, evidence_id: int | None
) -> list[ServiceObservation]:
    """The per-service shape: a payload naming **both** the host and the port it reached.

    Requiring both keys is what keeps this from inventing topology: plenty of payloads mention
    a port (a URL, a policy, a comparison) and plenty mention a host, but a documented probe
    records the pair it reached — that is the fact the model is allowed to use.
    """
    if _PORT_KEY not in payload:
        return []
    for key in _HOST_KEYS:
        if key not in payload:
            continue
        raw_host = payload.get(key)
        if not isinstance(raw_host, str) or not raw_host.strip():
            continue
        observation = _from_service_entry(payload, check_id, evidence_id, host_key=key)
        if observation is not None:
            return [observation]
    return []


def _from_service_entry(
    entry: Any, check_id: str, evidence_id: int | None, *, host_key: str = "host"
) -> ServiceObservation | None:
    """One entry of a list shape, or a whole per-service payload."""
    if not isinstance(entry, Mapping):
        return None
    raw = entry.get(host_key)
    host = host_of(str(raw).strip()) if isinstance(raw, str) and raw.strip() else ""
    port = _as_int(entry.get(_PORT_KEY))
    if not host or port is None:
        return None
    protocol = str(entry.get("protocol") or "tcp").lower()
    name = str(entry.get("service") or entry.get("name") or "").strip() or None
    if name is None:
        product = str(entry.get("product") or "").strip()
        version = str(entry.get("version") or "").strip()
        name = " ".join(part for part in (product, version) if part) or None
    return ServiceObservation(
        host=host,
        port=port,
        protocol=protocol,
        service=name,
        source_check=normalise_check_id(check_id),
        evidence_id=evidence_id,
    )


def _dedupe(observations: Iterable[ServiceObservation]) -> tuple[ServiceObservation, ...]:
    """One observation per ``(host, port, protocol)``, keeping the most informative one."""
    best: dict[tuple[str, int, str], ServiceObservation] = {}
    for item in observations:
        key = (item.host, item.port, item.protocol)
        current = best.get(key)
        if current is None or (current.service is None and item.service is not None):
            best[key] = item
    ordered = sorted(best.values(), key=lambda item: (item.host, item.port, item.protocol))
    return tuple(ordered[:MAX_SERVICES])
