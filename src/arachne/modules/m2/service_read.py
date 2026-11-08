"""WP-33 · the shared read-only exposed-service probe helper (REQ-DET-026).

The requirement's scope is a catalogue of *management and data services that answer without
authentication* — IPMI/Redfish, the container daemon API, etcd, Consul, Vault, ZooKeeper,
Kafka, Elasticsearch, RabbitMQ, Jenkins, Grafana, Prometheus, Kibana, CouchDB, Redis and
memcached. Every one of them is a service where "just checking" is one call away from a
write: ``elasticsearch DELETE``, ``redis FLUSHALL``, a Kafka topic creation, a Jenkins job
trigger. The controlling decision of this work package is therefore the *shared helper*: the
reachability logic is written once here, and the only thing a check can send is an entry of a
closed, read-only vocabulary.

**Read-only is the control, and it is a closed allowlist.** Three facts are structural rather
than promised:

* :class:`ServiceReadProbe` carries **no request method at all** — an HTTP probe is a ``GET``
  by construction, because there is no field in which to name another verb. A wire probe names
  a *command*, and :data:`TCP_READ_COMMANDS` is the closed set of commands each protocol may
  receive; :meth:`ServiceReadProbe.__post_init__` refuses anything outside it. "The scanner
  sent a mutating command" is therefore unrepresentable rather than merely untested.
* :func:`http_url` and :func:`tcp_payload` refuse a probe object that is not a member of the
  family's declared table (:data:`ALL_PROBES`), so a check cannot smuggle a path or a command
  of its own invention into a request — the same guard the WP-31/32 cloud families use.
* The wire vocabulary is *read* commands only: ``INFO`` sections, memcached ``stats`` views
  and the ZooKeeper ``mntr`` four-letter word. The mutation vocabulary
  (:data:`MUTATING_COMMANDS`) exists so ``tests/unit/test_service_read.py`` can assert the
  read set is disjoint from it — it is the test's assertion list, never the runtime control.

**Exposure is "the service answered, unauthenticated".** A port that is open, a service on a
non-default port, or a service that answers a challenge is **not** an exposure (the pitfall is
explicit). A finding requires a ``2xx`` whose own content proves the service's document, a
wire reply that carries the protocol's own fields, and no authentication error anywhere in the
answer. A ``401``/``403`` (or a protocol auth error) is reported as a *non-finding* — the
service is there, and a caller who has not authenticated cannot read it.

**Nothing here writes, and nothing reads a secret.** No check names a mutation endpoint or a
value-returning call: the Redis ``INFO`` sections report the server's own counters, not stored
values; the memcached ``stats`` views report the daemon's configuration, not cached items; and
the CouchDB check reads the node configuration document's *own keys*, never a document. No
credential is used and no state changes anywhere on the target.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from arachne.core.http import HttpExchange
from arachne.core.net import TcpExchange
from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import NetworkInventory, ServiceRecord
from arachne.modules.m2.support import (
    inventory_or_skip,
    net_or_skip,
    services_of,
    skip_result,
    target_kinds_for_network_probes,
)

__all__ = [
    "ALL_PROBES",
    "HTTP_TRANSPORT",
    "MUTATING_COMMANDS",
    "TCP_READ_COMMANDS",
    "TCP_TRANSPORT",
    "ReadOutcome",
    "ServiceReadCheck",
    "ServiceReadError",
    "ServiceReadProbe",
    "http_url",
    "matching_services",
    "service_read_metadata",
    "tcp_payload",
]

#: The two transports a probe may use. ``http`` is a bounded ``GET`` through the shared scoped
#: client; ``tcp`` is one read command over the raw-network client.
HTTP_TRANSPORT: Final = "http"
TCP_TRANSPORT: Final = "tcp"
_TRANSPORTS: Final[frozenset[str]] = frozenset({HTTP_TRANSPORT, TCP_TRANSPORT})

#: The closed read vocabulary of the wire protocols, keyed by service. A command outside its
#: service's set cannot be represented; this *is* the control the requirement names.
TCP_READ_COMMANDS: Final[Mapping[str, frozenset[str]]] = {
    # The two INFO sections report the server's own replication topology and persistence
    # configuration. Neither returns a stored value.
    "redis": frozenset({"info replication", "info persistence"}),
    # memcached's read-only statistic views: the daemon's settings and its slab allocator.
    "memcached": frozenset({"stats settings", "stats slabs"}),
    # The ZooKeeper monitor four-letter word: version, role and connection counters.
    "zookeeper": frozenset({"mntr"}),
}

#: The mutation vocabulary the read set must be disjoint from. This is the *test's* assertion
#: list (``tests/unit/test_service_read.py``); the runtime control is the allowlist above, not
#: a denylist, exactly as the pitfalls require.
MUTATING_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        # Redis
        "append",
        "acl setuser",
        "auth",
        "bgsave",
        "bgrewriteaof",
        "client kill",
        "cluster",
        "config set",
        "config rewrite",
        "debug",
        "del",
        "discard",
        "eval",
        "exec",
        "expire",
        "flushall",
        "flushdb",
        "getset",
        "hset",
        "incr",
        "decr",
        "lpush",
        "rpush",
        "migrate",
        "monitor",
        "module",
        "move",
        "multi",
        "psubscribe",
        "publish",
        "rename",
        "replicaof",
        "restore",
        "sadd",
        "script load",
        "set",
        "shutdown",
        "slaveof",
        "sort",
        "subscribe",
        "swapdb",
        "unwatch",
        "watch",
        "xadd",
        "xdel",
        "zadd",
        # memcached
        "add",
        "cas",
        "delete",
        "flush_all",
        "prepend",
        "replace",
        "touch",
        "verbosity",
        "quit",
        # ZooKeeper (the AdminServer / four-letter administration words)
        "close",
        "conf",
        "cons",
        "crst",
        "create",
        "delquota",
        "dirs",
        "dump",
        "gtmk",
        "kill",
        "reconfig",
        "rmr",
        "setAcl",
        "setquota",
        "srst",
        "stmk",
        "sync",
        "wchc",
        "wchp",
    }
)

#: Hard cap on how many service instances of one kind a single check will probe. The inventory
#: is bounded, but this keeps one check's request estimate honest even on a large /16.
MAX_INSTANCES: Final = 8

#: HTTP statuses that answer "you are not authenticated". A service behind a challenge is not
#: an exposure, and these are the statuses that say so.
_AUTH_STATUSES: Final[frozenset[int]] = frozenset({401, 403})


class ServiceReadError(ValueError):
    """A probe is not one this build's read-only vocabulary permits."""


# --------------------------------------------------------------------------- the probe model
@dataclass(frozen=True, slots=True)
class ServiceReadProbe:
    """One read-only service probe: which service, over which transport, asking for what.

    There is deliberately **no method field**: an HTTP probe is a ``GET`` because the shape has
    nowhere to say otherwise, and a wire probe names a command that must be a member of
    :data:`TCP_READ_COMMANDS[service]`. ``paths`` is the small inventory of locations the
    document is commonly served at; ``command`` is the wire read. ``markers`` is the service's
    *own* content — the JSON keys or the protocol fields that prove the answer is that service's
    document and not a generic page or a soft 404.
    """

    service: str
    transport: str
    markers: tuple[str, ...]
    paths: tuple[str, ...] = ()
    command: str = ""
    auth_markers: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    scheme: str = "http"

    def __post_init__(self) -> None:
        if self.transport not in _TRANSPORTS:
            msg = (
                f"{self.service}: transport {self.transport!r} is not one of {sorted(_TRANSPORTS)}"
            )
            raise ServiceReadError(msg)
        if not self.markers:
            msg = f"{self.service}: a probe with no marker could never be confirmed"
            raise ServiceReadError(msg)
        if self.transport == HTTP_TRANSPORT:
            if self.command:
                msg = f"{self.service}: an HTTP probe may not carry a wire command"
                raise ServiceReadError(msg)
            if not self.paths or any(not path.startswith("/") for path in self.paths):
                msg = f"{self.service}: HTTP probe paths must be absolute (got {self.paths!r})"
                raise ServiceReadError(msg)
            if self.scheme not in {"http", "https"}:
                msg = f"{self.service}: scheme {self.scheme!r} is not http or https"
                raise ServiceReadError(msg)
        else:
            if self.paths:
                msg = f"{self.service}: a wire probe may not carry HTTP paths"
                raise ServiceReadError(msg)
            allowed = TCP_READ_COMMANDS.get(self.service, frozenset())
            if self.command not in allowed:
                msg = (
                    f"{self.service}: {self.command!r} is not a declared read command "
                    f"(allowed: {sorted(allowed)})"
                )
                raise ServiceReadError(msg)

    @property
    def key(self) -> str:
        target = ",".join(self.paths) if self.transport == HTTP_TRANSPORT else self.command
        return f"{self.service}:{self.transport}:{target}"


def http_url(probe: ServiceReadProbe, base: str, path: str) -> str:
    """The URL for one HTTP probe path, refusing anything but a declared ``GET`` probe."""
    if probe.transport != HTTP_TRANSPORT:
        msg = f"{probe.service}: {probe.transport} is not an HTTP probe"
        raise ServiceReadError(msg)
    if path not in probe.paths:
        msg = f"{probe.service}: path {path!r} is not part of this probe"
        raise ServiceReadError(msg)
    return base.rstrip("/") + path


def tcp_payload(probe: ServiceReadProbe) -> bytes:
    """The bytes one wire probe sends, built from the closed read vocabulary."""
    if probe.transport != TCP_TRANSPORT:
        msg = f"{probe.service}: {probe.transport} is not a wire probe"
        raise ServiceReadError(msg)
    allowed = TCP_READ_COMMANDS.get(probe.service, frozenset())
    if probe.command not in allowed:
        msg = f"{probe.service}: {probe.command!r} is not a declared read command"
        raise ServiceReadError(msg)
    parts = probe.command.split()
    if probe.service == "redis":
        # The RESP verb is the protocol's own upper-case form; the section name is kept as
        # declared. The command set is fixed, so this cannot introduce a verb of the caller's.
        return wire.redis_command(parts[0].upper(), *parts[1:])
    if probe.service == "memcached":
        return (probe.command + "\r\n").encode()
    # The ZooKeeper four-letter word is sent as-is; the server answers with a text report.
    return probe.command.encode()


# --------------------------------------------------------------------------- classification
@dataclass(frozen=True, slots=True)
class ReadOutcome:
    """What one probe established: the service's answer, classified.

    ``state`` is ``exposed`` (the service answered unauthenticated with its own document),
    ``authenticated`` (it is there but a challenge answered), ``absent`` (a ``2xx`` that is not
    the service's document, or a non-2xx) or ``refused`` (nothing came back at all).
    """

    state: str
    service: str
    target: str
    detail: str
    observed: dict[str, Any]
    evidence: tuple[Evidence, ...] = ()
    exchanges: tuple[Any, ...] = ()

    @property
    def exposed(self) -> bool:
        return self.state == "exposed"


def _marker_in(text: str, markers: Iterable[str]) -> str | None:
    lowered = text.lower()
    for marker in markers:
        if marker and marker.lower() in lowered:
            return marker
    return None


# --------------------------------------------------------------------------- reference data
#: Names a record can carry that identify no *product*: the fingerprinter's transport words
#: and the inventory's "nothing identified yet" placeholder. A record whose only names are
#: these is unnamed for matching purposes, so its port may stand in for its identity.
_PLACEHOLDER_NAMES: Final[frozenset[str]] = frozenset(
    {"", "unknown", "tcp", "udp", "http", "https", "tls", "ssl"}
)


# --------------------------------------------------------------------------- reference data
def _default_ports(probe: ServiceReadProbe) -> tuple[int, ...]:
    return probe.ports


def matching_services(
    inventory: NetworkInventory,
    asset: Any,
    probe: ServiceReadProbe,
) -> tuple[ServiceRecord, ...]:
    """The inventory services this probe applies to, in inventory order.

    A service matches when the fingerprinter or the port catalogue *named* the product (so a
    deployment on a non-default port is still probed) or when it sits on one of the service's
    documented default ports **and nothing else named it** (so a deployment whose banner was
    never read is probed too, without one service's default port dragging another service's
    check onto it — 8080 is both Jenkins' and the ZooKeeper AdminServer's default, and the
    record's own name, not the port, decides which check probes it).
    """
    wanted = probe.service.lower()
    ports = _default_ports(probe)
    seen: dict[str, ServiceRecord] = {}
    for record in services_of(inventory, asset):
        if record.protocol != "tcp":
            continue
        named = {
            record.effective_service.lower(),
            (record.service or "").lower(),
            (record.product or "").lower(),
        }
        identified_elsewhere = any(
            name and name not in _PLACEHOLDER_NAMES and name != wanted for name in named
        )
        if wanted in named or (record.port in ports and not identified_elsewhere):
            seen.setdefault(record.key, record)
        if len(seen) >= MAX_INSTANCES:
            break
    return tuple(seen.values())


# --------------------------------------------------------------------------- metadata
def service_read_metadata(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    compliance: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
) -> CheckMetadata:
    """One family check's metadata: L1, safe, active, read-only, default-on.

    The family's contract is uniform — an active read-only probe of a management or data
    service, gated by ``--active-checks`` and the attestation like every other M2 probe — so no
    member declares a credentials requirement (nothing here authenticates) and none requires a
    state-change attestation (nothing here changes state).

    The arguments are keyword-only on purpose: the research-coverage scanner
    (``modules/coverage.py``) attributes a ``research_ref`` to the nearest preceding ``name=``
    literal, so a factory whose check name is positional would hide its reference from the
    matrix — the defect WP-25 ... WP-30 recorded. Every call site writes ``name=``.
    """
    return CheckMetadata(
        id=f"m2.{name}",
        module="M2",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        target_kinds=(*target_kinds_for_network_probes(), TargetKind.URL),
        requires_active_checks=True,
        runs_on_discovered=True,
    )


# --------------------------------------------------------------------------- the base check
class ServiceReadCheck:
    """The family's shared shape: find the service, issue the read, classify, report.

    A concrete check is declared ``class X(ServiceReadCheck, NetworkCheck, Module)`` and sets
    its ``metadata`` and its ``probe``. This is a plain mixin (not a :class:`Module` subclass)
    for the same reason WP-30's ``_ServerCheck`` is: the base refuses to be created without
    metadata and a family base has none of its own.
    """

    metadata: ClassVar[CheckMetadata]
    #: The single read-only probe this check issues.
    probe: ClassVar[ServiceReadProbe]
    #: The candidate title; ``{target}`` is the probed URL or ``host:port``.
    finding_title: ClassVar[str] = "Service answers without authentication ({target})"

    def probes(self) -> tuple[ServiceReadProbe, ...]:
        return (self.probe,)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None
        probes = self.probes()
        if not probes:
            yield skip_result(ctx, "this check declares no read-only probe")
            return
        probe = probes[0]
        if probe.transport == TCP_TRANSPORT:
            _client, net_skip = net_or_skip(ctx)
            if net_skip is not None:
                yield net_skip
                return
        elif ctx.http is None:
            yield skip_result(
                ctx,
                "no HTTP client in this run: the probe needs a live scan "
                "(a dry run sends nothing — F-01-10)",
            )
            return

        records = matching_services(inventory, ctx.asset, probe)
        if not records:
            yield skip_result(
                ctx,
                f"no {probe.service} service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish services first)",
            )
            return

        outcomes: list[ReadOutcome] = []
        for record in records:
            outcomes.extend(await self._read(ctx, probe, record))

        findings = 0
        for outcome in outcomes:
            if outcome.exposed:
                findings += 1
                yield self._candidate(ctx, outcome)
            elif outcome.state == "authenticated":
                yield ctx.info(
                    f"{probe.service} on {outcome.target} requires authentication",
                    detail=outcome.detail,
                    confidence=0.9,
                    evidence=list(outcome.evidence),
                )
        if not findings:
            yield ctx.clean(
                f"no unauthenticated {probe.service} {self._surface()} found",
                detail=(
                    f"probed {len(records)} {probe.service} instance(s) on {ctx.asset.key}; "
                    "every answer was a challenge, an error or another document"
                ),
            )

    def _surface(self) -> str:
        return "service"

    async def _read(
        self, ctx: CheckContext, probe: ServiceReadProbe, record: ServiceRecord
    ) -> list[ReadOutcome]:
        if probe.transport == HTTP_TRANSPORT:
            return await self._read_http(ctx, probe, record)
        return await self._read_tcp(ctx, probe, record)

    async def _read_http(
        self, ctx: CheckContext, probe: ServiceReadProbe, record: ServiceRecord
    ) -> list[ReadOutcome]:
        http = ctx.http
        base = f"{probe.scheme}://{record.host}:{record.port}"
        outcomes: list[ReadOutcome] = []
        for path in probe.paths:
            url = http_url(probe, base, path)
            try:
                exchange = await http.get(url)
            except Exception as exc:  # a refused probe is data, not a crash
                record.probes += 1
                outcomes.append(
                    ReadOutcome(
                        state="refused",
                        service=probe.service,
                        target=_target(record),
                        detail=f"{url} could not be read ({exc.__class__.__name__})",
                        observed={"url": url, "error": exc.__class__.__name__},
                    )
                )
                continue
            record.probes += 1
            outcomes.append(_http_outcome(probe, record, url, exchange))
        return outcomes

    async def _read_tcp(
        self, ctx: CheckContext, probe: ServiceReadProbe, record: ServiceRecord
    ) -> list[ReadOutcome]:
        client = ctx.net
        if client is None:  # pragma: no cover - guarded by run()
            return []
        exchange = await client.tcp(record.host, record.port, payload=tcp_payload(probe), reads=1)
        record.probes += 1
        return [_tcp_outcome(probe, record, exchange)]

    def _candidate(self, ctx: CheckContext, outcome: ReadOutcome) -> CheckResult:
        return ctx.candidate(
            self.finding_title.format(target=outcome.target),
            detail=outcome.detail,
            confidence=0.9,
            evidence=[
                *outcome.evidence,
                Evidence.of(
                    "artifact",
                    {
                        "signal": "service-exposure",
                        "family": "exposed-service",
                        "service": outcome.service,
                        "target": outcome.target,
                        "anonymous": True,
                        "read_only": True,
                        "state_changed": False,
                        **outcome.observed,
                    },
                    source=outcome.target,
                ),
            ],
        )


def _target(record: ServiceRecord) -> str:
    return f"{record.host}:{record.port}"


def _http_outcome(
    probe: ServiceReadProbe,
    record: ServiceRecord,
    url: str,
    exchange: HttpExchange,
) -> ReadOutcome:
    status = int(exchange.status_code)
    request_evidence, response_evidence = exchange.to_evidence()
    evidence = (request_evidence, response_evidence)
    observed: dict[str, Any] = {
        "url": url,
        "status": status,
        "content_type": exchange.header("content-type", "") or "",
        "bytes": len(exchange.body),
        "command_issued": False,
    }
    if status in _AUTH_STATUSES:
        challenge = exchange.header("www-authenticate", "") or ""
        return ReadOutcome(
            state="authenticated",
            service=probe.service,
            target=_target(record),
            detail=(
                f"{url} answered HTTP {status}"
                + (f" ({challenge[:80]})" if challenge else "")
                + "; the service is reachable but a caller who has not authenticated cannot "
                "read it"
            ),
            observed={**observed, "challenge": challenge},
            evidence=evidence,
            exchanges=(exchange,),
        )
    if not exchange.ok:
        return ReadOutcome(
            state="absent",
            service=probe.service,
            target=_target(record),
            detail=f"{url} answered HTTP {status}",
            observed=observed,
            evidence=evidence,
            exchanges=(exchange,),
        )
    auth_marker = _marker_in(exchange.body, probe.auth_markers)
    if auth_marker is not None:
        return ReadOutcome(
            state="authenticated",
            service=probe.service,
            target=_target(record),
            detail=f"{url} answered a login challenge (marker {auth_marker!r})",
            observed={**observed, "auth_marker": auth_marker},
            evidence=evidence,
            exchanges=(exchange,),
        )
    marker = _marker_in(exchange.body, probe.markers)
    if marker is None:
        return ReadOutcome(
            state="absent",
            service=probe.service,
            target=_target(record),
            detail=(
                f"{url} answered HTTP {status} but did not carry the service's own document "
                "(no marker matched): a different service, a soft 404 or a proxy page"
            ),
            observed=observed,
            evidence=evidence,
            exchanges=(exchange,),
        )
    return ReadOutcome(
        state="exposed",
        service=probe.service,
        target=_target(record),
        detail=(
            f"{url} returned HTTP {status} and the service's own document without any "
            f"credential (marker {marker!r}); nothing was written, changed or executed"
        ),
        observed={**observed, "marker": marker},
        evidence=evidence,
        exchanges=(exchange,),
    )


def _tcp_outcome(
    probe: ServiceReadProbe,
    record: ServiceRecord,
    exchange: TcpExchange,
) -> ReadOutcome:
    observed: dict[str, Any] = {
        "host": record.host,
        "port": record.port,
        "command": probe.command,
        "state": exchange.state,
        "command_issued": False,
    }
    evidence = (
        Evidence.of(
            "note",
            {
                "service": record.evidence_payload(),
                "probe": "read-only command",
                "command": probe.command,
            },
            source=record.key,
        ),
    )
    if not exchange.is_open:
        return ReadOutcome(
            state="refused",
            service=probe.service,
            target=_target(record),
            detail=f"{_target(record)} did not answer ({exchange.state})",
            observed=observed,
            evidence=evidence,
        )
    text = exchange.banner_text(limit=8192)
    observed["bytes"] = len(exchange.banner)
    error = _wire_auth_error(probe.service, text)
    if error is not None:
        return ReadOutcome(
            state="authenticated",
            service=probe.service,
            target=_target(record),
            detail=f"{_target(record)} refused the read command unauthenticated ({error})",
            observed={**observed, "error": error},
            evidence=evidence,
        )
    marker = _marker_in(text, probe.markers)
    if marker is None:
        return ReadOutcome(
            state="absent",
            service=probe.service,
            target=_target(record),
            detail=(
                f"{_target(record)} answered the read command but not with "
                f"{probe.service}'s own fields"
            ),
            observed={**observed, "response": text[:256]},
            evidence=evidence,
        )
    return ReadOutcome(
        state="exposed",
        service=probe.service,
        target=_target(record),
        detail=(
            f"{_target(record)} served {probe.command!r} without any credential "
            f"(marker {marker!r}); nothing was written, flushed or executed"
        ),
        observed={**observed, "marker": marker},
        evidence=evidence,
    )


def _wire_auth_error(service: str, text: str) -> str | None:
    """A protocol's own "you are not authenticated" answer, or ``None``."""
    if service == "redis":
        stripped = text.strip()
        if stripped.startswith("-") and any(
            word in stripped.upper() for word in ("NOAUTH", "WRONGPASS", "NOPERM")
        ):
            return stripped[:120]
    if service == "memcached":
        upper = text.upper()
        if (
            "CLIENT_ERROR" in upper
            or "AUTHENTICATION" in upper
            or upper.strip().startswith("ERROR")
        ):
            return text.strip()[:120]
    if service == "zookeeper":
        upper = text.upper()
        if "NOT ALLOWED" in upper or "AUTHENTICATION" in upper:
            return text.strip()[:120]
    return None


#: The union of every probe the shipped family declares. Populated by the checks module at
#: import (``exposed_services.declare_probes``), so the guard below knows the whole table
#: without this helper importing the checks back.
ALL_PROBES: set[ServiceReadProbe] = set()


def declare_probes(probes: Sequence[ServiceReadProbe]) -> None:
    """Register the family's probes, refusing a duplicate identity."""
    for probe in probes:
        if probe in ALL_PROBES:
            msg = f"{probe.key} is declared twice"
            raise ServiceReadError(msg)
        ALL_PROBES.add(probe)
