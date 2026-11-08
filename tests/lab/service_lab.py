"""The exposed-service lab (WP-33, REQ-DET-026).

The requirement's decoy is explicit — "the same services, on non-default ports and behind
authentication" — and this fixture implements exactly that as *data*: for each of the sixteen
services the WP-33 family covers, a **bare** installation (the service on its documented
default port, answering an unauthenticated caller with its own document) and a **hardened**
one (the same service name, on a non-default ephemeral port, behind a challenge).

The fixture is a recorded response set rather than a set of sockets, because that is how M2's
checks are driven (the ``make_m2_harness`` helper in ``tests/helpers/checks.py``): an HTTP
service is a table of
``(url, status, body)`` recordings the shared scoped client replays, and a wire service is a
scripted reply for the raw-network client. The important property a real server would add —
"what did the check actually send?" — is preserved: the harness's transport records every
probe, and the fixture's wire replies are answered by callables that capture the exact bytes
the check put on the wire, so a test can assert the command vocabulary directly.

Three fixture shapes exist beyond the two modes:

``bare``
    the positive: the service's own document, unauthenticated, on the default port.
``hardened``
    **the requirement's decoy**: a ``401`` with a challenge (HTTP) or the protocol's own
    auth-required error (wire), on a non-default port. A check that fired on a status code, on
    a port being open, or on the path merely existing reports this installation as vulnerable.
``echo-404``
    the pitfall's own trap: every path answers ``200 OK`` with a short body that echoes the
    requested path, so a check whose marker is a substring of the path it probes fires here.

Nothing in this file authenticates, accepts a body, starts anything or writes anything: the
hardened wire replies are the protocols' *refusals*, and the bare ones are the daemons' own
read-only statistic or status documents.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from arachne.modules.m2.exposed_services import ExposedServiceChecks, probe_of
from arachne.modules.m2.service_read import ServiceReadProbe

__all__ = [
    "HOST",
    "MODES",
    "SERVICES",
    "ServiceFixture",
    "WiredFixture",
    "build_fixture",
    "default_ports",
    "echo_routes",
    "fixtures",
    "published_paths",
    "wire_fixture",
]

#: The address every fixture is reached at (the harness's asset value).
HOST = "93.184.216.34"

#: The three modes. The first is the positive, the second the requirement's decoy, the third
#: the echoing soft-404 the pitfalls warn about.
MODES: tuple[str, ...] = ("bare", "hardened", "echo-404")

#: The sixteen services the requirement names, in the family's own order.
SERVICES: tuple[str, ...] = tuple(
    dict.fromkeys(probe_of(check).service for check in ExposedServiceChecks)
)

#: The port each hardened installation is published on. All above the ephemeral floor, so no
#: service's non-default port can collide with another service's documented default.
_HARDENED_BASE = 49152


def _probes_of(service: str) -> tuple[ServiceReadProbe, ...]:
    return tuple(
        probe_of(check) for check in ExposedServiceChecks if probe_of(check).service == service
    )


def default_ports(service: str) -> tuple[int, ...]:
    """Every documented default port the family's checks for ``service`` name."""
    ports: list[int] = []
    for probe in _probes_of(service):
        for port in probe.ports:
            if port not in ports:
                ports.append(port)
    return tuple(ports)


def _port_for(service: str, mode: str) -> int:
    """The port a fixture names for one service in one mode."""
    if mode == "bare":
        return default_ports(service)[0]
    return _HARDENED_BASE + SERVICES.index(service)


@dataclass(frozen=True, slots=True)
class ServiceFixture:
    """One installation: the inventory it seeds, the HTTP recordings and the wire replies."""

    service: str
    mode: str
    port: int
    #: ``(port, service_name)`` pairs the inventory is seeded with.
    records: tuple[tuple[int, str], ...]
    #: Recorded HTTP responses, keyed by the URL the check will build.
    http_routes: tuple[Mapping[str, Any], ...] = ()
    #: Scripted wire replies, keyed by the *commanded* payload's command string. The value is
    #: a callable-free constant reply; the harness records the request payload separately.
    tcp_replies: Mapping[str, bytes] = field(default_factory=dict)
    #: The endpoints this installation publishes (a finding's target must be one of these).
    paths: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.service}/{self.mode}"


def _json(body: str) -> dict[str, str]:
    return {"headers": {"content-type": "application/json"}}


def _text(body: str) -> dict[str, str]:
    return {"headers": {"content-type": "text/plain"}}


#: The bare installations: for each service, the endpoints its checks read and the document
#: each one answers with. Every body is the service's own shape, so a check's marker is a real
#: field of the document rather than a word the fixture was written to contain.
_BARE_HTTP: Mapping[str, Mapping[str, tuple[str, dict[str, str]]]] = {
    "redfish": {
        "/redfish/v1/": (
            '{"@odata.type":"#ServiceRoot.v1_5_0.ServiceRoot","Id":"RootService",'
            '"Name":"Root Service","RedfishVersion":"1.6.0","UUID":"92384634"}',
            _json(""),
        ),
        "/redfish/v1/Systems": (
            '{"@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",'
            '"Name":"Computer System Collection","Members@odata.count":1,'
            '"Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}',
            _json(""),
        ),
    },
    "container-daemon": {
        "/info": (
            '{"ID":"FIXTURE","ServerVersion":"25.0.3","Containers":3,"ContainersRunning":3,'
            '"DockerRootDir":"/var/lib/docker","Plugins":{"Volume":["local"]}}',
            _json(""),
        ),
    },
    "etcd": {
        "/version": ('{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}', _json("")),
        "/v2/members": (
            '{"members":[{"id":"8e9e05c52164694d","name":"etcd-1",'
            '"peerURLs":["http://10.0.0.1:2380"],"clientURLs":["http://10.0.0.1:2379"]}]}',
            _json(""),
        ),
    },
    "consul": {
        "/v1/catalog/services": (
            '{"consul":[],"web":["passing"],"payments":["passing"]}',
            _json(""),
        ),
        "/v1/kv/?keys": (
            '["acme/config/database","acme/feature-flags","acme/registry/dsn"]',
            _json(""),
        ),
    },
    "vault": {
        "/v1/sys/seal-status": (
            '{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"progress":0,'
            '"nonce":"","version":"1.13.0"}',
            _json(""),
        ),
        "/v1/sys/auth": (
            '{"token/":{"type":"token","description":"token based credentials","config":{}},'
            '"approle/":{"type":"approle","description":"","config":{}}}',
            _json(""),
        ),
    },
    "zookeeper": {
        "/commands/stat": (
            "Zookeeper version: 3.8.1-0000000000, built on 2022-01-01\n"
            "Clients:\n /10.0.0.7:52344[1](queued=0,recved=12,sent=12)\n"
            "Latency min/avg/max: 0/0/3\nReceived: 24\nSent: 23\nConnections: 1\n"
            "Outstanding: 0\nZxid: 0x1a\nMode: standalone\nNode count: 6\n",
            _text(""),
        ),
    },
    "kafka": {
        "/topics": ('["orders","payments","shipments"]', _json("")),
        "/brokers": ('{"brokers":[{"host":"kafka-1","port":9092,"rack":"r1"}]}', _json("")),
    },
    "elasticsearch": {
        "/_cluster/health": (
            '{"cluster_name":"acme","status":"yellow","timed_out":false,"number_of_nodes":3}',
            _json(""),
        ),
        "/_cat/nodes?format=json": (
            '[{"ip":"10.0.0.2","heap.percent":"41","ram.percent":"62","node.role":"dim",'
            '"name":"es-1"}]',
            _json(""),
        ),
    },
    "rabbitmq": {
        "/api/queues": (
            '[{"vhost":"/","name":"orders","messages":42,"durable":true}]',
            _json(""),
        ),
        "/api/nodes": (
            '[{"name":"rabbit@node1","type":"disc","running":true,"mem_used":1048576,'
            '"proc_used":230}]',
            _json(""),
        ),
    },
    "jenkins": {
        "/api/json": (
            '{"assignedLabels":[{"name":"built-in"}],"jobs":[{"name":"deploy-prod",'
            '"url":"/job/deploy-prod/","color":"blue"}]}',
            _json(""),
        ),
        "/computer/api/json": (
            '{"computer":[{"displayName":"built-in","executors":[{"idle":true}]}]}',
            _json(""),
        ),
    },
    "grafana": {
        "/api/datasources": (
            '[{"id":1,"uid":"prom","name":"prom","type":"prometheus","url":'
            '"http://prom:9090","access":"proxy","isDefault":true,"basicAuth":false}]',
            _json(""),
        ),
        "/api/search": (
            '[{"id":1,"uid":"d1","title":"API latency","type":"dash-db",'
            '"url":"/d/d1/api-latency","tags":["api"]}]',
            _json(""),
        ),
    },
    "prometheus": {
        "/api/v1/targets": (
            '{"status":"success","data":{"activeTargets":[{"scrapeUrl":'
            '"http://10.0.0.9:9100/metrics","health":"up","labels":{}}],"droppedTargets":[]}}',
            _json(""),
        ),
        "/api/v1/status/config": (
            '{"status":"success","data":{"yaml":"global:\\n  scrape_interval: 15s\\n"}}',
            _json(""),
        ),
    },
    "kibana": {
        "/api/saved_objects/_find?type=dashboard": (
            '{"page":1,"per_page":20,"total":1,"saved_objects":[{"id":"x","type":"dashboard",'
            '"attributes":{"title":"Overview"}}]}',
            _json(""),
        ),
        "/api/spaces/space": (
            '[{"id":"default","name":"Default","initials":"D","description":"",'
            '"disabledFeatures":[]}]',
            _json(""),
        ),
    },
    "couchdb": {
        "/_node/_local/_config": (
            '{"httpd":{"port":"5984","bind_address":"0.0.0.0"},'
            '"couchdb":{"database_dir":"/opt/couchdb/data","uuid":"fixture"},"log":'
            '{"level":"info"}}',
            _json(""),
        ),
        "/_session": (
            '{"ok":true,"userCtx":{"name":null,"roles":["_admin"]},"info":'
            '{"authentication_handlers":["cookie","default"],"authenticated":"default"}}',
            _json(""),
        ),
    },
}

#: The bare wire replies, keyed by the read command the check sends.
_BARE_TCP: Mapping[str, Mapping[str, bytes]] = {
    "redis": {
        "info replication": (
            b"# Replication\r\nrole:master\r\nconnected_slaves:1\r\n"
            b"slave0:ip=10.0.0.5,port=6379,state=online,offset=1234,lag=0\r\n"
        ),
        "info persistence": (
            b"# Persistence\r\nloading:0\r\nrdb_changes_since_last_save:12\r\n"
            b"aof_enabled:0\r\nrdb_last_save_time:1700000000\r\n"
        ),
    },
    "memcached": {
        "stats settings": (
            b"STAT maxbytes 67108864\r\nSTAT maxconns 1024\r\nSTAT evictions on\r\nEND\r\n"
        ),
        "stats slabs": b"STAT active_slabs 3\r\nSTAT total_malloced 3145728\r\nEND\r\n",
    },
    "zookeeper": {
        "mntr": (
            b"zk_version\t3.8.1-0000000000, built on 2022-01-01\n"
            b"zk_server_state\tstandalone\nzk_avg_latency\t0\nzk_num_alive_connections\t1\n"
        ),
    },
}

#: The hardened wire replies: each protocol's own "you are not authenticated" answer.
_HARDENED_TCP: Mapping[str, bytes] = {
    "redis": b"-NOAUTH Authentication required.\r\n",
    "memcached": b"CLIENT_ERROR authentication required\r\n",
    "zookeeper": b"Authentication is not valid : /\n",
}

#: The challenge a hardened HTTP service answers every published path with.
_CHALLENGE_BODY = (
    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body>"
    "<h1>Unauthorized</h1></body></html>"
)


def _bare_fixture(service: str) -> ServiceFixture:
    port = _port_for(service, "bare")
    http: list[Mapping[str, Any]] = []
    paths: list[str] = []
    for path, (body, extra) in _BARE_HTTP.get(service, {}).items():
        http.append(
            {
                "url": f"http://{HOST}:{port}{path}",
                "status": 200,
                "body": body,
                "headers": dict(extra.get("headers") or {}),
            }
        )
        paths.append(path)
    replies = _BARE_TCP.get(service, {})
    return ServiceFixture(
        service=service,
        mode="bare",
        port=port,
        records=((port, service),),
        http_routes=tuple(http),
        tcp_replies=dict(replies),
        paths=tuple(paths),
    )


def _hardened_fixture(service: str) -> ServiceFixture:
    port = _port_for(service, "hardened")
    http: list[Mapping[str, Any]] = []
    paths: list[str] = []
    for path in _BARE_HTTP.get(service, {}):
        http.append(
            {
                "url": f"http://{HOST}:{port}{path}",
                "status": 401,
                "body": _CHALLENGE_BODY,
                "headers": {
                    "content-type": "text/html",
                    "www-authenticate": 'Basic realm="management"',
                },
            }
        )
        paths.append(path)
    replies = _HARDENED_TCP.get(service)
    tcp = dict.fromkeys(_BARE_TCP.get(service, {}), replies) if replies is not None else {}
    return ServiceFixture(
        service=service,
        mode="hardened",
        port=port,
        records=((port, service),),
        http_routes=tuple(http),
        tcp_replies=tcp,
        paths=tuple(paths),
    )


def echo_routes(service: str, *, port: int | None = None) -> tuple[Mapping[str, Any], ...]:
    """The echoing soft-404 trap: every published path answers 200 and echoes the path.

    Deliberately short so it is not similar to any not-found reference; a check whose marker is
    a substring of the path it probes is the only thing that can fire here.
    """
    port = port if port is not None else _port_for(service, "bare")
    return tuple(
        {
            "url": f"http://{HOST}:{port}{path}",
            "status": 200,
            "body": f"Not found: {path}\n",
            "headers": {"content-type": "text/plain"},
        }
        for path in _BARE_HTTP.get(service, {})
    )


def _echo_fixture(service: str) -> ServiceFixture:
    port = _port_for(service, "bare")
    replies = {
        command: b"Not found: " + command.encode() + b"\n" for command in _BARE_TCP.get(service, {})
    }
    return ServiceFixture(
        service=service,
        mode="echo-404",
        port=port,
        records=((port, service),),
        http_routes=echo_routes(service, port=port),
        tcp_replies=replies,
        paths=tuple(_BARE_HTTP.get(service, {})),
    )


def build_fixture(service: str, mode: str) -> ServiceFixture:
    """One installation of ``service`` in ``mode``."""
    if service not in SERVICES:
        raise ValueError(f"unknown service {service!r}; expected one of {SERVICES}")
    if mode == "bare":
        return _bare_fixture(service)
    if mode == "hardened":
        return _hardened_fixture(service)
    if mode == "echo-404":
        return _echo_fixture(service)
    raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")


def fixtures(modes: Iterable[str] = MODES) -> tuple[ServiceFixture, ...]:
    """Every service in every requested mode, in the family's order."""
    return tuple(build_fixture(service, mode) for mode in modes for service in SERVICES)


def published_paths() -> Mapping[str, tuple[str, ...]]:
    """``{service: its published endpoints}`` — the acceptance test's own control table."""
    return {service: tuple(_BARE_HTTP.get(service, {})) for service in SERVICES}


@dataclass
class WiredFixture:
    """A fixture applied to a scripted M2 harness, plus the bytes the checks put on the wire."""

    fixture: ServiceFixture
    harness: Any
    #: Every payload the raw-network client was handed (the read-only vocabulary, observed).
    sent: list[bytes] = field(default_factory=list)


def wire_fixture(fixture: ServiceFixture, *, host: str = HOST) -> WiredFixture:
    """Build an M2 harness that serves ``fixture`` and records what the checks send.

    The HTTP side is the fixture's recorded responses. The wire side is a per-port dispatcher
    keyed by the exact payload the shared helper builds for each declared read command, so a
    check that sent anything else would get an empty answer (and, more importantly, would show
    up in ``sent`` where the acceptance test asserts the vocabulary).
    """
    from tests.helpers.checks import make_m2_harness

    from arachne.modules.m2.service_read import tcp_payload

    harness = make_m2_harness(
        host=host,
        seed_services=list(fixture.records),
        http_routes=fixture.http_routes,
    )
    sent: list[bytes] = []
    replies: dict[bytes, bytes] = {}
    if fixture.tcp_replies:
        for check in ExposedServiceChecks:
            probe = probe_of(check)
            if probe.service != fixture.service or probe.transport != "tcp":
                continue
            reply = fixture.tcp_replies.get(probe.command)
            if reply is not None:
                replies[tcp_payload(probe)] = reply

    def dispatch(payload: bytes | None) -> bytes:
        sent.append(payload or b"")
        return replies.get(payload or b"", b"")

    for port in {port for port, _ in fixture.records}:
        harness.transport.routes[("tcp", host, port)] = dispatch
    return WiredFixture(fixture=fixture, harness=harness, sent=sent)
