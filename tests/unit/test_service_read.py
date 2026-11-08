"""The WP-33 shared read-only service probe helper (REQ-DET-026).

The requirement's third deliverable is "a shared read-only probe helper, so the reachability
logic is written once and tested once", and its exit criterion is that "the shared helper
enforces it, and a test asserts the helper's command vocabulary is read-only". These are those
tests, plus the classification behaviour the whole family depends on:

* the closed allowlist refuses anything that is not a declared read — an HTTP path outside the
  probe, a wire command outside its protocol's vocabulary, a probe whose transport is unknown;
* the wire vocabulary is disjoint from every mutating command, and every command it holds opens
  with a read verb;
* the reachability decision: a ``2xx`` carrying the service's own marker is exposed, a ``401``
  (or a protocol auth error) is *not*, and a ``2xx`` that is some other document is not either;
* matching: a service is found by its identified name (so a non-default port is still probed)
  or by a documented default port when nothing named it — and never by a port another service
  has already claimed.
"""

from __future__ import annotations

import pytest
from tests.helpers.checks import make_m2_harness
from tests.lab.service_lab import HOST, build_fixture, default_ports, wire_fixture

from arachne.modules.m2 import wire
from arachne.modules.m2.exposed_services import ExposedServiceChecks, probe_of
from arachne.modules.m2.service_read import (
    ALL_PROBES,
    HTTP_TRANSPORT,
    MUTATING_COMMANDS,
    TCP_READ_COMMANDS,
    TCP_TRANSPORT,
    ServiceReadError,
    ServiceReadProbe,
    http_url,
    matching_services,
    tcp_payload,
)

pytestmark = pytest.mark.usefixtures("_reset_arachne_logging")


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in ExposedServiceChecks}


async def _run(check_id: str, harness: object) -> list[object]:
    check = _by_id()[check_id]
    context = harness.context(check)  # type: ignore[attr-defined]
    return [result async for result in context.module.run(context)]


def _findings(results: list[object]) -> list[object]:
    return [result for result in results if result.status == "vulnerable"]  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- the allowlist
def test_a_wire_command_outside_the_vocabulary_is_unrepresentable() -> None:
    for service, commands in TCP_READ_COMMANDS.items():
        for command in commands:
            probe = ServiceReadProbe(
                service=service, transport=TCP_TRANSPORT, command=command, markers=("x",)
            )
            assert probe.command == command
    for bad in ("flushall", "set", "config set", "delete", "shutdown", "rmr", "quit"):
        with pytest.raises(ServiceReadError):
            ServiceReadProbe(service="redis", transport=TCP_TRANSPORT, command=bad, markers=("x",))
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(
            service="no-such-service", transport=TCP_TRANSPORT, command="mntr", markers=("x",)
        )


def test_an_http_probe_carries_no_command_and_a_wire_probe_carries_no_path() -> None:
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(
            service="etcd",
            transport=HTTP_TRANSPORT,
            paths=("/version",),
            command="get",
            markers=("x",),
        )
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(
            service="redis",
            transport=TCP_TRANSPORT,
            command="info server",
            paths=("/",),
            markers=("x",),
        )
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(service="etcd", transport="gopher", markers=("x",))  # type: ignore[arg-type]
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(
            service="etcd", transport=HTTP_TRANSPORT, paths=("relative",), markers=("x",)
        )
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(service="etcd", transport=HTTP_TRANSPORT, paths=("/version",), markers=())


def test_the_helper_has_no_request_method_field() -> None:
    """A verb is unrepresentable: the probe shape has nowhere to name one."""
    fields = set(ServiceReadProbe.__dataclass_fields__)
    assert "method" not in fields
    assert "verb" not in fields
    assert "headers" not in fields or "body" not in fields


def test_http_url_refuses_a_path_that_is_not_part_of_the_probe() -> None:
    probe = ServiceReadProbe(
        service="etcd", transport=HTTP_TRANSPORT, paths=("/version",), markers=("etcdserver",)
    )
    assert http_url(probe, "http://10.0.0.1:2379", "/version") == "http://10.0.0.1:2379/version"
    with pytest.raises(ServiceReadError):
        http_url(probe, "http://10.0.0.1:2379", "/v2/keys/?recursive=true")
    with pytest.raises(ServiceReadError):
        http_url(probe, "http://10.0.0.1:2379", "/version/")


def test_tcp_payload_refuses_a_non_wire_probe() -> None:
    probe = ServiceReadProbe(
        service="etcd", transport=HTTP_TRANSPORT, paths=("/version",), markers=("etcdserver",)
    )
    with pytest.raises(ServiceReadError):
        tcp_payload(probe)


def test_the_read_vocabulary_is_read_only() -> None:
    """The exit criterion's test: no command in the allowlist is a mutating one."""
    mutation_payloads = {command.encode() for command in MUTATING_COMMANDS}
    for service, commands in TCP_READ_COMMANDS.items():
        lowered = {command.lower() for command in commands}
        assert not (lowered & {command.lower() for command in MUTATING_COMMANDS}), service
        for command in commands:
            head = command.split()[0].lower()
            assert head in {"info", "stats", "mntr"}, (service, command)
            # The payload the helper builds never *is* a mutating command: the leading token
            # is the read verb, and the whole payload matches no mutation.
            payload = tcp_payload(
                ServiceReadProbe(
                    service=service, transport=TCP_TRANSPORT, command=command, markers=("x",)
                )
            )
            assert head.encode() in payload.lower(), (service, command)
            assert payload not in mutation_payloads, (service, command)


def test_the_family_probes_are_all_registered_and_unique() -> None:
    probes = [probe_of(check) for check in ExposedServiceChecks]
    assert len(probes) == len(set(probes)) == len(ALL_PROBES)
    for probe in probes:
        assert probe in ALL_PROBES


def test_redis_and_memcached_payloads_are_the_protocol_reads() -> None:
    redis = ServiceReadProbe(
        service="redis", transport=TCP_TRANSPORT, command="info replication", markers=("role:",)
    )
    assert tcp_payload(redis) == wire.redis_command("INFO", "replication")
    memcached = ServiceReadProbe(
        service="memcached", transport=TCP_TRANSPORT, command="stats settings", markers=("STAT",)
    )
    assert tcp_payload(memcached) == b"stats settings\r\n"
    zookeeper = ServiceReadProbe(
        service="zookeeper", transport=TCP_TRANSPORT, command="mntr", markers=("zk_version",)
    )
    assert tcp_payload(zookeeper) == b"mntr"


# --------------------------------------------------------------------------- matching
def test_a_service_is_matched_by_name_on_a_non_default_port() -> None:
    """The pitfall: a service identified on a non-default port is still probed (and then judged)."""
    harness = make_m2_harness(seed_services=[(49999, "redis")])
    probe = probe_of(_by_id()["m2.redis-replication-exposed"])
    records = matching_services(harness.inventory, harness.asset, probe)
    assert [record.port for record in records] == [49999]


def test_an_unnamed_service_is_matched_by_its_default_port() -> None:
    harness = make_m2_harness(seed_services=[(6379, "")])
    probe = probe_of(_by_id()["m2.redis-replication-exposed"])
    assert matching_services(harness.inventory, harness.asset, probe)


def test_a_port_claimed_by_another_named_service_is_never_probed() -> None:
    """8080 is both Jenkins' and the ZooKeeper AdminServer's default: the name decides."""
    harness = make_m2_harness(seed_services=[(8080, "jenkins")])
    zookeeper = probe_of(_by_id()["m2.zookeeper-admin-stat-exposed"])
    assert matching_services(harness.inventory, harness.asset, zookeeper) == ()
    jenkins = probe_of(_by_id()["m2.jenkins-api-exposed"])
    assert [
        record.port for record in matching_services(harness.inventory, harness.asset, jenkins)
    ] == [8080]


# --------------------------------------------------------------------------- classification
@pytest.mark.parametrize(
    ("check_id", "service"),
    [
        ("m2.etcd-version-exposed", "etcd"),
        ("m2.elasticsearch-cluster-exposed", "elasticsearch"),
        ("m2.redis-replication-exposed", "redis"),
        ("m2.memcached-settings-exposed", "memcached"),
    ],
)
def test_bare_installation_is_a_finding_and_hardened_is_not(check_id: str, service: str) -> None:
    import asyncio

    bare = wire_fixture(build_fixture(service, "bare"))
    hardened = wire_fixture(build_fixture(service, "hardened"))
    assert _findings(asyncio.run(_run(check_id, bare.harness)))
    assert not _findings(asyncio.run(_run(check_id, hardened.harness)))
    statuses = {result.status for result in asyncio.run(_run(check_id, hardened.harness))}
    assert "vulnerable" not in statuses


def test_an_http_answer_that_is_a_different_document_is_not_a_finding() -> None:
    import asyncio

    harness = make_m2_harness(
        seed_services=[(2379, "etcd")],
        http_routes=[
            {
                "url": f"http://{HOST}:2379/version",
                "status": 200,
                "body": '{"detail":"Not Found"}',
                "headers": {"content-type": "application/json"},
            }
        ],
    )
    results = asyncio.run(_run("m2.etcd-version-exposed", harness))
    assert not _findings(results)
    assert any(result.status == "not_vulnerable" for result in results)


def test_a_wire_read_answered_with_an_auth_error_is_not_a_finding() -> None:
    import asyncio

    harness = make_m2_harness(seed_services=[(6379, "redis")])
    harness.transport.routes[("tcp", HOST, 6379)] = b"-NOAUTH Authentication required.\r\n"
    results = asyncio.run(_run("m2.redis-replication-exposed", harness))
    assert not _findings(results)
    assert any("requires authentication" in result.title for result in results)


def test_default_ports_are_declared_for_every_service() -> None:
    from tests.lab.service_lab import SERVICES

    for service in SERVICES:
        assert default_ports(service), service
        # Every default port a check declares is a real TCP port.
        assert all(0 < port < 65536 for port in default_ports(service)), service
