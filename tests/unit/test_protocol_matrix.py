"""The protocol matrix and its cross-reference (REQ-DET-010).

The requirement's whole point is that a capability cannot *appear* to exist: a protocol
named in a port catalogue, a probe table or a protocol set must have an implementing check
or be explicitly marked. These tests drive the cross-reference against the **live**
surfaces — the loaded catalogue, the datastore dispatcher's table, the probe vocabulary and
the registry — and then break each surface on purpose to prove the checker bites.
"""

from __future__ import annotations

from typing import get_args

import pytest

from arachne.modules.m2.catalog import PortCatalog, PortEntry, ProbeName, load_port_catalog
from arachne.modules.m2.datastores import (
    DATASTORE_PROTOCOLS,
    HTTP_DATASTORE_PORTS,
    PROTOCOL_PORTS,
    PROTOCOL_PROBES,
    datastore_protocol_for,
)
from arachne.modules.m2.inventory import ServiceIdentity, ServiceRecord
from arachne.modules.protocol_matrix import (
    MATRIX_VERSION,
    PROTOCOL_MATRIX,
    ProtocolEntry,
    by_protocol,
    matrix_states,
    problems,
    to_dict,
)
from arachne.modules.registry import ModuleRegistry


def _registry_ids() -> set[str]:
    return set(ModuleRegistry.discover().check_ids())


def _live_problems(**overrides: object) -> tuple[str, ...]:
    kwargs: dict[str, object] = {
        "catalogue": load_port_catalog(),
        "datastore_protocols": DATASTORE_PROTOCOLS,
        "datastore_probes": PROTOCOL_PROBES,
        "probe_vocabulary": get_args(ProbeName),
        "registry_check_ids": _registry_ids(),
        "http_datastore_ports": HTTP_DATASTORE_PORTS,
    }
    kwargs.update(overrides)
    return problems(**kwargs)  # type: ignore[arg-type]


def _service(port: int, service: str) -> ServiceRecord:
    return ServiceRecord(
        host="127.0.0.1",
        port=port,
        protocol="tcp",
        service=service,
        identity=ServiceIdentity(protocol=service, product=service, banner=""),
    )


# --------------------------------------------------------------------------- the live product
def test_the_live_surfaces_agree_with_the_matrix() -> None:
    """The gate: registry, catalogue, probe vocabulary and dispatcher all match the table."""
    assert _live_problems() == ()


def test_every_probe_vocabulary_value_has_a_row() -> None:
    table = by_protocol()
    missing = sorted(set(get_args(ProbeName)) - set(table))
    assert missing == [], f"probe vocabulary values with no matrix row: {missing}"


def test_every_implemented_row_names_a_registered_check() -> None:
    registered = _registry_ids()
    for entry in PROTOCOL_MATRIX:
        if entry.state == "implemented":
            assert entry.check_id in registered, entry


def test_the_datastore_dispatch_table_equals_the_datastore_protocol_set() -> None:
    """REQ-DET-010's measured defect: a name in the set with no dispatch branch."""
    assert set(PROTOCOL_PROBES) == set(DATASTORE_PROTOCOLS)
    assert set(PROTOCOL_PORTS) == set(PROTOCOL_PROBES)


def test_no_protocol_is_left_with_an_unexplained_unknown_probe() -> None:
    """The exit criterion, stated directly: every non-implemented row carries its decision."""
    for entry in PROTOCOL_MATRIX:
        if entry.state in {"fingerprint_only", "not_supported"}:
            assert entry.reason.strip(), f"{entry.protocol} has no recorded decision"
            assert entry.check_id is None or entry.state == "fingerprint_only"


def test_every_state_in_the_vocabulary_is_used() -> None:
    """A three-state table with an unused state would be a table nobody trusts."""
    assert set(matrix_states()) == {"implemented", "fingerprint_only", "not_supported"}


@pytest.mark.parametrize("protocol", ["oracle", "sip", "opcua"])
def test_the_three_named_protocols_are_resolved(protocol: str) -> None:
    """REQ-DET-010 acceptance: Oracle, SIP and OPC-UA each resolve to a state and a reason."""
    entry = by_protocol()[protocol]
    assert entry.state in {"implemented", "fingerprint_only", "not_supported"}
    assert entry.reason.strip()


def test_oracle_is_no_longer_treated_as_a_datastore() -> None:
    """The measured bug: an Oracle port used to fall through to 'database port reachable'."""
    assert "oracle" not in DATASTORE_PROTOCOLS
    assert datastore_protocol_for(_service(1521, "oracle")) is None
    assert datastore_protocol_for(_service(1521, "unknown")) is None


def test_the_datastore_dispatcher_still_resolves_every_protocol_it_claims() -> None:
    assert datastore_protocol_for(_service(6379, "unknown")) == "redis"
    assert datastore_protocol_for(_service(11211, "unknown")) == "memcached"
    assert datastore_protocol_for(_service(27018, "unknown")) == "mongodb"
    assert datastore_protocol_for(_service(3306, "mysql")) == "mysql"
    assert datastore_protocol_for(_service(5432, "postgres")) == "postgres"
    assert datastore_protocol_for(_service(1433, "mssql")) == "mssql"
    assert datastore_protocol_for(_service(9200, "unknown")) == "http"


def test_the_matrix_serialises_with_its_version() -> None:
    payload = to_dict()
    assert payload["matrix_version"] == MATRIX_VERSION
    assert len(payload["protocols"]) == len(PROTOCOL_MATRIX)
    assert sum(payload["totals"].values()) == len(PROTOCOL_MATRIX)


# --------------------------------------------------------------------------- the checker bites
def test_a_protocol_added_to_the_datastore_set_without_a_branch_fails() -> None:
    found = _live_problems(datastore_protocols=(*DATASTORE_PROTOCOLS, "oracle"))
    assert any("oracle" in item and "generic 'port reachable'" in item for item in found)


def test_a_removed_dispatch_branch_fails() -> None:
    broken = {name: method for name, method in PROTOCOL_PROBES.items() if name != "mysql"}
    found = _live_problems(datastore_probes=broken)
    assert any("mysql" in item and "dispatch table" in item for item in found)


def test_a_dispatch_branch_for_an_unrecorded_protocol_fails() -> None:
    broken = {**PROTOCOL_PROBES, "oracle": "_oracle"}
    found = _live_problems(datastore_probes=broken)
    assert any("oracle" in item for item in found)


def test_an_implemented_row_with_an_unknown_owner_fails() -> None:
    found = _live_problems(registry_check_ids=set())
    assert any("not a registered check" in item for item in found)


def test_a_probe_vocabulary_value_without_a_row_fails() -> None:
    found = _live_problems(probe_vocabulary=(*get_args(ProbeName), "telnet-reverse"))
    assert any("telnet-reverse" in item for item in found)


def test_an_http_datastore_port_for_an_unrecorded_protocol_fails() -> None:
    found = _live_problems(http_datastore_ports={8086: "influxdb", 9999: "cassandra"})
    assert any("cassandra" in item for item in found)


def test_a_catalogue_entry_that_drops_the_probe_of_an_implemented_protocol_fails() -> None:
    live = load_port_catalog()
    mangled = PortCatalog(
        catalog_version=live.catalog_version,
        source=live.source,
        tcp=tuple(
            PortEntry(port=entry.port, service=entry.service, probe="unknown")
            if entry.probe == "redis"
            else entry
            for entry in live.tcp
        ),
        udp=live.udp,
    )
    found = _live_problems(catalogue=mangled)
    assert any("redis" in item and "probe 'unknown'" in item for item in found)


def test_an_unexplained_row_fails_the_matrix_itself() -> None:
    """A row with no reason is exactly the 'unexplained declaration' this module forbids."""
    silent = ProtocolEntry("mystery", "not_supported", None, "   ", ("port_catalogue",))
    import arachne.modules.protocol_matrix as module

    original = module.PROTOCOL_MATRIX
    try:
        module.PROTOCOL_MATRIX = (*original, silent)
        found = _live_problems()
    finally:
        module.PROTOCOL_MATRIX = original
    assert any("mystery" in item and "without a recorded reason" in item for item in found)
