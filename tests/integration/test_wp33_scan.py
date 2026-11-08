"""WP-33 acceptance: the exposed-service family meets its ground truth (REQ-DET-026).

The requirement's acceptance criteria are the shape of this module:

* **at least 24 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state — checked at the source (the helper
  has no request-method field at all and the wire vocabulary is a closed read set) and on the
  wire (every payload the fixture was handed across the whole matrix is a declared read
  command);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoy is the requirement's own ("the same services, on non-default ports and
  behind authentication", implemented as the ``hardened`` mode of ``tests/lab/service_lab.py``),
  plus the cross-service installations, which are decoys for one another's checks, and the
  echoing soft-404 the pitfalls warn about;
* the registry total is printed for the handoff.

One measurement drives all thirty-one checks against all forty-eight installations (sixteen
services in three modes), reusing one scripted harness per installation: the family is a single
read-only probe per check, so a harness per check would add nothing the shared inventory does
not already hold.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.lab.service_lab import (
    MODES,
    SERVICES,
    WiredFixture,
    build_fixture,
    default_ports,
    published_paths,
    wire_fixture,
)

from arachne.core.proof import ProofLevel
from arachne.modules.m2.exposed_services import (
    AREA_OF_CHECK,
    AREAS,
    ExposedServiceChecks,
    probe_of,
)
from arachne.modules.m2.service_read import (
    ALL_PROBES,
    MUTATING_COMMANDS,
    TCP_READ_COMMANDS,
    TCP_TRANSPORT,
    ServiceReadError,
    ServiceReadProbe,
    tcp_payload,
)

#: Every check the WP-33 family registers, from the family tuple the module exports.
WP33_IDS: tuple[str, ...] = tuple(check.metadata.id for check in ExposedServiceChecks)

#: The fixture mode that plants each service's signal, and the decoy modes the matrix runs.
POSITIVE = "bare"
DECOYS: tuple[str, ...] = ("hardened", "echo-404")

#: The proof level every member of the family declares.
_FAMILY_PROOF = ProofLevel.L1

#: The module that carries the family (the source-level read-only assertion reads it).
FAMILY_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m2"

#: Every wire payload the whole matrix may have sent, as the exact bytes the helper builds.
_ALLOWED_PAYLOADS: frozenset[bytes] = frozenset(
    tcp_payload(probe) for probe in ALL_PROBES if probe.transport == TCP_TRANSPORT
)


def _owner(check_id: str) -> str:
    """The service a family check belongs to, read from the module's own declaration."""
    return AREA_OF_CHECK[check_id]


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], WiredFixture]]:
    """One wired fixture per (service, mode), built once for the module."""
    yield {
        (service, mode): wire_fixture(build_fixture(service, mode))
        for mode in MODES
        for service in SERVICES
    }


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in ExposedServiceChecks}


async def _run(harness: Any, check_id: str) -> list[Any]:
    check = _by_id()[check_id]
    context = harness.context(check)
    return [result async for result in context.module.run(context)]


def _findings(results: list[Any]) -> list[Any]:
    return [result for result in results if result.status == "vulnerable"]


def _artifact(result: Any) -> dict[str, Any]:
    for item in result.evidence:
        if item.kind == "artifact":
            return dict(item.payload)
    return {}


def _strip_query(path: str) -> str:
    return path.split("?", 1)[0]


def _measure(
    installations: dict[tuple[str, str], WiredFixture],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings."""
    counts: dict[tuple[str, str, str], int] = {}
    for (service, mode), wired in installations.items():
        for check_id in WP33_IDS:
            counts[(service, mode, check_id)] = len(
                _findings(asyncio.run(_run(wired.harness, check_id)))
            )
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], WiredFixture],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all forty-eight installations."""
    return _measure(installations)


def _registry_total() -> int:
    from arachne.modules.registry import ModuleRegistry

    return len(ModuleRegistry.discover().checks())


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_four_checks(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """REQ-DET-026: at least 24 new checks in this family, covering every named service."""
    del measured
    assert len(WP33_IDS) >= 24, WP33_IDS
    assert len(set(WP33_IDS)) == len(WP33_IDS)
    assert len(AREAS) == 16, AREAS
    assert set(AREAS) == {_owner(check_id) for check_id in WP33_IDS}
    # Every service the requirement names owns at least one check, and every check belongs to
    # exactly one service.
    for service in AREAS:
        owned = [check_id for check_id in WP33_IDS if _owner(check_id) == service]
        assert owned, service
    decoy_cells = len(WP33_IDS) * (len(SERVICES) * len(MODES) - 1)
    print(
        f"\nregistry total: {_registry_total()} checks; "
        f"WP-33 family: {len(WP33_IDS)} across {len(SERVICES)} services; "
        f"decoy-clean cells: {decoy_cells}"
    )


def test_every_check_reports_its_positive_and_stays_silent_on_every_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The acceptance core: a planted signal is found, every decoy is silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    cross_service = 0
    for check_id in WP33_IDS:
        owner = _owner(check_id)
        if measured[(owner, POSITIVE, check_id)] < 1:
            misses.append(f"{check_id}: no finding on the {owner} installation")
        for service in SERVICES:
            for mode in MODES:
                if (service, mode) == (owner, POSITIVE):
                    continue
                found = measured[(service, mode, check_id)]
                if found != 0:
                    false_positives.append(f"{check_id}: {found} finding(s) on {service}/{mode}")
                    continue
                if mode == POSITIVE:
                    cross_service += 1
    assert not misses, misses
    assert not false_positives, false_positives
    assert cross_service == len(WP33_IDS) * (len(SERVICES) - 1)
    decoy_cells = len(WP33_IDS) * (len(SERVICES) * len(MODES) - 1)
    print(
        f"\n{len(WP33_IDS)} checks x {len(SERVICES) * len(MODES)} installations: "
        f"every positive found, 0 findings on every decoy ({decoy_cells} decoy-clean cells: "
        f"{len(WP33_IDS)} hardened, {len(WP33_IDS)} echo-404, {cross_service} cross-service)"
    )


def test_the_hardened_installation_answers_a_challenge(
    installations: dict[tuple[str, str], WiredFixture],
) -> None:
    """The requirement's decoy is *behind authentication*, not merely absent.

    This is the pitfall's second half — "a service that answers on a non-default port is not
    necessarily exposed" — so the decoy is asserted to be a live challenge: every hardened
    installation names the same service on a non-default port and answers an unauthenticated
    read with a ``401`` and a challenge (HTTP) or the protocol's own auth error (wire), and no
    family check finds anything there (the matrix asserts the second half).
    """
    for service in SERVICES:
        wired = installations[(service, "hardened")]
        fixture = wired.fixture
        assert fixture.port not in default_ports(service), (service, fixture.port)
        assert fixture.records[0][1] == service, fixture.records
        if fixture.http_routes:
            for route in fixture.http_routes:
                assert route["status"] == 401, (service, route)
                assert "www-authenticate" in route["headers"], (service, route)
        if fixture.tcp_replies:
            for check_id in WP33_IDS:
                if _owner(check_id) != service:
                    continue
                probe = probe_of(_by_id()[check_id])
                if probe.transport != TCP_TRANSPORT:
                    continue
                reply = fixture.tcp_replies.get(probe.command)
                assert reply is not None, (service, probe.command)
                assert reply[:1] == b"-" or b"AUTHENTICATION" in reply.upper(), reply


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-026: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP33_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is _FAMILY_PROOF, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith("WSTG-") for item in metadata.framework), check_id
        assert any(item.startswith("API") for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch02#"), check_id
        assert metadata.requires_active_checks is True, check_id
        assert metadata.requires_credentials == (), check_id
        assert metadata.type == "active", check_id
        assert metadata.id == f"m2.{metadata.name}", check_id
        assert metadata.module == "M2", check_id
        probe = probe_of(by_id[check_id])
        assert probe in ALL_PROBES, check_id


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no verb is ever chosen and no body is ever sent.

    Every request the family makes goes through :mod:`arachne.modules.m2.service_read`, whose
    probe shape has **no method field** — an HTTP probe is a ``GET`` because there is nowhere to
    say otherwise. What this test adds is that the *checks module* never names a method, never
    hands a body to a helper, and never sends a wire command outside the allowlist.
    """
    source = (FAMILY_SOURCE / "exposed_services.py").read_text(encoding="utf-8")
    assert "POST" not in source
    assert "PUT" not in source
    assert "DELETE" not in source
    assert "PATCH" not in source
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        assert name not in {"json_post", "post_form", "request_raw", "tcp"}, (
            f"an unsafe helper is called at line {node.lineno}"
        )
    # Every wire command the module names is a member of the helper's closed read vocabulary.
    helper = (FAMILY_SOURCE / "service_read.py").read_text(encoding="utf-8")
    tree = ast.parse(helper)
    declared = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword)
        and node.arg == "command"
        and isinstance(node.value, ast.Constant)
    }
    for command in declared:
        assert any(command in commands for commands in TCP_READ_COMMANDS.values()), command


def test_the_helper_exposes_no_request_method_field() -> None:
    """A verb is unrepresentable, not merely unused: the probe shape has no method field."""
    fields = set(ServiceReadProbe.__dataclass_fields__)
    assert "method" not in fields, fields
    assert "verb" not in fields, fields
    # A wire probe outside its protocol's read vocabulary cannot be constructed at all.
    for service, commands in TCP_READ_COMMANDS.items():
        for command in commands:
            probe = ServiceReadProbe(
                service=service, transport=TCP_TRANSPORT, command=command, markers=("x",)
            )
            assert probe.command == command
    with pytest.raises(ServiceReadError):
        ServiceReadProbe(
            service="redis", transport=TCP_TRANSPORT, command="flushall", markers=("x",)
        )


def test_the_read_vocabulary_is_disjoint_from_every_mutating_command() -> None:
    """The allowlist is the control and it is *read-only*: no command writes, flushes or runs."""
    for service, commands in TCP_READ_COMMANDS.items():
        overlap = {command.lower() for command in commands} & {
            command.lower() for command in MUTATING_COMMANDS
        }
        assert not overlap, (service, overlap)
        for command in commands:
            # A read verb opens the command; nothing that opens with a mutation verb is here.
            head = command.split()[0].lower()
            assert head in {"info", "stats", "mntr"}, (service, command)


def test_no_wire_payload_outside_the_read_vocabulary_was_ever_sent(
    installations: dict[tuple[str, str], WiredFixture],
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The read-only claim on the wire, for the whole matrix's single measurement."""
    del measured  # ensures the matrix has driven every check before the log is read
    offenders: list[str] = []
    sent_total = 0
    for (service, mode), wired in installations.items():
        for payload in wired.sent:
            sent_total += 1
            if payload not in _ALLOWED_PAYLOADS:
                offenders.append(f"{service}/{mode}: {payload!r}")
    assert not offenders, offenders
    # Every wire check was actually driven: one payload per wire check per mode it owns.
    wire_checks = [
        check_id for check_id in WP33_IDS if probe_of(_by_id()[check_id]).transport == TCP_TRANSPORT
    ]
    assert sent_total >= len(wire_checks) * len(MODES), sent_total


def test_the_echo_404_trap_is_silent() -> None:
    """The pitfall's own decoy: a 200 that echoes the requested path is not an exposure."""
    failures: list[str] = []
    for service in SERVICES:
        wired = wire_fixture(build_fixture(service, "echo-404"))
        for check_id in WP33_IDS:
            found = _findings(asyncio.run(_run(wired.harness, check_id)))
            failures.extend(f"{service}: {check_id}" for _ in found)
    assert not failures, failures


def test_no_marker_is_a_substring_of_the_path_it_probes() -> None:
    """A marker may not be a substring of its own probed path: that is the echo-404 trap.

    The pitfall warns that a page which echoes the requested path is not an exposure. A marker
    that appears in the path it probes matches that echo, which is exactly how a soft 404
    becomes a finding. ``test_the_echo_404_trap_is_silent`` measures the trap; this makes the
    rule structural, so the next batch cannot reintroduce one.
    """
    offenders: list[str] = []
    for check in ExposedServiceChecks:
        probe = probe_of(check)
        for path in probe.paths:
            lowered = path.lower()
            for marker in probe.markers:
                if marker.lower() in lowered:
                    offenders.append(f"{check.metadata.id}: {path} contains marker {marker!r}")
    assert not offenders, offenders


def test_every_check_finding_names_a_published_endpoint(
    installations: dict[tuple[str, str], WiredFixture],
) -> None:
    """A finding's target is a service the fixture actually published, on the fixture's port."""
    published = published_paths()
    for service in SERVICES:
        wired = installations[(service, POSITIVE)]
        expected_port = wired.fixture.port
        for check_id in WP33_IDS:
            if _owner(check_id) != service:
                continue
            findings = _findings(asyncio.run(_run(wired.harness, check_id)))
            assert findings, check_id
            for result in findings:
                artifact = _artifact(result)
                assert artifact["service"] == service, check_id
                assert artifact["target"].endswith(f":{expected_port}"), artifact
                assert artifact["anonymous"] is True, artifact
                assert artifact["read_only"] is True, artifact
                assert artifact["state_changed"] is False, artifact
                assert artifact["command_issued"] is False, artifact
                if artifact.get("url"):
                    path = "/" + artifact["url"].split(f":{expected_port}", 1)[1].lstrip("/")
                    assert _strip_query(path) in {
                        _strip_query(item) for item in published[service]
                    }, artifact
                elif artifact.get("command"):
                    probe = probe_of(_by_id()[check_id])
                    assert artifact["command"] in TCP_READ_COMMANDS[service], artifact
                    assert probe.command == artifact["command"], check_id


def test_the_checks_are_deterministic(installations: dict[tuple[str, str], WiredFixture]) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    for service in SERVICES:
        wired = installations[(service, POSITIVE)]
        for check_id in WP33_IDS:
            if _owner(check_id) != service:
                continue
            first = sorted((r.status, r.title) for r in asyncio.run(_run(wired.harness, check_id)))
            second = sorted((r.status, r.title) for r in asyncio.run(_run(wired.harness, check_id)))
            assert first == second, check_id


def test_a_dry_run_sends_nothing(installations: dict[tuple[str, str], WiredFixture]) -> None:
    """F-01-10: no client, no request, and every check says so rather than pretending."""
    for service in SERVICES:
        wired = installations[(service, POSITIVE)]
        wired.harness.step.http = None
        wired.harness.step.net = None
        try:
            for check_id in WP33_IDS:
                results = asyncio.run(_run(wired.harness, check_id))
                assert results, check_id
                assert all(
                    any(dict(item.payload).get("skipped") for item in result.evidence)
                    for result in results
                ), check_id
        finally:
            wired.harness.step.http = wired.harness.http_transport
            wired.harness.step.net = wired.harness.client


def test_the_family_source_is_the_only_place_the_checks_are_declared() -> None:
    """One definition of the family: the module's tuple is the registry's set."""
    from arachne.modules.registry import ModuleRegistry

    registry = ModuleRegistry.discover()
    for check_id in WP33_IDS:
        assert registry.get(check_id) is not None, check_id
    assert len(WP33_IDS) == len(set(WP33_IDS))
    assert len(ALL_PROBES) == len(WP33_IDS), len(ALL_PROBES)


def test_every_service_the_requirement_names_has_a_fixture() -> None:
    """The sixteen services the requirement names are the sixteen the fixture plants."""
    assert set(SERVICES) == set(AREAS)
    for service in SERVICES:
        assert default_ports(service), service
        fixture = build_fixture(service, "bare")
        assert fixture.http_routes or fixture.tcp_replies, service
        assert fixture.records == ((fixture.port, service),), service
    # An unknown service degrades to an explicit error rather than an empty fixture.
    with pytest.raises(ValueError):
        build_fixture("no-such-service", "bare")
