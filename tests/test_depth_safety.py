"""Safety tests for the S29 depth-expansion checks, in ``tests/test_safety.py`` style.

Four properties are asserted here, and the first is the one the requirement is really about:

1. **The mobile-artifact analysis makes zero network calls, and it is structural.** The check is
   the only new one that reads a local file, so "offline" must be a property of the code, not a
   promise in a docstring: the test arms every socket entry point (the way
   ``tests/test_sim_safety.py`` arms them for simulation) and fails if one is reached while the
   check runs — and, anti-vacuously, asserts the check actually read the artifact and reported
   the planted secret, so it cannot pass by doing nothing.
2. **The artifact target is deny-by-default.** A path that the scope does not declare is
   refused, and a declared root grants only the artifacts under it.
3. **Every new check declares the proof level it actually uses.** The metadata is read from the
   *shipped registry*, so this is an assertion about what the product ships rather than about a
   class defined in a test.
4. **The opt-in gates are real.** The OT probe sends nothing without ``ARACHNE_NET_OT_PROBE``,
   and nothing in the new family is in the default check set except the three gRPC posture
   checks and the (already-default) M1 bundle scan.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from arachne.core.config import NetSettings, WebSettings
from arachne.core.errors import SafetyError
from arachne.core.proof import ProofLevel
from arachne.core.safety import Scope
from arachne.core.target import TargetKind, TargetSelector
from arachne.modules.m1 import M1_CHECKS
from arachne.modules.m1.mobile import read_artifact
from arachne.modules.m2 import M2_CHECKS
from arachne.modules.m3 import M3_CHECKS
from tests.helpers.checks import asset_for
from tests.helpers.depth import make_depth_harness
from tests.helpers.mobile import PLANTED_ENDPOINTS, PLANTED_SECRET, build_apk, build_ipa

#: The S29 check ids and the proof level each declares. Written out rather than derived, so a
#: level that changes has to change here too — which is the point of the test.
EXPECTED_PROOF_LEVELS: dict[str, ProofLevel] = {
    "m1.mobile-artifact": ProofLevel.L0,
    "m2.grpc-plaintext": ProofLevel.L1,
    "m2.grpc-reflection": ProofLevel.L1,
    "m2.grpc-metadata-leak": ProofLevel.L1,
    "m2.ot-protocol-probe": ProofLevel.L1,
    "m3.graphql-depth-abuse": ProofLevel.L1,
    "m3.graphql-resolver-auth": ProofLevel.L1,
    "m3.websocket-upgrade-auth": ProofLevel.L1,
    "m3.websocket-injection": ProofLevel.L1,
    "m3.client-secret-verify": ProofLevel.L2,
}


@pytest.fixture
def armed_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Record any attempt to reach the network and fail the test loudly if one happens.

    The socket *entry points* are armed, not the constructor: patching ``socket.socket`` itself
    would also break the event loop's own self-pipe, and the property under test is "this check
    does not reach out", not "no socket object exists in the process".
    """
    attempts: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        attempts.append(str(args[:1]))
        msg = "an armed socket was reached"
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "gethostbyname_ex", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    yield attempts
    assert attempts == [], f"the artifact analysis touched the network: {attempts}"


def _checks() -> dict[str, type]:
    return {check.metadata.id: check for check in (*M1_CHECKS, *M2_CHECKS, *M3_CHECKS)}


# ------------------------------------------------------------------ 1. zero network
async def test_mobile_artifact_analysis_is_offline_and_finds_the_planted_secret(
    tmp_path: Path, armed_sockets: list[str]
) -> None:
    """REQ-DEPTH-005: an APK with a planted secret is analyzed with zero network use."""
    apk = build_apk(tmp_path)
    check_cls = _checks()["m1.mobile-artifact"]
    harness = make_depth_harness(asset=asset_for("artifact", str(apk)))
    try:
        ctx = harness.context(check_cls())
        results = [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()

    # Anti-vacuous: the analysis really happened, and the planted material was found.
    assert any(result.status == "vulnerable" for result in results), [
        result.title for result in results
    ]
    blob = " ".join(
        f"{key}={value}"
        for result in results
        for item in result.evidence
        for key, value in item.payload.items()
    )
    assert "aws-access-key-id" in blob, blob
    assert "network_requests=0" in blob
    assert any(endpoint in blob for endpoint in PLANTED_ENDPOINTS), blob
    # The masked finding never carries the value itself (F-08-04).
    assert PLANTED_SECRET not in blob


async def test_the_ipa_variant_is_analyzed_the_same_way(
    tmp_path: Path, armed_sockets: list[str]
) -> None:
    """REQ-DEPTH-005 covers IPA as well as APK: one reader, both containers."""
    ipa = build_ipa(tmp_path)
    check_cls = _checks()["m1.mobile-artifact"]
    harness = make_depth_harness(asset=asset_for("artifact", str(ipa)))
    try:
        ctx = harness.context(check_cls())
        results = [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()
    blob = " ".join(
        f"{key}={value}"
        for result in results
        for item in result.evidence
        for key, value in item.payload.items()
    )
    assert "aws-access-key-id" in blob or PLANTED_ENDPOINTS[0] in blob, blob


def test_the_resource_entry_is_not_reported(tmp_path: Path) -> None:
    """The false-positive control: a secret-shaped string in a *resource* is not a code finding.

    ``res/raw/config.bin`` carries the same value as ``classes.dex``. Only the dex is code, so
    only the dex is scanned — and the evidence names which entries were read, which is what
    makes the claim checkable.
    """
    apk = build_apk(tmp_path)
    contents = read_artifact(str(apk))
    names = [name for name, _ in contents.entries]
    assert "classes.dex" in names
    assert "AndroidManifest.xml" in names
    assert "res/raw/config.bin" not in names


def test_a_relative_or_missing_artifact_is_refused(tmp_path: Path) -> None:
    """The reader refuses anything but an absolute path to a real file."""
    with pytest.raises(SafetyError):
        read_artifact("relative/app.apk")
    with pytest.raises(SafetyError):
        read_artifact(str(tmp_path / "absent.apk"))
    with pytest.raises(SafetyError):
        read_artifact(str(tmp_path))  # a directory is not an artifact


# ------------------------------------------------------------------ 2. scope gate
def test_the_artifact_scope_dimension_is_deny_by_default() -> None:
    """An undeclared artifact path is refused; a declared root grants only what is under it."""
    empty = Scope.deny_all()
    assert empty.check_artifact("/srv/builds/app.apk").allowed is False

    granted = Scope(allowed_artifacts=("/srv/builds",))
    assert granted.check_artifact("/srv/builds/app.apk").allowed is True
    assert granted.check_artifact("/srv/builds/2024/app.apk").allowed is True
    assert granted.check_artifact("/srv/builds2/app.apk").allowed is False
    assert granted.check_artifact("/etc/passwd").allowed is False
    assert granted.check_artifact("relative/app.apk").allowed is False

    excluded = Scope(allowed_artifacts=("/srv/builds",), excluded_artifacts=("/srv/builds/secret",))
    assert excluded.check_artifact("/srv/builds/secret/app.apk").allowed is False
    assert excluded.check_artifact("/srv/builds/app.apk").allowed is True


def test_an_artifact_target_compiles_to_the_artifact_scope_dimension() -> None:
    """A declared artifact target is what grants the read — not the check running."""
    selector = TargetSelector(kind=TargetKind.ARTIFACT, value="/srv/builds/app.apk")
    assert selector.value == "/srv/builds/app.apk"
    assert selector.host is None
    assert Scope(allowed_artifacts=(selector.value,)).check_artifact(selector.value).allowed


def test_the_documented_artifact_scan_request_parses_and_authorizes(tmp_path: Path) -> None:
    """The operator-guide §48.6 document is a real, working scan request.

    A documented shape that does not parse is worse than no documentation, so this drives the
    exact document through the loader and asserts the three things an operator relies on: the
    path normalises, the scope gains the artifact dimension and allows *that* file, and the
    attestation covers the declared target. The negative control (a path outside the grant) is
    asserted in the same test, so the check cannot pass by allowing everything.
    """
    from arachne.core.target import load_scan_request_from_text

    apk = build_apk(tmp_path)
    document = f"""
target:
  name: android-build
  targets:
    - kind: artifact
      value: {apk}
  attestation:
    attested_by: "Jane Operator <jane@example.com>"
    attested_at: "2026-11-01T00:00:00Z"
    scope_statement: "Offline analysis of our own signed build outputs"
    allowed_targets: ["{tmp_path}"]
    active_checks_authorized: false
"""
    definition = load_scan_request_from_text(document).target
    target = definition.targets[0]
    assert target.kind is TargetKind.ARTIFACT
    assert target.value == str(apk)

    scope = definition.compile_scope()
    assert scope.describe()["allowed_artifacts"] == [str(apk)]
    assert scope.check_artifact(target.value).allowed is True
    assert scope.check_artifact("/etc/passwd").allowed is False
    # Nothing network-shaped was granted by declaring an artifact.
    assert scope.allowed_hosts == ()
    assert scope.url_prefixes == ()
    assert definition.attestation is not None
    assert definition.attestation.covers(target) is True


def test_an_artifact_target_is_attested_as_a_path() -> None:
    """An attestation entry written as a path covers an artifact target under it (F-01-01)."""
    from arachne.core.target import _classify_attested_entry

    kind, value = _classify_attested_entry("/srv/builds")
    assert kind is TargetKind.ARTIFACT
    assert value == "/srv/builds"


# ------------------------------------------------------------------ 3. proof declarations
def test_every_new_check_declares_the_proof_level_it_uses() -> None:
    """The shipped registry agrees with the declared levels (REQ-PROOF-001/002)."""
    shipped = {check.metadata.id: check.metadata for check in M1_CHECKS + M2_CHECKS + M3_CHECKS}
    for check_id, level in EXPECTED_PROOF_LEVELS.items():
        assert check_id in shipped, f"{check_id} is not registered"
        metadata = shipped[check_id]
        assert metadata.proof is level, f"{check_id} declares {metadata.proof}, expected {level}"
        # Opt-in is required at L2+, and only L3/L4 may demand a state attestation.
        if level.is_opt_in:
            assert metadata.enabled_by_default is False, check_id
        assert metadata.requires_state_attestation is False, check_id


def test_the_mobile_check_is_passive_and_asks_for_nothing() -> None:
    """L0 means L0: a passive check with no estimated requests and no active-checks gate."""
    metadata = {check.metadata.id: check.metadata for check in M1_CHECKS}["m1.mobile-artifact"]
    assert metadata.type == "passive"
    assert metadata.estimated_requests == 0
    assert metadata.requires_active_checks is False


def test_the_client_secret_check_is_opt_in_by_construction() -> None:
    """REQ-DEPTH-004's dynamic half is L2: opt-in, and never in the default set."""
    metadata = {check.metadata.id: check.metadata for check in M3_CHECKS}["m3.client-secret-verify"]
    assert metadata.proof is ProofLevel.L2
    assert metadata.enabled_by_default is False
    assert metadata.requires_active_checks is True


# ------------------------------------------------------------------ 4. opt-in gates
async def test_the_ot_probe_sends_nothing_with_its_switch_off(tmp_path: Path) -> None:
    """REQ-DEPTH-006: strictly opt-in — the check reports the switch, and probes nothing."""
    from tests.lab.arachne_lab import start_m2_lab

    fixture = start_m2_lab(include_udp=False)
    try:
        check_cls = _checks()["m2.ot-protocol-probe"]
        harness = make_depth_harness(
            asset=asset_for("host", "127.0.0.1"),
            net=NetSettings(ot_probe=False, read_timeout_s=0.5, connect_timeout_s=0.5),
            seed_services=((fixture.port("s7"), "iso-tsap"),),
        )
        try:
            ctx = harness.context(check_cls())
            results = [result async for result in check_cls().run(ctx)]
        finally:
            await harness.aclose()
    finally:
        fixture.stop()
    assert all(result.status != "vulnerable" for result in results)
    assert any("ARACHNE_NET_OT_PROBE" in (result.detail or "") for result in results)


def test_the_depth_families_are_opt_in_except_the_grpc_posture_probes() -> None:
    """Which new checks join the default set is a decision, recorded here.

    The three gRPC posture probes join it: they are read-only socket reads on a port the port
    catalogue already named, gated by the active-checks switch and the attestation like every
    other M2 protocol check. Everything else is opt-in — the mobile artifact (a file read), the
    OT probe (reaching an industrial protocol), and the crafted GraphQL/WebSocket/L2 probes.
    """
    default_ids = {
        check.metadata.id
        for check in M1_CHECKS + M2_CHECKS + M3_CHECKS
        if check.metadata.enabled_by_default
    }
    expected_default = {"m2.grpc-plaintext", "m2.grpc-reflection", "m2.grpc-metadata-leak"}
    for check_id in EXPECTED_PROOF_LEVELS:
        if check_id in expected_default:
            assert check_id in default_ids, check_id
        else:
            assert check_id not in default_ids, f"{check_id} should be opt-in"


async def test_a_websocket_probe_declares_its_opt_in_switch_reason(tmp_path: Path) -> None:
    """A disabled probe says which switch enables it, rather than looking like a clean scan."""
    from tests.lab.web_lab import start_web_lab

    with start_web_lab() as lab:
        check_cls = _checks()["m3.websocket-injection"]
        harness = make_depth_harness(
            asset=asset_for("url", lab.base_url),
            web=replace(WebSettings(max_pages=10), ws_probe=False),
        )
        try:
            await harness.prepare([f"{lab.base_url.rstrip('/')}/ws"])
            ctx = harness.context(check_cls())
            results = [result async for result in check_cls().run(ctx)]
        finally:
            await harness.aclose()
    assert any("ARACHNE_WEB_WS_PROBE" in (result.detail or "") for result in results)
    assert lab.ws_messages == []
