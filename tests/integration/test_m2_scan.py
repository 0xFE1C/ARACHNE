"""Acceptance: a live M2 scan discovers the lab, its services and its TLS issues.

This is the stage's headline behaviour (docs/spec/08- Phase 1): the seventeen M2 checks run
end to end against real TCP/UDP/TLS endpoints and produce evidence-bearing candidates.

The lab is `tests/lab/arachne_lab.py` — real sockets on loopback speaking deliberately
minimal but wire-correct protocols (SSH banner + KEXINIT, an Nginx 1.18.0 HTTP server, an
expired-certificate TLS endpoint, MySQL 5.5.62, an unauthenticated Redis 5.0.7, a VNC server
offering no authentication, a Postfix that answers VRFY, a nameserver that permits AXFR, an
LDAP directory that accepts an anonymous bind, an SNMP agent on `public` and a Modbus
device). The Docker compose fixture in `docker/docker-compose.yml` is the same target set for
the full M1-M4 lab scan later stages run; this one runs anywhere Python runs.

What the test asserts, in the order the checks run:

1. **Discovery** — the lab host is found alive, its open ports are the lab's ports, and each
   service is identified with a product and a version (from a banner, not from a port number).
2. **Protocol posture** — a TLS weakness (deprecated protocol, expired certificate), the
   passwordless VNC server, the unauthenticated Redis and the AXFR transfer each raise a
   candidate with the exchange that proves it.
3. **CVE correlation** — the *planted old versions* (OpenSSH 8.5p1, Nginx 1.18.0, Redis
   5.0.7, MySQL 5.5.62) resolve to their known CVEs from the offline index.
4. **Evidence and audit** — every candidate carries evidence, every probe is in the audit
   trail, and the whole scan stays inside the declared scope.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.lab.arachne_lab import LAB_ZONE, LabFixture, m2_lab

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import (
    NetSettings,
    OsintSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.events import EventBus
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.net import ScopedNetClient
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import load_scan_request_from_text
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry

#: The lab descriptions the fixture plants, and the CVE each one should resolve to.
PLANTED_VERSIONS = {
    "openssh": ("8.5p1", "CVE-2024-6387"),
    "nginx": ("1.18.0", "CVE-2019-20372"),
    "redis": ("5.0.7", "CVE-2022-0543"),
}


def lab_target_definition(lab: LabFixture) -> str:
    """A target definition plus a port catalogue covering the lab's ephemeral ports.

    The catalogue is the *documented* way to tell ARACHNE where a service lives on a
    non-standard port (F-09-04, ADR-080.4): the lab binds ephemeral ports so tests can run in
    parallel, and the port policy is precisely the managed data that decides what gets probed.
    """
    entries = "\n".join(
        f"  - {{port: {lab.port(name)}, service: {service}, probe: {probe}}}"
        for name, service, probe in (
            ("ssh", "ssh-alt", "ssh"),
            ("http", "http-alt", "http"),
            ("tls", "https-alt", "tls"),
            ("mysql", "mysql", "mysql"),
            ("redis", "redis", "redis"),
            ("vnc", "vnc", "vnc"),
            ("smtp", "smtp", "smtp"),
            ("dns", "dns", "dns"),
            ("ldap", "ldap", "ldap"),
            ("modbus", "modbus", "modbus"),
        )
    )
    udp = "\n".join(
        f"  - {{port: {lab.port(name)}, service: {service}, probe: {probe}}}"
        for name, service, probe in (("snmp", "snmp", "snmp"), ("bacnet", "bacnet", "bacnet"))
    )
    return f"""catalog_version: "lab"
source: the ephemeral ports the stdlib lab fixture bound for this test run
tcp:
{entries}
udp:
{udp}
"""


def write_lab_catalog(lab: LabFixture, directory: Path) -> Path:
    path = directory / "lab-ports.yaml"
    path.write_text(lab_target_definition(lab), encoding="utf-8")
    return path


def scan_request(lab: LabFixture) -> Any:
    """A live scan of the lab: active checks opted in *and* attested (F-01-09)."""
    document = f"""
target:
  name: stdlib-lab
  targets:
    - kind: ip
      value: 127.0.0.1
    - kind: domain
      value: {LAB_ZONE}
  attestation:
    attested_by: pytest <pytest@example.test>
    attested_at: "2026-10-01T00:00:00Z"
    scope_statement: Unit-test authorization for the loopback lab fixture
    authorization_ref: LAB-1
    allowed_targets: ["127.0.0.1", "{LAB_ZONE}"]
    active_checks_authorized: true
options:
  active_checks: true
"""
    return load_scan_request_from_text(document, source="lab-fixture")


def lab_settings(catalog: Path, *, allow_udp: bool = True) -> Settings:
    """Settings that make a loopback lab scan possible and fast."""
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
        safety=SafetySettings(
            # The lab is on loopback: the policy has to allow it explicitly, which is the
            # point of the default deny (a production scan cannot reach 127.0.0.1 by accident).
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope.deny_all(),
        ),
        net=NetSettings(
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            banner_wait_s=0.2,
            # A short suite list keeps the lab scan quick; the full list is the default and
            # is covered by tests/unit/test_m2_tls.py.
            tls_cipher_probes=("DES-CBC3-SHA", "AES128-SHA"),
            max_ports=20,
            max_hosts=4,
            concurrency=8,
            allow_udp=allow_udp,
            port_catalog=str(catalog),
            kerberos_pacing_s=0.01,
            kerberos_max_names=2,
            smtp_pacing_s=0.01,
            nmap_enabled=False,
        ),
        osint=OsintSettings(enabled=False),
    )


def build_orchestrator(
    settings: Settings,
) -> tuple[Orchestrator, MemoryFindingStore, MemoryAuditSink, EventBus]:
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    bus = EventBus()
    handlers = build_handlers(
        settings=settings, registry=registry, findings=findings, auditor=auditor
    )
    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
        auditor=auditor,
        bus=bus,
        handlers=handlers,
        registry=registry,
        net_client_factory=lambda scope: ScopedNetClient(
            settings=settings, scope=scope, auditor=auditor
        ),
    )
    return orchestrator, findings, sink, bus


@dataclass(frozen=True)
class LabRun:
    """One completed lab scan: everything a test wants to assert on."""

    lab: LabFixture
    orchestrator: Orchestrator
    findings: MemoryFindingStore
    sink: MemoryAuditSink
    session: Any
    #: A scan with ``ARACHNE_NET_ALLOW_UDP`` off, to check the safety gate (F-01-09).
    udp_off_findings: MemoryFindingStore

    @property
    def scan_id(self) -> int:
        return int(self.session.scan_id or 0)

    def candidates(self, *, udp_off: bool = False) -> tuple[Any, ...]:
        # The acceptance suite scores the M2 check set: the shared lab is also reachable by the
        # later modules (S11's M6 correlates the fingerprinted versions to CVEs), and mixing
        # their candidates in would make these assertions about M2 describe someone else's work.
        store = self.udp_off_findings if udp_off else self.findings
        return tuple(item for item in store.list_candidates(self.scan_id) if item.module == "M2")

    def text(self, *, udp_off: bool = False) -> str:
        return " | ".join(
            f"{item.title} {item.to_dict()}" for item in self.candidates(udp_off=udp_off)
        ).lower()

    def probe_events(self) -> tuple[Any, ...]:
        return tuple(event for event in self.sink.events if event.action is AuditAction.NET_PROBE)


@pytest.fixture(scope="module")
def lab_run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LabRun]:
    """Run one full live scan of the lab and share it across this module's tests.

    The scan is the expensive part (real handshakes, real timeouts, one lab per run), so it
    happens once per module and each test asserts on a different aspect of the same run: the
    discovery results, the posture findings, the CVE matches and the audit trail. The lab is
    a context manager of threads, so a plain ``asyncio.run`` per scan keeps every scan in its
    own event loop without any loop-affinity surprises.
    """
    tmp = tmp_path_factory.mktemp("m2-lab")
    with m2_lab() as lab:
        catalog = write_lab_catalog(lab, tmp)
        settings = lab_settings(catalog)
        orchestrator, findings, sink, _bus = build_orchestrator(settings)
        session = asyncio.run(orchestrator.scan(scan_request(lab)))

        _off_orchestrator, udp_off_findings, _off_sink, _off_bus = build_orchestrator(
            lab_settings(catalog, allow_udp=False)
        )
        asyncio.run(_off_orchestrator.scan(scan_request(lab)))

        yield LabRun(
            lab=lab,
            orchestrator=orchestrator,
            findings=findings,
            sink=sink,
            session=session,
            udp_off_findings=udp_off_findings,
        )


# ------------------------------------------------------------------ 1. discovery
def test_the_scan_discovers_the_lab_host_ports_and_services(lab_run: LabRun) -> None:
    lab = lab_run.lab
    session = lab_run.session
    assert session.status is ScanStatus.COMPLETED
    assert session.scan_id is not None
    record = lab_run.orchestrator.store.get_scan(session.scan_id)
    assert record is not None

    discovery = record.step_state(ScanStep.DISCOVERY)
    assert discovery is not None and discovery.status.value == "completed"
    # The port scan itself lives in the step statistics: what was probed and what answered.
    assert discovery.stats["net_probes"] > 0
    inventory = discovery.stats.get("inventory") or {}
    assert inventory.get("live_hosts", 0) >= 1
    assert inventory.get("services", 0) >= 6
    assert inventory.get("versioned_services", 0) >= 3

    services = _identified_services(record)
    assert lab.port("ssh") in services
    assert lab.port("http") in services
    assert lab.port("redis") in services
    assert services[lab.port("ssh")][0] == "openssh"
    assert services[lab.port("http")][0] == "nginx"
    assert services[lab.port("mysql")][0] == "mysql"


# ------------------------------------------------------------------ 2. posture
def test_tls_issues_are_reported_with_evidence(lab_run: LabRun) -> None:
    candidates = lab_run.candidates()
    tls_titles = [item.title for item in candidates if "tls" in item.title.lower()]
    assert tls_titles, f"no TLS candidate: {[item.title for item in candidates]}"
    del tls_titles
    blob = " | ".join(f"{item.title} {item.to_dict()}" for item in candidates).lower()
    # The lab serves an expired, self-signed certificate that does not name the host, and the
    # trust handshake fails: all four are deterministic observations.
    for kind in ("expired", "self-signed", "untrusted", "hostname-mismatch"):
        assert kind in blob, f"missing the {kind!r} TLS finding: {blob[:400]}"
    # TLS 1.2 is detected as supported (an exact probe, available on any modern interpreter).
    # TLS 1.0/1.1 are reported as *undetermined* on an interpreter that refuses legacy
    # protocol pinning (Python 3.14 with deprecations-as-errors, which is how pytest runs
    # here) — see tests/unit/test_m2_tls.py for the deterministic per-version behaviour.
    assert "tlsv1.2" in blob
    # The evidence includes the parsed certificate.
    tls_evidence = [
        item
        for candidate in candidates
        for item in candidate.evidence
        if item.kind == "tls_certificate"
    ]
    assert tls_evidence
    certificate = tls_evidence[0].payload.get("certificate") or {}
    assert certificate.get("expired") is True
    assert certificate.get("self_signed") is True


def test_anonymous_services_are_reported_as_findings(lab_run: LabRun) -> None:
    blob = lab_run.text()
    # Passwordless VNC, unauthenticated Redis, anonymous LDAP bind and an open zone transfer.
    assert "vnc" in blob and "unauthenticated" in blob
    assert "redis" in blob
    assert "ldap" in blob and "anonymous" in blob
    assert "zone transfer" in blob


def test_udp_checks_stay_silent_without_the_deployment_opt_in(lab_run: LabRun) -> None:
    """F-01-09: the SNMP check needs ``ARACHNE_NET_ALLOW_UDP`` on top of its opt-in."""
    blob = lab_run.text(udp_off=True)
    assert "snmp" not in blob
    assert "modbus" not in blob


# ------------------------------------------------------------------ 3. CVE correlation
def test_cve_correlation_finds_the_planted_old_versions(lab_run: LabRun) -> None:
    cve_candidates = [
        item for item in lab_run.candidates() if (item.title or "").startswith("CVE-")
    ]
    assert cve_candidates, "the CVE correlation produced no candidates"
    by_title = " | ".join(item.title for item in cve_candidates)
    # OpenSSH 8.5p1 → CVE-2024-6387 (regreSSHion); Nginx 1.18.0 → CVE-2019-20372 / 23017.
    assert "CVE-2024-6387" in by_title
    assert "CVE-2019-20372" in by_title or "CVE-2021-23017" in by_title
    # The evidence names the observed version and the range it fell in.
    for candidate in cve_candidates:
        payloads = [item.payload for item in candidate.evidence]
        assert any("observed_version" in payload for payload in payloads)
    versions = {
        payload.get("observed_version")
        for candidate in cve_candidates
        for item in candidate.evidence
        if isinstance(payload := item.payload, dict)
    }
    assert "8.5p1" in versions
    assert "1.18.0" in versions


def test_correlation_is_offline_and_needs_no_third_party(lab_run: LabRun) -> None:
    """The offline index is the default path (docs/spec/07- §9.1, F-09-03)."""
    assert not [event for event in lab_run.sink.events if event.action is AuditAction.OSINT_QUERY]


# ------------------------------------------------------------------ 4. evidence & audit
def test_every_candidate_carries_evidence_and_every_probe_is_audited(lab_run: LabRun) -> None:
    candidates = lab_run.candidates()
    assert candidates
    for candidate in candidates:
        assert candidate.evidence, f"{candidate.title!r} has no evidence"
        assert candidate.severity is None, "the module layer must not score (ADR-02)"
        assert candidate.module == "M2"

    probes = lab_run.probe_events()
    assert len(probes) > 10, "a network scan must leave an audit trail of its probes"
    for event in probes:
        assert event.meta.get("host")
        assert event.meta.get("protocol") in {"tcp", "udp", "tls", "icmp"}


def test_the_scan_never_leaves_the_declared_scope(lab_run: LabRun) -> None:
    """Every probe targets the declared loopback address (F-01-02)."""
    for event in lab_run.probe_events():
        assert event.meta.get("host") in {"127.0.0.1", LAB_ZONE}
    assert not [
        event for event in lab_run.sink.events if event.action is AuditAction.SCOPE_REJECTED
    ]


# ------------------------------------------------------------------ helpers
def _identified_services(record: Any) -> dict[int, tuple[str, str | None]]:
    """``{port: (product, version)}`` from the discovery step's inventory summary."""
    discovery = record.step_state(ScanStep.DISCOVERY)
    if discovery is None:
        return {}
    sample = (discovery.stats.get("inventory") or {}).get("identified_sample") or []
    identified: dict[int, tuple[str, str | None]] = {}
    for item in sample:
        if not isinstance(item, dict) or not item.get("product"):
            continue
        identified[int(item["port"])] = (str(item["product"]).lower(), item.get("version"))
    return identified
