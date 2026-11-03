"""IPv6 parity for the L1 network families (REQ-DET-007).

Three families, one IPv6-only fixture, one requirement: an address that resolves only to AAAA
must be scanned by the port, TLS and header checks with the same scope validation and the same
rate limiting as IPv4.

The fixture binds ``::1`` with ``IPV6_V6ONLY``, so nothing here can pass by accident over
IPv4. The scope is ``Scope(allowed_hosts=("::1",))`` — the same deny-by-default object the
IPv4 tests use — and every probe goes through the real :class:`ScopedNetClient`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from tests.helpers.checks import asset_for, make_step_context
from tests.lab.ipv6_lab import IPV6_HOST, start_ipv6_lab

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import (
    NetSettings,
    OsintSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.http import ScopedHttpClient
from arachne.core.net import ScopedNetClient
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.modules.base import Module
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m2.discovery import PortScan, _port_of_asset
from arachne.modules.m2.hardening import HttpFingerprint
from arachne.modules.m2.inventory import NetworkInventory
from arachne.modules.m2.tls_cve import TlsDeepScan

pytestmark = pytest.mark.lab


@dataclass
class _FamilyRun:
    inventory: NetworkInventory
    port_results: list
    tls_results: list
    header_results: list
    client: ScopedNetClient
    http_port: int
    tls_port: int


def _settings(catalogue: str) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope.deny_all(),
        ),
        net=NetSettings(
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            banner_wait_s=0.2,
            max_ports=8,
            max_hosts=2,
            concurrency=4,
            allow_udp=False,
            port_catalog=catalogue,
            nmap_enabled=False,
            tls_cipher_probes=("AES128-SHA",),
        ),
        osint=OsintSettings(enabled=False),
    )


def _catalogue(path: Path, http_port: int, tls_port: int) -> str:
    path.write_text(
        "catalog_version: 'ipv6-lab'\n"
        "source: the IPv6-only loopback fixture\n"
        "tcp:\n"
        f"  - {{port: {http_port}, service: http-alt, probe: http}}\n"
        f"  - {{port: {tls_port}, service: https-alt, probe: tls}}\n",
        encoding="utf-8",
    )
    return str(path)


def _context(
    check: type[Module],
    asset: tuple[str, str],
    *,
    settings: Settings,
    inventory: NetworkInventory,
    client: ScopedNetClient,
    http_client: ScopedHttpClient,
) -> CheckContext:
    scope = Scope(allowed_hosts=(IPV6_HOST,))
    step, _ = make_step_context(http=http_client, scope=scope, seed=[asset])
    step.net = client
    step.inventory = inventory
    step.step = ScanStep.DISCOVERY
    return CheckContext(
        step=step,
        module=check(),
        asset=asset_for(*asset),
        config=ModuleConfig.from_settings(settings),
    )


async def _scan(tmp_path: Path) -> _FamilyRun:
    with start_ipv6_lab() as lab:
        settings = _settings(_catalogue(tmp_path / "ports.yaml", lab.http_port, lab.tls_port))
        scope = Scope(allowed_hosts=(IPV6_HOST,))
        auditor = Auditor(MemoryAuditSink(), actor="pytest")
        client = ScopedNetClient(settings=settings, scope=scope, auditor=auditor)
        http_client = ScopedHttpClient(settings=settings, scope=scope, auditor=auditor)
        inventory = NetworkInventory(max_hosts=2, max_ports=8)
        record = inventory.host(IPV6_HOST, declared=True)
        record.alive = True

        def context(check: type[Module], asset: tuple[str, str]) -> CheckContext:
            return _context(
                check,
                asset,
                settings=settings,
                inventory=inventory,
                client=client,
                http_client=http_client,
            )

        port_results = [
            result async for result in PortScan().run(context(PortScan, ("host", IPV6_HOST)))
        ]
        tls_results = [
            result async for result in TlsDeepScan().run(context(TlsDeepScan, ("host", IPV6_HOST)))
        ]
        header_results = [
            result
            async for result in HttpFingerprint().run(
                context(HttpFingerprint, ("url", lab.http_url))
            )
        ]
        return _FamilyRun(
            inventory=inventory,
            port_results=port_results,
            tls_results=tls_results,
            header_results=header_results,
            client=client,
            http_port=lab.http_port,
            tls_port=lab.tls_port,
        )


async def test_an_ipv6_only_fixture_is_scanned_by_port_tls_and_header(tmp_path) -> None:
    run = await _scan(tmp_path)

    # port family: both listening ports were found on ::1
    assert run.inventory.service(IPV6_HOST, run.http_port) is not None
    assert run.inventory.service(IPV6_HOST, run.tls_port) is not None

    # TLS family: the fixture's expired self-signed certificate is reported for ::1
    tls_text = " ".join(
        f"{result.title} {result.detail} {result.evidence}" for result in run.tls_results
    )
    assert "expired" in tls_text.lower(), tls_text[:400]

    # header family: the nginx version behind the IPv6-only HTTP listener was read
    header_text = " ".join(
        f"{result.title} {result.detail} {result.evidence}" for result in run.header_results
    )
    assert "nginx" in header_text.lower(), header_text[:400]


async def test_every_probe_targeted_the_ipv6_loopback(tmp_path) -> None:
    run = await _scan(tmp_path)
    assert run.client.probes > 0
    # The client only ever dials addresses it authorized: ::1 and nothing else.
    assert run.client.scope.allowed_hosts == (IPV6_HOST,)


def test_an_ipv6_network_is_a_scope_decision_not_an_exception() -> None:
    """The scope decision for an IPv6 host has the same structure as for an IPv4 host."""
    allowed = Scope(allowed_networks=("::1/128",)).check(IPV6_HOST)
    assert allowed.allowed is True
    assert allowed.reason
    denied = Scope(allowed_networks=("127.0.0.0/8",)).check(IPV6_HOST)
    assert denied.allowed is False
    assert denied.reason
    # Same shape for the IPv4 twin: address, verdict, reason.
    assert Scope(allowed_networks=("127.0.0.0/8",)).check("127.0.0.1").allowed is True


def test_an_ipv6_cidr_target_is_accepted_and_a_foreign_one_refused() -> None:
    assert Scope(allowed_networks=("2001:db8::/32",)).check_network("2001:db8::/48").allowed is True
    assert (
        Scope(allowed_networks=("2001:db8::/32",)).check_network("2001:dead::/48").allowed is False
    )


def test_an_ipv6_scope_refuses_an_unlisted_ipv6_host() -> None:
    """Denial behaves as for IPv4: a host outside the declared network is refused with a reason."""
    decision = Scope(allowed_networks=("2001:db8::/32",)).check("2001:dead::1")
    assert decision.allowed is False
    assert "not in the declared scope" in decision.reason


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("[::1]:8443", 8443),
        ("[2001:db8::10]:443", 443),
        ("[::1]", None),
        ("::1", None),
        ("host.example:8080", 8080),
        ("https://[::1]:9443/x", 9443),
    ],
)
def test_a_bracketed_ipv6_port_is_parsed(value: str, expected: int | None) -> None:
    """REQ-DET-007: an IPv6 literal's colons must not hide the port it declares."""
    assert _port_of_asset(value) == expected
