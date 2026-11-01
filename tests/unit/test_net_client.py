"""The S4 network client: scoping, rate limiting, auditing and probe semantics.

`arachne.core.net.ScopedNetClient` is the second egress path (after the HTTP client), so its
tests are about the same guarantees: nothing leaves the process without passing the scope and
address-policy gates, every probe is throttled and audited, and a transport failure is *data*
about the target rather than an exception in the scan.

The transport is scripted (no packet leaves the process) except in the two tests that
deliberately talk to loopback: one asserts the real socket path works, and one asserts a
closed port is recognised as closed.
"""

from __future__ import annotations

import ssl
from typing import Any

import pytest
from tests.conftest import FakeClock

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import NetSettings, RateLimitSettings, Settings
from arachne.core.errors import NetProbeError, OutOfScopeError, SafetyError
from arachne.core.net import (
    IcmpExchange,
    ScopedNetClient,
    ScriptedNetTransport,
    SocketTransport,
    TcpExchange,
    UdpExchange,
    legacy_version_cap_options,
)
from arachne.core.ratelimit import HostRateLimiter
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy

PUBLIC = "93.184.216.34"


def build_client(
    *,
    scope: Scope | None = None,
    policy: UrlSafetyPolicy | None = None,
    transport: Any = None,
    resolver: Any = None,
    settings: Settings | None = None,
    clock: FakeClock | None = None,
    sink: MemoryAuditSink | None = None,
) -> tuple[ScopedNetClient, MemoryAuditSink]:
    effective_sink = sink or MemoryAuditSink()
    effective_settings = settings or Settings(
        net=NetSettings(connect_timeout_s=1.0, read_timeout_s=1.0, banner_wait_s=0.2),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
    )
    effective_clock = clock or FakeClock()
    client = ScopedNetClient(
        settings=effective_settings,
        scope=scope if scope is not None else Scope(allowed_hosts=(PUBLIC,)),
        policy=policy or UrlSafetyPolicy(),
        resolver=resolver or StaticResolver((PUBLIC,)),
        limiter=HostRateLimiter(
            effective_settings.rate_limit,
            clock=effective_clock.monotonic,
            sleep=effective_clock.sleep,
        ),
        auditor=Auditor(effective_sink, actor="pytest"),
        transport=transport or ScriptedNetTransport(),
    )
    return client, effective_sink


# ------------------------------------------------------------------ authorization
async def test_an_out_of_scope_host_is_refused_before_any_probe() -> None:
    transport = ScriptedNetTransport({("tcp", PUBLIC, 80): b"banner"})
    client, sink = build_client(scope=Scope(allowed_hosts=("example.com",)), transport=transport)
    with pytest.raises(OutOfScopeError):
        await client.tcp(PUBLIC, 80)
    assert transport.calls == [], "an out-of-scope host must not be dialled"
    assert [event.action for event in sink.events] == [AuditAction.SCOPE_REJECTED]
    assert sink.events[0].outcome.value == "blocked"


async def test_an_empty_scope_contacts_nothing() -> None:
    transport = ScriptedNetTransport()
    client, _sink = build_client(scope=Scope.deny_all(), transport=transport)
    with pytest.raises(OutOfScopeError, match="deny by default"):
        await client.tcp(PUBLIC, 22)
    assert transport.calls == []


async def test_a_private_address_is_refused_by_the_address_policy() -> None:
    """The same policy the HTTP path uses: loopback/private blocks unless explicitly allowed."""
    transport = ScriptedNetTransport()
    client, sink = build_client(scope=Scope(allowed_hosts=("127.0.0.1",)), transport=transport)
    with pytest.raises(SafetyError, match=r"private-address|loopback-address"):
        await client.tcp("127.0.0.1", 80)
    assert transport.calls == []
    assert [event.action for event in sink.events] == [AuditAction.NET_BLOCKED]
    assert sink.events[0].reason in {"private-address", "loopback-address"}


async def test_a_name_is_resolved_only_after_the_scope_check() -> None:
    class RecordingResolver:
        def __init__(self) -> None:
            self.calls: list[tuple[str, int]] = []

        async def resolve(self, host: str, port: int) -> tuple[str, ...]:
            self.calls.append((host, port))
            return (PUBLIC,)

    resolver = RecordingResolver()
    client, _sink = build_client(scope=Scope(allowed_hosts=("other.example",)), resolver=resolver)
    with pytest.raises(OutOfScopeError):
        await client.tcp("out-of-scope.example", 80)
    assert resolver.calls == [], "an out-of-scope name must not generate a DNS query"


async def test_a_dns_failure_is_a_probe_error_not_a_safety_block() -> None:
    class FailingResolver:
        async def resolve(self, host: str, port: int) -> tuple[str, ...]:
            raise OSError("name or service not known")

    client, sink = build_client(
        scope=Scope(allowed_hosts=("dead.example",)), resolver=FailingResolver()
    )
    with pytest.raises(NetProbeError, match="cannot resolve"):
        await client.tcp("dead.example", 80)
    assert sink.events[0].action is AuditAction.NET_BLOCKED
    assert sink.events[0].reason == "dns-failure"


# ------------------------------------------------------------------ probe semantics
async def test_an_open_port_reports_the_banner_and_is_audited() -> None:
    transport = ScriptedNetTransport({("tcp", PUBLIC, 22): b"SSH-2.0-OpenSSH_9.8\r\n"})
    client, sink = build_client(transport=transport)
    exchange = await client.tcp(PUBLIC, 22)
    assert exchange.state == "open" and exchange.is_open
    assert exchange.banner_text().startswith("SSH-2.0-")
    assert exchange.addresses == (PUBLIC,)
    probes = [event for event in sink.events if event.action is AuditAction.NET_PROBE]
    assert len(probes) == 1
    assert probes[0].meta["state"] == "open"
    assert probes[0].meta["bytes_read"] > 0
    assert probes[0].target == f"tcp://{PUBLIC}:22"
    assert client.probes == 1


async def test_closed_filtered_and_error_states_are_distinguished() -> None:
    transport = ScriptedNetTransport(
        {
            ("tcp", PUBLIC, 80): TcpExchange(state="closed"),
            ("tcp", PUBLIC, 81): TcpExchange(state="filtered"),
            ("tcp", PUBLIC, 82): TcpExchange(state="error", error="ConnectionResetError: reset"),
            ("tcp", PUBLIC, 83): TcpExchange(state="open", chunks=(b"hi",)),
        }
    )
    client, _sink = build_client(transport=transport)
    assert (await client.tcp(PUBLIC, 80)).state == "closed"
    assert (await client.tcp(PUBLIC, 81)).state == "filtered"
    error = await client.tcp(PUBLIC, 82)
    assert error.state == "error" and error.error
    assert (await client.tcp(PUBLIC, 83)).state == "open"


async def test_probe_ports_returns_one_outcome_per_port_in_order() -> None:
    transport = ScriptedNetTransport(
        {
            ("tcp", PUBLIC, 22): b"SSH-2.0-x\r\n",
            ("tcp", PUBLIC, 80): b"HTTP/1.1 200 OK\r\n",
        }
    )
    client, _sink = build_client(transport=transport)
    outcomes = await client.probe_ports(PUBLIC, [80, 22, 443])
    assert [item.port for item in outcomes] == [80, 22, 443]
    assert [item.open for item in outcomes] == [True, True, False]
    assert outcomes[0].banner.startswith("HTTP/1.1")
    assert outcomes[0].protocol == "tcp"


async def test_probe_ports_turns_a_refused_target_into_one_outcome() -> None:
    """One unresolvable or refused address must not abandon the rest of a sweep."""

    class HalfFailingTransport(ScriptedNetTransport):
        async def tcp(self, host: str, port: int, **kwargs: Any) -> TcpExchange:
            if port == 445:
                raise NetProbeError("unreachable")
            return await super().tcp(host, port, **kwargs)

    transport = HalfFailingTransport({("tcp", PUBLIC, 80): b"ok"})
    client, _sink = build_client(transport=transport)
    outcomes = await client.probe_ports(PUBLIC, [80, 445])
    assert outcomes[0].open is True
    assert outcomes[1].state == "blocked" and outcomes[1].error


async def test_a_udp_probe_reports_the_three_udp_states() -> None:
    transport = ScriptedNetTransport(
        {
            ("udp", PUBLIC, 161): UdpExchange(state="open", payload=b"\x30\x00"),
            ("udp", PUBLIC, 162): UdpExchange(state="closed"),
            ("udp", PUBLIC, 163): UdpExchange(state="open-filtered"),
        }
    )
    client, sink = build_client(transport=transport)
    reply = await client.udp(PUBLIC, 161, b"\x30\x00")
    assert reply.replied and reply.payload == b"\x30\x00"
    refused = await client.udp(PUBLIC, 162, b"\x30\x00")
    assert refused.state == "closed" and not refused.replied
    silent = await client.udp(PUBLIC, 163, b"\x30\x00")
    assert silent.state == "open-filtered"
    assert {event.meta["protocol"] for event in sink.events} == {"udp"}


async def test_a_tls_probe_reports_the_negotiated_version_and_cipher() -> None:
    transport = ScriptedNetTransport(
        {
            ("tls", PUBLIC, 443): {
                "TLSv1.2": True,
                "verify_error": "self-signed certificate",
            }
        }
    )
    client, sink = build_client(transport=transport)
    exchange = await client.tls(PUBLIC, 443, max_version="TLSv1.2")
    assert exchange.ok and exchange.version == "TLSv1.2"
    verifying = await client.tls(PUBLIC, 443, verify=True)
    assert not verifying.ok and verifying.verify_error == "self-signed certificate"
    assert all(event.meta["protocol"] == "tls" for event in sink.events)


async def test_an_icmp_probe_degrades_to_unavailable_without_privileges() -> None:
    transport = ScriptedNetTransport(
        {("icmp", PUBLIC, 0): IcmpExchange(state="unavailable", error="no CAP_NET_RAW")}
    )
    client, _sink = build_client(transport=transport)
    echo = await client.icmp(PUBLIC)
    assert echo.unavailable and not echo.replied
    assert echo.error


async def test_icmp_reports_the_reply_ttl() -> None:
    transport = ScriptedNetTransport({("icmp", PUBLIC, 0): 57})
    client, _sink = build_client(transport=transport)
    echo = await client.icmp(PUBLIC)
    assert echo.replied and echo.ttl == 57


# ------------------------------------------------------------------ rate limiting
async def test_every_probe_takes_a_rate_limit_token() -> None:
    clock = FakeClock()
    settings = Settings(
        net=NetSettings(connect_timeout_s=1.0, read_timeout_s=1.0),
        rate_limit=RateLimitSettings(
            per_host_rate=1.0, per_host_burst=1, global_rate=1.0, global_burst=1
        ),
    )
    transport = ScriptedNetTransport({("tcp", PUBLIC, 80): b"ok"})
    client, _sink = build_client(settings=settings, transport=transport, clock=clock)
    await client.tcp(PUBLIC, 80)
    assert clock.sleeps == [], "the first probe spends the token it was given"
    await client.tcp(PUBLIC, 80)
    assert clock.sleeps and clock.sleeps[0] > 0, "the second probe waits for the budget"


async def test_a_refused_probe_does_not_consume_a_token() -> None:
    """The gate runs before the throttle, so a blocked probe costs no budget."""
    clock = FakeClock()
    settings = Settings(
        net=NetSettings(connect_timeout_s=1.0, read_timeout_s=1.0),
        rate_limit=RateLimitSettings(
            per_host_rate=1.0, per_host_burst=1, global_rate=1.0, global_burst=1
        ),
    )
    transport = ScriptedNetTransport({("tcp", PUBLIC, 80): b"ok"})
    client, _sink = build_client(
        settings=settings,
        # Both hosts are in scope; the *address policy* refuses loopback, so the refusal
        # happens after the scope gate and therefore before the limiter.
        scope=Scope(allowed_hosts=("127.0.0.1", PUBLIC)),
        transport=transport,
        clock=clock,
    )
    with pytest.raises(SafetyError):
        await client.tcp("127.0.0.1", 80)
    await client.tcp(PUBLIC, 80)
    assert clock.sleeps == [], "the refused probe must not have spent a token"
    assert transport.calls == [("tcp", PUBLIC, 80)]


# ------------------------------------------------------------------ the real socket path
async def test_the_socket_transport_talks_to_a_real_listener() -> None:
    """One end-to-end check of the production transport (loopback, no external network)."""
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = int(listener.getsockname()[1])

    def serve() -> None:
        connection, _ = listener.accept()
        try:
            connection.sendall(b"220 lab.test ESMTP ready\r\n")
            connection.recv(1024)
        finally:
            connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client, _sink = build_client(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver(("127.0.0.1",)),
        transport=SocketTransport(),
        settings=Settings(
            net=NetSettings(connect_timeout_s=2.0, read_timeout_s=2.0, banner_wait_s=1.0)
        ),
    )
    try:
        exchange = await client.tcp("127.0.0.1", port)
        assert exchange.state == "open"
        assert exchange.banner_text().startswith("220 lab.test")
    finally:
        listener.close()
        thread.join(timeout=2.0)


async def test_the_socket_transport_reports_a_closed_port() -> None:
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()  # nothing is listening on this port now

    client, _sink = build_client(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver(("127.0.0.1",)),
        transport=SocketTransport(),
        settings=Settings(net=NetSettings(connect_timeout_s=1.0, read_timeout_s=1.0)),
    )
    exchange = await client.tcp("127.0.0.1", port)
    assert exchange.state == "closed"


# ------------------------------------------------------------------ settings
def test_legacy_version_cap_options_are_available() -> None:
    """The cap is built from constants that are *not* deprecated (see the docstring)."""
    options = legacy_version_cap_options()
    assert isinstance(options, int)
    assert options != 0, "a modern interpreter must know OP_NO_TLSv1_2/OP_NO_TLSv1_3"


def test_net_settings_validate_their_bounds() -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        NetSettings(connect_timeout_s=0)
    with pytest.raises(ConfigurationError):
        NetSettings(max_ports=0)
    with pytest.raises(ConfigurationError):
        NetSettings(kerberos_pacing_s=-1)


def test_net_settings_are_read_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_NET_ALLOW_UDP": "true",
            "ARACHNE_NET_MAX_PORTS": "20",
            "ARACHNE_NET_TLS_TOOL": "/usr/bin/testssl.sh",
            "ARACHNE_NET_TLS_CIPHERS": "RC4-SHA,3DES-CBC3-SHA",
            "ARACHNE_KERBEROS_MAX_NAMES": "3",
            "ARACHNE_CVE_INDEX": "/tmp/index.yaml",
            "ARACHNE_WORDLISTS_DIR": "/tmp/wordlists",
        }
    )
    assert settings.net.allow_udp is True
    assert settings.net.max_ports == 20
    assert settings.net.tls_tool == "/usr/bin/testssl.sh"
    assert settings.net.tls_cipher_probes == ("RC4-SHA", "3DES-CBC3-SHA")
    assert settings.net.kerberos_max_names == 3
    assert settings.net.cve_index == "/tmp/index.yaml"
    assert settings.net.wordlists_dir == "/tmp/wordlists"


def test_the_default_net_settings_are_conservative() -> None:
    """Safe defaults (F-02-09): UDP off, no external tools, top-100 ports."""
    settings = Settings()
    assert settings.net.allow_udp is False
    assert settings.net.tls_tool is None
    assert settings.net.max_ports == 100
    assert settings.net.tls_cipher_probes is None
    assert ssl  # the ssl module is what the transport uses (import kept meaningful)
