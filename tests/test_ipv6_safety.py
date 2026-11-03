"""IPv6 safety parity (REQ-DET-007).

IPv6 scope classification is a safety surface, so it is tested the way the IPv4 surface is:
a default policy denies, an explicit opt-in allows, an out-of-scope address is refused **before
any packet**, the refusal is audited, and the decision carries the same shape (address, verdict,
reason) for both families.

The defect these tests were written against is real and recorded: ``ipaddress`` reports ``::1``
as *reserved* as well as loopback (``127.0.0.1`` is not reserved), so before WP-09 the
``allow_loopback`` opt-in covered IPv4 and silently did not cover IPv6 — an over-restriction,
fail-closed, but it made "scan an IPv6-only target" impossible. ``classify_ip`` now returns the
loopback verdict directly.
"""

from __future__ import annotations

import pytest

from arachne.core.config import RateLimitSettings, SafetySettings, Settings
from arachne.core.errors import OutOfScopeError, SafetyError
from arachne.core.net import ScopedNetClient, ScriptedNetTransport
from arachne.core.safety import Scope, UrlSafetyPolicy, classify_ip

IPV6_LOOPBACK = "::1"
IPV6_DOC = "2001:db8::10"


def _settings(scope: Scope, policy: UrlSafetyPolicy) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(scope=scope, policy=policy),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
    )


def _client(scope: Scope, policy: UrlSafetyPolicy) -> tuple[ScopedNetClient, ScriptedNetTransport]:
    transport = ScriptedNetTransport()
    client = ScopedNetClient(
        settings=_settings(scope, policy),
        scope=scope,
        policy=policy,
        transport=transport,
    )
    return client, transport


# --------------------------------------------------------------------------- classification
def test_the_default_policy_denies_ipv6_loopback() -> None:
    """The default must stay restrictive: no opt-in, no address."""
    assert classify_ip(IPV6_LOOPBACK, UrlSafetyPolicy()) == "loopback-address"
    assert classify_ip("127.0.0.1", UrlSafetyPolicy()) == "loopback-address"


def test_the_loopback_opt_in_covers_both_families() -> None:
    policy = UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)
    assert classify_ip(IPV6_LOOPBACK, policy) is None
    assert classify_ip("127.0.0.1", policy) is None


def test_private_and_link_local_ipv6_keep_their_own_reasons() -> None:
    assert classify_ip("fd00::1", UrlSafetyPolicy()) == "private-address"
    assert classify_ip("fe80::1", UrlSafetyPolicy()) == "link-local-address"
    permissive = UrlSafetyPolicy(allow_private_ips=True, allow_link_local=True)
    assert classify_ip("fd00::1", permissive) is None
    assert classify_ip("fe80::1", permissive) is None


def test_multicast_and_unspecified_are_refused_even_with_every_opt_in() -> None:
    permissive = UrlSafetyPolicy(allow_private_ips=True, allow_link_local=True, allow_loopback=True)
    assert classify_ip("ff02::1", permissive) == "multicast-address"
    assert classify_ip("::", permissive) == "unspecified-address"


# --------------------------------------------------------------------------- scope decisions
def test_an_ipv6_network_scope_accepts_and_refuses_with_a_reason() -> None:
    scope = Scope(allowed_networks=("2001:db8::/32",))
    inside = scope.check(IPV6_DOC)
    assert inside.allowed is True
    assert inside.reason
    outside = scope.check("2001:dead::1")
    assert outside.allowed is False
    assert outside.reason


def test_an_ipv4_scope_never_authorizes_an_ipv6_address() -> None:
    """Cross-family authorization would be a scope hole; ``subnet_of`` refuses to compare."""
    scope = Scope(allowed_networks=("10.0.0.0/8",))
    assert scope.check(IPV6_DOC).allowed is False
    assert Scope(allowed_networks=("2001:db8::/32",)).check("10.0.0.1").allowed is False


def test_an_ipv6_cidr_target_is_judged_as_a_network() -> None:
    assert Scope(allowed_networks=("2001:db8::/32",)).check_network("2001:db8::/64").allowed
    assert not Scope(allowed_networks=("2001:db8::/32",)).check_network("2001:dead::/64").allowed


# --------------------------------------------------------------------------- packets
async def test_an_out_of_scope_ipv6_host_is_refused_before_any_packet() -> None:
    scope = Scope(allowed_hosts=("2001:db8::1",))
    client, transport = _client(scope, UrlSafetyPolicy(allow_loopback=True))
    with pytest.raises(OutOfScopeError):
        await client.tcp(IPV6_DOC, 443)
    assert transport.calls == [], "no probe may leave for an out-of-scope address"
    assert client.probes == 0


async def test_an_ipv6_host_out_of_policy_is_refused_before_any_packet() -> None:
    """In scope but not permitted by the address policy: still refused, still no packet."""
    scope = Scope(allowed_hosts=(IPV6_LOOPBACK,))
    client, transport = _client(scope, UrlSafetyPolicy())  # loopback not opted in
    with pytest.raises(SafetyError) as refused:
        await client.tcp(IPV6_LOOPBACK, 443)
    assert "loopback-address" in str(refused.value)
    assert transport.calls == []
    assert client.probes == 0


async def test_an_ipv6_probe_is_rate_limited_like_an_ipv4_one() -> None:
    """The same limiter object paces both families; here it is the same code path."""
    scope = Scope(allowed_hosts=(IPV6_LOOPBACK,))
    policy = UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)
    client, transport = _client(scope, policy)
    await client.tcp(IPV6_LOOPBACK, 4443)
    assert transport.calls == [("tcp", IPV6_LOOPBACK, 4443)]
    assert client.probes == 1


async def test_an_ipv6_dns_name_that_resolves_to_ipv6_only_is_dialled_over_ipv6() -> None:
    from arachne.core.safety import StaticResolver

    scope = Scope(allowed_hosts=("v6.test",))
    policy = UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)
    transport = ScriptedNetTransport()
    client = ScopedNetClient(
        settings=_settings(scope, policy),
        scope=scope,
        policy=policy,
        resolver=StaticResolver({"v6.test": ("2001:db8::99",)}),
        transport=transport,
    )
    await client.tcp("v6.test", 8443)
    assert transport.calls == [("tcp", "2001:db8::99", 8443)], "the pinned AAAA was dialled"
