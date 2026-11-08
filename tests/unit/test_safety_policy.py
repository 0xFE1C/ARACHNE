"""URL safety and scope-policy unit tests (F-08-03, F-01-02)."""

from __future__ import annotations

import pytest
from tests.conftest import PUBLIC_IP, TARGET_HOST

from arachne.core.errors import OutOfScopeError, UnsafeUrlError
from arachne.core.safety import (
    Scope,
    StaticResolver,
    UrlSafetyPolicy,
    classify_ip,
    validate_url,
)

PUBLIC_SCOPE = Scope(allowed_hosts=(TARGET_HOST,))


async def test_public_https_url_passes() -> None:
    resolved = await validate_url(
        f"https://{TARGET_HOST}/path", PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,))
    )
    assert resolved.host == TARGET_HOST
    assert resolved.port == 443
    assert resolved.addresses == (PUBLIC_IP,)
    assert resolved.origin == f"https://{TARGET_HOST}:443"


async def test_default_port_depends_on_scheme() -> None:
    resolved = await validate_url(
        f"http://{TARGET_HOST}/", PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,))
    )
    assert resolved.port == 80


@pytest.mark.parametrize(
    "url",
    ["ftp://example.com/f", "file:///etc/shadow", "gopher://example.com/", "data:text/html,x"],
)
async def test_non_http_schemes_rejected(url: str) -> None:
    with pytest.raises(UnsafeUrlError) as excinfo:
        await validate_url(url, PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,)))
    assert excinfo.value.reason == "scheme-not-allowed"
    assert "not allowed" in str(excinfo.value)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://localhost/", "internal-hostname"),
        ("http://api.internal/", "internal-hostname"),
        ("http://printer.local/", "internal-hostname"),
        ("http://metadata.google.internal/", "metadata-endpoint"),
        ("http://2130706433/", "ambiguous-ip-encoding"),
        ("http://0x7f000001/", "ambiguous-ip-encoding"),
    ],
)
async def test_hostname_policy_rejections(url: str, reason: str) -> None:
    host = url.split("//", 1)[1].split("/", 1)[0]
    with pytest.raises(UnsafeUrlError) as excinfo:
        await validate_url(url, Scope(allowed_hosts=(host,)), resolver=StaticResolver((PUBLIC_IP,)))
    assert excinfo.value.reason == reason


async def test_ip_range_policy() -> None:
    scope = Scope(allowed_hosts=("10.0.0.1", "93.184.216.34"))
    with pytest.raises(UnsafeUrlError, match="private-address"):
        await validate_url("http://10.0.0.1/", scope)
    ok = await validate_url("http://93.184.216.34/", scope)
    assert ok.addresses == ("93.184.216.34",)


async def test_private_ips_allowed_only_by_explicit_policy() -> None:
    scope = Scope(allowed_hosts=("10.0.0.1",))
    permissive = UrlSafetyPolicy(allow_private_ips=True)
    resolved = await validate_url("http://10.0.0.1/", scope, policy=permissive)
    assert resolved.addresses == ("10.0.0.1",)


async def test_localhost_is_reachable_only_by_the_loopback_opt_in() -> None:
    """``localhost`` names *this* machine, so the loopback switch governs it — and only it.

    A self-hosted model server is named ``localhost`` in the path every deployment
    documents, so the default must keep refusing it (the reserved ``.localhost`` spelling
    stays internal) while an explicit ``allow_loopback`` reaches it. No other internal name
    may ride along with that opt-in: those name a network, not this host.
    """
    scope = Scope(allowed_hosts=("localhost",))
    with pytest.raises(UnsafeUrlError) as refused:
        await validate_url("http://localhost/", scope, resolver=StaticResolver(("127.0.0.1",)))
    assert refused.value.reason == "internal-hostname"

    permissive = UrlSafetyPolicy(allow_loopback=True)
    resolved = await validate_url(
        "http://localhost/", scope, policy=permissive, resolver=StaticResolver(("127.0.0.1",))
    )
    assert resolved.host == "localhost"
    assert resolved.addresses == ("127.0.0.1",)

    for host in ("foo.localhost", "printer.local", "api.internal"):
        with pytest.raises(UnsafeUrlError) as still_internal:
            await validate_url(
                f"http://{host}/",
                Scope(allowed_hosts=(host,)),
                policy=permissive,
                resolver=StaticResolver(("127.0.0.1",)),
            )
        assert still_internal.value.reason == "internal-hostname"


async def test_any_blocked_address_in_a_record_set_blocks_the_host() -> None:
    """A name resolving to one public and one private address is refused entirely."""
    scope = Scope(allowed_hosts=(TARGET_HOST,))
    resolver = StaticResolver((PUBLIC_IP, "192.168.0.10"))
    with pytest.raises(UnsafeUrlError, match="private-address"):
        await validate_url(f"https://{TARGET_HOST}/", scope, resolver=resolver)


async def test_dns_failure_is_reported_as_such() -> None:
    with pytest.raises(UnsafeUrlError) as excinfo:
        await validate_url(f"https://{TARGET_HOST}/", PUBLIC_SCOPE, resolver=StaticResolver({}))
    assert excinfo.value.reason == "dns-failure"


async def test_empty_resolution_is_rejected() -> None:
    with pytest.raises(UnsafeUrlError) as excinfo:
        await validate_url(f"https://{TARGET_HOST}/", PUBLIC_SCOPE, resolver=StaticResolver(()))
    assert excinfo.value.reason == "dns-empty"


@pytest.mark.parametrize("url", ["", "   ", "https://example.com/a b", "not-a-url"])
async def test_malformed_urls_rejected(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        await validate_url(url, PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,)))


async def test_port_zero_and_out_of_range_rejected() -> None:
    for url in (f"https://{TARGET_HOST}:0/", f"https://{TARGET_HOST}:70000/"):
        with pytest.raises(UnsafeUrlError) as excinfo:
            await validate_url(url, PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,)))
        assert excinfo.value.reason == "invalid-port"


async def test_missing_host_rejected() -> None:
    with pytest.raises(UnsafeUrlError) as excinfo:
        await validate_url("https:///path", PUBLIC_SCOPE, resolver=StaticResolver((PUBLIC_IP,)))
    assert excinfo.value.reason == "missing-host"


def test_scope_matching_rules() -> None:
    scope = Scope(
        allowed_hosts=("*.example.com", "api.test.dev"),
        allowed_domains=("corp.internal.example",),
        excluded_hosts=("secret.example.com",),
    )
    assert scope.check("www.example.com").allowed
    assert scope.check("api.test.dev").allowed
    assert scope.check("deep.corp.internal.example").allowed
    assert scope.check("corp.internal.example").allowed
    assert not scope.check("secret.example.com").allowed
    assert "excluded" in scope.check("secret.example.com").reason
    assert not scope.check("example.org").allowed


def test_scope_is_case_insensitive_and_denies_by_default() -> None:
    scope = Scope(allowed_hosts=("Example.COM",))
    assert scope.check("EXAMPLE.com").allowed
    assert not Scope.deny_all().check("example.com").allowed
    assert "deny by default" in Scope.deny_all().check("example.com").reason


async def test_out_of_scope_raises_the_dedicated_error() -> None:
    scope = Scope(allowed_hosts=("example.com",))
    with pytest.raises(OutOfScopeError) as excinfo:
        await validate_url(
            "https://other.example.net/", scope, resolver=StaticResolver((PUBLIC_IP,))
        )
    assert excinfo.value.reason == "host is not in the declared scope"


def test_classify_ip_categories() -> None:
    assert classify_ip("8.8.8.8") is None
    assert classify_ip("127.0.0.1") == "loopback-address"
    assert classify_ip("::1") == "loopback-address"
    assert classify_ip("fe80::1") == "link-local-address"
    assert classify_ip("169.254.169.254") == "link-local-address"
    assert classify_ip("10.1.2.3") == "private-address"
    assert classify_ip("fc00::1") == "private-address"
    assert classify_ip("0.0.0.0") == "unspecified-address"
    assert classify_ip("224.0.0.1") == "multicast-address"
    assert classify_ip("240.0.0.1") == "reserved-address"
    assert classify_ip("not-an-ip") == "unparseable-address"


def test_safety_policy_defaults_are_restrictive() -> None:
    policy = UrlSafetyPolicy()
    assert policy.allowed_schemes == frozenset({"http", "https"})
    assert not policy.allow_private_ips
    assert not policy.allow_loopback
    assert not policy.allow_link_local
