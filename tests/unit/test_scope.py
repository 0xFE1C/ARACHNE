"""The scope model's dimensions and its fail-closed paths (F-01-02, F-08-03).

``Scope`` is the one object standing between a scan and the network, so its edges get
explicit tests: every allow dimension, every exclusion, the dispatcher, and each way a
value can be rejected or unparseable.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.core.safety import (
    Scope,
    host_in_domain,
    host_matches_glob,
    is_valid_hostname,
    normalize_host,
    ref_matches,
    subnet_of,
    url_under_prefix,
)


# ------------------------------------------------------------------ helper functions
@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("example.com", "example.com", True),
        ("EXAMPLE.com.", "example.com", True),
        ("api.example.com", "example.com", False),
        ("api.example.com", "*.example.com", True),
        ("example.com", "*.example.com", False),
        ("deep.api.example.com", "*.example.com", True),
        ("example.com", "", False),
    ],
)
def test_host_glob_matching(host: str, pattern: str, expected: bool) -> None:
    assert host_matches_glob(host, pattern) is expected


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("api.example.com", "example.com", True),
        ("example.com", "*.example.com", True),  # a domain entry means apex + subdomains
        ("example.net", "example.com", False),
        ("example.com", "", False),
    ],
)
def test_domain_suffix_matching(host: str, domain: str, expected: bool) -> None:
    assert host_in_domain(host, domain) is expected


@pytest.mark.parametrize(
    ("url", "prefix", "expected"),
    [
        ("https://example.com/api", "https://example.com/api", True),
        ("https://example.com/api/v1", "https://example.com/api/", True),
        ("https://example.com:443/api", "https://example.com/api", True),
        ("HTTPS://Example.COM/api", "https://example.com/api", True),
        ("https://example.com/apiary", "https://example.com/api", False),
        ("https://example.com/other", "https://example.com/api", False),
        ("https://other.example.com/api", "https://example.com/api", False),
        ("", "https://example.com/", False),
        ("https://example.com/", "", False),
    ],
)
def test_url_prefix_matching_is_not_a_substring_test(url: str, prefix: str, expected: bool) -> None:
    assert url_under_prefix(url, prefix) is expected


def test_reference_patterns_support_an_exact_or_prefix_form() -> None:
    assert ref_matches("aws:123456789012", "aws:123456789012")
    assert ref_matches("aws:*", "aws:123456789012/us-east-1")
    assert not ref_matches("aws:999", "aws:123456789012")
    assert not ref_matches("", "aws:1")


def test_subnet_of_is_version_safe() -> None:
    import ipaddress

    v4_outer = ipaddress.ip_network("192.0.2.0/24")
    v6_outer = ipaddress.ip_network("2001:db8::/32")
    assert subnet_of(ipaddress.ip_network("192.0.2.0/28"), v4_outer)
    assert subnet_of(ipaddress.ip_network("2001:db8::/48"), v6_outer)
    assert not subnet_of(ipaddress.ip_network("2001:db8::/48"), v4_outer)
    assert not subnet_of(ipaddress.ip_network("198.51.100.0/24"), v4_outer)


def test_hostname_validation_rejects_addresses_and_junk() -> None:
    assert is_valid_hostname("api.example.com")
    assert not is_valid_hostname("93.184.216.34")
    assert not is_valid_hostname("not a host")
    assert not is_valid_hostname("")


def test_host_normalization() -> None:
    assert normalize_host("  Example.COM.  ") == "example.com"


# ------------------------------------------------------------------------ dimensions
def test_network_targets_need_a_declared_network() -> None:
    scope = Scope(allowed_hosts=("example.com",))
    decision = scope.check_network("192.0.2.0/24")
    assert not decision.allowed
    assert "not in the declared scope" in decision.reason


def test_empty_scope_denies_every_dimension() -> None:
    empty = Scope.deny_all()
    assert empty.is_empty
    for decision in (
        empty.check("example.com"),
        empty.check_url("https://example.com/"),
        empty.check_network("192.0.2.0/24"),
        empty.check_ref("aws:1234"),
        empty.check_value("cloud", "aws:1234"),
    ):
        assert not decision.allowed
        assert "deny by default" in decision.reason


def test_invalid_network_in_a_scope_fails_fast() -> None:
    with pytest.raises(ConfigurationError, match="not a valid CIDR"):
        Scope(allowed_networks=("192.0.2.0/33",))
    with pytest.raises(ConfigurationError):
        Scope(excluded_networks=("nonsense",))


def test_a_network_fully_inside_an_excluded_network_is_denied() -> None:
    scope = Scope(allowed_networks=("192.0.2.0/22",), excluded_networks=("192.0.2.0/24",))
    assert not scope.check_network("192.0.2.0/28").allowed
    assert "excluded network" in scope.check_network("192.0.2.0/28").reason
    assert scope.check_network("192.0.3.0/24").allowed


def test_unparseable_network_value_is_denied_not_raised() -> None:
    scope = Scope(allowed_networks=("192.0.2.0/24",))
    assert not scope.check_network("not-a-network").allowed
    assert "unparseable" in scope.check_network("not-a-network").reason


def test_excluded_reference_wins() -> None:
    scope = Scope(allowed_refs=("aws:*",), excluded_refs=("aws:123456789012",))
    assert not scope.check_ref("aws:123456789012").allowed
    assert "excluded" in scope.check_ref("aws:123456789012").reason
    assert scope.check_ref("aws:999999999999").allowed


def test_excluded_url_prefix_wins_over_a_declared_prefix() -> None:
    scope = Scope(
        url_prefixes=("https://example.com/api/",),
        excluded_url_prefixes=("https://example.com/api/private/",),
    )
    assert scope.check_url("https://example.com/api/v1").allowed
    private = scope.check_url("https://example.com/api/private/keys")
    assert not private.allowed
    assert "excluded URL prefix" in private.reason


def test_a_url_with_no_host_is_denied() -> None:
    scope = Scope(allowed_hosts=("example.com",))
    decision = scope.check_url("file:///etc/passwd")
    assert not decision.allowed
    assert decision.reason == "missing host"


def test_a_host_of_only_dots_is_denied() -> None:
    scope = Scope(allowed_hosts=("example.com",))
    decision = scope.check("...")
    assert not decision.allowed


def test_excluded_domain_wins_over_an_allowed_subdomain() -> None:
    scope = Scope(allowed_domains=("example.com",), excluded_domains=("admin.example.com",))
    assert scope.check("api.example.com").allowed
    assert not scope.check("admin.example.com").allowed
    assert "excluded" in scope.check("admin.example.com").reason


def test_excluded_address_inside_an_allowed_network_is_denied() -> None:
    scope = Scope(allowed_networks=("192.0.2.0/24",), excluded_networks=("192.0.2.9/32",))
    assert scope.check("192.0.2.1").allowed
    assert not scope.check("192.0.2.9").allowed


def test_from_hosts_builds_a_host_allowlist() -> None:
    scope = Scope.from_hosts(["example.com"])
    assert scope.check("example.com").allowed
    assert not scope.check("other.example").allowed


# ------------------------------------------------------------------------ dispatcher
def test_check_value_routes_each_kind_to_its_dimension() -> None:
    scope = Scope(
        allowed_hosts=("api.example.com",),
        allowed_domains=("example.com",),
        allowed_networks=("192.0.2.0/24",),
        url_prefixes=("https://example.com/api/",),
        allowed_refs=("aws:123456789012", "git@github.com:org/repo.git"),
    )
    assert scope.check_value("host", "api.example.com").allowed
    assert scope.check_value("domain", "www.example.com").allowed
    assert scope.check_value("domain_pattern", "api.example.com").allowed
    assert scope.check_value("ip", "192.0.2.5").allowed
    assert scope.check_value("cidr", "192.0.2.0/28").allowed
    assert scope.check_value("network", "192.0.2.0/28").allowed
    assert scope.check_value("url", "https://example.com/api/v1").allowed
    assert scope.check_value("cloud", "aws:123456789012").allowed
    assert scope.check_value("git", "git@github.com:org/repo.git").allowed


def test_check_value_falls_back_to_the_reference_host_for_a_git_target() -> None:
    """A Git target declared only by its host still passes when the host is allowlisted."""
    scope = Scope(allowed_hosts=("github.com",))
    assert scope.check_value("git", "git@github.com:org/repo.git").allowed
    # ... and a Git reference with no host at all cannot be resolved to one.
    assert not scope.check_value("git", "just-a-string").allowed


def test_check_value_denies_an_unknown_kind() -> None:
    scope = Scope(allowed_hosts=("example.com",))
    decision = scope.check_value("quantum", "example.com")
    assert not decision.allowed
    assert "unsupported target kind" in decision.reason


def test_check_value_honours_exclusions_for_every_kind() -> None:
    scope = Scope(
        allowed_domains=("example.com",),
        allowed_networks=("192.0.2.0/24",),
        allowed_refs=("aws:*",),
        excluded_domains=("admin.example.com",),
        excluded_networks=("192.0.2.0/28",),
        excluded_refs=("aws:123456789012",),
    )
    assert scope.check_value("domain", "api.example.com").allowed
    assert not scope.check_value("domain", "admin.example.com").allowed
    assert scope.check_value("ip", "192.0.2.20").allowed
    assert not scope.check_value("ip", "192.0.2.2").allowed
    assert scope.check_value("cloud", "aws:999").allowed
    assert not scope.check_value("cloud", "aws:123456789012").allowed


def test_describe_reports_every_dimension_for_reports_and_plans() -> None:
    described = Scope(allowed_hosts=("a.example",), excluded_refs=("aws:1",)).describe()
    assert set(described) == {
        "allowed_hosts",
        "allowed_domains",
        "allowed_networks",
        "url_prefixes",
        "allowed_refs",
        # S29 (REQ-DEPTH-005): the local-artifact dimension. A plan and a report must be able
        # to show that a scan was authorized to read a file, not only to contact a host.
        "allowed_artifacts",
        "excluded_hosts",
        "excluded_domains",
        "excluded_networks",
        "excluded_url_prefixes",
        "excluded_refs",
        "excluded_artifacts",
    }
    assert described["allowed_hosts"] == ["a.example"]
