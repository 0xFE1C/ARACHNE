"""Target definition, exclusions and the authorization attestation (F-01-01/02/09, F-08-05)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.conftest import DEFAULT_ATTESTATION, EXAMPLES_DIR, build_scan_request

from arachne.core.errors import AuthorizationError, ConfigurationError
from arachne.core.safety import Scope
from arachne.core.target import (
    AuthorizationAttestation,
    EngineName,
    ModuleSelection,
    TargetDefinition,
    TargetSelector,
    load_scan_request,
    load_scan_request_from_text,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------- selectors
@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("domain", "Example.COM.", "example.com"),
        ("domain_pattern", "*.Example.com", "*.example.com"),
        ("domain_pattern", "API.example.com", "api.example.com"),
        ("url", "HTTPS://Example.com:443/path?a=1", "https://example.com/path?a=1"),
        ("ip", "[2001:db8::1]", "2001:db8::1"),
        ("cidr", "192.0.2.7/30", "192.0.2.4/30"),  # normalized to the containing network
        ("git", "HTTPS://GitHub.com/org/repo.git", "https://github.com/org/repo.git"),
        ("cloud", "AWS:123456789012", "aws:123456789012"),
    ],
)
def test_selectors_are_normalized(kind: str, value: str, expected: str) -> None:
    assert TargetSelector(kind=kind, value=value).value == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("domain", "not a domain"),
        ("domain", "93.184.216.34"),  # an address is the `ip` kind
        ("domain_pattern", "*.example.com/path"),
        ("url", "ftp://example.com/"),
        ("url", "https://user:secret@example.com/"),  # credentials must not be stored
        ("url", "https:///no-host"),
        ("ip", "999.1.1.1"),
        ("cidr", "0.0.0.0/0"),  # a default route is never a scan target
        ("cidr", "::/0"),
        ("cidr", "192.0.2.0/33"),
        ("git", "github.com/org/repo"),
        ("cloud", "aws"),
        ("cloud", "aws:has space"),
    ],
)
def test_invalid_selectors_are_rejected(kind: str, value: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TargetSelector(kind=kind, value=value)


def test_git_selector_accepts_scp_like_form_and_reports_its_host() -> None:
    selector = TargetSelector(kind="git", value="git@github.com:org/repo.git")
    assert selector.value == "git@github.com:org/repo.git"
    assert selector.host == "github.com"


def test_non_host_selectors_report_no_host() -> None:
    assert TargetSelector(kind="cidr", value="192.0.2.0/24").host is None
    assert TargetSelector(kind="cloud", value="aws:1234").host is None


# ------------------------------------------------------------------------- scope
def test_compile_scope_maps_every_kind_and_exclusion() -> None:
    definition = TargetDefinition.model_validate(
        {
            "name": "mapping",
            "targets": [
                {"kind": "domain", "value": "example.com"},
                {"kind": "domain_pattern", "value": "*.example.com"},
                {"kind": "ip", "value": "93.184.216.34"},
                {"kind": "cidr", "value": "192.0.2.0/30"},
                {"kind": "url", "value": "https://example.com/api/?q=1"},
                {"kind": "git", "value": "git@github.com:org/repo.git"},
                {"kind": "cloud", "value": "aws:1234"},
            ],
            "exclusions": [
                {"kind": "domain", "value": "admin.example.com"},
                {"kind": "ip", "value": "93.184.216.35"},
                {"kind": "cidr", "value": "192.0.2.2/32"},
                {"kind": "url", "value": "https://example.com/api/private/"},
                {"kind": "cloud", "value": "aws:9999"},
            ],
        }
    )
    scope = definition.compile_scope()

    assert scope.allowed_domains == ("example.com",)
    assert "*.example.com" in scope.allowed_hosts
    assert "93.184.216.34" in scope.allowed_hosts
    assert "github.com" in scope.allowed_hosts  # a Git selector's own host
    assert scope.allowed_networks == ("192.0.2.0/30",)
    assert scope.url_prefixes == ("https://example.com/api/",)  # query dropped
    assert set(scope.allowed_refs) == {"git@github.com:org/repo.git", "aws:1234"}
    assert scope.excluded_domains == ("admin.example.com",)
    assert "93.184.216.35" in scope.excluded_hosts
    assert scope.excluded_networks == ("192.0.2.2/32",)
    assert scope.excluded_url_prefixes == ("https://example.com/api/private/",)
    assert scope.excluded_refs == ("aws:9999",)


def test_compiled_scope_denies_a_host_that_was_not_declared() -> None:
    definition = TargetDefinition.model_validate(
        {"name": "one-domain", "targets": [{"kind": "domain", "value": "example.com"}]}
    )
    scope = definition.compile_scope()
    assert scope.check("api.example.com").allowed
    assert not scope.check("example.net").allowed


def test_exclusion_of_a_single_address_inside_a_declared_range_is_allowed() -> None:
    definition = TargetDefinition.model_validate(
        {
            "name": "range",
            "targets": [{"kind": "cidr", "value": "192.0.2.0/30"}],
            "exclusions": [{"kind": "cidr", "value": "192.0.2.2/32"}],
        }
    )
    scope = definition.compile_scope()
    assert scope.check_network("192.0.2.0/30").allowed
    assert not scope.check("192.0.2.2").allowed  # the per-address exclusion still holds
    assert scope.check("192.0.2.1").allowed


def test_scope_reports_every_declared_dimension() -> None:
    described = Scope(allowed_networks=("192.0.2.0/30",), allowed_refs=("aws:*",)).describe()
    assert described["allowed_networks"] == ["192.0.2.0/30"]
    assert described["allowed_refs"] == ["aws:*"]


def test_a_cidr_target_must_sit_inside_a_declared_network() -> None:
    scope = Scope(allowed_networks=("192.0.2.0/24",))
    assert scope.check_network("192.0.2.0/30").allowed
    assert not scope.check_network("198.51.100.0/30").allowed
    assert "not in the declared scope" in scope.check_network("198.51.100.0/30").reason


def test_a_reference_target_needs_a_reference_dimension() -> None:
    scope = Scope(allowed_refs=("aws:123456789012", "https://github.com/org/*"))
    assert scope.check_ref("aws:123456789012").allowed
    assert scope.check_ref("https://github.com/org/repo.git").allowed
    assert not scope.check_ref("gcp:other-project").allowed


# ----------------------------------------------------------------- attestation
def attestation(**overrides: object) -> AuthorizationAttestation:
    payload = dict(DEFAULT_ATTESTATION) | overrides
    return AuthorizationAttestation.model_validate(payload)


def test_attestation_requires_a_timezone() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AuthorizationAttestation.model_validate(
            {**DEFAULT_ATTESTATION, "attested_at": "2026-10-01T00:00:00"}
        )


def test_attestation_window_must_be_ordered() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AuthorizationAttestation.model_validate(
            {
                **DEFAULT_ATTESTATION,
                "attested_at": "2026-10-01T00:00:00Z",
                "expires_at": "2026-09-01T00:00:00Z",
            }
        )


@pytest.mark.parametrize(
    ("allowed", "selector", "covered"),
    [
        (["example.com"], {"kind": "domain", "value": "example.com"}, True),
        (["example.com"], {"kind": "domain", "value": "api.example.com"}, True),
        (["example.com"], {"kind": "domain_pattern", "value": "*.example.com"}, True),
        (["example.com"], {"kind": "url", "value": "https://www.example.com/x"}, True),
        (["example.com"], {"kind": "domain", "value": "example.net"}, False),
        (["example.com"], {"kind": "ip", "value": "93.184.216.34"}, False),
        (["*.example.com"], {"kind": "domain", "value": "example.com"}, False),
        (["*.example.com"], {"kind": "domain_pattern", "value": "*.example.com"}, True),
        (["*.example.com"], {"kind": "domain_pattern", "value": "*.api.example.com"}, True),
        (["*.example.com"], {"kind": "domain_pattern", "value": "example.com"}, False),
        (["192.0.2.0/24"], {"kind": "cidr", "value": "192.0.2.0/28"}, True),
        (["192.0.2.0/24"], {"kind": "cidr", "value": "192.0.2.0/16"}, False),
        (["192.0.2.0/24"], {"kind": "ip", "value": "192.0.2.9"}, True),
        (["192.0.2.0/24"], {"kind": "ip", "value": "192.0.3.9"}, False),
        (["https://github.com/org/repo.git"], {"kind": "git"}, True),
        (["aws:123456789012"], {"kind": "cloud", "value": "aws:123456789012"}, True),
        (["aws:*"], {"kind": "cloud", "value": "aws:123456789012/us-east-1"}, True),
        (["aws:999999999999"], {"kind": "cloud", "value": "aws:123456789012"}, False),
        (
            ["https://example.com/api/"],
            {"kind": "url", "value": "https://example.com/api/v1"},
            True,
        ),
        (["https://example.com/api/"], {"kind": "url", "value": "https://example.com/x"}, False),
    ],
)
def test_attestation_coverage_rules(
    allowed: list[str], selector: dict[str, str], covered: bool
) -> None:
    value = selector.get("value", "https://github.com/org/repo.git")
    target = TargetSelector(kind=selector["kind"], value=value)
    assert attestation(allowed_targets=allowed).covers(target) is covered


def test_attestation_rejects_a_malformed_entry() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        attestation(allowed_targets=["ftp://example.com/"])


# ------------------------------------------------------------- authorization gate
def test_definition_without_attestation_is_refused() -> None:
    request = build_scan_request(attestation=None)
    errors = request.target.authorization_errors(now=NOW)
    assert errors and "no authorization attestation" in errors[0]
    with pytest.raises(AuthorizationError):
        request.target.assert_authorized(now=NOW)


def test_expired_attestation_is_refused() -> None:
    request = build_scan_request(attestation={"expires_at": "2026-10-02T00:00:00Z"})
    errors = request.target.authorization_errors(now=NOW)
    assert any("expired" in error for error in errors)
    assert not request.target.is_live_ready(now=NOW)


def test_attestation_dated_in_the_future_is_refused() -> None:
    request = build_scan_request(attestation={"attested_at": "2027-01-01T00:00:00Z"})
    assert any("future" in error for error in request.target.authorization_errors(now=NOW))


def test_uncovered_target_is_refused_and_named() -> None:
    request = build_scan_request(
        targets=[
            {"kind": "domain", "value": "example.com"},
            {"kind": "ip", "value": "93.184.216.34"},
        ]
    )
    errors = request.target.authorization_errors(now=NOW)
    assert len(errors) == 1
    assert "ip:93.184.216.34" in errors[0]


def test_active_checks_need_the_attestation_flag() -> None:
    request = build_scan_request(options={"active_checks": True})
    errors = request.target.authorization_errors(active_checks=True, now=NOW)
    assert any("active checks" in error for error in errors)

    authorized = build_scan_request(
        attestation={"active_checks_authorized": True}, options={"active_checks": True}
    )
    assert authorized.target.is_live_ready(active_checks=True, now=NOW)


def test_authorized_definition_reports_no_errors() -> None:
    request = build_scan_request()
    assert request.target.authorization_errors(now=NOW) == ()
    assert request.target.assert_authorized(now=NOW).attested_by.startswith("Jane Operator")


def test_authorization_error_is_non_retryable_context_for_the_audit_trail() -> None:
    request = build_scan_request(attestation=None)
    with pytest.raises(AuthorizationError) as excinfo:
        request.target.assert_authorized(now=NOW)
    assert excinfo.value.reason
    assert excinfo.value.category.value == "authorization"


# ----------------------------------------------------------------------- options
def test_module_selection_defaults_to_everything_and_disabled_wins() -> None:
    assert ModuleSelection().includes("M3")
    assert ModuleSelection(enabled=("M1",)).includes("M1")
    assert not ModuleSelection(enabled=("M1",)).includes("M2")
    assert not ModuleSelection(enabled=("M1",), disabled=("M1",)).includes("M1")
    assert not ModuleSelection(disabled=("M4",)).includes("M4")


def test_module_selection_rejects_unknown_ids() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ModuleSelection(enabled=("M7",))


def test_engine_names_cover_the_spec_choices() -> None:
    assert {engine.value for engine in EngineName} == {"heuristic", "ai", "hybrid"}


# ----------------------------------------------------------------------- loading
def test_shipped_example_fixture_is_valid_and_authorized() -> None:
    request = load_scan_request(EXAMPLES_DIR / "lab-fixture.yaml")
    assert request.target.name == "lab-fixture"
    assert len(request.target.targets) == 5
    assert len(request.target.exclusions) == 2
    assert request.options.engine is EngineName.HEURISTIC
    # The attestation covers every declared target and active checks stay off.
    assert request.target.is_live_ready(active_checks=request.options.active_checks, now=NOW)


def test_fixture_can_be_json(tmp_path: Path) -> None:
    path = tmp_path / "target.json"
    path.write_text(
        """{"target": {"name": "json", "targets": [{"kind": "domain", "value": "example.com"}]}}""",
        encoding="utf-8",
    )
    assert load_scan_request(path).target.name == "json"


def test_missing_fixture_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_scan_request(tmp_path / "nope.yaml")


def test_empty_fixture_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="empty"):
        load_scan_request_from_text("# only a comment\n")


def test_invalid_fixture_reports_the_offending_location() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        load_scan_request_from_text(
            "target:\n  name: broken\n  targets:\n    - {kind: url, value: 'ftp://x/'}\n"
        )
    assert "target.targets.0" in str(excinfo.value)


def test_fixture_without_targets_is_rejected() -> None:
    with pytest.raises(ConfigurationError):
        load_scan_request_from_text("target:\n  name: empty\n  targets: []\n")


def test_definition_round_trips_through_scope_and_attestation_dicts() -> None:
    request = build_scan_request()
    document = request.target.to_dict()
    restored = TargetDefinition.model_validate(
        {
            "name": document["name"],
            "targets": document["targets"],
            "exclusions": document["exclusions"],
            "attestation": document["attestation"],
        }
    )
    assert restored == request.target


def test_attestation_summary_carries_who_scope_and_when() -> None:
    summary = attestation(expires_at="2027-01-01T00:00:00Z").summary()
    assert summary["attested_by"] == DEFAULT_ATTESTATION["attested_by"]
    assert summary["attested_at"].startswith("2026-10-01")
    assert summary["authorization_ref"] == "TEST-1"
    assert summary["expires_at"].startswith("2027-01-01")
    assert summary["allowed_targets"] == ["example.com"]


def test_attestation_expiry_helpers_use_the_supplied_clock() -> None:
    signed = attestation(expires_at=(NOW + timedelta(days=1)).isoformat())
    assert not signed.is_expired(NOW)
    assert signed.is_expired(NOW + timedelta(days=2))
    assert not signed.is_future_dated(NOW)
