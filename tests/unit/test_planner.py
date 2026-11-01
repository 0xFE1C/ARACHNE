"""The dry-run planner (F-01-10) and the scan plan (F-01-03).

The property under test throughout is that planning is **pure computation**: no resolver,
no socket, no module import. ``test_planning_makes_no_network_call`` pins that by making
every egress path explode during the call.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime

import httpx
import pytest
from tests.conftest import build_scan_request

from arachne.core.catalog import load_catalog
from arachne.core.config import PlannerSettings
from arachne.core.http import ScopedHttpClient
from arachne.core.planner import DEFAULT_PIPELINE, Planner, ScanStep, expand_targets
from arachne.core.target import TargetSelector

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def planner() -> Planner:
    return Planner(load_catalog())


def plan_for(planner: Planner, request, **kwargs):  # type: ignore[no-untyped-def]
    defaults = {
        "dry_run": True,
        "scope": request.target.compile_scope(),
        "active_checks_allowed": False,
        "handled_steps": frozenset(ScanStep),
        "now": NOW,
    }
    return planner.plan(request, **(defaults | kwargs))


# ----------------------------------------------------------------- target expansion
def test_domain_expansion_counts_one_host_by_default() -> None:
    assets = expand_targets(
        (TargetSelector(kind="domain", value="example.com"),), PlannerSettings()
    )
    assert assets[0].host_count == 1
    assert assets[0].request_units == 1
    assert not assets[0].capped


def test_subdomain_assumption_is_applied_and_visible() -> None:
    settings = PlannerSettings(assumed_subdomains_per_domain=4)
    assets = expand_targets(
        (TargetSelector(kind="domain_pattern", value="*.example.com"),), settings
    )
    assert assets[0].request_units == 5


def test_ipv4_network_size_excludes_network_and_broadcast_addresses() -> None:
    assets = expand_targets((TargetSelector(kind="cidr", value="192.0.2.0/29"),), PlannerSettings())
    assert assets[0].host_count == 6  # 8 addresses minus network and broadcast


def test_wide_network_is_capped_and_flagged() -> None:
    assets = expand_targets(
        (TargetSelector(kind="cidr", value="10.0.0.0/8"),),
        PlannerSettings(max_hosts_per_network=128),
    )
    assert assets[0].request_units == 128
    assert assets[0].capped


def test_ipv6_network_is_capped_rather_than_counted_exactly() -> None:
    assets = expand_targets(
        (TargetSelector(kind="cidr", value="2001:db8::/32"),),
        PlannerSettings(max_hosts_per_network=64),
    )
    assert assets[0].request_units == 64
    assert assets[0].capped


def test_git_and_cloud_references_contribute_no_host() -> None:
    assets = expand_targets(
        (
            TargetSelector(kind="git", value="https://github.com/o/r.git"),
            TargetSelector(kind="cloud", value="aws:1234"),
        ),
        PlannerSettings(),
    )
    assert [asset.host_count for asset in assets] == [0, 0]
    assert [asset.request_units for asset in assets] == [1, 1]


# --------------------------------------------------------------------------- plans
def test_plan_lists_every_catalogue_check_with_a_decision(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request())
    assert len(plan.checks) == len(planner.catalog.checks)
    included = {check.key for check in plan.included_checks}
    withheld = {check.key for check in plan.withheld_checks}
    assert included | withheld == {check.key for check in plan.checks}
    assert not included & withheld


def test_plan_groups_checks_into_the_f01_03_pipeline(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request())
    assert [step.step for step in plan.steps] == list(DEFAULT_PIPELINE)
    by_step = {step.step: step for step in plan.steps}
    # M1 is reconnaissance, M2 is discovery, the rest are per-module checks (02- §3).
    assert all(key.startswith("M1/") for key in by_step[ScanStep.RECON].checks)
    assert all(key.startswith("M2/") for key in by_step[ScanStep.DISCOVERY].checks)
    assert all(
        key.startswith(("M3/", "M4/", "M5/", "M6/")) for key in by_step[ScanStep.CHECKS].checks
    )


def test_step_request_estimates_add_up_to_the_total(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request())
    assert sum(step.estimated_requests for step in plan.steps) == plan.totals.estimated_requests
    assert plan.estimated_requests == sum(
        check.estimated_requests for check in plan.included_checks
    )


def test_request_estimate_scales_with_the_number_of_applicable_assets(planner: Planner) -> None:
    one = plan_for(
        planner, build_scan_request(targets=[{"kind": "url", "value": "https://e.example/"}])
    )
    two = plan_for(
        planner,
        build_scan_request(
            targets=[
                {"kind": "url", "value": "https://a.example/"},
                {"kind": "url", "value": "https://b.example/"},
            ]
        ),
    )
    env_one = next(check for check in one.included_checks if check.name == "env-file-probe")
    env_two = next(check for check in two.included_checks if check.name == "env-file-probe")
    assert env_one.applicable_assets == 1
    assert env_two.applicable_assets == 2
    assert env_two.estimated_requests == env_one.estimated_requests * 2


def test_active_checks_are_withheld_without_opt_in(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request())
    withheld = [check for check in plan.withheld_checks if check.requires_active_checks]
    assert withheld
    assert any(check.skip_code == "active-checks-not-opted-in" for check in withheld)
    assert plan.totals.active_checks == 0
    assert any("withheld pending opt-in" in warning for warning in plan.warnings)


def test_active_checks_are_included_when_authorized(planner: Planner) -> None:
    plan = plan_for(
        planner,
        build_scan_request(options={"active_checks": True}),
        active_checks_allowed=True,
    )
    assert plan.totals.active_checks == len(
        [check for check in plan.included_checks if check.requires_active_checks]
    )
    assert not any("withheld" in warning for warning in plan.warnings)
    assert not any("not authorize" in warning for warning in plan.warnings)


def test_requested_but_unauthorized_active_checks_are_reported(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request(options={"active_checks": True}))
    assert any("does not authorize them" in warning for warning in plan.warnings)


def test_checks_without_an_applicable_target_are_withheld(planner: Planner) -> None:
    # A cloud-only target: M3/M4 (URL-driven) have nothing to attach to.
    request = build_scan_request(
        targets=[{"kind": "cloud", "value": "aws:123456789012"}],
        attestation={"allowed_targets": ["aws:123456789012"]},
    )
    plan = plan_for(planner, request)
    withheld = {check.module for check in plan.withheld_checks}
    assert "M3" in withheld and "M4" in withheld
    assert all(
        check.skip_code == "no-applicable-target"
        for check in plan.withheld_checks
        if check.module in {"M3", "M4"}
    )
    assert "M5" in plan.totals.modules


def test_module_selection_excludes_the_other_modules(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request(options={"modules": {"enabled": ["M4"]}}))
    assert set(plan.totals.modules) == {"M4"}
    assert all(
        check.skip_code == "module-not-selected"
        for check in plan.withheld_checks
        if check.module == "M1"
    )


def test_steps_without_a_handler_are_marked_not_executable(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request(), handled_steps=frozenset({ScanStep.RECON}))
    by_step = {step.step: step for step in plan.steps}
    assert by_step[ScanStep.RECON].executable
    assert not by_step[ScanStep.CHECKS].executable
    # A step with planned checks is still planned even when this build cannot run it, and it
    # is reported as skipped because nothing will happen when the pipeline reaches it (S3:
    # "no handler" and "handler but nothing implemented" are both skips, with distinct reasons).
    assert by_step[ScanStep.CHECKS].checks
    assert by_step[ScanStep.CHECKS].skipped
    assert by_step[ScanStep.CHECKS].skip_reason == "no step handler is registered in this build"
    assert by_step[ScanStep.ANALYSIS].skipped
    assert by_step[ScanStep.ANALYSIS].skip_reason == "no step handler is registered in this build"


def test_planned_only_checks_are_reported_and_do_not_make_a_step_runnable(
    planner: Planner,
) -> None:
    """A step whose only checks are unimplemented is executable but skips at runtime (S3)."""
    plan = plan_for(
        planner,
        build_scan_request(),
        handled_steps=frozenset({ScanStep.RECON, ScanStep.CHECKS}),
    )
    by_step = {step.step: step for step in plan.steps}
    checks_step = by_step[ScanStep.CHECKS]
    assert checks_step.executable
    assert checks_step.skipped
    assert checks_step.skip_reason == "no implemented check targets this step in this build"
    assert checks_step.planned_only == len(checks_step.checks)
    assert plan.totals.planned_only_checks > 0


def test_implemented_checks_make_their_step_runnable(planner: Planner) -> None:
    """With the M1 checks implemented, the recon step is not skipped."""
    plan = plan_for(
        planner,
        build_scan_request(),
        handled_steps=frozenset({ScanStep.RECON, ScanStep.CHECKS}),
        implemented_checks=frozenset(
            check.key for check in load_catalog().checks if check.module == "M1"
        ),
    )
    by_step = {step.step: step for step in plan.steps}
    assert not by_step[ScanStep.RECON].skipped
    assert by_step[ScanStep.RECON].planned_only == 0
    assert any(check.implemented for check in plan.included_checks)


def test_assumption_and_cap_warnings_are_printed(planner: Planner) -> None:
    narrow = Planner(
        load_catalog(),
        settings=PlannerSettings(max_hosts_per_network=4, assumed_subdomains_per_domain=2),
    )
    plan = plan_for(
        narrow,
        build_scan_request(
            targets=[
                {"kind": "cidr", "value": "192.0.2.0/24"},
                {"kind": "domain", "value": "example.com"},
            ]
        ),
    )
    assert any("capped" in warning for warning in plan.warnings)
    assert any(
        "assumption" in warning or "assumed_subdomains" in warning for warning in plan.warnings
    )
    assert plan.totals.capped_networks == 1


def test_plan_reports_missing_attestation_and_is_not_live_ready(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request(attestation=None))
    assert plan.attestation is None
    assert not plan.live_ready
    assert any("no authorization attestation" in warning for warning in plan.warnings)


def test_plan_records_the_attestation_and_live_readiness(planner: Planner) -> None:
    plan = plan_for(planner, build_scan_request())
    assert plan.live_ready
    assert plan.attestation is not None
    assert plan.attestation["authorization_ref"] == "TEST-1"


def test_plan_is_json_safe(planner: Planner) -> None:
    import json

    document = plan_for(planner, build_scan_request()).to_dict()
    assert json.loads(json.dumps(document))["totals"]["estimated_requests"] >= 0
    assert document["steps"][0]["step"] == "recon"


def test_plan_serializes_and_restores(planner: Planner) -> None:
    from arachne.core.planner import ScanPlan

    plan = plan_for(planner, build_scan_request())
    restored = ScanPlan.model_validate(plan.to_dict())
    assert restored.target_name == plan.target_name
    assert restored.totals == plan.totals
    assert [step.step for step in restored.steps] == [step.step for step in plan.steps]


def test_planning_makes_no_network_call(monkeypatch: pytest.MonkeyPatch, planner: Planner) -> None:
    """F-01-10: planning must be pure computation, so every egress path raises."""

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("planning attempted a network call")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(ScopedHttpClient, "request", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "request", forbidden)

    plan = plan_for(planner, build_scan_request())
    assert plan.totals.included_checks > 0


def test_plan_scope_comes_from_the_definition(planner: Planner) -> None:
    """The plan reports the compiled scope verbatim — it invents no dimension."""
    plan = plan_for(planner, build_scan_request())
    assert plan.scope["url_prefixes"] == ["https://example.com/"]
    assert plan.scope["allowed_domains"] == []
    assert plan.assets[0].kind.value == "url"
