"""The fix-plan catalog: selection, specificity and the refusals that are not guesses (S27).

REQ-FIX-001's acceptance is "a golden proposal for a known vuln class" — which starts here,
with the mechanical question "which plan fits this finding, and is the answer unique?".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.fix.patch import apply_plan, repo_root_of, resolve_targets, strip_location
from arachne.fix.plans import (
    EditOp,
    FindingProfile,
    FixPlan,
    PlanTargeting,
    load_fix_plan_catalog,
    parse_fix_plan_catalog,
)

K8S_MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: registry.internal/api:1.2.3
          securityContext:
            privileged: true   # needed for the HSM
"""

TF_DATABASE = """\
resource "aws_db_instance" "payments" {
  identifier          = "payments"
  storage_encrypted   = true
  publicly_accessible = true
}
"""


def _plan(**overrides: object) -> FixPlan:
    payload: dict[str, object] = {
        "id": "test-plan",
        "summary": "Turn the dangerous flag off.",
        "applies_to": {"checks": ["M5/tfstate-exposure"], "rules": ["k8s-privileged"]},
        "globs": ["*.yaml"],
        "edits": [
            {
                "op": "replace",
                "pattern": r"(?m)^(?P<lead>\s*privileged\s*:\s*)true(?P<tail>\s*(?:#.*)?)$",
                "replacement": r"\g<lead>false\g<tail>",
            }
        ],
        "already_fixed": r"(?m)^\s*privileged\s*:\s*false\s*(?:#.*)?$",
    }
    payload.update(overrides)
    return FixPlan.model_validate(payload)


# ------------------------------------------------------------------ the shipped catalog
def test_the_shipped_catalog_loads_and_every_plan_can_bite() -> None:
    catalog = load_fix_plan_catalog()
    assert catalog.version
    assert len(catalog.plans) >= 6
    for plan in catalog.plans:
        assert any(edit.required for edit in plan.edits), plan.id
        assert plan.applies_to.checks or plan.applies_to.rules, plan.id


def test_the_shipped_catalog_selects_the_privileged_container_plan() -> None:
    catalog = load_fix_plan_catalog()
    selection = catalog.select(
        FindingProfile(
            check_key="M5/tfstate-exposure@1.1",
            rule="k8s-privileged",
            remediation_id="insecure-configuration",
        )
    )
    assert selection.plan is not None
    assert selection.plan.id == "k8s-privileged-container"
    assert not selection.ambiguous


def test_the_regex_rule_and_the_structural_rule_reach_the_same_plan() -> None:
    """The M5 review reports both ``privileged-container`` (regex) and ``k8s-privileged``."""
    catalog = load_fix_plan_catalog()
    for rule in ("k8s-privileged", "privileged-container"):
        selection = catalog.select(FindingProfile(check_key="M5/tfstate-exposure@1.1", rule=rule))
        assert selection.plan is not None and selection.plan.id == "k8s-privileged-container"


def test_an_uncovered_class_is_unsupported_not_guessed() -> None:
    catalog = load_fix_plan_catalog()
    selection = catalog.select(FindingProfile(check_key="M1/exposed-dotfile@1.0", rule="env-file"))
    assert selection.unsupported
    assert selection.plan is None


def test_two_equally_specific_plans_are_reported_as_ambiguous() -> None:
    catalog = parse_fix_plan_catalog(
        {
            "version": "1",
            "plans": [
                {
                    "id": "plan-a",
                    "summary": "First candidate for the same class.",
                    "applies_to": {"rules": ["shared-rule"]},
                    "edits": [{"op": "replace", "pattern": "a", "replacement": "b"}],
                },
                {
                    "id": "plan-b",
                    "summary": "Second candidate for the same class.",
                    "applies_to": {"rules": ["shared-rule"]},
                    "edits": [{"op": "replace", "pattern": "a", "replacement": "c"}],
                },
            ],
        }
    )
    selection = catalog.select(FindingProfile(rule="shared-rule"))
    assert selection.plan is None
    assert selection.ambiguous
    assert [plan.id for plan in selection.candidates] == ["plan-a", "plan-b"]


def test_the_more_specific_plan_wins() -> None:
    catalog = parse_fix_plan_catalog(
        {
            "version": "1",
            "plans": [
                {
                    "id": "broad-plan",
                    "summary": "Matches the check alone.",
                    "applies_to": {"checks": ["M5"]},
                    "edits": [{"op": "replace", "pattern": "x", "replacement": "y"}],
                },
                {
                    "id": "narrow-plan",
                    "summary": "Matches the check and the exact rule.",
                    "applies_to": {"checks": ["M5"], "rules": ["precise"]},
                    "edits": [{"op": "replace", "pattern": "x", "replacement": "y"}],
                },
            ],
        }
    )
    selection = catalog.select(FindingProfile(check_key="M5/tfstate-exposure@1.1", rule="precise"))
    assert selection.plan is not None and selection.plan.id == "narrow-plan"


def test_a_disabled_plan_is_never_selected() -> None:
    catalog = parse_fix_plan_catalog(
        {
            "version": "1",
            "plans": [
                {
                    "id": "off-plan",
                    "summary": "Turned off by the operator.",
                    "enabled": False,
                    "applies_to": {"rules": ["r"]},
                    "edits": [{"op": "replace", "pattern": "a", "replacement": "b"}],
                }
            ],
        }
    )
    assert catalog.select(FindingProfile(rule="r")).unsupported


# ------------------------------------------------------------------ catalog validation
def test_a_plan_whose_edits_are_all_optional_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="silently do nothing"):
        parse_fix_plan_catalog(
            {
                "version": "1",
                "plans": [
                    {
                        "id": "noop",
                        "summary": "This plan can never change anything.",
                        "applies_to": {"rules": ["r"]},
                        "edits": [
                            {
                                "op": "replace",
                                "pattern": "a",
                                "replacement": "b",
                                "min_matches": 0,
                            }
                        ],
                    }
                ],
            }
        )


def test_a_plan_glob_may_not_escape_the_repository() -> None:
    with pytest.raises(ConfigurationError, match="must be a relative pattern"):
        parse_fix_plan_catalog(
            {
                "version": "1",
                "plans": [
                    {
                        "id": "escaping",
                        "summary": "This plan reaches outside the repository.",
                        "applies_to": {"rules": ["r"]},
                        "globs": ["../*.yaml"],
                        "edits": [{"op": "replace", "pattern": "a", "replacement": "b"}],
                    }
                ],
            }
        )


def test_a_catastrophic_pattern_is_refused_before_it_is_compiled() -> None:
    with pytest.raises(ConfigurationError, match="not a valid regular expression"):
        EditOp(op="replace", pattern="(unclosed", replacement="x")


def test_an_insert_edit_needs_the_text_it_inserts() -> None:
    with pytest.raises(ValueError, match="needs the text"):
        EditOp(op="insert_after", pattern="^deny", text="")


def test_an_unknown_field_in_a_plan_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        parse_fix_plan_catalog(
            {
                "version": "1",
                "plans": [
                    {
                        "id": "unknown-field",
                        "summary": "Carries a field the schema does not know.",
                        "applies_to": {"rules": ["r"]},
                        "command": "rm -rf /",
                        "edits": [{"op": "replace", "pattern": "a", "replacement": "b"}],
                    }
                ],
            }
        )


# ------------------------------------------------------------------ applying a plan
def test_applying_a_plan_changes_only_the_matched_line(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(K8S_MANIFEST, encoding="utf-8")
    application = apply_plan(_plan(), tmp_path, ("deploy.yaml",))
    assert application.applied
    assert application.changed_paths == ("deploy.yaml",)
    after = application.files[0].after
    assert "privileged: false   # needed for the HSM" in after
    assert "hostNetwork: true" in after
    assert after.count("\n") == K8S_MANIFEST.count("\n")


def test_the_diff_is_deterministic_and_scoped_to_the_file() -> None:
    diff = apply_plan(_plan(), Path("/nonexistent-but-not-read"), ()).diff()
    assert diff == ""


def test_an_already_fixed_tree_is_reported_as_such(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(
        K8S_MANIFEST.replace("privileged: true", "privileged: false"), encoding="utf-8"
    )
    application = apply_plan(_plan(), tmp_path, ("deploy.yaml",))
    assert not application.applied
    assert application.already_fixed
    assert application.reason == "already-fixed"


def test_a_plan_that_does_not_match_is_refused_with_a_reason(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")
    application = apply_plan(_plan(), tmp_path, ("deploy.yaml",))
    assert not application.applied
    assert not application.already_fixed
    assert "does not apply" in application.reason
    assert application.skipped and "matched 0 time(s)" in application.skipped[0]


def test_a_terraform_plan_flips_the_boolean_in_place(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF_DATABASE, encoding="utf-8")
    catalog = load_fix_plan_catalog()
    selection = catalog.select(
        FindingProfile(check_key="M5/tfstate-exposure@1.1", rule="public-database")
    )
    assert selection.plan is not None
    application = apply_plan(selection.plan, tmp_path, ("main.tf",))
    assert application.applied
    assert "publicly_accessible = false" in application.files[0].after
    assert "storage_encrypted   = true" in application.files[0].after


# ------------------------------------------------------------------ target resolution
def test_a_target_outside_the_root_is_never_resolved(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "api.yaml").write_text(K8S_MANIFEST, encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text(K8S_MANIFEST, encoding="utf-8")
    resolved, skipped = resolve_targets(
        root, ("../outside.yaml", "deploy/api.yaml"), globs=("*.yaml",)
    )
    assert resolved == ("deploy/api.yaml",)
    assert any("escapes the repository root" in item for item in skipped)


def test_a_symlink_out_of_the_tree_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text(K8S_MANIFEST, encoding="utf-8")
    (root / "link.yaml").symlink_to(outside)
    resolved, skipped = resolve_targets(root, ("link.yaml",))
    assert resolved == ()
    assert any("escapes the repository root" in item for item in skipped)


def test_a_location_outside_the_plan_globs_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    resolved, skipped = resolve_targets(root, ("notes.txt",), globs=("*.yaml",))
    assert resolved == ()
    assert any("outside the plan's globs" in item for item in skipped)


def test_the_location_fragment_is_stripped() -> None:
    assert strip_location("deploy/api.yaml#spec/template/spec") == "deploy/api.yaml"
    assert strip_location("deploy/api.yaml") == "deploy/api.yaml"


def test_a_remote_reference_names_no_local_repository() -> None:
    assert repo_root_of("git@github.com:acme/payments.git") is None
    assert repo_root_of("https://github.com/acme/payments.git") is None
    assert repo_root_of(f"repo:{Path.cwd()}") == Path.cwd().resolve()


def test_a_plan_targeting_selects_on_the_check_name_too() -> None:
    targeting = PlanTargeting(checks=["M5/tfstate-exposure"])
    assert targeting.matches(FindingProfile(check_key="M5/tfstate-exposure@1.1"))
    assert not targeting.matches(FindingProfile(check_key="M5/k8s-exposure@1.0"))
    assert PlanTargeting(checks=["M5"]).matches(FindingProfile(check_key="M5/anything@9.9"))
