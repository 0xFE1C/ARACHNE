"""The check deprecation lifecycle (REQ-DET-008).

Three claims, three proofs:

* **the table is empty and valid** — no shipped check is deprecated today, and the gate says so
  rather than passing silently;
* **the horizon bites** — a check deprecated for more than two minor releases fails
  :func:`problems` (and therefore the ledger's ``--check`` gate CI runs);
* **a deprecated check still runs** — the state travels with the registry summary, so plan
  output can flag it, and it stays registered (deprecating is not deleting).
"""

from __future__ import annotations

import pytest

from arachne import __version__
from arachne.modules import lifecycle_policy
from arachne.modules.lifecycle_policy import (
    DEPRECATED_CHECKS,
    REMOVAL_HORIZON_MINORS,
    Deprecation,
    annotate,
    horizon_expired,
    ledger_section,
    problems,
)
from arachne.modules.registry import ModuleRegistry

REGISTERED = set(ModuleRegistry.discover().check_ids())


def _dep(**overrides: object) -> Deprecation:
    values: dict[str, object] = {
        "check_id": "m2.smtp-enum",
        "successor": "m2.smtp-transport",
        "deprecated_in": "0.1",
        "reason": "superseded by the transport check",
    }
    values.update(overrides)
    return Deprecation(**values)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the shipped state
def test_no_shipped_check_is_deprecated_today() -> None:
    assert DEPRECATED_CHECKS == ()


def test_the_live_table_is_valid() -> None:
    assert problems(registry_check_ids=REGISTERED) == ()


def test_a_live_check_is_not_flagged() -> None:
    assert annotate("m2.db-service-probe") == {
        "deprecated": False,
        "successor": None,
        "removal_horizon": None,
    }


def test_the_registry_summary_carries_the_lifecycle_state() -> None:
    """REQ-DET-008: the flag travels with the check, so plan output can show it."""
    group = ModuleRegistry.discover().summary()[0]
    assert all("lifecycle" in check for check in group["checks"])
    assert all(check["lifecycle"]["deprecated"] is False for check in group["checks"])


# --------------------------------------------------------------------------- the horizon
def test_a_deprecation_within_the_horizon_is_allowed() -> None:
    deprecation = _dep(deprecated_in="0.1")
    assert horizon_expired(deprecation, current_version="0.2") is False
    assert horizon_expired(deprecation, current_version=f"0.1.{REMOVAL_HORIZON_MINORS}") is False
    assert (
        problems(current_version="0.2", deprecations=(deprecation,), registry_check_ids=REGISTERED)
        == ()
    )


def test_a_deprecation_older_than_two_minors_fails() -> None:
    """The exit criterion: more than two minors after deprecation is a build failure."""
    deprecation = _dep(deprecated_in="0.1")
    assert horizon_expired(deprecation, current_version="0.4") is True
    found = problems(
        current_version="0.4", deprecations=(deprecation,), registry_check_ids=REGISTERED
    )
    assert any("must be removed by 0.3" in problem for problem in found)


def test_the_horizon_is_two_minors_and_crosses_a_major_boundary_cleanly() -> None:
    deprecation = _dep(deprecated_in="1.9")
    assert deprecation.horizon == "1.11"
    assert horizon_expired(deprecation, current_version="1.11") is False
    assert horizon_expired(deprecation, current_version="1.12") is True


def test_a_malformed_version_is_reported_not_raised() -> None:
    found = problems(current_version="1", deprecations=(_dep(),), registry_check_ids=REGISTERED)
    assert any("not a major.minor version" in problem for problem in found)


def test_a_future_deprecation_is_reported() -> None:
    found = problems(
        current_version="0.1",
        deprecations=(_dep(deprecated_in="0.9"),),
        registry_check_ids=REGISTERED,
    )
    assert any("later than the running version" in problem for problem in found)


# --------------------------------------------------------------------------- the table's integrity
def test_an_unknown_successor_is_reported() -> None:
    found = problems(
        current_version="0.1",
        deprecations=(_dep(successor="m2.does-not-exist"),),
        registry_check_ids=REGISTERED,
    )
    assert any("not a registered check" in problem for problem in found)


def test_a_removed_check_cannot_carry_a_deprecation() -> None:
    found = problems(
        current_version="0.1",
        deprecations=(_dep(check_id="m2.retired"),),
        registry_check_ids=REGISTERED,
    )
    assert any("is not registered" in problem for problem in found)


def test_a_check_cannot_succeed_itself() -> None:
    found = problems(
        current_version="0.1",
        deprecations=(_dep(successor="m2.smtp-enum"),),
        registry_check_ids=REGISTERED,
    )
    assert any("names itself as its successor" in problem for problem in found)


def test_a_silent_deprecation_is_reported() -> None:
    found = problems(
        current_version="0.1", deprecations=(_dep(reason="  "),), registry_check_ids=REGISTERED
    )
    assert any("no recorded deprecation reason" in problem for problem in found)


def test_a_duplicate_deprecation_is_reported() -> None:
    found = problems(
        current_version="0.1", deprecations=(_dep(), _dep()), registry_check_ids=REGISTERED
    )
    assert any("deprecated twice" in problem for problem in found)


# --------------------------------------------------------------------------- the ledger + CLI
def test_the_ledger_lists_deprecated_checks_with_their_successor_and_horizon() -> None:
    section = ledger_section()
    assert section["lifecycle_version"]
    assert section["current_version"] == __version__
    assert section["removal_horizon_minors"] == REMOVAL_HORIZON_MINORS
    assert section["deprecated"] == []


def test_the_cli_passes_on_the_shipped_table(capsys) -> None:
    assert lifecycle_policy.main(["--check"]) == 0
    assert "OK 0 deprecated check" in capsys.readouterr().out


def test_the_cli_fails_on_an_expired_deprecation(monkeypatch, capsys) -> None:
    """The CI gate: an outlived deprecation is a non-zero exit that names the check."""
    monkeypatch.setattr(lifecycle_policy, "DEPRECATED_CHECKS", (_dep(deprecated_in="0.0"),))
    # The running version is ahead of every shipped minor, so the horizon has passed.
    assert lifecycle_policy.main(["--check", "--version", "0.4"]) == 1
    output = capsys.readouterr().out
    assert "FAIL" in output and "m2.smtp-enum" in output


def test_the_ledger_check_reports_a_lifecycle_failure(monkeypatch, tmp_path) -> None:
    """``check_ledger`` — the step CI already runs — surfaces the lifecycle defect."""
    from arachne.modules import coverage

    assert coverage.check_ledger(*coverage.default_ledger_paths())[0] is True
    # A check deprecated in 0.0, asked about from 0.4: more than two minors have passed, so
    # the gate must fail with a message naming the check and the release to remove it by.
    monkeypatch.setattr(lifecycle_policy, "DEPRECATED_CHECKS", (_dep(deprecated_in="0.0"),))
    monkeypatch.setattr(lifecycle_policy, "__version__", "0.4")
    ok, differences = coverage.check_ledger(*coverage.default_ledger_paths())
    assert ok is False
    assert any(
        problem.startswith("lifecycle:") and "m2.smtp-enum" in problem for problem in differences
    )


@pytest.mark.parametrize("field", ["check_id", "successor", "deprecated_in", "reason"])
def test_every_lifecycle_field_has_a_default_free_definition(field: str) -> None:
    deprecation = _dep()
    assert getattr(deprecation, field)
