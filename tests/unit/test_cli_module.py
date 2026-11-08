"""``arachne module list`` — the registry's operator view (F-07-01, F-02-10).

The command answers "what is installed, at what version, and what does it do", which is the
first thing an operator (and a bug report) needs. The assertions here are about the
*information* being present, not about formatting: a version that stops being printed is a
silent regression in F-02-10.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.modules.m1 import M1
from arachne.modules.m2 import M2
from arachne.modules.registry import ModuleRegistry

runner = CliRunner()


def test_module_list_shows_m1_and_every_check_with_its_version() -> None:
    result = runner.invoke(app, ["module", "list"])
    assert result.exit_code == 0, result.output
    output = result.output
    assert "M1" in output
    assert M1.title in output
    assert f"v{M1.version}" in output
    for check in M1.checks:
        assert check.metadata.id in output
        assert check.metadata.research_ref in output
    assert "25 check(s)" in output
    # The flags an operator has to know about: the opt-in check and its credential.
    assert "opt-in" in output
    assert "needs github_token" in output


def test_module_list_as_json_is_the_registry_summary() -> None:
    result = runner.invoke(app, ["module", "list", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["totals"]["modules"] == len(ModuleRegistry.builtin().module_ids())
    assert payload["totals"]["checks"] == len(ModuleRegistry.builtin().metadata())
    assert payload["versions"]["M1"] == M1.version
    assert payload["versions"]["M2"] == M2.version
    assert payload["versions"]["m1.ct-lookup"] == "1.0"
    modules = {module["id"]: module for module in payload["modules"]}
    assert modules["M1"]["step"] == "recon"
    assert modules["M1"]["research_chapter"] == "ch01"
    assert {check["id"] for check in modules["M1"]["checks"]} == {
        check.metadata.id for check in M1.checks
    }


def test_module_list_can_be_limited_to_one_module() -> None:
    result = runner.invoke(app, ["module", "list", "--module", "M1"])
    assert result.exit_code == 0, result.output
    assert "m1.ct-lookup" in result.output
    absent = runner.invoke(app, ["module", "list", "--module", "M7"])
    assert absent.exit_code == 2
    assert "no module 'M7' is installed" in absent.output


def test_module_list_is_read_only() -> None:
    """Describing the build must not need a database, a scope or an attestation."""
    result = runner.invoke(app, ["module", "list"])
    assert result.exit_code == 0
    assert "database" not in result.output.lower()


@pytest.mark.parametrize("flag", ["--help"])
def test_module_subcommands_have_help(flag: str) -> None:
    assert runner.invoke(app, ["module", flag]).exit_code == 0
    assert runner.invoke(app, ["module", "list", flag]).exit_code == 0
    assert runner.invoke(app, ["module", "coverage", flag]).exit_code == 0


def test_coverage_is_reachable_both_ways() -> None:
    nested = runner.invoke(app, ["module", "coverage", "--json"])
    top_level = runner.invoke(app, ["coverage", "matrix", "--json"])
    assert nested.exit_code == 0 and top_level.exit_code == 0
    assert json.loads(nested.output)["total"] == json.loads(top_level.output)["total"]


def test_the_ledger_is_a_coverage_subcommand() -> None:
    """``arachne coverage ledger --format json`` is REQ-DET-001's command shape."""
    result = runner.invoke(app, ["coverage", "ledger", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["checks"]
    # The group offers help, and both spellings of the matrix command still work.
    assert runner.invoke(app, ["coverage", "--help"]).exit_code == 0
    assert runner.invoke(app, ["coverage", "matrix", "--help"]).exit_code == 0
    assert runner.invoke(app, ["coverage", "ledger", "--help"]).exit_code == 0


def test_the_registry_the_cli_uses_is_the_installed_one() -> None:
    """A plugin installed in the environment shows up in ``module list`` without code changes."""
    assert ModuleRegistry.discover().module_ids() == ("M1", "M2", "M3", "M4", "M5", "M6")
