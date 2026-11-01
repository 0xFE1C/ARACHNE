"""``arachne fix``: the operator's front door, and its refusals (S27, area FIX).

The workflow itself is exercised end to end in ``tests/integration/test_fix_proposal.py``;
this module pins the *surface*: that the verbs are registered, that the two read-only ones
answer without a database, and — the part that matters most — that an unconfigured
deployment refuses at the door instead of doing something surprising. ``propose`` against a
deployment with no proposal store must exit non-zero with a message, never silently succeed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import reset_settings_cache

runner = CliRunner()


@pytest.fixture(autouse=True)
def _fresh_settings() -> None:
    """Settings are read from the environment once per process; each test states its own."""
    reset_settings_cache()


def test_the_fix_verbs_are_registered() -> None:
    result = runner.invoke(app, ["fix", "--help"])
    assert result.exit_code == 0
    for verb in (
        "plans",
        "repos",
        "propose",
        "list",
        "show",
        "approve",
        "reject",
        "submit",
        "applied",
        "verify",
    ):
        assert verb in result.stdout, verb


def test_the_plan_catalog_is_readable_without_a_deployment() -> None:
    result = runner.invoke(app, ["fix", "plans", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"]
    ids = {plan["id"] for plan in payload["plans"]}
    assert "k8s-privileged-container" in ids
    assert all(plan["edits"] for plan in payload["plans"])


def test_no_grant_file_means_no_fixable_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARACHNE_FIX_GRANTS", raising=False)
    result = runner.invoke(app, ["fix", "repos"])
    assert result.exit_code == 0
    assert "no repository is granted" in result.stdout


def test_grants_are_reported_with_their_test_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    grants = tmp_path / "grants.yaml"
    grants.write_text(
        "version: '1.0'\n"
        "repos:\n"
        "  - name: payments-api\n"
        f"    path: {repo}\n"
        "    default_branch: main\n"
        "    test_command: [python3, -m, pytest, -q]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ARACHNE_FIX_GRANTS", str(grants))
    result = runner.invoke(app, ["fix", "repos", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["repos"][0]["name"] == "payments-api"
    assert payload["repos"][0]["testable"] is True


def test_a_missing_grants_file_is_a_loud_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARACHNE_FIX_GRANTS", str(tmp_path / "absent.yaml"))
    result = runner.invoke(app, ["fix", "repos"])
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_propose_without_a_store_refuses_rather_than_pretending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An un-migrated deployment cannot propose; the verb says so and exits non-zero."""
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    result = runner.invoke(app, ["fix", "propose", "1"])
    assert result.exit_code == 2
    assert "fix:" in result.output
