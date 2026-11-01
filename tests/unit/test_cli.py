"""CLI tests (F-07-01)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne import __version__
from arachne.cli.main import app
from arachne.core.config import reset_settings_cache

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point the CLI at a throwaway database and a clean settings cache."""
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    yield
    reset_settings_cache()


def test_version_flag_prints_a_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_help_lists_the_s1_command_groups() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for expected in ("--version", "db", "info"):
        assert expected in result.stdout


def test_info_reports_effective_configuration_without_secrets() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "arachne version:" in result.stdout
    assert "sqlite:///" in result.stdout
    assert "redaction enabled: True" in result.stdout
    assert "allow_private_ips=False" in result.stdout


def test_db_upgrade_creates_the_schema_and_current_reports_it() -> None:
    upgrade = runner.invoke(app, ["db", "upgrade"])
    assert upgrade.exit_code == 0, upgrade.output
    assert "done" in upgrade.stdout

    current = runner.invoke(app, ["db", "current"])
    assert current.exit_code == 0, current.output
    assert "up to date" in current.stdout

    tables = runner.invoke(app, ["db", "tables"])
    assert tables.exit_code == 0
    assert "findings" in tables.stdout
    assert "audit_log" in tables.stdout


def test_db_current_fails_when_not_migrated() -> None:
    result = runner.invoke(app, ["db", "current"])
    assert result.exit_code == 1
    assert "out of date" in result.stdout


def test_db_upgrade_can_target_a_specific_revision_and_roll_back() -> None:
    assert runner.invoke(app, ["db", "upgrade", "0001"]).exit_code == 0
    rollback = runner.invoke(app, ["db", "downgrade", "base"])
    assert rollback.exit_code == 0, rollback.output

    tables = runner.invoke(app, ["db", "tables"])
    assert "findings" not in tables.stdout


def test_db_upgrade_accepts_an_explicit_database_url(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'explicit.db'}"
    result = runner.invoke(app, ["db", "upgrade", "--database-url", url])
    assert result.exit_code == 0
    assert url in result.stdout
    assert (tmp_path / "explicit.db").exists()


def test_subcommand_help_is_available() -> None:
    result = runner.invoke(app, ["db", "--help"])
    assert result.exit_code == 0
    assert "upgrade" in result.stdout
    assert "tables" in result.stdout
