"""Integration: the CI gate exit codes over a real scan (S12, F-07-05).

Runs the actual ``arachne scan`` command against the M1 recorded-fixture target with a
throwaway database, and asserts the exit-code policy (0 clean, 1 below
threshold, 2 at-or-above) plus the machine-readable ``severities`` block ``--json`` emits.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import reset_settings_cache
from arachne.data.db import create_all, create_db_engine

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"


@pytest.fixture
def env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """A temp database with the schema applied, plus the offline M1 fixture environment."""
    url = f"sqlite:///{tmp_path / 'ci.db'}"
    engine = create_db_engine(url)
    create_all(engine)
    engine.dispose()
    environment = {
        "ARACHNE_DATABASE_URL": url,
        "ARACHNE_HTTP_FIXTURES": str(FIXTURES / "http"),
        "ARACHNE_OSINT_ENABLED": "true",
        "ARACHNE_OSINT_FIXTURES": str(FIXTURES / "osint"),
        "ARACHNE_OSINT_SEARCH_URL": "https://search.example.net/search?q={query}&limit={limit}",
        "ARACHNE_LOG_LEVEL": "CRITICAL",
        "ARACHNE_OSINT_REQUEST_BUDGET": "50",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ARACHNE_CI_FAIL_ON", raising=False)
    reset_settings_cache()
    try:
        yield environment
    finally:
        reset_settings_cache()


def _run(*args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def test_the_gate_is_clean_when_disabled(env: dict[str, str]) -> None:
    result = _run("scan", "--target", str(TARGET_FIXTURE))
    assert result.exit_code == 0, result.output


def test_findings_below_the_threshold_exit_1(env: dict[str, str]) -> None:
    # The M1 replay yields medium/low findings — none at or above `high`.
    result = _run("scan", "--target", str(TARGET_FIXTURE), "--fail-on", "high")
    assert result.exit_code == 1, result.output
    assert "below threshold" in result.output


def test_findings_at_or_above_the_threshold_exit_2(env: dict[str, str]) -> None:
    result = _run("scan", "--target", str(TARGET_FIXTURE), "--fail-on", "low")
    assert result.exit_code == 2, result.output


def test_json_output_carries_the_severity_counts(env: dict[str, str]) -> None:
    result = _run("scan", "--target", str(TARGET_FIXTURE), "--json", "--fail-on", "none")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert set(payload["severities"]) == {"info", "low", "medium", "high", "critical"}
    assert sum(payload["severities"].values()) >= 1, "the M1 replay must produce findings"


def test_the_environment_sets_the_default_threshold(env: dict[str, str], monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ARACHNE_CI_FAIL_ON", "high")
    reset_settings_cache()
    result = _run("scan", "--target", str(TARGET_FIXTURE))
    assert result.exit_code == 1, result.output


def test_an_unknown_threshold_is_a_usage_error(env: dict[str, str]) -> None:
    result = _run("scan", "--target", str(TARGET_FIXTURE), "--fail-on", "blocker")
    assert result.exit_code != 0
    assert "threshold must be one of" in result.output
