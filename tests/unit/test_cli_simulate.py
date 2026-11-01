"""``arachne simulate`` — the operator verbs of area SIM (S28).

The CLI is where an operator meets the feature, so these tests drive the real command through
``typer``'s runner against a real (seeded) deployment database, and assert on what an operator
would read: the model's shape, the ``simulated`` label on every what-if line, the delta's sign,
and that the four verbs agree with each other.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api import ApiHarness, make_api_harness
from typer.testing import CliRunner

from arachne.cli.main import app

RUNNER = CliRunner()

#: One finding per host, with the severities a real analysis produces for those classes. The
#: model stages a *candidate-only* weakness by its severity (there is no CWE on the row), which
#: is exactly what `analyzer.paths` does, so these seeds give the CLI a known estate:
#: ``app.example`` carries an execution→impact chain, and the other two hosts carry one hop.
SEEDS: tuple[tuple[str, tuple[str, str], str], ...] = (
    ("M4/env-file-probe@1.0", ("url", "https://app.example/.env"), "high"),
    ("M4/default-credentials@1.0", ("host", "app.example"), "critical"),
    ("M3/sqli-oracle@1.0", ("url", "https://app.example/login"), "critical"),
    ("M5/exposed-database@1.0", ("host", "db.internal"), "high"),
    ("M2/telnet-service@1.0", ("host", "legacy.example"), "medium"),
)


@pytest.fixture
def deployed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """A seeded deployment database the CLI reads through its own composition root."""
    harness: ApiHarness = make_api_harness(tmp_path)
    scan_id = harness.seed_scan()
    for check_key, asset, severity in SEEDS:
        harness.seed_finding(
            scan_id=scan_id,
            title=f"{check_key} on {asset[1]}",
            check_key=check_key,
            asset=asset,
            severity=severity,
        )
    # The CLI builds its own stack from the environment: point it at this harness's database.
    monkeypatch.setenv("ARACHNE_DATABASE_URL", harness.services.settings.database_url)
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    yield {"scan_id": scan_id, "harness": harness, "tmp": tmp_path}
    harness.services.close()


def _hypotheses_file(tmp_path: Path) -> Path:
    path = tmp_path / "what-if.yaml"
    path.write_text(
        "hypotheses:\n"
        "  - id: public-console\n"
        "    kind: new-exposure\n"
        "    asset: legacy.example\n"
        "    port: 8443\n"
        "    service: https\n"
        "    note: the legacy console is published by mistake\n"
        "  - id: leaked-password\n"
        "    kind: compromised-credential\n"
        "    asset: db.internal\n"
        "    identity: portal\n",
        encoding="utf-8",
    )
    return path


def _change_file(tmp_path: Path) -> Path:
    path = tmp_path / "change.yaml"
    path.write_text(
        "name: harden-app\n"
        "description: close the default credentials and the injection flaw\n"
        "hypotheses:\n"
        "  - id: fix-1\n"
        "    kind: applied-fix\n"
        "    asset: app.example\n"
        "    target_check_id: m4.default-credentials\n"
        "  - id: fix-2\n"
        "    kind: applied-fix\n"
        "    asset: app.example\n"
        "    target_check_id: m3.sqli-oracle\n",
        encoding="utf-8",
    )
    return path


def test_the_model_verb_shows_the_estate_and_its_verified_paths(
    deployed: dict[str, Any],
) -> None:
    result = RUNNER.invoke(app, ["simulate", "model", "--scan", str(deployed["scan_id"])])

    assert result.exit_code == 0, result.output
    assert "hosts=3" in result.output
    assert "app.example" in result.output
    assert "legacy.example" in result.output
    assert "verified attack paths already composed from the estate:" in result.output
    assert "ap-" in result.output and "terminal critical" in result.output


def test_the_model_verb_emits_the_graph_as_json(deployed: dict[str, Any]) -> None:
    result = RUNNER.invoke(
        app, ["simulate", "model", "--scan", str(deployed["scan_id"]), "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["estate_key"] == f"scan:{deployed['scan_id']}"
    assert payload["summary"]["hosts"] == 3
    assert payload["summary"]["weaknesses"] == len(SEEDS)
    assert {node["kind"] for node in payload["nodes"]} >= {"host", "weakness"}
    assert all(item["observed"] for item in payload["weaknesses"])


def test_the_what_if_verb_labels_every_line_simulated(
    deployed: dict[str, Any], tmp_path: Path
) -> None:
    result = RUNNER.invoke(
        app,
        [
            "simulate",
            "what-if",
            "--scan",
            str(deployed["scan_id"]),
            "--hypotheses",
            str(_hypotheses_file(tmp_path)),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "NOTHING HERE WAS OBSERVED ON A TARGET" in result.output
    assert "public-console" in result.output and "leaked-password" in result.output
    assert "hypothetical" in result.output
    assert "sim.new-exposure.public-console" in result.output
    assert "legacy.example" in result.output
    # The injected hop's cheapest-break line must not borrow the verified report's vocabulary.
    assert "hypothetical hop introduced by public-console" in result.output


def test_the_what_if_verb_refuses_an_empty_hypothesis_set(deployed: dict[str, Any]) -> None:
    result = RUNNER.invoke(
        app, ["simulate", "what-if", "--scan", str(deployed["scan_id"])]
    )

    assert result.exit_code == 2
    assert "name a hypothesis document" in result.output


def test_the_change_verb_reports_a_negative_delta_for_a_hardening(
    deployed: dict[str, Any], tmp_path: Path
) -> None:
    result = RUNNER.invoke(
        app,
        [
            "simulate",
            "change",
            str(_change_file(tmp_path)),
            "--scan",
            str(deployed["scan_id"]),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "exposure: 10 → 0 (-10)" in result.output
    assert "removed:" in result.output


def test_the_trend_verb_records_a_point_and_shows_the_series(
    deployed: dict[str, Any], tmp_path: Path
) -> None:
    estate = f"scan:{deployed['scan_id']}"
    first = RUNNER.invoke(
        app,
        [
            "simulate",
            "trend",
            "--scan",
            str(deployed["scan_id"]),
            "--estate",
            estate,
            "--hypotheses",
            str(_hypotheses_file(tmp_path)),
            "--run",
        ],
    )
    assert first.exit_code == 0, first.output
    assert "Re-simulation | Paths | New under hypotheses | Exposure score" in first.output

    second = RUNNER.invoke(
        app, ["simulate", "trend", "--estate", estate, "--json"]
    )
    assert second.exit_code == 0, second.output
    payload = json.loads(second.output)
    assert payload["provenance"] == "simulated"
    assert len(payload["points"]) == 1
    assert payload["points"][0]["provenance"] == "simulated"
    assert payload["estate_key"] == estate


def test_the_trend_verb_says_so_when_there_is_nothing_to_simulate(
    deployed: dict[str, Any],
) -> None:
    result = RUNNER.invoke(
        app,
        [
            "simulate",
            "trend",
            "--scan",
            "999999",
            "--estate",
            "absent-estate",
            "--run",
        ],
    )

    assert result.exit_code == 2
    assert "nothing to simulate" in result.output


def test_the_report_verb_attaches_the_simulated_section(
    deployed: dict[str, Any], tmp_path: Path
) -> None:
    """``arachne report --simulate``: the section an operator can hand to a reader."""
    output = tmp_path / "report.md"
    result = RUNNER.invoke(
        app,
        [
            "report",
            "--scan",
            str(deployed["scan_id"]),
            "--simulate",
            "--hypotheses",
            str(_hypotheses_file(tmp_path)),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    text = output.read_text(encoding="utf-8")
    assert "## 13. Simulated scenarios (what-if)" in text
    assert "Simulated — nothing here was observed on a target" in text
    assert "sim.new-exposure.public-console" in text


def test_the_report_verb_without_simulate_has_no_section(
    deployed: dict[str, Any], tmp_path: Path
) -> None:
    output = tmp_path / "plain.md"
    result = RUNNER.invoke(
        app,
        [
            "report",
            "--scan",
            str(deployed["scan_id"]),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Simulated" not in output.read_text(encoding="utf-8")


def test_the_verbs_agree_on_the_same_estate(deployed: dict[str, Any], tmp_path: Path) -> None:
    """The model the CLI shows is the model the verbs compute over — not a second one."""
    scan = str(deployed["scan_id"])
    model = json.loads(
        RUNNER.invoke(app, ["simulate", "model", "--scan", scan, "--json"]).output
    )
    what_if = json.loads(
        RUNNER.invoke(
            app,
            [
                "simulate",
                "what-if",
                "--scan",
                scan,
                "--hypotheses",
                str(_hypotheses_file(tmp_path)),
                "--json",
            ],
        ).output
    )

    assert what_if["estate_key"] == model["estate_key"]
    assert what_if["model_before"] == model["summary"]
    assert what_if["provenance"] == "simulated"
    # The database identity of the lab estate, unchanged by either verb.
    assert model["summary"]["weaknesses"] == what_if["model_before"]["weaknesses"]
