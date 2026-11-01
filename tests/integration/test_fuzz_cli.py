"""``arachne fuzz run`` against the protocol lab (S30, area FUZZ).

The last mile of the area: the verb an operator actually types, over a real plan document, against
a real service. Two outcomes matter and both are asserted — a completed run that found the planted
parsing bug and exited 0, and an aborted run that stopped at a degradation signal and exited
non-zero, because a script that treats "stopped early" as success is a script that will one day
keep fuzzing something it should not.

The test is synchronous on purpose: the CLI calls ``asyncio.run`` itself, so an async test would be
running the event loop the command is trying to start.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.helpers.fuzz import arc_grammars_registered, fuzz_settings, lab_arc
from typer.testing import CliRunner

from arachne.cli.main import app

pytestmark = pytest.mark.lab

PLAN_TEMPLATE = """
schema_version: "1.0"
fuzz:
  attested_by: owner <owner@example.test>
  attested_at: "2026-10-01T00:00:00Z"
  scope_statement: "Authorization to fuzz the loopback ARC/1 lab"
  allowed_targets: ["127.0.0.1"]
  environment: lab
budget:
  max_cases: 200
  max_requests: 200
  max_seconds: 30
  batch_size: 8
target:
  name: arc-lab-cli
  targets:
    - kind: ip
      value: 127.0.0.1
  attestation:
    attested_by: owner <owner@example.test>
    attested_at: "2026-10-01T00:00:00Z"
    scope_statement: "Authorization for the loopback fuzz lab"
    authorization_ref: LAB-FUZZ-1
    allowed_targets: ["127.0.0.1"]
    active_checks_authorized: true
wire:
  - label: arc1-peer
    grammar: arc1.lookup
    host: 127.0.0.1
    port: {port}
notes: "the CLI acceptance run"
"""


def write_plan(tmp_path: Path, port: int, **overrides: str) -> Path:
    document = PLAN_TEMPLATE.format(port=port)
    for old, new in overrides.items():
        document = document.replace(old, new)
    path = tmp_path / "fuzz-plan.yaml"
    path.write_text(document, encoding="utf-8")
    return path


@pytest.fixture()
def permissive(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI's settings, with the loopback policy a lab run needs."""
    settings = fuzz_settings()
    monkeypatch.setattr("arachne.cli.fuzz.get_settings", lambda: settings)


def test_fuzz_run_finds_the_planted_bug_and_exits_zero(
    tmp_path: Path, permissive: None
) -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            report_path = tmp_path / "report.json"
            result = CliRunner().invoke(
                app,
                ["fuzz", "run", str(write_plan(tmp_path, lab.port)), "-o", str(report_path)],
            )

    assert result.exit_code == 0, result.output
    assert "completed within its bounds" in result.output
    assert "candidates are not findings" in result.output
    assert "healthy after yes" in result.output
    assert "candidate" in result.output and "key-length" in result.output

    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["status"] == "completed"
    assert document["aborted"] is False
    assert document["healthy_after"] is True
    assert document["candidate_count"] >= 1
    for candidate in document["targets"][0]["candidates"]:
        assert candidate["is_finding"] is False
        assert candidate["status"] == "needs-manual-triage", (
            "no shipped check can prove an ARC/1 fault"
        )
    # The report carries the safety machinery's own reading, not just the run's result.
    assert document["prohibitions"]["protocols"]
    assert document["authorization"]["environment_class"] == "non-production"


def test_fuzz_run_exits_non_zero_when_the_guard_aborts(tmp_path: Path, permissive: None) -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            lab.arm_drop_after(10)
            result = CliRunner().invoke(
                app, ["fuzz", "run", str(write_plan(tmp_path, lab.port))]
            )

    assert result.exit_code == 1, "an abort is not a success exit code"
    assert "aborted-on-degradation" in result.output
    assert "stopped:" in result.output
    assert "healthy after NO" in result.output


def test_fuzz_run_refuses_a_plan_without_a_fuzzing_grant(tmp_path: Path, permissive: None) -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            path = write_plan(tmp_path, lab.port)
            document = path.read_text(encoding="utf-8").replace(
                "  environment: lab", "  environment: production"
            )
            path.write_text(document, encoding="utf-8")
            result = CliRunner().invoke(app, ["fuzz", "run", str(path)])

    assert result.exit_code == 2
    assert "does not permit production targets" in result.output


def test_fuzz_run_refuses_a_plan_file_that_is_not_a_plan(tmp_path: Path, permissive: None) -> None:
    path = tmp_path / "not-a-plan.yaml"
    path.write_text("- a\n- list\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["fuzz", "run", str(path)])
    assert result.exit_code == 2
    assert "must be a mapping" in result.output
