"""The fuzzing plan document and the ``arachne fuzz`` CLI (S30, area FUZZ).

A fuzzing run is described in a file, so the first thing to test is the file: a bad one must be
refused with a reason that names what is wrong, and it must be refused *before* anything dials.
The CLI verbs are then tested in the two shapes an operator uses them — ``limits``/``engines`` to
learn what the deployment will allow, ``check`` to review a plan without running it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.errors import ConfigurationError
from arachne.fuzz.plan import load_fuzz_plan, render_fuzz_plan

GOOD_PLAN = """
schema_version: "1.0"
fuzz:
  attested_by: owner <owner@example.test>
  attested_at: "2026-10-01T00:00:00Z"
  scope_statement: "Authorization to fuzz the lab fixture"
  allowed_targets: ["127.0.0.1"]
  environment: lab
budget:
  max_cases: 12
  max_requests: 30
  max_seconds: 10
  batch_size: 4
target:
  name: fuzz-cli-fixture
  targets:
    - kind: ip
      value: 127.0.0.1
  attestation:
    attested_by: owner <owner@example.test>
    attested_at: "2026-10-01T00:00:00Z"
    scope_statement: "Authorization for the loopback fixture"
    authorization_ref: LAB-1
    allowed_targets: ["127.0.0.1"]
    active_checks_authorized: true
wire:
  - label: s7-peer
    grammar: s7.cotp-connect
    host: 127.0.0.1
    port: 102
http:
  - label: web-fixture
    parameters:
      - url: "http://127.0.0.1:8080/search?q=1"
        parameter: q
    families: [boundary, xss-reflection]
engine: grammar
notes: "a change-review example"
"""


def test_a_plan_document_loads_into_both_grants_and_its_targets() -> None:
    plan = load_fuzz_plan(GOOD_PLAN, source="test")
    assert plan.definition.name == "fuzz-cli-fixture"
    assert plan.definition.attestation is not None, "the inherited gate comes from `target:`"
    assert plan.attestation is not None
    assert plan.attestation.environment == "lab"
    assert plan.engine == "grammar"
    assert [target.grammar for target in plan.wire_targets] == ["s7.cotp-connect"]
    assert plan.http_plans[0].families == ("boundary", "xss-reflection")
    assert plan.http_plans[0].parameters[0].parameter == "q"
    assert plan.budget is not None and plan.budget.max_cases == 12
    assert plan.target_count == 2


def test_the_rendered_plan_states_the_grant_the_bounds_and_the_targets() -> None:
    rendered = render_fuzz_plan(load_fuzz_plan(GOOD_PLAN, source="test"))
    assert "fuzz-cli-fixture" in rendered
    assert "lab (non-production" in rendered
    assert "12 cases, 30 requests" in rendered
    assert "s7-peer" in rendered and "s7.cotp-connect" in rendered
    assert "web-fixture" in rendered and "boundary,xss-reflection" in rendered
    assert "a change-review example" in rendered


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("grammar: s7.cotp-connect", "grammar: libfuzzer", "unknown grammar"),
        ("families: [boundary, xss-reflection]", "families: [nosuch]", "unknown payload family"),
        ("    port: 102", "    port: 102\n    transport: quic", "transport must be"),
    ],
)
def test_a_plan_this_build_cannot_run_is_refused_with_a_reason(
    old: str, new: str, expected: str
) -> None:
    document = GOOD_PLAN.replace(old, new)
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan(document, source="test")
    assert expected in str(caught.value)


def test_a_plan_with_a_bad_transport_is_refused() -> None:
    document = GOOD_PLAN.replace("    port: 102", "    port: 102\n    transport: quic")
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan(document, source="test")
    assert "transport must be 'tcp' or 'udp'" in str(caught.value)


def test_a_plan_with_no_targets_is_refused() -> None:
    document = GOOD_PLAN.split("wire:")[0] + "notes: no targets\n"
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan(document, source="test")
    assert "at least one wire or http target" in str(caught.value)


def test_a_plan_without_a_fuzzing_grant_is_refused_by_the_loader() -> None:
    document = GOOD_PLAN.replace("fuzz:\n", "fuzz_grant_removed:\n", 1)
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan(document, source="test")
    assert "invalid fuzzing plan" in str(caught.value)


def test_a_plan_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan("- just\n- a\n- list\n", source="test")
    assert "must be a mapping" in str(caught.value)


def test_a_plan_with_a_broken_target_definition_is_refused() -> None:
    document = GOOD_PLAN.replace("      value: 127.0.0.1", "      value: not-an-ip")
    with pytest.raises(ConfigurationError) as caught:
        load_fuzz_plan(document, source="test")
    assert "invalid target definition" in str(caught.value)


def test_the_plan_loader_defaults_the_bounds_to_the_deployments() -> None:
    document = GOOD_PLAN.replace(
        "budget:\n  max_cases: 12\n  max_requests: 30\n  max_seconds: 10\n  batch_size: 4\n",
        "",
    )
    plan = load_fuzz_plan(document, source="test")
    assert plan.budget is not None
    assert plan.budget.max_cases == 200, "an omitted bound is the deployment's default"


# --------------------------------------------------------------------------- the CLI


def write_plan(tmp_path: Path, text: str = GOOD_PLAN) -> Path:
    path = tmp_path / "fuzz-plan.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_fuzz_limits_reads_out_the_ceilings_and_the_prohibition_table() -> None:
    result = CliRunner().invoke(app, ["fuzz", "limits"])
    assert result.exit_code == 0, result.output
    assert "cases per target" in result.output
    assert "production fuzzing  refused" in result.output
    assert "modbus" in result.output and "0x2b" in result.output
    assert "destructive SQL heads" in result.output


def test_fuzz_engines_lists_the_engines_and_the_grammars() -> None:
    result = CliRunner().invoke(app, ["fuzz", "engines", "--verbose"])
    assert result.exit_code == 0, result.output
    assert "grammar (default)" in result.output
    assert "fingerprint" in result.output
    assert "NOT instrumented code coverage" in result.output
    assert "dns.query" in result.output
    assert "dnp3.link-status" in result.output


def test_fuzz_check_reports_a_plan_and_sends_nothing(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["fuzz", "check", str(write_plan(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "nothing is sent by this command" in result.output
    assert "authorized: environment=non-production" in result.output
    assert "wire cases" in result.output and "http cases" in result.output
    assert "12 cases, 30 requests" in result.output, "the report shows the resolved bounds"


def test_fuzz_check_clamps_a_bound_a_plan_asks_too_much_for(tmp_path: Path) -> None:
    document = GOOD_PLAN.replace("  max_cases: 12", "  max_cases: 100000")
    result = CliRunner().invoke(app, ["fuzz", "check", str(write_plan(tmp_path, document))])
    assert result.exit_code == 0, result.output
    assert "bounds clamped to the deployment ceiling: max_cases" in result.output


def test_fuzz_check_refuses_a_production_plan(tmp_path: Path) -> None:
    document = GOOD_PLAN.replace("  environment: lab", "  environment: production")
    result = CliRunner().invoke(app, ["fuzz", "check", str(write_plan(tmp_path, document))])
    assert result.exit_code == 2
    assert "does not permit production targets" in result.output


def test_fuzz_check_refuses_a_plan_file_that_does_not_exist(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["fuzz", "check", str(tmp_path / "absent.yaml")])
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_the_fuzz_verb_is_registered_on_the_cli() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert "fuzz" in result.output
