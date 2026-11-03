"""The delivery-surface artefacts, pinned as they ship (S26, REQ-ECOS-003).

A shipped Action, a GitLab component, a Terraform module and a provider skeleton are only
real if they are the files a user copies *and* an operator can run. This suite therefore
does two things at once:

* **Structural** — the shipped YAML parses and carries the inputs/steps/artifacts the
  documentation promises; the Terraform module's variables are all referenced and its
  outputs defined (parsed with regex, because no Terraform binary is in the test
  environment); the provider skeleton's files exist and its README says "skeleton".
* **Behavioural** — the acceptance criterion. The command the Action and the component call
  is run, as a process, against the misconfigured fixture repo: it must emit `::error`
  annotations that name the planted violation's file and exit 2. This genuinely runs the
  scanner (a subprocess, the real orchestrator), not a stub.

Files are located relative to this test file, never the CWD (the discipline of
``test_autoscale_manifests.py`` / ``test_no_default_credentials.py``).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

from arachne.report.model import (
    AssetRef,
    ExecutiveSummary,
    RemediationPlan,
    ReportCover,
    ReportData,
    ReportFinding,
    ScopeMethodology,
    Score,
)
from tests.helpers.report import report_verification

CODE_ROOT = Path(__file__).resolve().parents[1]
# ``tests/`` sits directly under the project root, and the project root is the
# repository root, so the checkout root *is* the code root.
REPO_ROOT = CODE_ROOT

GITHUB_ACTION = CODE_ROOT / "src" / "arachne" / "templates" / "ci" / "github" / "action.yml"
GITLAB_COMPONENT = CODE_ROOT / "src" / "arachne" / "templates" / "ci" / "gitlab" / "component.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

TERRAFORM_MODULE = CODE_ROOT / "deploy" / "terraform" / "modules" / "arachne"
TERRAFORM_PROVIDER = CODE_ROOT / "deploy" / "terraform" / "provider"

FIXTURES = CODE_ROOT / "tests" / "fixtures" / "iac"
MISCONFIGURED = FIXTURES / "misconfigured"
CLEAN = FIXTURES / "clean"


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


# ------------------------------------------------------------------ shipped GitHub Action
def test_the_github_action_parses_and_declares_its_inputs() -> None:
    action = _yaml(GITHUB_ACTION)
    assert action["runs"]["using"] == "composite"
    inputs = action["inputs"]
    for name in ("path", "fail-on", "format", "api-url", "api-key"):
        assert name in inputs, f"the action does not declare input {name!r}"
    assert inputs["format"]["default"] == "github"
    assert inputs["fail-on"]["default"] == "high"
    assert "exit-code" in action["outputs"]


def test_the_github_action_runs_the_annotate_tool_and_forwards_the_exit_code() -> None:
    text = GITHUB_ACTION.read_text(encoding="utf-8")
    assert "python -m arachne.tools.ci_annotate" in text or (
        '"$ARACHNE_PYTHON" -m arachne.tools.ci_annotate' in text
    )
    # The gate's verdict is re-raised by a final step (so uploads can run first).
    assert "exit-code" in text
    assert "exit " in text
    # SARIF is uploaded only when the file exists (guarded by a step output).
    assert "github/codeql-action/upload-sarif" in text
    assert "sarif-written" in text
    # No network is required for the offline scan; permissions are guidance in comments.
    assert "offline" in text.lower()
    assert "permissions" in text.lower()


# ------------------------------------------------------------------ shipped GitLab component
def test_the_gitlab_component_parses_and_publishes_the_codequality_report() -> None:
    component = _yaml(GITLAB_COMPONENT)
    assert "spec" in component
    assert "path" in component["spec"]["inputs"]
    assert "fail_on" in component["spec"]["inputs"]
    job = component["arachne-gate"]
    assert job["artifacts"]["reports"]["codequality"] == "codequality.json"
    # A gate blocks by default; `allow_failure` is an input whose default is false.
    assert job["allow_failure"] == "$[[ inputs.allow_failure ]]"
    assert component["spec"]["inputs"]["allow_failure"]["default"] is False
    assert job["rules"], "the component must ship rules defaults"
    script = "\n".join(job["script"])
    assert "python -m arachne.tools.ci_annotate" in script
    assert "--format gitlab" in script


# ------------------------------------------------------------------ the meta-test
def test_the_ci_workflow_runs_the_gate() -> None:
    """The delivery surface is real only if this repository's own CI runs it."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "arachne.tools.ci_annotate" in text
    assert "iac gate" in text.lower() or "REQ-ECOS-003" in text


# ------------------------------------------------------------------ acceptance test
def _run(cmd: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - a fixed argv built from our own interpreter
        cmd,
        cwd=CODE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _isolated_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["ARACHNE_DATABASE_URL"] = f"sqlite:///{tmp_path / 'ci-surfaces.db'}"
    env["ARACHNE_LOG_LEVEL"] = "CRITICAL"
    env["ARACHNE_LOG_JSON"] = "false"
    return env


def _migrate(env: dict[str, str]) -> None:
    completed = _run([sys.executable, "-m", "arachne.cli.main", "db", "upgrade"], env=env)
    assert completed.returncode == 0, completed.stderr


def test_the_action_run_on_the_fixture_repo_produces_annotations(tmp_path: Path) -> None:
    """REQ-ECOS-003's accept criterion, end to end through the real scanner as a process."""
    env = _isolated_env(tmp_path)
    _migrate(env)
    completed = _run(
        [
            sys.executable,
            "-m",
            "arachne.tools.ci_annotate",
            "--path",
            str(MISCONFIGURED),
            "--format",
            "github",
            "--fail-on",
            "high",
        ],
        env=env,
    )
    assert completed.returncode == 2, completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.startswith("::")]
    assert lines, completed.stdout
    assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in lines)
    annotations = "\n".join(lines)
    # The planted violation's file is named on the diff.
    assert ".github/workflows/ci.yml" in annotations
    assert "main.tf" in annotations
    assert "file=" in annotations and "line=" in annotations and "col=" in annotations


def test_the_tool_exit_code_matches_the_iac_gate_command(tmp_path: Path) -> None:
    """The tool *is* the gate: its verdict equals ``arachne iac gate``'s, per threshold."""
    env = _isolated_env(tmp_path)
    _migrate(env)
    for threshold in ("high", "critical"):
        gate = _run(
            [
                sys.executable,
                "-m",
                "arachne.cli.main",
                "iac",
                "gate",
                str(MISCONFIGURED),
                "--fail-on",
                threshold,
            ],
            env=env,
        )
        tool = _run(
            [
                sys.executable,
                "-m",
                "arachne.tools.ci_annotate",
                "--path",
                str(MISCONFIGURED),
                "--format",
                "github",
                "--fail-on",
                threshold,
            ],
            env=env,
        )
        assert tool.returncode == gate.returncode, threshold


def test_the_clean_fixture_passes_the_gate(tmp_path: Path) -> None:
    env = _isolated_env(tmp_path)
    _migrate(env)
    completed = _run(
        [
            sys.executable,
            "-m",
            "arachne.tools.ci_annotate",
            "--path",
            str(CLEAN),
            "--format",
            "github",
            "--fail-on",
            "high",
        ],
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


def test_the_gitlab_format_produces_a_codequality_report(tmp_path: Path) -> None:
    env = _isolated_env(tmp_path)
    _migrate(env)
    completed = _run(
        [
            sys.executable,
            "-m",
            "arachne.tools.ci_annotate",
            "--path",
            str(MISCONFIGURED),
            "--format",
            "gitlab",
            "--fail-on",
            "high",
        ],
        env=env,
    )
    assert completed.returncode == 2, completed.stderr
    report = json.loads(completed.stdout)
    assert isinstance(report, list) and report
    for row in report:
        assert set(row) == {
            "description",
            "check_name",
            "fingerprint",
            "severity",
            "location",
        }
        assert set(row["location"]) == {"path", "lines"}
        assert set(row["location"]["lines"]) == {"begin"}


def test_the_tool_reads_a_precomputed_report(tmp_path: Path) -> None:
    """``--report`` needs no database: a stored report is annotated directly."""
    report = ReportData(
        scan_id="7",
        target_name="iac:fixture",
        cover=ReportCover(
            title="report",
            target="iac:fixture",
            scan_id="7",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        executive_summary=ExecutiveSummary(),
        scope=ScopeMethodology(target_name="iac:fixture"),
        findings=(
            ReportFinding(
                id="F-000001",
                scan_id="7",
                module="M5",
                check_id="m5.tfstate-exposure",
                title="open security group",
                asset=AssetRef(kind="cloud", value="infra/main.tf"),
                severity="critical",
                score=Score(confidence=90),
                verification=report_verification(),
                remediation=RemediationPlan(id="REM-1", summary="restrict the CIDR"),
            ),
        ),
    )
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")
    completed = _run(
        [
            sys.executable,
            "-m",
            "arachne.tools.ci_annotate",
            "--report",
            str(report_file),
            "--format",
            "github",
            "--fail-on",
            "high",
        ],
        env=_isolated_env(tmp_path),
    )
    assert completed.returncode == 2, completed.stderr
    assert "::error file=infra/main.tf,line=1,col=1::open security group" in completed.stdout


# ------------------------------------------------------------------ Terraform module
def _declared_variables() -> list[str]:
    text = (TERRAFORM_MODULE / "variables.tf").read_text(encoding="utf-8")
    return re.findall(r'variable\s+"([^"]+)"', text)


def test_the_terraform_module_ships_the_expected_files() -> None:
    for name in ("main.tf", "variables.tf", "outputs.tf", "versions.tf", "README.md"):
        assert (TERRAFORM_MODULE / name).is_file(), f"missing {name}"


def test_every_terraform_variable_is_referenced() -> None:
    body = "\n".join(
        (TERRAFORM_MODULE / name).read_text(encoding="utf-8") for name in ("main.tf", "outputs.tf")
    )
    variables = _declared_variables()
    assert variables, "no variables declared"
    for name in variables:
        assert f"var.{name}" in body, f"variable {name!r} is declared but never used"


def test_the_terraform_module_declares_its_outputs_and_they_resolve() -> None:
    outputs = (TERRAFORM_MODULE / "outputs.tf").read_text(encoding="utf-8")
    names = re.findall(r'output\s+"([^"]+)"', outputs)
    assert names, "no outputs declared"
    assert len(names) == len(set(names))
    body = (TERRAFORM_MODULE / "main.tf").read_text(encoding="utf-8")
    for output in names:
        assert f'output "{output}"' in outputs
    # The service-name outputs are computed from a local defined in main.tf.
    assert "local.fullname" in outputs
    assert "fullname" in body


def test_the_terraform_module_deploys_the_shipped_helm_chart() -> None:
    main = (TERRAFORM_MODULE / "main.tf").read_text(encoding="utf-8")
    versions = (TERRAFORM_MODULE / "versions.tf").read_text(encoding="utf-8")
    assert 'resource "helm_release" "arachne"' in main
    # The chart this repository ships, by default, with no second copy.
    assert "helm/arachne" in main
    assert "hashicorp/helm" in versions
    assert "hashicorp/kubernetes" in versions


# ------------------------------------------------------------------ provider skeleton
def test_the_provider_is_explicitly_a_skeleton() -> None:
    for name in (
        "main.go",
        "provider.go",
        "data_source_findings.go",
        "resource_tenant.go",
        "go.mod",
        "Makefile",
        "README.md",
    ):
        assert (TERRAFORM_PROVIDER / name).is_file(), f"missing provider file {name}"
    readme = (TERRAFORM_PROVIDER / "README.md").read_text(encoding="utf-8")
    assert "skeleton" in readme.lower()
    # The skeleton must not claim to be functional.
    assert "not functional" in readme.lower()
    for name in ("main.go", "provider.go", "data_source_findings.go", "resource_tenant.go"):
        source = (TERRAFORM_PROVIDER / name).read_text(encoding="utf-8")
        assert "SKELETON" in source, f"{name} is not marked as a skeleton"
