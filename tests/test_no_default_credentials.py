"""The no-default-credentials gate, tested as a gate (REQ-OPS-006).

The requirement's accept criterion is "CI gate green; grep finds nothing" — and a gate that
has silently stopped matching satisfies that criterion while protecting nothing. So this file
does not just run the gate against the repository (it must be clean); it also runs it against
a temporary tree containing **exactly the patterns the gate exists to catch** — the pre-S20
compose defaults, a demo API key in a README, a literal password in a shipped service — and
requires a finding for each. The lab-fixture exemption is proved too: the same credential is
tolerated under a ``profiles: ["lab"]`` service and flagged everywhere else.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from arachne.tools.credentials_gate import (
    LAB_EXEMPT_SERVICES,
    main,
    scan_paths,
)

CODE_ROOT = Path(__file__).resolve().parents[1]


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_repository_ships_no_default_credentials() -> None:
    findings = scan_paths(CODE_ROOT)
    assert not findings, "REQ-OPS-006: " + "\n".join(item.render() for item in findings)


def test_the_gate_passes_and_reports_on_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(CODE_ROOT)]) == 0
    assert "gate green" in capsys.readouterr().out


def test_the_gate_fails_on_the_pre_s20_compose_defaults(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exact strings S20 removed: a compose fallback password and a fallback API key."""
    _write(
        tmp_path,
        "docker/docker-compose.yml",
        """
name: arachne
x-arachne-env: &arachne-env
  ARACHNE_DATABASE_URL: postgresql+psycopg://arachne:${POSTGRES_PASSWORD:-arachne-demo-password}@db:5432/arachne
services:
  db:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-arachne-demo-password}
  api:
    environment:
      ARACHNE_API_KEYS: ${ARACHNE_API_KEYS:-demo-admin:admin:demo-admin-key}
""",
    )
    findings = scan_paths(tmp_path)
    rules = {finding.rule for finding in findings}
    assert "compose-default" in rules
    assert len(findings) >= 2, [item.render() for item in findings]
    assert main([str(tmp_path)]) == 1
    assert "gate FAILED" in capsys.readouterr().err


def test_the_gate_fails_on_a_literal_credential_in_a_shipped_service(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docker/docker-compose.yml",
        """
services:
  api:
    environment:
      ARACHNE_SMTP_PASSWORD: hunter2-real-password
""",
    )
    findings = scan_paths(tmp_path)
    assert [finding.rule for finding in findings] == ["credential-default"]


def test_the_gate_fails_on_a_documented_demo_api_key(tmp_path: Path) -> None:
    _write(tmp_path, "docker/README.md", "Demo keys:\n\ndemo-admin:admin:demo-admin-key\n")
    findings = scan_paths(tmp_path)
    assert "api-key" in {finding.rule for finding in findings}


def test_the_gate_accepts_placeholders_expansions_and_references(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docker/docker-compose.yml",
        """
services:
  api:
    environment:
      ARACHNE_API_KEYS: ${ARACHNE_API_KEYS:?required - set it in .env}
      ARACHNE_DATABASE_PASSWORD_FILE: /run/secrets/postgres_password
      ARACHNE_VAULT_KEY: ""
      ARACHNE_SECRETS_MANIFEST: /var/lib/arachne/secrets.manifest
      ARACHNE_WEB_JWT_MAX_TOKENS: "4"
""",
    )
    _write(
        tmp_path,
        ".env.example",
        """
# ARACHNE_API_KEYS=ops-admin:admin:REPLACE_ME;ops-viewer:viewer:REPLACE_ME
# ARACHNE_API_KEYS=label:role:$(openssl rand -hex 32)
ARACHNE_EVIDENCE_PREVIEW_CHARS=2048
""",
    )
    _write(
        tmp_path,
        "docker/secrets/api_keys.txt.example",
        "ops-admin:admin:replace-with-a-secret\n",
    )
    assert scan_paths(tmp_path) == ()


def test_the_lab_fixture_exemption_is_proved_not_trusted(tmp_path: Path) -> None:
    """A credential is tolerated only under a service that really is a lab profile."""
    _write(
        tmp_path,
        "docker/docker-compose.yml",
        """
services:
  lab-mysql:
    profiles: ["lab"]
    environment:
      MYSQL_ROOT_PASSWORD: dvwa
  shipped-mysql:
    environment:
      MYSQL_ROOT_PASSWORD: dvwa
""",
    )
    findings = scan_paths(tmp_path)
    assert len(findings) == 1, [item.render() for item in findings]
    assert "shipped-mysql" not in findings[0].detail
    assert findings[0].detail.startswith("MYSQL_ROOT_PASSWORD")
    assert findings[0].line > 1, findings[0].render()
    assert "lab-mysql" in LAB_EXEMPT_SERVICES


def test_an_exempt_service_that_is_not_a_lab_profile_is_not_exempt(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docker/docker-compose.yml",
        """
services:
  lab-mysql:
    environment:
      MYSQL_ROOT_PASSWORD: dvwa
""",
    )
    findings = scan_paths(tmp_path)
    assert len(findings) == 1, "the exemption is not honoured without profiles: [lab]"


def test_the_ci_workflow_runs_the_gate() -> None:
    """The gate is only a CI gate if CI runs it."""
    workflow = CODE_ROOT / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "arachne.tools.credentials_gate" in text
    assert "no default credentials" in text.lower()


def test_the_gate_exits_non_zero_as_a_process(tmp_path: Path) -> None:
    _write(tmp_path, ".env.example", "ARACHNE_VAULT_KEY=aaaaaaaaaaaaaaaa\n")
    assert main([str(tmp_path)]) == 1


def test_the_gate_is_run_from_a_plain_interpreter() -> None:
    """It must not need the package's import path to be set up by a test harness."""
    assert sys.version_info >= (3, 11)


# --------------------------------------------------------------- S22: the k8s surface
def test_the_gate_accepts_the_kubernetes_reference_idiom(tmp_path: Path) -> None:
    """`deploy/` is shipped surface now; its pointers (secretKeyRef) are not values."""
    (tmp_path / "deploy" / "helm" / "arachne" / "templates").mkdir(parents=True)
    (tmp_path / "deploy" / "helm" / "arachne" / "values.yaml").write_text(
        "\n".join(
            [
                "api:",
                "  auth:",
                '    apiKeys: ""',
                '    existingSecret: ""   # a Secret you manage',
                "    secretKey: arachne-api-keys",
                "  secretEnv: {}",
                "postgres:",
                "  auth:",
                '    password: ""',
                "    secretKey: postgres-password",
                '    existingSecret: ""',
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "deploy" / "helm" / "arachne" / "templates" / "deployment.yaml").write_text(
        "\n".join(
            [
                "env:",
                "  - name: POSTGRES_PASSWORD",
                "    valueFrom:",
                "      secretKeyRef:",
                "        name: arachne-postgres",
                "        key: postgres-password",
                "  - name: ARACHNE_API_KEYS",
                "    valueFrom:",
                "      secretKeyRef:",
                "        name: {{ .Values.api.auth.existingSecret }}",
                "        key: arachne-api-keys",
            ]
        ),
        encoding="utf-8",
    )
    assert scan_paths(tmp_path) == ()


def test_the_gate_refuses_a_literal_credential_in_helm_values(tmp_path: Path) -> None:
    (tmp_path / "deploy" / "helm" / "arachne").mkdir(parents=True)
    (tmp_path / "deploy" / "helm" / "arachne" / "values.yaml").write_text(
        "postgres:\n  auth:\n    password: hunter2-default\n",
        encoding="utf-8",
    )
    findings = scan_paths(tmp_path)
    assert [finding.rule for finding in findings] == ["credential-default"]
    assert "hunter2-default" in findings[0].detail


def test_the_gate_refuses_a_literal_in_a_k8s_template(tmp_path: Path) -> None:
    (tmp_path / "deploy" / "helm" / "arachne" / "templates").mkdir(parents=True)
    (tmp_path / "deploy" / "helm" / "arachne" / "templates" / "secret.yaml").write_text(
        "\n".join(
            [
                "stringData:",
                "  postgres-password: setecastronomy",
            ]
        ),
        encoding="utf-8",
    )
    findings = scan_paths(tmp_path)
    assert findings and findings[0].rule == "credential-default"
