"""``arachne vault`` — the operator surface over the encrypted vault (S19).

The properties worth testing are the ones an operator relies on: the vault is never usable
without its key, the secret never comes from the command line, listing and showing are metadata
only, and a revoked entry is visible as a refusal rather than vanishing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.vault import FileCredentialVault

PASSPHRASE = "cli-test-passphrase"
SECRET = "cli-credential-secret-value"


@pytest.fixture(autouse=True)
def _settings_from_env() -> None:
    """The CLI reads ``get_settings()``, which caches the environment once per process."""
    from arachne.core.config import reset_settings_cache

    reset_settings_cache()
    yield  # type: ignore[misc]
    reset_settings_cache()


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    vault_path = tmp_path / "vault.enc"
    monkeypatch.setenv("ARACHNE_VAULT_PATH", str(vault_path))
    monkeypatch.setenv("ARACHNE_VAULT_KEY", PASSPHRASE)
    monkeypatch.setenv("ARACHNE_VAULT_SECRET", SECRET)
    return {"path": str(vault_path)}


def run(args: list[str]) -> tuple[int, str]:
    result = CliRunner().invoke(app, ["vault", *args])
    return result.exit_code, result.output


def test_put_list_show_revoke_round_trip(env: dict[str, str]) -> None:
    code, output = run(
        [
            "put",
            "portal",
            "--username",
            "carol",
            "--kind",
            "web-form",
            "--scope-host",
            "app.internal",
        ]
    )
    assert code == 0, output
    assert "stored 'portal'" in output

    code, output = run(["list"])
    assert code == 0
    assert "portal" in output and "app.internal" in output
    # Nothing on the listing is material.
    assert SECRET not in output

    code, output = run(["show", "portal"])
    assert code == 0
    assert "web-form" in output
    assert "not shown" in output
    assert SECRET not in output

    code, output = run(["show", "portal", "--json"])
    document = json.loads(output)
    assert document["label"] == "portal" and document["active"] is True
    assert SECRET not in output

    code, output = run(["revoke", "portal"])
    assert code == 0 and "revoked" in output
    # A revoked entry is still listed with --all, and refused without it.
    assert "portal" not in run(["list"])[1]
    assert "portal" in run(["list", "--all"])[1]

    code, output = run(["remove", "portal"])
    assert code == 0
    assert "portal" not in run(["list", "--all"])[1]


def test_the_vault_refuses_without_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARACHNE_VAULT_PATH", str(tmp_path / "vault.enc"))
    monkeypatch.delenv("ARACHNE_VAULT_KEY", raising=False)
    code, output = run(["list"])
    assert code == 1
    assert "ARACHNE_VAULT_KEY" in output


def test_the_vault_refuses_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARACHNE_VAULT_PATH", raising=False)
    monkeypatch.delenv("ARACHNE_VAULT_KEY", raising=False)
    code, output = run(["list"])
    assert code == 1
    assert "no vault is configured" in output


def test_the_secret_is_never_taken_from_the_command_line(env: dict[str, str]) -> None:
    """There is no ``--secret`` option; the value comes from the environment or a prompt."""
    code, output = run(["put", "--help"])
    assert code == 0
    assert "--secret-env" in output
    assert "--secret " not in output


def test_a_stored_credential_is_readable_only_with_the_key(env: dict[str, str]) -> None:
    code, _ = run(["put", "portal", "--username", "carol", "--scope-host", "app.internal"])
    assert code == 0
    raw = Path(env["path"]).read_bytes()
    assert SECRET.encode() not in raw
    vault = FileCredentialVault(env["path"], passphrase=PASSPHRASE)
    handle = vault.resolve("portal", host="app.internal")
    assert handle is not None and handle.label == "portal"
