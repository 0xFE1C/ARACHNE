"""The S25 operator commands: integrity, packs and DR (REQ-RESIL-005, REQ-TRUST-005/007).

The commands are the operator's half of the requirement: ``verify-chain`` is named by
REQ-TRUST-005, ``packs`` is how content reaches an air-gapped estate, and ``dr`` is the
"tested backup/restore path" of REQ-RESIL-005. Each is driven here through the CLI with a
real (migrated) database, so what is asserted is what an operator would see.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import reset_settings_cache
from arachne.core.signing import DeploymentSigner

KEY = "s25-cli-integrity-key-00000001"
runner = CliRunner()


@pytest.fixture
def deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_INTEGRITY_KEY", KEY)
    monkeypatch.setenv("ARACHNE_CONTENT_DIR", str(tmp_path / "content"))
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    return tmp_path


def _json(output: str) -> dict[str, object]:
    """The first JSON document in ``output`` (the commands may print a line after it)."""
    start = output.index("{")
    value, _end = json.JSONDecoder().raw_decode(output[start:])
    assert isinstance(value, dict)
    return value


def test_verify_chain_on_an_empty_estate_reports_intact(deployment: Path) -> None:
    result = runner.invoke(app, ["verify-chain", "--json"])
    assert result.exit_code == 0, result.output
    payload = _json(result.output)
    assert payload["ok"] is True
    assert "no chained audit rows" in json.dumps(payload["notes"])


def test_integrity_status_names_the_key_and_the_region(deployment: Path) -> None:
    result = runner.invoke(app, ["integrity", "status", "--json"])
    assert result.exit_code == 0, result.output
    payload = _json(result.output)
    assert payload["integrity_key"]["configured"] is True
    assert payload["integrity_key"]["key_id"]
    assert payload["chain_head"] is None  # nothing audited yet
    assert payload["airgapped"] is False


def test_integrity_status_without_a_key_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'nokey.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.delenv("ARACHNE_INTEGRITY_KEY", raising=False)
    monkeypatch.delenv("ARACHNE_INTEGRITY_KEY_FILE", raising=False)
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    payload = _json(runner.invoke(app, ["integrity", "status", "--json"]).output)
    assert payload["integrity_key"] == {"configured": False}


def test_anchoring_needs_something_to_anchor(deployment: Path) -> None:
    result = runner.invoke(app, ["integrity", "anchor"])
    assert result.exit_code == 0
    assert "nothing to anchor" in result.output


def test_an_anchor_can_be_exported_off_the_host(deployment: Path) -> None:
    # One audit line first, so there is a chain head to anchor.
    assert runner.invoke(app, ["integrity", "status"]).exit_code == 0
    services_auditor = _audit_one(deployment)
    del services_auditor
    target = deployment / "anchor.json"
    result = runner.invoke(app, ["integrity", "anchor", "--export", str(target), "--json"])
    assert result.exit_code == 0, result.output
    payload = _json(result.output)
    assert target.is_file()
    exported = json.loads(target.read_text())
    assert exported["seq"] == payload["seq"]
    assert exported["signature"].startswith("v1:")


def test_sealing_a_scan_that_does_not_exist_is_refused(deployment: Path) -> None:
    result = runner.invoke(app, ["integrity", "seal", "--scan", "42"])
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_a_backup_then_a_restore_through_the_cli(deployment: Path) -> None:
    out = deployment / "bundle"
    created = runner.invoke(
        app, ["dr", "backup", "--out", str(out), "--json", "--rpo-seconds", "600"]
    )
    assert created.exit_code == 0, created.output
    payload = _json(created.output)
    assert payload["rpo_seconds"] == 600
    assert (out / "manifest.json").is_file()

    # This estate is empty, so the restore is allowed (the guard is about *live* data).
    restored = runner.invoke(app, ["dr", "restore", str(out), "--json"])
    assert restored.exit_code == 0, restored.output
    assert _json(restored.output)["tables"]["scans"] == 0
    # Restoring an empty bundle again is idempotent (there are no rows to collide). The
    # refusal that matters — a *populated* target — is asserted in tests/unit/test_backup.py,
    # where the bundle actually carries rows.
    again = runner.invoke(app, ["dr", "restore", str(out), "--json"])
    assert again.exit_code == 0
    assert _json(again.output)["rows"] == 0


def test_dr_status_reports_the_leases_and_the_scaling_decision(deployment: Path) -> None:
    result = runner.invoke(app, ["dr", "status", "--depth", "9", "--json"])
    assert result.exit_code == 0, result.output
    payload = _json(result.output)
    assert payload["queue_depth"] == 9
    assert payload["scaling"]["desired"] == 3  # 9 / 4 per worker, rounded up
    assert {lease["name"] for lease in payload["leases"]} >= {"scheduler", "retention"}
    assert payload["head_migration"]["expand_only"] is True


def test_packs_export_verify_list_round_trip(deployment: Path, monkeypatch) -> None:
    """Export → verify → import: the air-gap *transport*, which is what S25 built.

    Review is waived here deliberately (S26). This test is about carrying a pack across the air
    gap, not about the marketplace: a deployment importing content it exported itself already
    reviewed that content when the release shipped it. The gated path — a third-party pack that
    must pass the review pipeline before it can be listed or imported — is proven end to end in
    `tests/test_pack_review_safety.py::test_the_reviewed_pack_flow_works_end_to_end_over_the_cli`.
    """
    monkeypatch.setenv("ARACHNE_PLUGIN_REQUIRE_REVIEW", "false")
    reset_settings_cache()
    source = deployment / "src"
    (source / "plan").mkdir(parents=True)
    (source / "plan" / "check_catalog.yaml").write_text("version: test\n", encoding="utf-8")
    pack = deployment / "out.tar.gz"

    exported = runner.invoke(
        app,
        [
            "packs",
            "export",
            "--out",
            str(pack),
            "--name",
            "cli-baseline",
            "--version",
            "1.0.0",
            "--content",
            str(source),
            "--json",
        ],
    )
    assert exported.exit_code == 0, exported.output
    payload = _json(exported.output)
    assert payload["signed"] is True
    assert payload["key_id"] == DeploymentSigner(KEY).key_id

    verified = runner.invoke(app, ["packs", "verify", str(pack), "--json"])
    assert verified.exit_code == 0, verified.output
    assert _json(verified.output)["verified"] is True

    imported = runner.invoke(app, ["packs", "import", str(pack), "--json"])
    assert imported.exit_code == 0, imported.output
    # ``--content <dir>`` packs as the ``content`` kind, so the member keeps its kind segment
    # and its path relative to the root.
    installed = (
        deployment
        / "content"
        / "cli-baseline"
        / "1.0.0"
        / "content"
        / "plan"
        / "check_catalog.yaml"
    )
    assert installed.is_file()

    listed = runner.invoke(app, ["packs", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    listed_payload = _json(listed.output)
    assert [row["name"] for row in listed_payload["imported"]] == ["cli-baseline"]
    assert len(listed_payload["on_disk"]) == 1


def test_packs_export_without_a_key_refuses(
    deployment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARACHNE_INTEGRITY_KEY", raising=False)
    reset_settings_cache()
    source = deployment / "src2"
    source.mkdir()
    (source / "x.yaml").write_text("y: 1\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "packs",
            "export",
            "--out",
            str(deployment / "p.tar.gz"),
            "--name",
            "n",
            "--version",
            "1",
            "--content",
            str(source),
        ],
    )
    assert result.exit_code == 2
    assert "no content key" in result.output


def test_packs_verify_refuses_a_tampered_pack(deployment: Path) -> None:
    source = deployment / "src3"
    source.mkdir()
    (source / "x.yaml").write_text("y: 1\n", encoding="utf-8")
    pack = deployment / "t.tar.gz"
    assert (
        runner.invoke(
            app,
            [
                "packs",
                "export",
                "--out",
                str(pack),
                "--name",
                "n",
                "--version",
                "1",
                "--content",
                str(source),
            ],
        ).exit_code
        == 0
    )
    # Flip a byte in the signature: the pack is now unverifiable.
    original = pack.read_bytes()
    pack.write_bytes(original[:-40] + b"0" * 40)
    result = runner.invoke(app, ["packs", "verify", str(pack)])
    assert result.exit_code == 1
    assert "REFUSED" in result.output


def _audit_one(deployment: Path) -> object:
    """Write one audit line through the real stack, so a chain head exists."""
    from arachne.core.audit import AuditAction
    from arachne.core.config import get_settings
    from arachne.data.services import build_services

    services = build_services(get_settings())
    try:
        services.auditor.record(AuditAction.INTEGRITY_VERIFIED, meta={"test": True})
    finally:
        services.close()
    return None
