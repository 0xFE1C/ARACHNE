"""The generated coverage ledger (REQ-DET-001, REQ-DET-003, REQ-DET-005).

The ledger is the one artefact that can overstate coverage, so the assertions are about its
*correspondence* to the registry rather than its formatting:

* one record per registered check, no extras and no misses;
* every pre-existing check mapped to a WSTG or API item (the REQ-DET-002 burn-down is 0);
* all 97 WSTG ids in exactly one state, with ≥68 mapped;
* all ten API Top 10 items mapped;
* a committed ledger that is byte-identical to generated output, and a stale one that fails
  naming the check id that moved.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.coverage import (
    build_ledger,
    check_ledger,
    default_ledger_paths,
    render_ledger_json,
    render_ledger_markdown,
)
from arachne.modules.registry import ModuleGroup, ModuleRegistry

runner = CliRunner()


@pytest.fixture(scope="module")
def registry() -> ModuleRegistry:
    return ModuleRegistry.discover()


@pytest.fixture(scope="module")
def ledger(registry: ModuleRegistry):  # type: ignore[no-untyped-def]
    return build_ledger(registry, generated_at="2026-11-02")


# ------------------------------------------------------------------ records == registry
def test_the_record_set_equals_the_registry_exactly(ledger, registry: ModuleRegistry) -> None:  # type: ignore[no-untyped-def]
    assert [record.id for record in ledger.records] == [
        metadata.id for metadata in registry.metadata()
    ]
    assert ledger.check_count == len(registry.checks())


def test_every_record_carries_the_required_fields(ledger) -> None:  # type: ignore[no-untyped-def]
    for record in ledger.records:
        assert record.id and record.module and record.title
        assert record.proof in {"L0", "L1", "L2", "L3", "L4"}
        assert record.target_kinds
        assert record.framework
        assert record.last_verified == "2026-11-02"


def test_the_ledger_states_its_timestamp_registry_version_and_framework_versions(
    ledger,
) -> None:  # type: ignore[no-untyped-def]
    payload = ledger.to_dict()
    assert payload["generated_at"] == "2026-11-02"
    assert payload["registry_version"] == "registry-1.0"
    assert payload["registry_digest"].startswith("sha256:")
    assert payload["framework_versions"]["WSTG"] == "4.2"
    assert payload["framework_versions"]["API"] == "2023"


def test_the_json_document_has_a_checks_array(ledger) -> None:  # type: ignore[no-untyped-def]
    payload = json.loads(render_ledger_json(ledger))
    assert isinstance(payload["checks"], list)
    assert len(payload["checks"]) == ledger.check_count


# ------------------------------------------------------------------ REQ-DET-002 burn-down
def test_no_check_is_mapped_only_to_a_cwe(ledger) -> None:  # type: ignore[no-untyped-def]
    assert ledger.cwe_only == ()


def test_every_check_names_a_wstg_or_api_item(ledger) -> None:  # type: ignore[no-untyped-def]
    for record in ledger.records:
        assert any(item.startswith(("WSTG-", "API")) for item in record.framework), record.id


def test_the_original_152_checks_are_all_present_and_mapped(ledger) -> None:  # type: ignore[no-untyped-def]
    """REQ-DET-002's "all 152 existing checks" set, before WP-07's three MCP additions."""
    ids = {record.id for record in ledger.records}
    mcp = {record.id for record in ledger.records if record.id.startswith("m6.mcp-")}
    assert len(ids - mcp) == 152
    assert len(mcp) == 3


# ------------------------------------------------------------------ REQ-DET-003 WSTG
def test_all_97_wstg_ids_are_accounted_for_exactly_once(ledger) -> None:  # type: ignore[no-untyped-def]
    ids = [item["id"] for item in ledger.wstg_items]
    assert len(ids) == 97
    assert len(set(ids)) == 97
    assert {item["state"] for item in ledger.wstg_items} <= {
        "mapped",
        "out_of_scope",
        "gap",
    }


def test_at_least_68_of_97_wstg_ids_are_mapped(ledger) -> None:  # type: ignore[no-untyped-def]
    counts = ledger.wstg_counts()
    assert counts["total"] == 97
    assert counts["mapped"] >= 68
    assert counts["mapped"] + counts["out_of_scope"] + counts["gap"] == 97


def test_every_out_of_scope_item_carries_a_reason(ledger) -> None:  # type: ignore[no-untyped-def]
    for item in ledger.wstg_items:
        if item["state"] == "out_of_scope":
            assert item.get("reason")


def test_a_gap_names_no_check_and_a_mapped_item_names_one(ledger) -> None:  # type: ignore[no-untyped-def]
    for item in ledger.wstg_items:
        if item["state"] == "gap":
            assert item["checks"] == []
        if item["state"] == "mapped":
            assert item["checks"]


# ------------------------------------------------------------------ REQ-DET-005 API
def test_the_api_top10_is_mapped_ten_of_ten(ledger) -> None:  # type: ignore[no-untyped-def]
    assert ledger.api_counts() == {"mapped": 10, "total": 10}


def test_the_mcp_family_is_registered_and_mapped() -> None:
    metadata = {item.id: item for item in ModuleRegistry.builtin().metadata()}
    for check_id in ("m6.mcp-token-audience", "m6.mcp-session-auth", "m6.mcp-oauth-metadata"):
        assert check_id in metadata
        assert metadata[check_id].proof.value in {"L0", "L1"}
        assert metadata[check_id].enabled_by_default  # opt-out-able


# ------------------------------------------------------------------ the committed artefact
def test_the_committed_ledger_is_current() -> None:
    """G3 clause 1: the committed ledger is byte-identical to generated output in CI."""
    ok, differences = check_ledger(*default_ledger_paths())
    assert ok, differences


def test_the_markdown_is_deterministic(ledger) -> None:  # type: ignore[no-untyped-def]
    assert render_ledger_markdown(ledger) == render_ledger_markdown(
        build_ledger(ModuleRegistry.discover(), generated_at="2026-11-02")
    )


def test_a_stale_ledger_fails_naming_the_check_id(tmp_path: Path, registry: ModuleRegistry) -> None:
    """Adding a check without regenerating fails the build with the check id in the message."""
    ledger = build_ledger(registry, generated_at="2026-11-02")
    json_path = tmp_path / "coverage-ledger.json"
    markdown_path = tmp_path / "coverage-ledger.md"
    json_path.write_text(render_ledger_json(ledger), encoding="utf-8")
    markdown_path.write_text(render_ledger_markdown(ledger), encoding="utf-8")
    assert check_ledger(json_path, markdown_path, registry=registry)[0]

    class LedgerProbe(Module):
        metadata = CheckMetadata(
            id="m1.ledger-probe",
            module="M1",
            name="ledger-probe",
            version="1.0",
            title="Ledger probe",
            description="A check added without regenerating the ledger.",
            research_ref="ch01#1",
            framework=("WSTG-INFO-01",),
            target_kinds=(TargetKind.DOMAIN,),
        )

        async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
            yield ctx.info("never")  # pragma: no cover

    grown = ModuleRegistry.discover(
        include_entry_points=False,
        extra_groups=[
            ModuleGroup(
                id="M1",
                title="M1",
                description="test",
                version="1.0",
                checks=(LedgerProbe,),
            )
        ],
    )
    ok, differences = check_ledger(json_path, markdown_path, registry=grown)
    assert not ok
    assert any("m1.ledger-probe" in difference for difference in differences)


def test_the_cli_emits_the_same_records(registry: ModuleRegistry) -> None:
    result = runner.invoke(app, ["coverage", "ledger", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["checks"]) == len(registry.checks())


def test_the_cli_check_mode_passes_on_the_committed_ledger() -> None:
    result = runner.invoke(app, ["coverage", "ledger", "--check"])
    assert result.exit_code == 0, result.output
    assert "up to date" in result.output
