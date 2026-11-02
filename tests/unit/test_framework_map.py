"""The framework vocabulary and its pinned versions (REQ-DET-002, REQ-DET-003).

Two things are tested here: that the controlled vocabulary rejects every shape the requirement
names (a malformed WSTG id, an out-of-range CWE, a short ATT&CK id), and that the registry —
not only the dataclass — refuses a check with no mapping. The second half also pins the WSTG
denominator: 97 ids, 12 categories, and the per-category counts the technique-landscape
research recorded.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from arachne.core.errors import ConfigurationError
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.framework_map import (
    FRAMEWORK_FILES,
    Framework,
    framework,
    framework_for_item,
    framework_versions,
    frameworks,
    item_error,
    sorted_items,
    validate_items,
    wstg_coverage,
)
from arachne.modules.registry import ModuleGroup, ModuleRegistry

#: The per-category counts WSTG v4.2 publishes, and the total the ledger must account for.
CATEGORY_COUNTS = {
    "INFO": 10,
    "CONF": 11,
    "IDNT": 5,
    "ATHN": 10,
    "ATHZ": 4,
    "SESS": 9,
    "INPV": 19,
    "ERRH": 2,
    "CRYP": 4,
    "BUSL": 9,
    "CLNT": 13,
    "APIT": 1,
}


# ------------------------------------------------------------------ the pinned snapshots
def test_one_pinned_file_exists_per_framework() -> None:
    names = [name for name, _ in FRAMEWORK_FILES]
    assert set(names) == {"WSTG", "API", "CWE", "ATT&CK", "LLM", "ASI"}
    assert framework_versions() == {
        "WSTG": "4.2",
        "API": "2023",
        "CWE": "2025",
        "ATT&CK": "v20",
        "LLM": "2025",
        "ASI": "2026",
    }


def test_wstg_is_the_97_ids_in_twelve_categories() -> None:
    wstg = framework("WSTG")
    assert len(wstg.items) == 97
    counts: dict[str, int] = {}
    for item in wstg.items:
        assert item.id == f"WSTG-{item.category}-{item.number:02d}"
        counts[item.category] = counts.get(item.category, 0) + 1
    assert counts == CATEGORY_COUNTS


@pytest.mark.parametrize("name,count", [("API", 10), ("LLM", 10), ("ASI", 10)])
def test_the_top_ten_frameworks_have_ten_items(name: str, count: int) -> None:
    spec: Framework = framework(name)
    assert len(spec.items) == count
    assert len(spec.ids) == count


# ------------------------------------------------------------------ id validation
@pytest.mark.parametrize(
    "item",
    [
        "WSTG-INFO-01",
        "WSTG-APIT-01",
        "API1:2023",
        "API10:2023",
        "CWE-79",
        "CWE-1426",
        "ATT&CK-T1059",
        "ATT&CK-T1565.001",
        "LLM01:2025",
        "LLM10:2025",
        "ASI01:2026",
        "ASI10:2026",
    ],
)
def test_a_valid_item_has_no_error(item: str) -> None:
    assert item_error(item) is None


@pytest.mark.parametrize(
    "item,needle",
    [
        # REQ-DET-002's three examples, each with the offending id in the message.
        ("WSTG-ATHN", "'WSTG-ATHN'"),
        ("CWE-99999", "'CWE-99999'"),
        ("ATT&CK-T123", "'ATT&CK-T123'"),
        # A category that exists but a number that does not.
        ("WSTG-ATHN-11", "'WSTG-ATHN-11'"),
        # A top-ten number that does not exist.
        ("API11:2023", "'API11:2023'"),
        ("LLM11:2025", "'LLM11:2025'"),
        ("ASI11:2026", "'ASI11:2026'"),
        # An unknown framework prefix.
        ("NOPE-1", "'NOPE-1'"),
    ],
)
def test_an_invalid_item_names_itself(item: str, needle: str) -> None:
    problem = item_error(item)
    assert problem is not None
    assert needle in problem


def test_the_three_requirement_examples_are_refused_with_the_right_reason() -> None:
    assert "malformed" in (item_error("WSTG-ATHN") or "")
    assert "out of range" in (item_error("CWE-99999") or "")
    assert "malformed" in (item_error("ATT&CK-T123") or "")


def test_framework_for_item_dispatches_by_prefix() -> None:
    assert framework_for_item("WSTG-INFO-01") is framework("WSTG")  # type: ignore[comparison-overlap]
    assert framework_for_item("API7:2023").name == "API"  # type: ignore[union-attr]
    assert framework_for_item("ATT&CK-T1190").name == "ATT&CK"  # type: ignore[union-attr]
    assert framework_for_item("nonsense") is None


def test_sorted_items_put_wstg_before_cwe() -> None:
    assert sorted_items(("CWE-79", "WSTG-INPV-01", "API1:2023")) == (
        "WSTG-INPV-01",
        "API1:2023",
        "CWE-79",
    )
    # Pure function of the set: duplicates collapse and order does not matter.
    assert sorted_items(["CWE-79", "CWE-79"]) == ("CWE-79",)


# ------------------------------------------------------------------ WSTG states
def test_every_wstg_id_is_in_exactly_one_state() -> None:
    states = wstg_coverage({})
    assert len(states) == 97
    assert {state.state for state in states} <= {"mapped", "out_of_scope", "gap"}
    assert sum(1 for state in states if state.state == "out_of_scope") > 0
    for state in states:
        if state.state == "out_of_scope":
            assert state.item.reason, "an out_of_scope item must carry a reason"


def test_a_mapped_out_of_scope_item_is_a_contradiction() -> None:
    with pytest.raises(ConfigurationError, match="authored out_of_scope"):
        wstg_coverage({"WSTG-CONF-09": ("m4.env-file-probe",)})


# ------------------------------------------------------------------ registry refusal
def _metadata(check_id: str, **overrides: object) -> CheckMetadata:
    module, _, name = check_id.partition(".")
    base: dict[str, object] = {
        "id": check_id,
        "module": module.upper(),
        "name": name,
        "version": "1.0",
        "title": f"{name} check",
        "description": f"A check named {name}.",
        "research_ref": "ch01#1",
        "target_kinds": (TargetKind.DOMAIN,),
        "framework": ("CWE-200",),
    }
    return CheckMetadata(**{**base, **overrides})  # type: ignore[arg-type]


def _check(check_id: str, **overrides: object) -> type[Module]:
    metadata = _metadata(check_id, **overrides)

    async def run(self: Module, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        yield ctx.info(f"{metadata.id} ran")  # pragma: no cover - never executed

    return type(  # type: ignore[return-value]
        f"Check_{check_id.replace('.', '_')}", (Module,), {"metadata": metadata, "run": run}
    )


def _group(check: type[Module]) -> ModuleGroup:
    return ModuleGroup(
        id="M1",
        title="M1 test module",
        description="A module that exists only in this test.",
        version="9.9",
        checks=(check,),
    )


def test_the_registry_refuses_a_check_with_no_mapping() -> None:
    unmapped = _check("m1.unmapped", framework=())
    with pytest.raises(ConfigurationError) as caught:
        ModuleRegistry([_group(unmapped)])
    assert "m1.unmapped" in str(caught.value)
    assert "no framework mapping" in str(caught.value)


def test_the_registry_refuses_a_malformed_mapping_that_bypassed_construction() -> None:
    check = _check("m1.mutated")
    # A hand-mutated metadata object is exactly the case the registry re-validation exists
    # for: construction already refuses a bad id, so this is the only way to reach it.
    object.__setattr__(check.metadata, "framework", ("WSTG-ATHN",))
    with pytest.raises(ConfigurationError) as caught:
        ModuleRegistry([_group(check)])
    assert "m1.mutated" in str(caught.value)
    assert "WSTG-ATHN" in str(caught.value)


@pytest.mark.parametrize("item", ["WSTG-ATHN", "CWE-99999", "ATT&CK-T123"])
def test_metadata_construction_refuses_a_malformed_item(item: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        _metadata("m1.bad", framework=(item,))
    assert item in str(caught.value)


def test_a_cwe_that_is_not_in_the_framework_mapping_is_refused() -> None:
    """The mapping must be the whole story, so the ledger cannot show a partial view."""
    with pytest.raises(ConfigurationError, match="is not in framework"):
        _metadata("m1.partial", cwe="CWE-79", framework=("WSTG-INPV-01",))


def test_a_check_with_a_valid_mapping_registers() -> None:
    registry = ModuleRegistry([_group(_check("m1.mapped", framework=("WSTG-INFO-01", "CWE-200")))])
    assert registry.check_ids() == ("m1.mapped",)


def test_validate_items_reports_every_problem() -> None:
    problems = validate_items(("WSTG-INFO-01", "CWE-99999", "ATT&CK-T1"))
    assert len(problems) == 2
    assert all("WSTG-INFO-01" not in problem for problem in problems)


def test_frameworks_are_cached_and_stable() -> None:
    assert frameworks() is frameworks()
