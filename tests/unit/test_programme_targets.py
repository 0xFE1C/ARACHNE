"""The programme's published targets, asserted against the registry (REQ-DET-028).

Phase P8 promised three numbers and this module holds them to the artefacts that can be
measured rather than to prose:

* the registry reports **at least 400 registered checks**;
* **no module fell below its pre-programme count** — the target is breadth across all six
  modules, not one module absorbing the growth;
* the coverage ledger's **family breakdown sums to the registry total**, so every check the
  registry knows is a row in the ledger and every row belongs to a module.

The fourth clause — the false-positive rate at or below 2 per cent with its method and
corpus version stated — is asserted here too, reading the published measurement and the
document that publishes it. The number is a property of the corpus as much as of the scanner,
so the corpus version travels with it.

**The pre-programme counts.** REQ-DET-028 says "at least its pre-programme count". The
programme baseline is the registry at the commit phase P8 started from, measured then as
M1 17, M2 27, M3 47, M4 29, M5 20, M6 12 — 152 checks in total. The figures are committed
here as the floor, because the artefact they were first recorded in is build-time scaffolding
that the release cleanup removes (REQ-DOC-006). A floor that lives only in a file the release
deletes cannot police the release.

**Reading taken.** "The ledger's family breakdown" is read as the ledger's per-module
grouping: the six M1...M6 module families are the families the registry and the ledger both
name, and each contributed checks to the 400. The ledger carries no other family key, so this
is the strongest reading the artefact supports.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from arachne.modules.coverage import build_ledger
from arachne.modules.registry import ModuleRegistry
from arachne.quality.benchmark import load_baseline

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMITTED_LEDGER = REPO_ROOT / "coverage-ledger.json"
BENCHMARKS = REPO_ROOT / "benchmarks"
LAB = "arachne-lab"
PERFORMANCE_DOC = REPO_ROOT / "docs" / "performance.md"

#: REQ-DET-028's target: at least four hundred registered checks.
TARGET_CHECKS = 400

#: Each module's registered-check count at the programme baseline, before phase P8. Every
#: module must still meet or exceed its own figure (REQ-DET-028).
PRE_PROGRAMME_CHECKS = {
    "M1": 17,
    "M2": 27,
    "M3": 47,
    "M4": 29,
    "M5": 20,
    "M6": 12,
}

#: REQ-DET-028 / REQ-QUAL-009: the published false-positive rate's ceiling.
FP_CEILING = 0.02


def _registry() -> ModuleRegistry:
    """The shipped registry, without plugin entry points (nothing installed can inflate it)."""
    return ModuleRegistry.discover(include_entry_points=False)


def _per_module(counts: Counter[str]) -> dict[str, int]:
    return dict(sorted(counts.items()))


def test_the_registry_reports_at_least_four_hundred_checks() -> None:
    """REQ-DET-028: ``totals()['checks'] >= 400``, measured on the shipped registry."""
    registry = _registry()
    totals = registry.totals()
    assert totals["checks"] >= TARGET_CHECKS, (
        f"the registry reports {totals['checks']} checks; REQ-DET-028 requires {TARGET_CHECKS}"
    )
    # Breadth is across all six modules, not one module absorbing the growth.
    assert totals["modules"] == len(PRE_PROGRAMME_CHECKS)
    assert registry.module_ids() == tuple(PRE_PROGRAMME_CHECKS)
    counts = Counter(metadata.module for metadata in registry.metadata())
    assert sum(counts.values()) == totals["checks"]
    print(f"registry: {totals['checks']} checks across {totals['modules']} modules")
    print(f"per module: {_per_module(counts)}")


def test_no_module_is_empty_or_below_its_pre_programme_count() -> None:
    """REQ-DET-028: every module still reports at least the count it started with."""
    registry = _registry()
    counts = Counter(metadata.module for metadata in registry.metadata())
    shortfalls = {
        module: {"floor": floor, "now": counts.get(module, 0)}
        for module, floor in PRE_PROGRAMME_CHECKS.items()
        if counts.get(module, 0) < floor
    }
    assert shortfalls == {}, f"these modules fell below their pre-programme count: {shortfalls}"
    assert set(counts) == set(PRE_PROGRAMME_CHECKS), "a module disappeared from the registry"


def test_the_ledger_family_breakdown_sums_to_the_registry_total() -> None:
    """REQ-DET-028: every registered check is a ledger row, and each row is in a family.

    Measured twice — on the ledger freshly built from the registry and on the copy committed
    to the repository — because the requirement is about the artefact a reader receives, and a
    committed ledger that drifted from the registry would otherwise pass on the in-memory one.
    """
    registry = _registry()
    registry_total = registry.totals()["checks"]

    fresh = build_ledger(registry, generated_at="2026-11-08")
    fresh_by_module = Counter(record.module for record in fresh.records)
    assert sum(fresh_by_module.values()) == fresh.check_count == registry_total
    assert set(fresh_by_module) == set(PRE_PROGRAMME_CHECKS)

    committed = json.loads(COMMITTED_LEDGER.read_text(encoding="utf-8"))
    committed_by_module = Counter(check["module"] for check in committed["checks"])
    assert sum(committed_by_module.values()) == committed["totals"]["checks"] == registry_total, (
        "the committed ledger's family breakdown does not sum to the registry total: "
        f"{_per_module(committed_by_module)} vs {registry_total}"
    )
    assert _per_module(committed_by_module) == _per_module(fresh_by_module), (
        "the committed ledger's per-family counts drifted from the registry"
    )
    print(f"ledger: {registry_total} checks; per family {_per_module(committed_by_module)}")


def test_the_published_false_positive_rate_is_within_two_percent() -> None:
    """REQ-DET-028's precision clause, with the method and corpus version stated.

    The number is read from the committed measurement (its counts must be its own rate), and
    the *published* statement of it is read from the documentation that carries the method,
    the corpus version and the target. A rate without those three is not a measurement a
    reader can reproduce.
    """
    baseline = load_baseline(BENCHMARKS, LAB)
    assert baseline is not None, "the false-positive measurement is not committed"
    numbers = baseline.numbers
    assert numbers.candidates == numbers.true_positives + numbers.false_positives
    assert numbers.fp_rate <= FP_CEILING, (
        f"published false-positive rate {numbers.fp_rate:.1%} is over the {FP_CEILING:.0%} ceiling"
    )

    header = json.loads((BENCHMARKS / LAB / "baseline.json").read_text(encoding="utf-8"))
    assert header["suite"] == LAB
    assert header["suite_version"], "the corpus version is not stated"
    assert header["target"] and header["measured_at"]

    published = PERFORMANCE_DOC.read_text(encoding="utf-8")
    assert "false positives / (true positives + false positives)" in published, (
        "the published page does not state the method"
    )
    assert f"`{LAB}` version {header['suite_version']}" in published, (
        "the published page does not state the corpus version"
    )
    assert "≤ 2 %" in published, "the published page does not state the target"
    print(
        f"false-positive rate: {numbers.false_positives}/{numbers.candidates} "
        f"= {numbers.fp_rate:.1%} on {LAB} {header['suite_version']}"
    )
