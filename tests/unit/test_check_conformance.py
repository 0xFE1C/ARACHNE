"""The conformance kit rejects the four defect classes REQ-ECOS-007 names (G5 clause 7).

Each test builds a *candidate* — a real scaffolded check tree, then one mutation — and asserts
the kit refuses it with the right defect **class** and a message that says what to change. The
point of testing the class rather than the code string is that the requirement is about a defect
class, and a kit that reported "something is wrong" without saying which rule was broken would be
technically safe and operationally useless.

The four classes, plus the three further ones a loaded check makes free to check:

============  ==========================================================
``mapping``   no framework mapping, an id outside the pinned snapshot, drift
``proof``     L2+ without its opt-in, L3/L4 without the state attestation
``decoy``     no assigned decoy, or a decoy the check fires on
``evidence``  no finding, or a finding with nothing a human can confirm
``capability``a process, raw socket, dynamic code, FFI or unpickling
``fixture``   a fixture that does not record what the check requests
``determinism``two runs that disagree
============  ==========================================================
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.ecos.conformance import (
    DEFECT_CLASSES,
    REQUIRED_CLASSES,
    ConformanceReport,
    conform,
    conform_json,
    verification_relevant,
)
from arachne.ecos.sdk import scaffold_check
from arachne.modules.registry import ModuleRegistry

runner = CliRunner()

CHECK_ID = "m4.conformability-probe"
MODULE_FILE = "src/arachne_check_conformability_probe/__init__.py"
MAPPING_FILE = "mappings/conformability-probe.yaml"
POSITIVE = "fixtures/conformability-probe/positive.json"
DECOY = "fixtures/conformability-probe/decoy.json"


def _edit(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{relative} does not contain {old!r}; the scaffold changed shape"
    path.write_text(text.replace(old, new), encoding="utf-8")


def _drop(root: Path, relative: str, needle: str) -> None:
    path = root / relative
    kept = [line for line in path.read_text(encoding="utf-8").splitlines() if needle not in line]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    """A scaffolded candidate tree: valid until a test mutates it."""
    return scaffold_check(CHECK_ID, root=tmp_path / "candidate").root


def _report(root: Path) -> ConformanceReport:
    return conform(root / "conformance.yaml")


# ------------------------------------------------------------------ the happy path
def test_a_freshly_scaffolded_check_is_conformant(candidate: Path) -> None:
    report = _report(candidate)
    assert report.conformant, [(item.code, item.message) for item in report.blockers]
    assert [gate.gate for gate in report.gates] == ["capability", "metadata", "behaviour"]
    assert report.defect_classes == ()


def test_the_report_is_deterministic_json(candidate: Path) -> None:
    first = conform_json(_report(candidate))
    second = conform_json(_report(candidate))
    assert first == second


def test_every_refusal_reason_is_actionable(candidate: Path) -> None:
    """A rejection that does not say what to change is not a rejection an author can act on."""
    _drop(candidate, "conformance.yaml", "decoy:")
    _edit(candidate, MAPPING_FILE, "  - CWE-693", "  - CWE-200")
    report = _report(candidate)
    assert not report.conformant
    assert report.blockers, "the mutation must be refused"
    assert report.actionable, [item.message for item in report.blockers]
    for item in report.blockers:
        assert item.message.rstrip().endswith((".", "!")), item.message
        assert len(item.message.split()) >= 5, item.message


# ------------------------------------------------------------------ class: mapping
def test_no_framework_mapping_is_refused(candidate: Path) -> None:
    """An unmapped check is invisible to every buyer, auditor and coverage report."""
    _edit(
        candidate,
        MODULE_FILE,
        'check_framework = ("WSTG-CONF-07", "CWE-693")',
        "check_framework = ()",
    )
    _edit(candidate, MAPPING_FILE, "  - WSTG-CONF-07\n  - CWE-693", "[]")
    report = _report(candidate)
    assert not report.conformant
    assert "mapping" in report.defect_classes
    assert "no framework mapping" in " ".join(item.message for item in report.blockers)


def test_a_mapping_id_outside_the_pinned_snapshot_is_refused(candidate: Path) -> None:
    """The mapping entry may only claim a test that exists in the pinned snapshot."""
    _edit(candidate, MAPPING_FILE, "  - WSTG-CONF-07", "  - WSTG-CONF-99")
    report = _report(candidate)
    assert not report.conformant
    assert "mapping" in report.defect_classes
    assert "WSTG-CONF-99" in " ".join(item.message for item in report.blockers)


def test_a_manifest_without_a_mapping_entry_is_refused(candidate: Path) -> None:
    _drop(candidate, "conformance.yaml", "mapping:")
    report = _report(candidate)
    assert not report.conformant
    assert "mapping" in report.defect_classes
    assert "declares no mapping entry" in " ".join(item.message for item in report.blockers)


def test_a_mapping_entry_that_drifted_from_the_metadata_is_refused(candidate: Path) -> None:
    """The entry is the check's declaration of what it covers; the two may not disagree."""
    _edit(candidate, MAPPING_FILE, "  - CWE-693", "  - CWE-200")
    report = _report(candidate)
    assert not report.conformant
    assert "mapping" in report.defect_classes
    assert "regenerate it from the metadata" in " ".join(item.message for item in report.blockers)


# ------------------------------------------------------------------ class: proof
def test_l2_without_the_opt_in_is_refused(candidate: Path) -> None:
    """The writable place for this defect is the declaration, and the kit reads it back."""
    _edit(candidate, MAPPING_FILE, "proof: L1", "proof: L2")
    report = _report(candidate)
    assert not report.conformant
    assert "proof" in report.defect_classes
    message = " ".join(item.message for item in report.blockers)
    assert "opt-in" in message
    assert "enabled_by_default=True" in message


def test_l3_without_the_state_attestation_is_refused(candidate: Path) -> None:
    _edit(candidate, MAPPING_FILE, "proof: L1", "proof: L3")
    _edit(candidate, MAPPING_FILE, "enabled_by_default: true", "enabled_by_default: false")
    report = _report(candidate)
    assert not report.conformant
    assert "proof" in report.defect_classes
    assert "state-change attestation" in " ".join(item.message for item in report.blockers)


def test_metadata_that_bypasses_the_constructor_is_refused(candidate: Path) -> None:
    """A metadata object mutated after construction cannot smuggle an L2 in.

    The mutation is applied before the group is built, so this also proves the *registry's* own
    belt-and-braces re-check refuses it at import — the kit reports the refusal rather than
    letting a contradictory declaration reach a plan.
    """
    _edit(
        candidate,
        MODULE_FILE,
        "from arachne.core.results import CheckResult",
        "from arachne.core.proof import ProofLevel\nfrom arachne.core.results import CheckResult",
    )
    _edit(
        candidate,
        MODULE_FILE,
        "PLUGIN_GROUP = ModuleGroup(",
        "object.__setattr__(ConformabilityProbeCheck.metadata, 'proof', ProofLevel.L2)\n\n"
        "PLUGIN_GROUP = ModuleGroup(",
    )
    report = _report(candidate)
    assert not report.conformant
    assert "loadable" in report.defect_classes
    assert "proof declaration" in " ".join(item.message for item in report.blockers)


def test_the_proof_rule_is_pinned_on_the_metadata_object_itself() -> None:
    """The rule, asked directly of a metadata object that never went through the constructor."""
    from arachne.core.proof import ProofLevel
    from arachne.ecos.conformance import metadata_proof_defects
    from arachne.ecos.sdk import author_metadata

    clean = author_metadata(
        CHECK_ID, title="t", description="d", framework=("CWE-693",), proof="L1"
    )
    assert metadata_proof_defects(clean) == ()
    smuggled = author_metadata(
        CHECK_ID, title="t", description="d", framework=("CWE-693",), proof="L1"
    )
    object.__setattr__(smuggled, "proof", ProofLevel.L2)
    defects = metadata_proof_defects(smuggled)
    assert defects, "an L2 proof on an enabled-by-default check must be refused"
    assert defects[0].defect_class == "proof"
    assert "opt-in by definition" in defects[0].message


# ------------------------------------------------------------------ class: decoy
def test_no_decoy_is_refused(candidate: Path) -> None:
    _drop(candidate, "conformance.yaml", "decoy:")
    report = _report(candidate)
    assert not report.conformant
    assert "decoy" in report.defect_classes
    assert "false-positive trap" in " ".join(item.message for item in report.blockers)


def test_a_decoy_the_check_fires_on_is_refused(candidate: Path) -> None:
    """A loose oracle: matching the bare word ``demo`` fires on the trap."""
    _edit(
        candidate,
        MODULE_FILE,
        'MARKERS: tuple[str, ...] = ("demo-marker-exposed",)',
        'MARKERS: tuple[str, ...] = ("demo",)',
    )
    report = _report(candidate)
    assert not report.conformant
    assert "decoy" in report.defect_classes
    assert "tighten the match" in " ".join(item.message for item in report.blockers)


def test_a_decoy_file_that_does_not_exist_is_refused(candidate: Path) -> None:
    (candidate / DECOY).unlink()
    report = _report(candidate)
    assert not report.conformant
    assert "decoy" in report.defect_classes
    assert "does not exist" in " ".join(item.message for item in report.blockers)


# ------------------------------------------------------------------ class: evidence
def test_a_finding_with_no_evidence_is_refused(candidate: Path) -> None:
    _edit(candidate, MODULE_FILE, "evidence=[evidence],", "evidence=[],")
    report = _report(candidate)
    assert not report.conformant
    assert "evidence" in report.defect_classes
    assert "verification-relevant evidence" in " ".join(item.message for item in report.blockers)


def test_evidence_that_is_only_a_status_code_is_refused(candidate: Path) -> None:
    """The rejection example in the detection programme's review table: "status code only"."""
    _edit(
        candidate,
        MODULE_FILE,
        'ctx.evidence("http_response", body, source=ctx.asset.key)',
        'ctx.evidence("http_response", {"status_code": exchange.status_code})',
    )
    report = _report(candidate)
    assert not report.conformant
    assert "evidence" in report.defect_classes
    assert "status code alone is not evidence" in " ".join(item.message for item in report.blockers)


def test_a_check_that_never_fires_is_refused(candidate: Path) -> None:
    """A check whose claim its own positive fixture does not support has no evidence to offer."""
    _edit(
        candidate,
        MODULE_FILE,
        "        exchange = await client.get",
        "        exchange = None  # type: ignore\n        await client.get",
    )
    _edit(candidate, MODULE_FILE, "        if exchange.status_code >= 400:", "        if True:")
    report = _report(candidate)
    assert not report.conformant
    assert "evidence" in report.defect_classes
    assert "produced no finding against its positive fixture" in " ".join(
        item.message for item in report.blockers
    )


def test_the_evidence_rule_is_pinned_directly() -> None:
    """The rule itself: kind plus substance, not a status code and not a note."""
    from arachne.core.results import Evidence

    assert verification_relevant(Evidence.of("http_response", {"body": "ok"})) is True
    assert verification_relevant(Evidence.of("banner", {"banner": "Apache/2.4"})) is True
    assert verification_relevant(Evidence.of("http_response", {"status_code": 200})) is False
    assert verification_relevant(Evidence.of("note", {"body": "something happened"})) is False
    assert verification_relevant(Evidence.of("http_response", {"headers": {}})) is False


# ------------------------------------------------------------------ the further three
def test_a_capability_defect_is_refused_without_importing_the_candidate(candidate: Path) -> None:
    """The scan runs on the source, so a candidate that starts a process is never executed."""
    _edit(
        candidate,
        MODULE_FILE,
        "from collections.abc import AsyncIterator",
        "import subprocess\nfrom collections.abc import AsyncIterator",
    )
    module_name = "_arachne_candidate_conformability-probe"
    sys.modules.pop(module_name, None)
    report = _report(candidate)
    assert not report.conformant
    assert "capability" in report.defect_classes
    assert "refused without being imported" in " ".join(item.message for item in report.blockers)
    assert module_name not in sys.modules, "a refused candidate was imported anyway"


def test_a_registry_collision_is_refused(tmp_path: Path) -> None:
    """A plugin adds checks; it never replaces one the platform already ships."""
    existing = ModuleRegistry.builtin().check_ids()[0]
    root = scaffold_check(existing, root=tmp_path / "collision").root
    report = _report(root)
    assert not report.conformant
    assert "collision" in report.defect_classes
    assert "never replaces one" in " ".join(item.message for item in report.blockers)


def test_a_fixture_gap_is_a_defect_not_a_verdict(candidate: Path) -> None:
    _edit(
        candidate,
        POSITIVE,
        f"https://demo.example.test/{CHECK_ID.split('.')[1]}",
        "https://demo.example.test/elsewhere",
    )
    report = _report(candidate)
    assert not report.conformant
    assert "fixture" in report.defect_classes
    assert "records no response for" in " ".join(item.message for item in report.blockers)
    assert "fabricated 501" in " ".join(item.message for item in report.blockers)


def test_a_non_deterministic_check_is_refused(candidate: Path) -> None:
    """Rule 3 of the behavioural contract: the same input must produce the same verdict."""
    _edit(
        candidate,
        MODULE_FILE,
        "from collections.abc import AsyncIterator",
        "import itertools\nfrom collections.abc import AsyncIterator",
    )
    _edit(
        candidate,
        MODULE_FILE,
        'PATH = "/conformability-probe"',
        'PATH = "/conformability-probe"\n_RUNS = itertools.count()',
    )
    _edit(
        candidate,
        MODULE_FILE,
        '"Conformability probe is exposed",',
        'f"Conformability probe is exposed ({next(_RUNS)})",',
    )
    report = _report(candidate)
    assert not report.conformant
    assert "determinism" in report.defect_classes


def test_a_candidate_that_raises_on_import_is_reported(candidate: Path) -> None:
    _edit(
        candidate, MODULE_FILE, "from __future__ import annotations", "raise RuntimeError('boom')"
    )
    report = _report(candidate)
    assert not report.conformant
    assert "loadable" in report.defect_classes
    assert "could not be imported" in " ".join(item.message for item in report.blockers)
    assert "RuntimeError" in " ".join(item.message for item in report.blockers)


# ------------------------------------------------------------------ the contract itself
def test_the_four_required_classes_are_the_ones_the_requirement_names() -> None:
    assert set(REQUIRED_CLASSES) == {"mapping", "proof", "decoy", "evidence"}
    for name in REQUIRED_CLASSES:
        assert name in set(DEFECT_CLASSES.values()), f"{name} has no defect code"


def test_the_cli_refuses_a_defective_candidate(tmp_path: Path) -> None:
    root = scaffold_check(CHECK_ID, root=tmp_path / "cli").root
    _drop(root, "conformance.yaml", "decoy:")
    refused = runner.invoke(app, ["plugin", "conform", str(root / "conformance.yaml")])
    assert refused.exit_code == 2, refused.output
    assert "REFUSED" in refused.output
    assert "conformance.decoy_missing" in refused.output


def test_the_cli_reports_json_for_a_defective_candidate(tmp_path: Path) -> None:
    root = scaffold_check(CHECK_ID, root=tmp_path / "cli-json").root
    _drop(root, "conformance.yaml", "decoy:")
    emitted = runner.invoke(app, ["plugin", "conform", str(root / "conformance.yaml"), "--json"])
    assert emitted.exit_code == 2
    output = emitted.output
    import json

    payload = json.loads(output[output.index("{") : output.rindex("}") + 1])
    assert payload["conformant"] is False
    assert "decoy" in payload["defect_classes"]


@pytest.mark.parametrize("mutate", [lambda root: _drop(root, "conformance.yaml", "decoy:")])
def test_the_report_names_the_gate_that_failed(
    candidate: Path, mutate: Callable[[Path], None]
) -> None:
    mutate(candidate)
    report = _report(candidate)
    failed = [gate.gate for gate in report.gates if not gate.passed]
    assert failed, "a refusal must name the gate it came from"
    assert report.gate(failed[0]) is not None
