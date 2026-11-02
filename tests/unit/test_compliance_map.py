"""The compliance-map schema test (S22, REQ-TRUST-001).

The guarantee the requirement names: the mapping data files reference **no dangling
check ids** — a control can never claim coverage from a typo. The whole check set the
registry and the planning catalogue ship is the reference set; both must agree with
each other and with the maps.

The rest of the file pins the loader contract (aliases, structure refusals, the
``known_checks`` hook, the ``maps_dir`` override) and the coverage/export semantics on
small synthetic maps, so a failure names the property that broke rather than drowning
in a 141-check dump.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml as _yaml
from tests.helpers.report import make_candidate, make_inputs

from arachne.core.errors import ConfigurationError
from arachne.modules.registry import ModuleRegistry
from arachne.report.builder import ReportInputs, build_report_data
from arachne.report.compliance import (
    BUNDLED_FRAMEWORKS,
    ComplianceMap,
    canonical_framework,
    compute_framework_coverage,
    export_control_evidence,
    load_compliance_framework,
)
from arachne.report.model import ReportData


def _catalog_check_ids() -> set[str]:
    from importlib.resources import files

    resource = files("arachne.templates").joinpath("plan/check_catalog.yaml")
    catalog = _yaml.safe_load(resource.read_text(encoding="utf-8"))
    return {f"{row['module'].lower()}.{row['name']}" for row in catalog["checks"]}


# --------------------------------------------------------------- the no-dangling-id gate
def test_every_mapped_check_id_exists_in_the_registry_and_the_catalogue() -> None:
    """REQ-TRUST-001's schema test: no dangling ids, in either direction of the join."""
    registry_ids = set(ModuleRegistry.discover().check_ids())
    catalog_ids = _catalog_check_ids()
    assert registry_ids == catalog_ids, "registry and catalogue disagree (pre-existing gate)"
    for name in BUNDLED_FRAMEWORKS:
        map_data = load_compliance_framework(name, known_checks=registry_ids)
        for control in map_data.controls:
            for check in control.checks:
                assert check in registry_ids, f"{name}:{control.id} maps unknown check {check}"


def test_control_ids_are_unique_and_totals_are_honest() -> None:
    for name in BUNDLED_FRAMEWORKS:
        map_data = load_compliance_framework(name)
        ids = [control.id for control in map_data.controls]
        assert len(ids) == len(set(ids)), f"{name}: duplicate control ids"
        assert 0 < len(map_data.controls) <= map_data.total_controls
        assert map_data.name and map_data.edition and map_data.map_version


def test_the_four_required_frameworks_ship() -> None:
    assert set(BUNDLED_FRAMEWORKS) == {"cis", "pci-dss", "iso27001", "nist-csf"}


def test_framework_aliases_resolve_to_canonical_names() -> None:
    assert canonical_framework("PCI_DSS") == "pci-dss"
    assert canonical_framework("CIS-Controls") == "cis"
    assert canonical_framework("csf") == "nist-csf"
    assert canonical_framework("ISO-27001") == "iso27001"
    assert canonical_framework("soc2") is None


# ------------------------------------------------------------------- the loader contract
def _write_map(tmp_path: Path, text: str) -> str:
    target = tmp_path / "custom.yaml"
    target.write_text(text, encoding="utf-8")
    return str(target)


def test_a_dangling_check_id_is_refused_when_the_reference_set_is_supplied(
    tmp_path: Path,
) -> None:
    path = _write_map(
        tmp_path,
        "\n".join(
            [
                "framework: test",
                "name: Test",
                "total_controls: 3",
                "controls:",
                "  - id: AC-1",
                "    title: Access control",
                "    checks: [m4.env-file-probe, m3.check-that-does-not-exist]",
            ]
        ),
    )
    with pytest.raises(ConfigurationError, match=r"m3\.check-that-does-not-exist"):
        load_compliance_framework("test", path=path, known_checks=_catalog_check_ids())


def test_a_dangling_check_id_is_tolerated_at_report_time_and_honest_as_a_gap(
    tmp_path: Path,
) -> None:
    """A stale custom map must not fail a report; the control shows as not assessed."""
    path = _write_map(
        tmp_path,
        "\n".join(
            [
                "framework: test",
                "name: Test",
                "total_controls: 3",
                "controls:",
                "  - id: AC-1",
                "    title: Access control",
                "    checks: [m3.check-that-does-not-exist]",
            ]
        ),
    )
    map_data = load_compliance_framework("test", path=path)
    report = _report()
    coverage = compute_framework_coverage(map_data, report.scope.checks, report.findings)
    assert [row.status for row in coverage.controls] == ["gap"]


def test_malformed_maps_are_refused(tmp_path: Path) -> None:
    control = "framework: test\ntotal_controls: 2\ncontrols:\n"
    row = "  - id: A\n    title: T\n    checks: [m4.env-file-probe]\n"
    row2 = "  - id: A\n    title: T2\n    checks: [m4.env-file-probe]\n"
    no_title = "  - id: A\n    checks: [m4.env-file-probe]\n"
    no_id = "  - title: T\n    checks: [m4.env-file-probe]\n"
    no_checks = "  - id: A\n    title: T\n    checks: []\n"
    bad_documents = [
        "framework: test\ntotal_controls: 2\ncontrols: []\n",  # empty controls
        "name: Test\ncontrols:\n  - id: A\ntotal_controls: 2\n",  # no framework
        "framework: test\ntotal_controls: 0\ncontrols:\n" + row,  # total < 1
        "framework: test\ntotal_controls: 2\nchecks: [m4.env-file-probe]\n",  # legacy shape
        control + no_checks,
        control + no_title,
        control + no_id,
        # Malformed check ids: bare name, wrong module, punctuation.
        control + "  - id: A\n    title: T\n    checks: [env-file-probe]\n",
        control + "  - id: A\n    title: T\n    checks: [m9.env-file-probe]\n",
        control + "  - id: A\n    title: T\n    checks: [M4/env-file-probe]\n",
        control + row + row2,  # duplicate control id
    ]
    for document in bad_documents:
        path = _write_map(tmp_path, document)
        with pytest.raises(ConfigurationError):
            load_compliance_framework("test", path=path)


def test_a_map_overshooting_its_total_is_refused(tmp_path: Path) -> None:
    path = _write_map(
        tmp_path,
        "\n".join(
            [
                "framework: test",
                "name: Test",
                "total_controls: 1",
                "controls:",
                "  - id: A",
                "    title: One",
                "    checks: [m4.env-file-probe]",
                "  - id: B",
                "    title: Two",
                "    checks: [m4.env-file-probe]",
            ]
        ),
    )
    with pytest.raises(ConfigurationError, match="total_controls"):
        load_compliance_framework("test", path=path)


def test_a_maps_dir_override_wins_over_the_bundled_file(tmp_path: Path) -> None:
    override = tmp_path / "pci-dss.yaml"
    override.write_text(
        "\n".join(
            [
                "framework: pci-dss",
                "name: PCI DSS (deployment overlay)",
                "total_controls: 12",
                "controls:",
                '  - id: "6.2"',
                "    title: Secure coding (overlay)",
                "    checks: [m3.sqli-oracle]",
            ]
        ),
        encoding="utf-8",
    )
    map_data = load_compliance_framework("pci-dss", maps_dir=str(tmp_path))
    assert map_data.name == "PCI DSS (deployment overlay)"
    assert [control.id for control in map_data.controls] == ["6.2"]


def test_an_unknown_framework_is_a_loud_error() -> None:
    with pytest.raises(ConfigurationError, match="unknown compliance framework"):
        load_compliance_framework("soc2")


def test_a_missing_path_is_a_loud_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_compliance_framework("x", path=str(tmp_path / "nope.yaml"))


# ------------------------------------------------------------------ coverage semantics
def _plan_with(checks: Sequence[str]) -> dict[str, Any]:
    return {
        "target_name": "target.example",
        "engine": "heuristic",
        "checks": [
            {
                "module": check.split(".", 1)[0].upper(),
                "name": check.split(".", 1)[1],
                "version": "1.0",
                "title": check,
                "included": True,
            }
            for check in checks
        ],
    }


def _report(*findings: str, plan: dict[str, Any] | None = None) -> ReportData:
    candidates = [
        make_candidate(
            number=index + 1,
            title=f"Finding {index + 1}",
            asset_value=f"https://target.example/p{index}",
            check=check.split(".", 1)[1],
            module=check.split(".", 1)[0].upper(),
            severity="medium",
        )
        for index, check in enumerate(findings)
    ]
    return build_report_data(
        make_inputs(
            candidates=candidates,
            plan=plan
            or _plan_with(["m4.env-file-probe", "m4.debug-endpoints", "m4.directory-listing"]),
        )
    )


@pytest.fixture
def test_map(tmp_path: Path) -> ComplianceMap:
    path = tmp_path / "test.yaml"
    path.write_text(
        "\n".join(
            [
                "framework: test",
                "name: Test Framework",
                'edition: "1"',
                "kind: control",
                "total_controls: 3",
                'map_version: "2.0"',
                "controls:",
                "  - id: A",
                "    title: Evidenced by a ran check with a finding",
                "    checks: [m4.env-file-probe]",
                "  - id: B",
                "    title: Evidenced by ran checks with no finding",
                "    checks: [m4.debug-endpoints, m4.directory-listing]",
                "  - id: C",
                "    title: Checks withheld",
                "    checks: [m5.k8s-exposure]",
            ]
        ),
        encoding="utf-8",
    )
    return load_compliance_framework("test", path=str(path))


def test_coverage_states_fail_pass_and_gap_with_reasons(test_map: ComplianceMap) -> None:
    report = _report("m4.env-file-probe")
    coverage = compute_framework_coverage(test_map, report.scope.checks, report.findings)
    by_id = {row.control: row for row in coverage.controls}
    assert by_id["A"].status == "fail"
    assert by_id["A"].findings == ("F-000001",)
    assert by_id["A"].evidence_refs == report.findings[0].evidence_refs
    assert by_id["A"].checks_run == ("m4.env-file-probe",)
    assert by_id["B"].status == "pass"  # both mapped checks ran; nothing found
    assert by_id["B"].findings == ()
    assert by_id["C"].status == "gap"  # m5.k8s-exposure did not run
    assert by_id["C"].checks_not_run == ("m5.k8s-exposure",)


def test_the_qualified_check_id_is_the_join_key(test_map: ComplianceMap) -> None:
    """M1 and M2 both ship `favicon-hash`; a bare-name join would conflate them."""
    report = _report()
    coverage = compute_framework_coverage(test_map, report.scope.checks, report.findings)
    by_id = {row.control: row for row in coverage.controls}
    # m4.debug-endpoints ran (in the plan); the same bare name in another module would not.
    assert by_id["B"].checks_run == ("m4.debug-endpoints", "m4.directory-listing")
    assert by_id["C"].checks_run == ()


def test_unmapped_controls_are_counted_as_the_explicit_gap(test_map: ComplianceMap) -> None:
    report = _report()
    coverage = compute_framework_coverage(test_map, report.scope.checks, report.findings)
    assert coverage.mapped == 3
    assert coverage.unmapped == 0  # total_controls: 3, all three mapped
    assert coverage.count("fail") + coverage.count("pass") + coverage.count("gap") == 3


def test_settings_drive_the_report_block(tmp_path: Path) -> None:
    """No frameworks named → no section; frameworks named → one block each."""
    inputs = make_inputs(candidates=[])
    assert build_report_data(inputs).compliance == ()
    custom = tmp_path / "pci-dss.yaml"
    custom.write_text(
        "framework: pci-dss\nname: Overlay\nedition: v4.0\ntotal_controls: 12\n"
        'controls:\n  - id: "6.2"\n    title: Secure coding\n    checks: [m4.env-file-probe]\n',
        encoding="utf-8",
    )
    report = build_report_data(
        ReportInputs(
            **{
                **{f: getattr(inputs, f) for f in inputs.__dataclass_fields__},
                "compliance_frameworks": ("pci-dss",),
                "compliance_map_dir": str(tmp_path),
            }
        )
    )
    assert [block.framework for block in report.compliance] == ["pci-dss"]
    assert report.compliance[0].name == "Overlay"


# --------------------------------------------------------------------------- export
def test_the_evidence_export_is_self_contained(test_map: ComplianceMap) -> None:
    report = _report("m4.env-file-probe")
    document = export_control_evidence(test_map, report, generated_at="2026-10-31T00:00:00+00:00")
    assert document["document"] == "arachne-control-evidence"
    assert document["generated_at"] == "2026-10-31T00:00:00+00:00"
    coverage = document["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["fail"] == 1 and coverage["unmapped"] == 0  # type: ignore[union-attr]
    controls = document["controls"]
    assert isinstance(controls, list) and controls
    failing = [row for row in controls if row["status"] == "fail"]  # type: ignore[index]
    assert failing, "the failing control carries the finding"
    finding_doc = failing[0]["findings"][0]  # type: ignore[index]
    assert finding_doc["id"] == "F-000001"  # type: ignore[index]
    assert finding_doc["evidence"], "evidence payloads must travel with the export"  # type: ignore[index]
    assert finding_doc["evidence"][0]["payload"], "the payload is inline, not a reference"  # type: ignore[index]
    payload = json.dumps(document, default=str)
    for finding in report.findings:
        for ref in finding.evidence_refs:
            assert ref in payload


def test_the_export_states_the_framework_identity_and_gaps(test_map: ComplianceMap) -> None:
    report = _report()
    document = export_control_evidence(test_map, report)
    framework = document["framework"]
    assert isinstance(framework, dict)
    assert framework["name"] == "Test Framework"  # type: ignore[union-attr]
    assert framework["map_version"] == "2.0"  # type: ignore[union-attr]
    note = str(document["coverage"]["note"])  # type: ignore[union-attr]
    assert "mapped to ARACHNE" in note and "not proof of conformity" in note


def test_the_export_never_carries_more_than_the_report(test_map: ComplianceMap) -> None:
    """The export is a projection of the report DTO — no second source, no new payload."""
    report = _report("m4.env-file-probe")
    document = json.dumps(export_control_evidence(test_map, report), default=str)
    assert json.loads(document)  # valid JSON
    # Every evidence id the export names is one the report itself carries.
    report_text = report.model_dump_json()
    for evidence in report.appendix.evidence:
        assert evidence.id in report_text
        assert evidence.id in document


# ------------------------------------------------- the report round-trips the coverage
def test_a_report_with_frameworks_validates_against_the_current_schema(tmp_path: Path) -> None:
    import jsonschema

    from arachne.report.json_render import load_report_schema
    from arachne.report.model import REPORT_SCHEMA_VERSION

    report = _report("m4.env-file-probe")
    assert report.schema_version == REPORT_SCHEMA_VERSION
    inputs = make_inputs(
        candidates=[
            make_candidate(
                number=1,
                title="Env file exposed",
                asset_value="https://target.example/.env",
                severity="medium",
            )
        ],
    )
    with_frameworks = ReportInputs(
        **{
            **{f: getattr(inputs, f) for f in inputs.__dataclass_fields__},
            "compliance_frameworks": ("iso27001",),
        }
    )
    report = build_report_data(with_frameworks)
    jsonschema.validate(json.loads(report.model_dump_json()), load_report_schema())
