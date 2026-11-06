"""The planning catalogue (F-01-10, F-02-09/10)."""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.catalog import (
    DEFAULT_CATALOG_RESOURCE,
    default_catalog_text,
    load_catalog,
    load_catalog_from_text,
    parse_catalog,
)
from arachne.core.errors import ConfigurationError
from arachne.core.target import ModuleSelection, TargetKind

VALID = """
catalog_version: "1.0"
checks:
  - module: M1
    name: dork-sweep
    version: "1.0"
    title: Dork sweep
    description: Search engines are queried.
    research_ref: ch01#1
    target_kinds: [domain]
    estimated_requests: 2
  - module: M3
    name: sqli
    version: "1.0"
    title: SQL injection
    description: Injection oracles.
    research_ref: ch03#2
    cwe: CWE-89
    target_kinds: [url]
    estimated_requests: 6
    requires_active_checks: true
"""


def test_bundled_catalogue_covers_every_module_and_is_versioned() -> None:
    catalog = load_catalog()
    # 1.1 (S3) added the M1 rows the registry implements; 1.2 (S4) added M2's; ...
    # 1.3 (S11) replaced the planned M6 rows with the implemented set.
    # 1.5 (S15) added the proof-ladder declaration to every row (REQ-PROOF-002);
    # 1.6 (S15) added the six proof-ladder check rows; 1.7 (S18) the three opt-in intel
    # rows; 1.8 (S19) the credentialed M3 rows and the M2 host check; 1.9 (S23) the M5
    # continuous cloud-config posture row; 1.11 (WP-08) the four CWE Top 25 emitters and
    # five injection families (REQ-DET-004/009); 1.12 (WP-11) the DOM-sink browser row
    # (REQ-DET-015); 1.13 (WP-25) the WordPress ecosystem family (REQ-DET-018); 1.14 (WP-26)
    # the CMS family B (REQ-DET-019).
    # tests/unit/test_registry.py keeps the catalogue and the registry in step.
    assert catalog.catalog_version == "1.14"
    assert catalog.modules() == ("M1", "M2", "M3", "M4", "M5", "M6")
    assert len(catalog.checks) >= 30
    # "Version everything" : every check carries a version and a
    # traceability link into the research corpus.
    assert all(check.version and check.research_ref for check in catalog.checks)
    # Every row declares its proof level (S15). The original checks are L1 — 129 of them,
    # plus S18's three opt-in intel checks, S19's two credentialed M3 checks, S23's
    # continuous cloud-posture check and S29's eight L1 depth rows = 144; WP-07's three
    # read-only MCP checks bring it to 147; WP-08's nine L1 breadth rows bring it to 156;
    # WP-09's three L1 transport rows (mTLS, SMTP transport, HTTP/3) bring it to 159;
    # WP-10's five L1 identity/AI-surface rows (AD CS + four ASI) bring it to 164; WP-11's
    # one L1 browser row (m3.dom-xss) brings it to 165; WP-12's two L1 image/cloud rows
    # (m5.image-scan, m5.do-posture) bring it to 167; WP-20's one L1 SSH credential row
    # (m2.ssh-auth) brings it to 168; WP-25's twenty-six L1 WordPress rows bring it to 194;
    # WP-26's thirty L1 CMS family B rows bring it to 224.
    # The seven L2+ rows are opt-in, and only rce-echo/state-marker demand the
    # state-change attestation.
    # (S29's tenth depth row, m1.mobile-artifact, declares L0 — it is the one check that
    # contacts nothing at all — so it is in neither list and is pinned here explicitly.)
    originals = [check for check in catalog.checks if check.proof.value == "L1"]
    ladder = [check for check in catalog.checks if check.proof.value in {"L2", "L3", "L4"}]
    assert len(originals) == 224
    assert {check.name for check in catalog.checks if check.proof.value == "L0"} == {
        "mobile-artifact"
    }
    assert {check.proof.value for check in ladder} == {"L2", "L3", "L4"}
    assert all(check.requires_active_checks for check in ladder)
    assert {check.name for check in ladder if check.requires_state_attestation} == {
        "rce-echo",
        "state-marker",
    }
    # Both passive and active checks exist, so the plan has something to withhold.
    assert any(check.requires_active_checks for check in catalog.checks)
    assert any(not check.requires_active_checks for check in catalog.checks)


def test_bundled_catalogue_resource_path_is_stable() -> None:
    assert DEFAULT_CATALOG_RESOURCE == ("plan", "check_catalog.yaml")
    assert "catalog_version" in default_catalog_text()


def test_parse_catalog_validates_shape() -> None:
    catalog = parse_catalog(
        {
            "catalog_version": "1.0",
            "checks": [
                {
                    "module": "M2",
                    "name": "port-scan",
                    "version": "1.0",
                    "title": "Port scan",
                    "description": "TCP ports.",
                    "research_ref": "ch02#2",
                    "target_kinds": ["cidr"],
                    "estimated_requests": 1,
                }
            ],
        }
    )
    assert catalog.for_module("M2")[0].name == "port-scan"
    assert catalog.checks[0].supports(frozenset({TargetKind.CIDR}))
    assert not catalog.checks[0].supports(frozenset({TargetKind.URL}))


def test_check_key_is_stable_and_readable() -> None:
    from arachne.core.catalog import CheckSpec

    spec = CheckSpec(
        module="M4",
        name="env-file-probe",
        version="1.2",
        title="t",
        description="d",
        research_ref="ch04#1",
        target_kinds=(TargetKind.URL,),
        estimated_requests=3,
    )
    assert spec.key == "M4/env-file-probe@1.2"


def test_duplicate_checks_are_rejected() -> None:
    document = {
        "catalog_version": "1.0",
        "checks": [
            {
                "module": "M1",
                "name": "same",
                "version": "1.0",
                "title": "a",
                "description": "a",
                "research_ref": "ch01#1",
                "target_kinds": ["domain"],
                "estimated_requests": 1,
            },
            {
                "module": "M1",
                "name": "same",
                "version": "1.0",
                "title": "b",
                "description": "b",
                "research_ref": "ch01#2",
                "target_kinds": ["domain"],
                "estimated_requests": 1,
            },
        ],
    }
    with pytest.raises(ConfigurationError, match="duplicate check"):
        parse_catalog(document)


def _check_yaml(**overrides: object) -> str:
    fields: dict[str, object] = {
        "module": "M1",
        "name": "x",
        "version": "'1'",
        "title": "t",
        "description": "d",
        "research_ref": "c",
        "target_kinds": "[url]",
        "estimated_requests": 1,
    }
    fields.update(overrides)
    body = "".join(f"    {key}: {value}\n" for key, value in fields.items())
    return f"catalog_version: '1.0'\nchecks:\n  - {body.lstrip()}"


@pytest.mark.parametrize(
    "broken",
    [
        "catalog_version: '1.0'\nchecks: []\n",
        _check_yaml(module="M7"),
        _check_yaml(target_kinds="[not-a-kind]"),
        _check_yaml(estimated_requests=-1),
        _check_yaml(surprise=1),
        _check_yaml(version=""),
    ],
)
def test_malformed_catalogues_are_rejected(broken: str) -> None:
    with pytest.raises(ConfigurationError):
        load_catalog_from_text(broken)


def test_missing_catalogue_file_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_catalog(tmp_path / "absent.yaml")


def test_catalogue_can_be_loaded_from_an_explicit_path(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(VALID, encoding="utf-8")
    catalog = load_catalog(path)
    assert [check.name for check in catalog.checks] == ["dork-sweep", "sqli"]


def test_selection_filters_by_module() -> None:
    catalog = load_catalog_from_text(VALID)
    assert len(catalog.select(ModuleSelection())) == 2
    assert [check.module for check in catalog.select(ModuleSelection(enabled=("M1",)))] == ["M1"]
    assert [check.module for check in catalog.select(ModuleSelection(disabled=("M3",)))] == ["M1"]


def test_catalog_text_that_is_not_a_mapping_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="mapping"):
        load_catalog_from_text("- just\n- a\n- list\n")


def test_catalog_text_that_is_empty_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="empty"):
        load_catalog_from_text("# nothing here\n")
