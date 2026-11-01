"""The remediation catalog (F-06-04).

Lookup order is the contract: the rule's reference wins, then the check, then the CWE, then
the catalog default, then the built-in fallback. A finding must never come out of the
analyzer without an action.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from arachne.analyzer.model import Candidate
from arachne.analyzer.remediation import (
    RemediationCatalog,
    default_remediation,
    load_remediation_catalog,
    parse_remediation_catalog,
    ref_to_entry_id,
)
from arachne.core.errors import ConfigurationError


def candidate(**overrides: object) -> Candidate:
    base = {
        "scan_id": 1,
        "title": "t",
        "check_id": "m4.env-file-probe",
        "check_module": "M4",
        "check_name": "env-file-probe",
        "cwe": "CWE-200",
        "asset_kind": "url",
        "asset_value": "https://example.com/.env",
    }
    base.update(overrides)
    return Candidate(**base)  # type: ignore[arg-type]


def catalog() -> RemediationCatalog:
    return parse_remediation_catalog(
        {
            "version": "test",
            "entries": [
                {
                    "id": "by-check",
                    "checks": ["m4.env-file-probe"],
                    "summary": "entry that names the check",
                    "steps": ["1. step"],
                    "references": ["https://example.com/check"],
                },
                {
                    "id": "by-cwe",
                    "cwe": "CWE-200",
                    "summary": "entry that names the CWE only",
                },
                {
                    "id": "by-product",
                    "cwe": "CWE-200",
                    "product": "redis",
                    "summary": "entry for one product",
                },
                {
                    "id": "env-file-exposure",
                    "summary": "the rule's own entry",
                },
            ],
            "default": {
                "id": "default-generic",
                "summary": "the generic entry",
            },
        }
    )


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("remediation-catalog/env-file-exposure.yaml", "env-file-exposure"),
        ("remediation-catalog/env-file-exposure.yml", "env-file-exposure"),
        ("env-file-exposure.yaml", "env-file-exposure"),
        ("env-file-exposure", "env-file-exposure"),
        ("/abs/path/remediation-catalog/thing.yaml", "thing"),
    ],
)
def test_reference_normalization(reference: str, expected: str) -> None:
    assert ref_to_entry_id(reference) == expected


def test_a_rule_reference_wins_over_the_check_and_cwe_entries() -> None:
    resolved = catalog().resolve(
        candidate(), reference="remediation-catalog/env-file-exposure.yaml"
    )
    assert resolved.id == "env-file-exposure"
    assert resolved.summary == "the rule's own entry"
    assert resolved.source == "catalog"


def test_the_check_entry_wins_over_the_cwe_entry() -> None:
    resolved = catalog().resolve(candidate())
    assert resolved.id == "by-check"
    assert resolved.steps == ("1. step",)
    assert resolved.references == ("https://example.com/check",)


def test_the_cwe_entry_is_used_when_no_check_matches() -> None:
    resolved = catalog().resolve(candidate(check_id="m4.something-else"))
    assert resolved.id == "by-cwe"


def test_a_product_match_beats_the_generic_cwe_entry() -> None:
    resolved = catalog().resolve(candidate(check_id="m2.other"), product="Redis 5.0.7")
    assert resolved.id == "by-product"


def test_the_default_and_builtin_fallbacks() -> None:
    unresolved = catalog().resolve(candidate(check_id="m9.none", cwe="CWE-999"))
    assert unresolved.id == "default-generic"
    empty = parse_remediation_catalog(
        {"version": "1", "entries": [{"id": "only", "summary": "one entry only"}]}
    )
    fallback = empty.resolve(candidate(check_id="m9.none", cwe="CWE-999"))
    assert fallback.source == "builtin-default"
    assert fallback.id == "default-cwe-999"


def test_an_unresolved_rule_reference_keeps_its_id_but_borrows_guidance() -> None:
    resolved = catalog().resolve(
        candidate(), reference="remediation-catalog/not-in-the-catalog.yaml"
    )
    assert resolved.id == "not-in-the-catalog"
    assert resolved.source == "rule-ref+catalog"
    assert resolved.summary == "entry that names the check"


def test_default_remediation_names_what_identified_the_finding() -> None:
    remediation = default_remediation(cwe="CWE-89")
    assert remediation.id == "default-cwe-89"
    assert remediation.steps
    assert default_remediation(check_id="m1.x").id == "default-m1-x"


def test_a_directory_of_per_entry_files_is_supported(tmp_path: Path) -> None:
    (tmp_path / "one.yaml").write_text(
        yaml.safe_dump({"summary": "from a file", "cwe": "CWE-200"}), encoding="utf-8"
    )
    (tmp_path / "two.yaml").write_text(
        yaml.safe_dump({"id": "explicit", "summary": "explicit id"}), encoding="utf-8"
    )
    loaded = load_remediation_catalog(str(tmp_path))
    assert loaded.by_id("one") is not None
    assert loaded.by_id("explicit") is not None
    assert loaded.resolve(candidate(check_id="m4.none")).summary == "from a file"


def test_invalid_catalogs_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="duplicate remediation entry id"):
        parse_remediation_catalog(
            {
                "version": "1",
                "entries": [
                    {"id": "same", "summary": "first entry"},
                    {"id": "same", "summary": "second entry"},
                ],
            }
        )
    with pytest.raises(ConfigurationError, match="not CWE-NNN"):
        parse_remediation_catalog(
            {
                "version": "1",
                "entries": [{"id": "bad-cwe", "summary": "a long enough summary", "cwe": "nope"}],
            }
        )
    missing = tmp_path / "missing.yaml"
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_remediation_catalog(str(missing))


def test_the_shipped_catalog_covers_every_class_the_checks_can_report() -> None:
    shipped = load_remediation_catalog()
    assert shipped.version
    assert len(shipped.entries) >= 25
    assert shipped.default is not None
    # The classes S3/S4 can already report must resolve to something specific.
    for check_id in (
        "m1.js-asset-scan",
        "m1.internetdb-triage",
        "m2.db-service-probe",
        "m2.smb-enum",
        "m2.tls-deep-scan",
        "m2.cve-correlate",
        "m4.env-file-probe",
        "m4.git-probe",
    ):
        entry = shipped.by_check(check_id) or shipped.by_cwe(_cwe_of(check_id), product=None)
        assert entry is not None, check_id


def _cwe_of(check_id: str) -> str:
    return {
        "m1.js-asset-scan": "CWE-798",
        "m1.internetdb-triage": "CWE-1035",
        "m2.db-service-probe": "CWE-306",
        "m2.smb-enum": "CWE-287",
        "m2.tls-deep-scan": "CWE-327",
        "m2.cve-correlate": "CWE-1035",
        "m4.env-file-probe": "CWE-200",
        "m4.git-probe": "CWE-538",
    }[check_id]
