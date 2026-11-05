"""The report schema policy and its migration helper (WP-21, REQ-DATA-007).

Two claims, both mechanical:

* **The shipped schemas obey the policy.** Every ``report-schema-<version>.json`` declares a
  machine-readable changelog and a deprecation list, no field that was present two minors ago
  has vanished without a record, and a record never schedules a removal sooner than two minor
  versions after the deprecation.
* **The migration helper converts documents forward.** ``1.10 → 1.11`` is purely additive;
  ``1.11 → 1.12`` additionally writes the verification placeholder the 1.12 contract requires,
  which is why a migrated finding that carried no record comes out ``unverified`` at
  ``info`` rather than keeping a severity nothing establishes.

The checker is proven to bite on synthetic schemas: a removal without a record, and a record
that removes too soon, are both refused. A test that only inspects the real files would pass
vacuously the day the first removal lands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from arachne.core.errors import ReportError
from arachne.report.migrate import migrate_report, migration_path
from arachne.report.model import REPORT_SCHEMA_VERSION, UNVERIFIED_REASON
from arachne.report.schema_policy import (
    CHANGELOG_KEY,
    DEPRECATED_KEY,
    MAX_SUPPORTED_VERSIONS,
    SCHEMA_HISTORY,
    SUPPORTED_VERSION_WINDOW,
    SUPPORTED_VERSIONS,
    load_schema,
    policy_violations,
    schema_version_key,
)

GOLDEN = Path(__file__).resolve().parents[1] / "report_qa" / "golden"


def _synthetic(
    version: str,
    *,
    fields: tuple[str, ...],
    deprecations: list[dict[str, str]] | None = None,
    definition_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "properties": {name: {} for name in fields},
        "$defs": {
            "ScopeMethodology": {
                "properties": {name: {} for name in definition_fields},
            }
        },
        CHANGELOG_KEY: [{"version": version, "kind": "added"}],
        DEPRECATED_KEY: list(deprecations or ()),
    }


# --------------------------------------------------------------------- the real files
def test_every_shipped_schema_obeys_the_policy() -> None:
    """The one assertion the whole policy reduces to, over the committed files."""
    assert policy_violations() == ()


def test_the_supported_window_is_documented_and_bounded() -> None:
    assert len(SUPPORTED_VERSIONS) == SUPPORTED_VERSION_WINDOW
    assert len(SUPPORTED_VERSIONS) <= MAX_SUPPORTED_VERSIONS
    assert SUPPORTED_VERSIONS[-1] == REPORT_SCHEMA_VERSION
    majors = {schema_version_key(version)[0] for version in SUPPORTED_VERSIONS}
    assert majors == {1}
    minors = [schema_version_key(version)[1] for version in SUPPORTED_VERSIONS]
    assert minors == list(range(minors[0], minors[0] + len(minors)))


def test_every_history_entry_names_fields_the_schema_really_added() -> None:
    """A changelog that names a field the revision does not contain is a false claim."""
    previous: frozenset[str] = frozenset()
    from arachne.report.schema_policy import declared_fields

    for revision in SCHEMA_HISTORY:
        declared = declared_fields(load_schema(revision.version))
        for field_name in revision.fields:
            # Dotted paths name either a top-level field or a nested one; the first segment
            # (or the whole path for a nested entry) has to exist in the revision.
            root = field_name.split("[")[0].split(".")[0]
            assert root in declared, (
                f"{revision.version} claims {field_name!r}, absent from its schema"
            )
        assert declared >= previous or revision.kind == "initial"
        previous = previous | declared


# --------------------------------------------------------------------- the checker bites
def test_a_removal_without_a_record_is_refused() -> None:
    schemas = {
        "1.0": _synthetic("1.0", fields=("kept", "legacy")),
        "1.1": _synthetic("1.1", fields=("kept", "legacy")),
        "1.2": _synthetic("1.2", fields=("kept",)),
    }
    violations = policy_violations(schemas, history=())
    assert any(
        "legacy" in problem and "without a deprecation record" in problem for problem in violations
    )


def test_a_removal_sooner_than_two_minors_is_refused() -> None:
    schemas = {
        "1.0": _synthetic("1.0", fields=("kept", "legacy")),
        "1.1": _synthetic("1.1", fields=("kept", "legacy")),
        "1.2": _synthetic(
            "1.2",
            fields=("kept",),
            deprecations=[
                {
                    "field": "legacy",
                    "deprecated_in": "1.1",
                    "removal_version": "1.2",
                    "reason": "replaced",
                }
            ],
        ),
    }
    violations = policy_violations(schemas, history=())
    assert any("fewer than two minor versions" in problem for problem in violations)


def test_a_timely_record_permits_the_removal() -> None:
    schemas = {
        "1.0": _synthetic("1.0", fields=("kept", "legacy")),
        "1.1": _synthetic("1.1", fields=("kept", "legacy")),
        "1.2": _synthetic(
            "1.2",
            fields=("kept",),
            deprecations=[
                {
                    "field": "legacy",
                    "deprecated_in": "1.0",
                    "removal_version": "1.2",
                    "reason": "replaced by kept",
                }
            ],
        ),
    }
    assert policy_violations(schemas, history=()) == ()


def test_a_record_without_a_reason_is_refused() -> None:
    schemas = {
        "1.0": _synthetic("1.0", fields=("kept",)),
        "1.1": _synthetic(
            "1.1",
            fields=("kept",),
            deprecations=[
                {
                    "field": "legacy",
                    "deprecated_in": "1.0",
                    "removal_version": "1.2",
                    "reason": "",
                }
            ],
        ),
        "1.2": _synthetic("1.2", fields=("kept",)),
    }
    violations = policy_violations(schemas, history=())
    assert any("with no reason" in problem for problem in violations)


def test_a_nested_removal_is_checked_too() -> None:
    schemas = {
        "1.0": _synthetic("1.0", fields=("kept",), definition_fields=("requested_by",)),
        "1.1": _synthetic("1.1", fields=("kept",), definition_fields=("requested_by",)),
        "1.2": _synthetic("1.2", fields=("kept",), definition_fields=()),
    }
    violations = policy_violations(schemas, history=())
    assert any("ScopeMethodology.requested_by" in problem for problem in violations)


# --------------------------------------------------------------------- the migration
def _golden(name: str) -> dict[str, Any]:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("source", "target"), [("1.10", "1.11"), ("1.11", "1.12")])
def test_migrate_report_matches_its_golden(source: str, target: str) -> None:
    document = _golden(f"migrate-{source}-to-{target}.input.json")
    # The input is a real document for its version, and the output is real for its target.
    jsonschema.validate(document, load_schema(source))
    migrated = migrate_report(document, target_version=target)
    jsonschema.validate(migrated, load_schema(target))
    assert migrated == _golden(f"migrate-{source}-to-{target}.expected.json")


def test_the_1_10_to_1_11_step_is_purely_additive() -> None:
    document = _golden("migrate-1.10-to-1.11.input.json")
    migrated = migrate_report(document, target_version="1.11")
    assert set(document) <= set(migrated)
    assert migrated["simulation"] is None
    # Nothing that established a severity was rewritten: 1.11 does not require a record.
    assert [finding["severity"] for finding in migrated["findings"]] == [
        finding["severity"] for finding in document["findings"]
    ]


def test_the_1_11_to_1_12_step_writes_the_unverified_placeholder() -> None:
    document = _golden("migrate-1.11-to-1.12.input.json")
    assert all("verification" not in finding for finding in document["findings"])
    migrated = migrate_report(document, target_version="1.12")
    for finding in migrated["findings"]:
        record = finding["verification"]
        assert record["status"] == "unverified"
        assert record["level"] == "L0"
        assert record["method"] == UNVERIFIED_REASON
        # A finding with no record cannot keep a severity above info.
        assert finding["severity"] == "info"


def test_a_migration_chain_reaches_the_current_schema() -> None:
    document = _golden("migrate-1.10-to-1.11.input.json")
    migrated = migrate_report(document)
    assert migrated["schema_version"] == REPORT_SCHEMA_VERSION
    jsonschema.validate(migrated, load_schema(REPORT_SCHEMA_VERSION))
    # The path is every declared revision between the source and the target, in order.
    assert migration_path("1.10") == ("1.11", "1.12", "1.13", "1.14")


def test_a_healthy_document_is_unchanged_by_a_no_op_migration() -> None:
    document = _golden("migrate-1.11-to-1.12.expected.json")
    assert migrate_report(document, target_version="1.12") == document


def test_a_downgrade_is_refused() -> None:
    document = _golden("migrate-1.11-to-1.12.expected.json")
    with pytest.raises(ReportError, match="backwards"):
        migrate_report(document, target_version="1.10")


def test_an_unsupported_source_is_refused() -> None:
    document = _golden("migrate-1.10-to-1.11.input.json")
    document["schema_version"] = "1.0"
    with pytest.raises(ReportError, match="supported window"):
        migrate_report(document, target_version="1.11")


def test_a_document_with_no_version_is_refused() -> None:
    document = _golden("migrate-1.10-to-1.11.input.json")
    document.pop("schema_version")
    with pytest.raises(ReportError, match="no schema_version"):
        migrate_report(document)
