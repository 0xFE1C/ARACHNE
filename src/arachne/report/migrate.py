"""Convert a report document from an older supported schema to a newer one (WP-21, REQ-DATA-007).

The policy in :mod:`arachne.report.schema_policy` says which versions exist, what each added
and what may be removed. This module is the *conversion*: a consumer holding a ``1.11``
document (a saved report, an import in a data warehouse, a customer's archive) can move it
forward without re-running the scan, and the result validates against the target schema.

Three rules shape it:

**Forward only.** A migration never "downgrades": removing a field to satisfy an older schema
would destroy information the newer document legitimately carries, and no policy requires it.
Asking for an older target is a clear error, not a silent copy.

**Additive by construction, explicit where required.** A step fills the target schema's
declared defaults and, where a revision *strengthened* a requirement, writes the documented
placeholder. Schema 1.12 made a finding's verification record required; the migration writes
the same ``unverified``/``L0`` record the model itself synthesises for a finding with no
record, and forces the severity to ``info`` — the same rule, applied at the same place in the
document, so a migrated report can never claim a proven severity it has no record for.

**Deterministic.** The output is a function of the input and the shipped schemas only: no
timestamps, no clock, no ordering by a set. That is what makes a golden file a meaningful
review artefact rather than a snapshot of the day it was blessed.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any, Final

from arachne.core.errors import ReportError
from arachne.report.model import UNVERIFIED_REASON
from arachne.report.schema_policy import (
    CURRENT_VERSION,
    SCHEMA_HISTORY,
    SUPPORTED_VERSIONS,
    load_schema,
    schema_version_key,
)

__all__ = [
    "MIGRATION_STEPS",
    "migrate_report",
    "migration_path",
]

#: The verification placeholder 1.12 requires — the same record
#: :class:`~arachne.report.model.ReportFinding` synthesises for a finding that has none.
_UNVERIFIED_RECORD: Final[dict[str, Any]] = {
    "status": "unverified",
    "level": "L0",
    "method": UNVERIFIED_REASON,
    "observations": [{"what": "unverified", "reason": UNVERIFIED_REASON}],
}


def _fill_schema_defaults(document: dict[str, Any], version: str) -> dict[str, Any]:
    """Add every top-level declared default the document does not already carry.

    This is the mechanical half of an additive migration: a field the target schema declares
    with a default (``simulation: null``, ``locale: ""``) is present in the migrated document
    even when the source omitted it, so a consumer can read the new shape uniformly. A
    required field has no default and is left alone — if it is absent the document was not
    valid at the source version, and the caller's validation says so.
    """
    schema = load_schema(version)
    for name, prop in (schema.get("properties") or {}).items():
        if name in document or not isinstance(prop, Mapping):
            continue
        if "default" in prop:
            document[name] = copy.deepcopy(prop["default"])
    return document


def _add_verification_placeholders(document: dict[str, Any], _version: str) -> dict[str, Any]:
    """The 1.12 step: every finding gets a record, and an unrecorded one stays ``info``.

    Mirrors :meth:`arachne.report.model.ReportFinding._demand_a_verification_record`. A
    finding that already has a record is untouched; a finding that does not is marked
    ``unverified`` and its severity lowered to ``info`` rather than carrying its old score
    forward without a record behind it.
    """
    for key in ("findings", "low_confidence"):
        for finding in document.get(key) or ():
            if not isinstance(finding, dict) or finding.get("verification"):
                continue
            finding["verification"] = {
                **_UNVERIFIED_RECORD,
                "check_version": finding.get("check_version"),
            }
            finding.pop("verification_history", None)
            finding["severity"] = "info"
    return document


def _annotate_severity_feeds(document: dict[str, Any], _version: str) -> dict[str, Any]:
    """The 1.14 step: the intel block gains its severity-feed markers and warning list.

    A report from before the policy has no recorded severity-feed choice, so the lists are
    empty and every feed's ``severity_contributing`` marker is false: the migration states
    "this document did not say", never a guessed policy. A document whose scan already
    recorded the lists (a re-render, not a migration) is left exactly as recorded.
    """
    intel = document.get("intel")
    if not isinstance(intel, dict):
        return document
    severity = intel.setdefault("severity_feeds", [])
    intel.setdefault("warnings", [])
    if isinstance(severity, list):
        for feed in intel.get("feeds") or ():
            if isinstance(feed, dict):
                feed.setdefault("severity_contributing", feed.get("kind") in severity)
    return document


#: The explicit transform per target version. Every step also fills the target's defaults;
#: a version absent from this table is purely additive and needs only that.
MIGRATION_STEPS: Final[dict[str, Callable[[dict[str, Any], str], dict[str, Any]]]] = {
    "1.12": _add_verification_placeholders,
    "1.14": _annotate_severity_feeds,
}


def migration_path(source: str, target: str = CURRENT_VERSION) -> tuple[str, ...]:
    """The intermediate versions a conversion passes through, ``target`` included.

    ``1.10`` → ``1.14`` yields ``("1.11", "1.12", "1.13", "1.14")``. The path is derived from
    :data:`SCHEMA_HISTORY`, so a new revision is migrateable as soon as it is declared.
    """
    source_key = schema_version_key(source)
    target_key = schema_version_key(target)
    if target_key < source_key:
        msg = f"cannot migrate report schema {source} backwards to {target}"
        raise ReportError(msg)
    versions = [item.version for item in SCHEMA_HISTORY]
    return tuple(
        version for version in versions if source_key < schema_version_key(version) <= target_key
    )


def migrate_report(
    document: Mapping[str, Any],
    *,
    target_version: str = CURRENT_VERSION,
) -> dict[str, Any]:
    """Convert ``document`` to ``target_version`` (default: the current one).

    Raises :class:`~arachne.core.errors.ReportError` when the source version is not supported,
    when the target is older than the source, or when the document names no version at all.
    The input is not mutated.
    """
    source = str(document.get("schema_version") or "")
    if not source:
        msg = "the report document declares no schema_version; there is nothing to migrate from"
        raise ReportError(msg)
    if target_version not in {item.version for item in SCHEMA_HISTORY}:
        msg = f"unknown report schema target version {target_version!r}"
        raise ReportError(msg)
    if source not in SUPPORTED_VERSIONS:
        msg = (
            f"report schema {source} is outside the supported window "
            f"{list(SUPPORTED_VERSIONS)}; upgrade the document with the ARACHNE release "
            "that produced it"
        )
        raise ReportError(msg)

    migrated = copy.deepcopy(dict(document))
    versions = migration_path(source, target_version)
    for version in versions:
        migrated = _fill_schema_defaults(migrated, version)
        step = MIGRATION_STEPS.get(version)
        if step is not None:
            migrated = step(migrated, version)
        migrated["schema_version"] = version
    return migrated
