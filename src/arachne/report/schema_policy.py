"""The report schema's version policy: additive-only, deprecations with removal dates (WP-21).

Eleven (now fourteen) report schema revisions shipped without a *policy*. A consumer could
see the version number but not answer the two questions that matter: "will this field still be
here next release?" and "how long do I have to move off the one that is going away?" This
module is the answer, and it is executable: the policy is checked against the committed schema
files, not merely described.

Four rules, each with a mechanical check:

**Additive-only within a major.** A change to a ``1.x`` schema may add a field; it may not
remove or rename one, except through the deprecation path below. :func:`policy_violations`
takes the fields that disappeared and refuses any that has no record.

**A deprecated field survives two minor versions.** ``removal_version`` must be at least two
minor releases after ``deprecated_in`` — long enough for a consumer pinned to a reported
version to adopt the replacement. A record that removes sooner is a violation, not a warning.

**Every version carries a machine-readable changelog.** Each committed
``report-schema-<version>.json`` declares ``x-arachne-changelog``: what the revision added,
in a shape a tool can read. :data:`SCHEMA_HISTORY` is the source of truth, and the gate fails
when a file disagrees with it, so the two cannot drift.

**The number of supported versions is bounded.** A consumer may rely on the last
:data:`SUPPORTED_VERSION_WINDOW` minor versions (currently five). Older documents are still
readable — they are frozen history — but :func:`migrate_report` only guarantees a conversion
from a *supported* version, and the window is the documented promise rather than "whatever we
happen to have shipped".

The rewrite of a document is in :mod:`arachne.report.migrate`; this module owns only the
metadata and the rules. Nothing here touches a live report.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ReportError
from arachne.report.model import REPORT_SCHEMA_VERSION

__all__ = [
    "CHANGELOG_KEY",
    "CURRENT_VERSION",
    "DEPRECATED_KEY",
    "MAX_SUPPORTED_VERSIONS",
    "SCHEMA_HISTORY",
    "SUPPORTED_VERSIONS",
    "SUPPORTED_VERSION_WINDOW",
    "SchemaRevision",
    "changed_fields",
    "declared_fields",
    "load_schema",
    "policy_violations",
    "schema_version_key",
    "supported_versions",
]

#: The JSON-Schema extension keyword that carries a revision's machine-readable changelog.
CHANGELOG_KEY: Final = "x-arachne-changelog"
#: The JSON-Schema extension keyword that carries the deprecation records.
DEPRECATED_KEY: Final = "x-arachne-deprecations"

#: How many of the most recent minor versions a consumer may rely on (documented and bounded).
SUPPORTED_VERSION_WINDOW: Final = 5
#: A hard ceiling on the window: changing the promise is a deliberate, reviewed edit.
MAX_SUPPORTED_VERSIONS: Final = 5

CURRENT_VERSION: Final = REPORT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class SchemaRevision:
    """One report schema revision: what it changed, and what it deprecated."""

    version: str
    #: ``initial`` for the first contract, ``added`` for a revision that only added fields.
    kind: str
    #: Dotted field paths this revision introduced (``intel.warnings``).
    fields: tuple[str, ...] = ()
    note: str = ""
    #: Deprecation records: ``field``, ``deprecated_in``, ``removal_version``, ``reason``.
    deprecations: tuple[Mapping[str, str], ...] = field(default_factory=tuple)

    def changelog(self) -> list[dict[str, Any]]:
        """The revision's ``x-arachne-changelog`` value."""
        entry: dict[str, Any] = {"version": self.version, "kind": self.kind}
        if self.fields:
            entry["fields"] = list(self.fields)
        if self.note:
            entry["note"] = self.note
        return [entry]

    def metadata(self) -> dict[str, Any]:
        return {
            CHANGELOG_KEY: self.changelog(),
            DEPRECATED_KEY: [dict(item) for item in self.deprecations],
        }


#: Every revision the generator has written, oldest first. This is the policy's ledger: a
#: committed file whose ``x-arachne-*`` metadata disagrees with its entry here fails the gate.
SCHEMA_HISTORY: Final[tuple[SchemaRevision, ...]] = (
    SchemaRevision("1.0", "initial", note="the first versioned report contract"),
    SchemaRevision("1.1", "added", ("branding",), note="white-label branding for MSSP reports"),
    SchemaRevision(
        "1.2",
        "added",
        ("findings[].proof", "state_changes"),
        note="the per-finding proof artifact and the report-level state-change table",
    ),
    SchemaRevision(
        "1.3", "added", ("scope.requested_by",), note="the principal that requested the scan"
    ),
    SchemaRevision("1.4", "added", ("intel",), note="threat-intel freshness snapshot"),
    SchemaRevision(
        "1.5",
        "added",
        ("scope.credentials", "scope.authenticated"),
        note="the credential labels a scan authenticated with",
    ),
    SchemaRevision("1.6", "added", ("attack_paths",), note="composed attack paths"),
    SchemaRevision("1.7", "added", ("compliance",), note="per-framework control coverage"),
    SchemaRevision(
        "1.8",
        "added",
        ("attack_paths[].criticality", "attack_paths[].business_severity"),
        note="CMDB criticality on attack-path entries",
    ),
    SchemaRevision(
        "1.9", "added", ("detection_validation",), note="the purple-team run a scan performed"
    ),
    SchemaRevision("1.10", "added", ("locale",), note="the report's rendering language"),
    SchemaRevision("1.11", "added", ("simulation",), note="the what-if simulation block"),
    SchemaRevision(
        "1.12",
        "added",
        ("findings[].verification", "findings[].verification_history"),
        note="a finding's verification record became required",
    ),
    SchemaRevision(
        "1.13", "added", ("residue_attestation",), note="the scan's residue attestation"
    ),
    SchemaRevision(
        "1.14",
        "added",
        (
            "intel.severity_feeds",
            "intel.warnings",
            "intel.feeds[].severity_contributing",
        ),
        note="feed freshness SLA warnings for severity-contributing feeds",
    ),
)


def schema_version_key(version: str) -> tuple[int, int]:
    """``"1.14"`` → ``(1, 14)``; anything else is a report error, not an assumption."""
    parts = version.strip().split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        msg = f"{version!r} is not a report schema version of the form <major>.<minor>"
        raise ReportError(msg)
    return int(parts[0]), int(parts[1])


def supported_versions(history: Sequence[SchemaRevision] = SCHEMA_HISTORY) -> tuple[str, ...]:
    """The versions :func:`~arachne.report.migrate.migrate_report` promises to convert.

    The last :data:`SUPPORTED_VERSION_WINDOW` revisions, and only if they are consecutive
    minors of the current major and the window respects its ceiling — a policy that cannot
    silently widen itself.
    """
    ordered = tuple(item.version for item in history)
    window = ordered[-SUPPORTED_VERSION_WINDOW:]
    if len(window) > MAX_SUPPORTED_VERSIONS:  # pragma: no cover - the constant bounds it
        msg = f"the supported window {window} exceeds {MAX_SUPPORTED_VERSIONS} versions"
        raise ReportError(msg)
    majors = {schema_version_key(version)[0] for version in window}
    minors = [schema_version_key(version)[1] for version in window]
    if len(majors) != 1 or minors != list(range(minors[0], minors[0] + len(minors))):
        msg = f"the supported window is not a consecutive run of minor versions: {window}"
        raise ReportError(msg)
    return window


#: The documented window: five consecutive minor versions ending at the current one.
SUPPORTED_VERSIONS: Final = supported_versions()


def load_schema(version: str) -> dict[str, Any]:
    """Load the shipped schema for *any* version (not only the current one).

    Frozen history is kept precisely so a consumer can validate a document against the
    revision it claims; this is the read that makes that possible inside the process.
    """
    schema_version_key(version)
    resource = files("arachne.templates")
    for part in ("report", f"report-schema-{version}.json"):
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        msg = f"bundled report schema {version} is missing: {exc}"
        raise ReportError(msg) from exc
    import json

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - shipped files are valid
        msg = f"bundled report schema {version} is not valid JSON: {exc}"
        raise ReportError(msg) from exc
    if not isinstance(document, dict):  # pragma: no cover - defended by the file
        raise ReportError(f"bundled report schema {version} is not an object")
    return document


def declared_fields(schema: Mapping[str, Any]) -> frozenset[str]:
    """Every field path a schema declares, as dotted strings.

    Top-level properties use their bare name (``locale``); a definition's properties are
    qualified by the definition name (``ScopeMethodology.requested_by``). That is the
    vocabulary a deprecation record uses to name the field it removes, so the removal check
    and the record speak the same language.
    """
    found: set[str] = set()
    for name in schema.get("properties") or {}:
        found.add(str(name))
    for definition, body in (schema.get("$defs") or {}).items():
        if not isinstance(body, Mapping):
            continue
        for name in body.get("properties") or {}:
            found.add(f"{definition}.{name}")
    return frozenset(found)


def changed_fields(
    earlier: Mapping[str, Any], later: Mapping[str, Any]
) -> tuple[frozenset[str], frozenset[str]]:
    """``(added, removed)`` field paths between two schemas."""
    before = declared_fields(earlier)
    after = declared_fields(later)
    return after - before, before - after


def policy_violations(
    schemas: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    history: Sequence[SchemaRevision] = SCHEMA_HISTORY,
) -> tuple[str, ...]:
    """Every way the committed schemas break the policy (empty tuple when they do not).

    ``schemas`` maps version → schema document; ``None`` loads every version in ``history``
    from the shipped files. The checks are the four rules in the module docstring, plus the
    agreement between each file's metadata and :data:`SCHEMA_HISTORY`.
    """
    revisions = {item.version: item for item in history}
    documents = (
        {item.version: load_schema(item.version) for item in history}
        if schemas is None
        else {str(version): document for version, document in schemas.items()}
    )
    problems: list[str] = []
    ordered = sorted(documents, key=schema_version_key)

    for version in ordered:
        document = documents[version]
        changelog = document.get(CHANGELOG_KEY)
        deprecations = document.get(DEPRECATED_KEY)
        if not isinstance(changelog, list) or not changelog:
            problems.append(f"schema {version} does not declare a {CHANGELOG_KEY} list")
        if not isinstance(deprecations, list):
            problems.append(f"schema {version} does not declare a {DEPRECATED_KEY} list")
            continue
        declared = revisions.get(version)
        if declared is not None and changelog != declared.changelog():
            problems.append(
                f"schema {version}'s {CHANGELOG_KEY} disagrees with SCHEMA_HISTORY: "
                f"{changelog!r} != {declared.changelog()!r}"
            )
        for record in deprecations:
            problems.extend(_deprecation_problems(version, record))

    # Additive-only: a field present two minors ago and gone now needs a record.
    for index in range(2, len(ordered)):
        earlier, later = ordered[index - 2], ordered[index]
        _added, removed = changed_fields(documents[earlier], documents[later])
        for qualified in sorted(removed):
            if not _has_deprecation_record(documents, ordered, qualified, earlier, later):
                problems.append(
                    f"field {qualified!r} was present in {earlier} and removed in {later} "
                    "without a deprecation record"
                )
    return tuple(problems)


def _deprecation_problems(version: str, record: Any) -> list[str]:
    if not isinstance(record, Mapping):
        return [f"schema {version} has a non-object deprecation record: {record!r}"]
    problems: list[str] = []
    field_name = record.get("field")
    deprecated_in = record.get("deprecated_in")
    removal = record.get("removal_version")
    reason = record.get("reason")
    if not field_name:
        problems.append(f"schema {version} has a deprecation record with no 'field'")
    if not reason:
        problems.append(f"schema {version} deprecates {field_name!r} with no reason")
    try:
        deprecated_key = schema_version_key(str(deprecated_in))
        removal_key = schema_version_key(str(removal))
    except ReportError as exc:
        problems.append(f"schema {version} has an unreadable deprecation version: {exc}")
        return problems
    if deprecated_key[0] != removal_key[0]:
        problems.append(
            f"schema {version} deprecates {field_name!r} across a major boundary "
            f"({deprecated_in} -> {removal})"
        )
        return problems
    if removal_key[1] - deprecated_key[1] < 2:
        problems.append(
            f"schema {version} removes {field_name!r} in {removal}, fewer than two minor "
            f"versions after deprecating it in {deprecated_in}"
        )
    return problems


def _has_deprecation_record(
    documents: Mapping[str, Mapping[str, Any]],
    ordered: Sequence[str],
    qualified: str,
    earlier: str,
    later: str,
) -> bool:
    """True when some schema ≤ ``later`` records this removal with a timely window."""
    earlier_key = schema_version_key(earlier)
    later_key = schema_version_key(later)
    for version in ordered:
        if schema_version_key(version) > later_key:
            break
        for record in documents[version].get(DEPRECATED_KEY) or ():
            if not isinstance(record, Mapping) or record.get("field") != qualified:
                continue
            try:
                deprecated_key = schema_version_key(str(record.get("deprecated_in")))
                removal_key = schema_version_key(str(record.get("removal_version")))
            except ReportError:
                continue
            if deprecated_key <= earlier_key and removal_key <= later_key:
                return True
    return False
