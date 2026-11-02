"""The validated filter and sort vocabulary of the collection endpoints (REQ-UIX-002).

Each collection endpoint declares the query fields it accepts. FastAPI silently ignores an
undeclared query parameter, so a mistyped filter (``severiity=high``) would return the
unfiltered set and look as though it had worked; :func:`reject_unknown_query_params` turns
that into a ``400`` naming the field instead.

The value *domains* here are the same ones the route signatures declare as ``Literal``
types, so OpenAPI publishes them as enums. They are defined once here and imported by both
the routes and the contract tests, so a filter cannot be added to one and forgotten in the
other.
"""

from __future__ import annotations

from typing import Literal, get_args

__all__ = [
    "FINDING_FILTER_FIELDS",
    "FINDING_SORT_VALUES",
    "FINDING_STATUS_VALUES",
    "SCAN_FILTER_FIELDS",
    "SCAN_SORT_VALUES",
    "SEVERITY_VALUES",
    "STATUS_FILTER_FIELDS",
    "FindingStatusValue",
    "ScanStatusValue",
    "SeverityValue",
    "SortOrder",
]

#: Severities a finding filter may name, plus the ``unanalysed`` bucket (a NULL severity).
SeverityValue = Literal["critical", "high", "medium", "low", "info", "unanalysed"]
FindingStatusValue = Literal["open", "verified", "fp", "merged"]
ScanStatusValue = Literal["pending", "running", "completed", "failed", "aborted"]
SortOrder = Literal["asc", "desc"]

SEVERITY_VALUES: tuple[str, ...] = get_args(SeverityValue)
FINDING_STATUS_VALUES: tuple[str, ...] = get_args(FindingStatusValue)

#: The query fields ``GET /findings`` accepts (beyond the shared pagination parameters).
FINDING_FILTER_FIELDS: frozenset[str] = frozenset(
    {"scan_id", "module", "severity", "cwe", "status", "asset", "q"}
)

#: The query fields ``GET /scans`` accepts.
SCAN_FILTER_FIELDS: frozenset[str] = frozenset({"status", "target_id"})

#: The query fields ``GET /suppressions`` accepts.
STATUS_FILTER_FIELDS: frozenset[str] = frozenset({"include_revoked", "all_projects"})

#: The sortable fields of ``/findings`` and ``/scans`` (mirrors the data layer's enums).
FINDING_SORT_VALUES: tuple[str, ...] = ("id", "severity", "status", "title")
SCAN_SORT_VALUES: tuple[str, ...] = ("id", "status")
