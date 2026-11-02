"""Keyset (cursor) pagination SQL for the collection stores (REQ-UIX-001, REQ-UIX-002).

A cursor encodes the last sort key **plus an id tiebreaker**; the SQL predicate must match
the ``ORDER BY`` exactly or a page boundary can skip a row that shares a sort key with the
one before it. This module is the one place both are built, so the findings, scans and
targets queries cannot drift apart.

Safety properties that make this the right home for the code:

* The sort field is a **closed enum**. A caller passes a member, never a raw string, and the
  member is looked up in a map of literal SQLAlchemy columns — so a query parameter can
  never become an SQL identifier. :func:`finding_sort_field` does the string-to-member step
  and falls back to the primary key for anything outside the vocabulary.
* The cursor's boundary values are **bound parameters** (:func:`sqlalchemy.bindparam`),
  never interpolated into SQL text, so a cursor cannot alter the statement's shape.
* ``descending``/``backward`` only choose between ``ASC`` and ``DESC`` on columns from the
  closed vocabulary; they cannot introduce a new one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sqlalchemy import Select, bindparam, func, or_
from sqlalchemy.sql.elements import ColumnElement

from arachne.data.models import Finding, Scan, Target

__all__ = [
    "FindingSort",
    "PageWindow",
    "ScanSort",
    "finding_sort_field",
    "scan_sort_field",
    "with_finding_page",
    "with_scan_page",
    "with_target_page",
]


@dataclass(frozen=True, slots=True)
class PageWindow:
    """A validated page request: the sort member, the direction and the cursor boundary.

    The API layer builds one of these after validating the query string, so the store is
    handed a closed, typed value rather than raw request text. ``boundary`` is the
    ``(sort key, id)`` pair a cursor decoded to, or ``None`` for the first page.
    """

    sort_key: str | None = None
    descending: bool = False
    boundary: tuple[str | int | None, int] | None = None
    backward: bool = False


class FindingSort(StrEnum):
    """The documented ``sort`` vocabulary for ``/findings`` (REQ-UIX-002)."""

    ID = "id"
    SEVERITY = "severity"
    STATUS = "status"
    TITLE = "title"


class ScanSort(StrEnum):
    """The documented ``sort`` vocabulary for ``/scans`` (REQ-UIX-002)."""

    ID = "id"
    STATUS = "status"


#: Enum member -> literal SQLAlchemy column expression. Only ``id`` is indexed; the endpoint
#: documents the others as a full scan. ``severity`` is coalesced to ``""`` so an unanalysed
#: finding sorts as one value on both SQLite and Postgres (which disagree about NULL order).
_FINDING_COLUMNS: dict[FindingSort, Any] = {
    FindingSort.ID: Finding.id,
    FindingSort.SEVERITY: func.coalesce(Finding.severity, ""),
    FindingSort.STATUS: Finding.status,
    FindingSort.TITLE: Finding.title,
}

_SCAN_COLUMNS: dict[ScanSort, Any] = {
    ScanSort.ID: Scan.id,
    ScanSort.STATUS: Scan.status,
}


def finding_sort_field(raw: str | None) -> FindingSort:
    """Map a request value onto the enum; anything outside the vocabulary means ``id``.

    The route validates the value first (a bad one is a 400), so this is the second half of
    the same guard: the store is only ever handed a member of a closed set.
    """
    for member in FindingSort:
        if member.value == raw:
            return member
    return FindingSort.ID


def scan_sort_field(raw: str | None) -> ScanSort:
    for member in ScanSort:
        if member.value == raw:
            return member
    return ScanSort.ID


def keyset_condition(
    column: Any,
    id_column: Any,
    *,
    key: str | int | None,
    item_id: int,
    descending: bool,
    backward: bool = False,
) -> ColumnElement[bool]:
    """Rows strictly after ``(key, item_id)`` in the endpoint's order.

    ``descending`` is the endpoint's declared order; ``backward`` reverses it for a ``prev``
    fetch, so a cursor always means "continue in the direction I came from".
    """
    bound_key: Any = bindparam("keyset_key", key)
    bound_id: Any = bindparam("keyset_id", item_id)
    if descending != backward:
        return or_(column < bound_key, (column == bound_key) & (id_column < bound_id))
    return or_(column > bound_key, (column == bound_key) & (id_column > bound_id))


def with_finding_page(
    statement: Select[Any], *, window: PageWindow | None, limit: int
) -> Select[Any]:
    """Attach the total ordering (and the cursor boundary) to a findings ``SELECT``.

    Findings default to ascending ``id`` — the order they were recorded in — which is also
    what the query returned before the cursor was added, so a report path that reads the
    store directly is unaffected.
    """
    active = window if window is not None else PageWindow()
    return _with_page(
        statement,
        column=_FINDING_COLUMNS[finding_sort_field(active.sort_key)],
        id_column=Finding.id,
        descending=active.descending,
        boundary=active.boundary,
        backward=active.backward,
        limit=limit,
    )


def with_scan_page(statement: Select[Any], *, window: PageWindow | None, limit: int) -> Select[Any]:
    """Scans default to descending ``id`` — newest first, as the dashboard expects."""
    active = _active(window, default_descending=True)
    return _with_page(
        statement,
        column=_SCAN_COLUMNS[scan_sort_field(active.sort_key)],
        id_column=Scan.id,
        descending=active.descending,
        boundary=active.boundary,
        backward=active.backward,
        limit=limit,
    )


def with_target_page(
    statement: Select[Any], *, window: PageWindow | None, limit: int
) -> Select[Any]:
    """Targets have a single sort field (``id``) and default to newest first."""
    active = _active(window, default_descending=True)
    return _with_page(
        statement,
        column=Target.id,
        id_column=Target.id,
        descending=active.descending,
        boundary=active.boundary,
        backward=active.backward,
        limit=limit,
    )


def _active(window: PageWindow | None, *, default_descending: bool = False) -> PageWindow:
    if window is not None:
        return window
    return PageWindow(descending=default_descending)


def _with_page(
    statement: Select[Any],
    *,
    column: Any,
    id_column: Any,
    descending: bool,
    boundary: tuple[str | int | None, int] | None,
    backward: bool,
    limit: int,
) -> Select[Any]:
    effective_desc = descending != backward
    if boundary is not None:
        statement = statement.where(
            keyset_condition(
                column,
                id_column,
                key=boundary[0],
                item_id=boundary[1],
                descending=descending,
                backward=backward,
            )
        )
    if effective_desc:
        return statement.order_by(column.desc(), id_column.desc()).limit(max(1, limit))
    return statement.order_by(column.asc(), id_column.asc()).limit(max(1, limit))
