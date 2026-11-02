"""Cursor pagination and query-vocabulary validation (REQ-UIX-001, REQ-UIX-002).

Every collection endpoint in the REST API pages with an **opaque cursor** that encodes the
last sort key plus an ``id`` tiebreaker, so the ordering is *total*: two rows that share a
sort key (two ``high`` findings, two ``completed`` scans) can never make a page boundary
skip one of them. A cursor is opaque — a caller must not parse it — but it is deliberately
not encrypted either: it carries no secret, only a position. It is unsigned base64url JSON.

The rules the endpoints follow, and this module enforces:

* ``limit`` is **clamped** to :data:`MAX_LIMIT`; a larger value is not honoured, and it is
  not refused either, so an over-large page size degrades to the maximum rather than a 422.
* The store is asked for ``limit + 1`` rows, so ``has_more`` needs no second query.
* Both ``Link`` (``rel="next"`` / ``rel="prev"``) and ``X-Next-Cursor`` / ``X-Prev-Cursor``
  headers are emitted. The body stays a bare JSON array, which is what the existing clients
  and the web UI already consume.
* An unknown *filter or sort* field is a ``400`` naming the field — never silently ignored.

The cursor codec is dialect-free; the keyset comparison lives in the stores that own the
SQL (``arachne.data.api_store``, ``arachne.data.scan_store``).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from fastapi import HTTPException, Request, Response, status

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "Cursor",
    "InvalidCursorError",
    "Page",
    "apply_page",
    "clamp_limit",
    "decode_cursor",
    "encode_cursor",
    "link_header",
    "paginate_sequence",
    "reject_unknown_query_params",
    "resolve_sort_field",
]

#: Page size used when a caller gives none.
DEFAULT_LIMIT = 50

#: The documented maximum page size (REQ-UIX-001: "a documented `limit` bound"). A larger
#: requested limit is clamped to this, never refused.
MAX_LIMIT = 200

#: Longest cursor string accepted, so a hostile caller cannot make the decoder work hard.
_MAX_CURSOR_LENGTH = 4096

#: Query parameters that are part of the pagination contract itself (and the tenant
#: selector), accepted by every collection endpoint without being declared as filters.
PAGINATION_PARAMS: frozenset[str] = frozenset(
    {"limit", "cursor", "sort", "order", "offset", "project"}
)

T = TypeVar("T")


class InvalidCursorError(ValueError):
    """The cursor is not a cursor this API issued."""


@dataclass(frozen=True, slots=True)
class Cursor:
    """A decoded pagination position: the last sort key plus the ``id`` tiebreaker.

    ``backward`` marks a cursor that came from a ``prev`` link: the server fetches the page
    *ending* at the boundary rather than starting after it.
    """

    key: str | int | None
    item_id: int
    backward: bool = False


@dataclass(frozen=True, slots=True)
class Page:
    """One page of a collection, plus the cursors needed to continue either way."""

    items: list[Any]
    limit: int
    has_more: bool
    next_cursor: str | None
    prev_cursor: str | None


# --------------------------------------------------------------------------- limit
def clamp_limit(
    requested: int | None, *, default: int = DEFAULT_LIMIT, maximum: int = MAX_LIMIT
) -> int:
    """Coerce a requested page size into ``[1, maximum]``.

    A caller that asks for more than the documented maximum gets the maximum, not an error
    and not the figure it asked for (REQ-UIX-001).
    """
    if requested is None:
        return default
    return max(1, min(int(requested), maximum))


# --------------------------------------------------------------------------- cursor codec
def encode_cursor(key: str | int | None, item_id: int, *, backward: bool = False) -> str:
    """Encode a position as an opaque, URL-safe token."""
    payload: dict[str, Any] = {"i": int(item_id), "k": key}
    if backward:
        payload["b"] = 1
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(raw: str | None) -> Cursor | None:
    """Decode a cursor; ``None`` when absent, :class:`InvalidCursorError` when malformed."""
    if raw is None or raw == "":
        return None
    if len(raw) > _MAX_CURSOR_LENGTH:
        raise InvalidCursorError("cursor is too long")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise InvalidCursorError("cursor is not valid base64url JSON") from exc
    if not isinstance(decoded, dict):
        raise InvalidCursorError("cursor is not a JSON object")
    item_id = decoded.get("i")
    if not isinstance(item_id, int) or isinstance(item_id, bool):
        raise InvalidCursorError("cursor carries no integer id")
    key = decoded.get("k")
    if key is not None and not isinstance(key, (str, int)):
        raise InvalidCursorError("cursor carries an unsupported sort key")
    return Cursor(key=key, item_id=item_id, backward=bool(decoded.get("b")))


def cursor_or_400(raw: str | None) -> Cursor | None:
    """Decode a cursor, turning a malformed one into a 400 rather than a 500."""
    try:
        return decode_cursor(raw)
    except InvalidCursorError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# --------------------------------------------------------------------------- validation
def reject_unknown_query_params(request: Request, allowed: Iterable[str]) -> None:
    """400 with the field name when the query string carries a parameter outside ``allowed``.

    This is how REQ-UIX-002 is kept: FastAPI ignores an undeclared query parameter silently,
    so a typo (``severiity=high``) would otherwise return the unfiltered set and look like a
    working filter.
    """
    permitted = set(allowed) | PAGINATION_PARAMS
    unknown = sorted({name for name in request.query_params if name not in permitted})
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown filter field: {unknown[0]!r}",
        )


def resolve_sort_field(raw: str | None, allowed: Sequence[str], *, default: str) -> str:
    """Validate a sort field name; an unknown one is a 400 naming it.

    ``order`` (``asc``/``desc``) is validated by FastAPI's declared enum on the endpoint, so
    only the field name is checked here.
    """
    if raw is None:
        return default
    if raw not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown sort field: {raw!r}",
        )
    return raw


# --------------------------------------------------------------------------- page building
def build_page(
    rows: Sequence[T],
    *,
    limit: int,
    key_of: Callable[[T], str | int | None],
    id_of: Callable[[T], int],
    cursor: Cursor | None,
    backward: bool,
) -> Page:
    """Turn ``limit + 1`` fetched rows (in forward order) into a :class:`Page`.

    A ``backward`` window is the previous page plus one row *older than it*, so the extra
    row is dropped from the front; a forward window's extra row is the newest one and is
    dropped from the back.
    """
    has_more = len(rows) > limit
    # A backward window carries one row *older* than the page, at the front; a forward
    # window carries one row *newer* than the page, at the back.
    skipped = 1 if backward and has_more else 0
    items = list(rows[skipped : skipped + limit])
    next_cursor: str | None = None
    prev_cursor: str | None = None
    if items:
        first, last = items[0], items[-1]
        if backward:
            # Fetching backwards: the extra row means an *earlier* page exists.
            if has_more:
                prev_cursor = encode_cursor(key_of(first), id_of(first), backward=True)
            next_cursor = encode_cursor(key_of(last), id_of(last))
        else:
            if has_more:
                next_cursor = encode_cursor(key_of(last), id_of(last))
            if cursor is not None:
                prev_cursor = encode_cursor(key_of(first), id_of(first), backward=True)
    return Page(
        items=items,
        limit=limit,
        has_more=has_more,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
    )


def paginate_sequence(
    items: Iterable[T],
    *,
    limit: int,
    key_of: Callable[[T], str | int | None],
    id_of: Callable[[T], int],
    descending: bool = False,
    cursor: Cursor | None = None,
) -> Page:
    """Page an in-memory sequence with the same total ordering the SQL path uses.

    Used by the collection endpoints whose backing store has no keyset support (modules,
    tenants, schedules, quality rules). The sequence is re-sorted here so the order is a
    property of the endpoint rather than of whatever order the store happened to return.
    """
    ordered = sorted(items, key=lambda item: (key_of(item), id_of(item)), reverse=descending)
    if cursor is None:
        window = ordered
    else:
        boundary = (cursor.key, cursor.item_id)
        if cursor.backward:
            window = [
                item
                for item in ordered
                if _before((key_of(item), id_of(item)), boundary, descending)
            ][-(limit + 1) :]
        else:
            window = [
                item
                for item in ordered
                if _before(boundary, (key_of(item), id_of(item)), descending)
            ][: limit + 1]
    return build_page(
        window,
        limit=limit,
        key_of=key_of,
        id_of=id_of,
        cursor=cursor,
        backward=bool(cursor and cursor.backward),
    )


def _before(left: tuple[Any, int], right: tuple[Any, int], descending: bool) -> bool:
    """True when ``left`` sorts before ``right`` in the endpoint's order."""
    return left > right if descending else left < right


# --------------------------------------------------------------------------- headers
def link_header(
    request: Request, *, next_cursor: str | None, prev_cursor: str | None
) -> str | None:
    """The RFC 8288 ``Link`` value for the page, with ``rel="next"`` and ``rel="prev"``."""
    links: list[str] = []
    for rel, cursor in (("next", next_cursor), ("prev", prev_cursor)):
        if cursor is None:
            continue
        url = request.url.include_query_params(cursor=cursor).remove_query_params("offset")
        links.append(f'<{url}>; rel="{rel}"')
    return ", ".join(links) if links else None


def apply_page(response: Response, request: Request, page: Page) -> None:
    """Attach the pagination headers to a response (the body stays the bare array)."""
    response.headers["X-Limit"] = str(page.limit)
    response.headers["X-Has-More"] = "true" if page.has_more else "false"
    if page.next_cursor is not None:
        response.headers["X-Next-Cursor"] = page.next_cursor
    if page.prev_cursor is not None:
        response.headers["X-Prev-Cursor"] = page.prev_cursor
    header = link_header(request, next_cursor=page.next_cursor, prev_cursor=page.prev_cursor)
    if header is not None:
        response.headers["Link"] = header
