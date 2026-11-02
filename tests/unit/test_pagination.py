"""Unit: the pagination codec, the limit clamp and the query-vocabulary guard (REQ-UIX-001/002).

The cursor is the part of the pagination contract that is easiest to get subtly wrong: it
must round-trip, it must be opaque (no caller can be allowed to depend on its bytes beyond
"pass it back"), and a malformed one must be a 400 rather than a 500. Those properties are
asserted here, without a database, so a failure says which property moved.
"""

from __future__ import annotations

import pytest

from arachne.api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Cursor,
    InvalidCursorError,
    apply_page,
    build_page,
    clamp_limit,
    decode_cursor,
    encode_cursor,
    link_header,
    paginate_sequence,
    reject_unknown_query_params,
    resolve_sort_field,
)


class _Row:
    """A stand-in for a store row: a sort key and an id, nothing else."""

    def __init__(self, key: str | int | None, item_id: int) -> None:
        self.key = key
        self.id = item_id


# --------------------------------------------------------------------------- limit clamp
@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (None, DEFAULT_LIMIT),
        (1, 1),
        (50, 50),
        (MAX_LIMIT, MAX_LIMIT),
        (MAX_LIMIT + 1, MAX_LIMIT),
        (10_000_000, MAX_LIMIT),
        (0, 1),
        (-5, 1),
    ],
)
def test_a_limit_above_the_maximum_is_clamped_not_honoured(
    requested: int | None, expected: int
) -> None:
    assert clamp_limit(requested, default=DEFAULT_LIMIT, maximum=MAX_LIMIT) == expected


def test_the_documented_maximum_is_a_module_constant() -> None:
    """The bound OpenAPI publishes and the bound the code applies are the same number."""
    assert MAX_LIMIT == 200


# --------------------------------------------------------------------------- cursor codec
def test_a_cursor_round_trips_a_string_key_and_an_id() -> None:
    token = encode_cursor("high", 41)
    assert decode_cursor(token) == Cursor(key="high", item_id=41, backward=False)


def test_a_cursor_round_trips_an_integer_key_and_a_backward_marker() -> None:
    token = encode_cursor(17, 3, backward=True)
    assert decode_cursor(token) == Cursor(key=17, item_id=3, backward=True)


def test_a_cursor_is_opaque_not_a_plain_readable_position() -> None:
    token = encode_cursor("high", 41)
    assert "high" not in token
    assert token == encode_cursor("high", 41), "encoding must be deterministic"


def test_an_absent_cursor_is_no_cursor() -> None:
    assert decode_cursor(None) is None
    assert decode_cursor("") is None


@pytest.mark.parametrize(
    "token",
    ["not base64!", "====", "eyJpIjogIm5vdC1hbi1pbnQifQ", "WzEsMiwzXQ", "e30"],
)
def test_a_malformed_cursor_is_refused(token: str) -> None:
    with pytest.raises(InvalidCursorError):
        decode_cursor(token)


def test_an_over_long_cursor_is_refused() -> None:
    with pytest.raises(InvalidCursorError, match="too long"):
        decode_cursor("A" * 5000)


# --------------------------------------------------------------------------- page building
def _page(rows: list[_Row], *, limit: int, cursor: Cursor | None = None) -> object:
    return build_page(
        rows,
        limit=limit,
        key_of=lambda row: row.key,
        id_of=lambda row: row.id,
        cursor=cursor,
        backward=False,
    )


def test_limit_plus_one_rows_yield_a_full_page_and_a_next_cursor() -> None:
    rows = [_Row(i, i) for i in range(6)]
    page = _page(rows, limit=5)
    assert [item.id for item in page.items] == [0, 1, 2, 3, 4]
    assert page.has_more is True
    assert decode_cursor(page.next_cursor) == Cursor(key=4, item_id=4)

    exhausted = _page(rows[:4], limit=5)
    assert exhausted.has_more is False
    assert exhausted.next_cursor is None


def test_the_first_page_has_no_previous_cursor() -> None:
    page = _page([_Row(i, i) for i in range(3)], limit=2)
    assert page.prev_cursor is None


def test_a_page_reached_by_cursor_offers_a_previous_cursor() -> None:
    # ``build_page`` is handed the window the store already fetched (strictly after the
    # boundary), not the whole collection.
    page = build_page(
        [_Row(2, 2), _Row(3, 3)],
        limit=2,
        key_of=lambda row: row.key,
        id_of=lambda row: row.id,
        cursor=Cursor(key=1, item_id=1),
        backward=False,
    )
    assert [item.id for item in page.items] == [2, 3]
    assert decode_cursor(page.prev_cursor) == Cursor(key=2, item_id=2, backward=True)


# --------------------------------------------------------------------------- sequence paging
def test_iterating_a_sequence_by_cursor_yields_every_item_once() -> None:
    rows = [_Row(f"{index:03d}", index) for index in range(25)]
    seen: list[int] = []
    cursor: Cursor | None = None
    for _ in range(20):
        page = paginate_sequence(
            rows,
            limit=7,
            key_of=lambda row: row.key,
            id_of=lambda row: row.id,
            cursor=cursor,
        )
        seen.extend(item.id for item in page.items)
        if page.next_cursor is None:
            break
        cursor = decode_cursor(page.next_cursor)
    assert seen == list(range(25))


def test_paging_backwards_returns_the_previous_page_in_forward_order() -> None:
    rows = [_Row(f"{index:03d}", index) for index in range(20)]
    third = paginate_sequence(
        rows,
        limit=5,
        key_of=lambda r: r.key,
        id_of=lambda r: r.id,
        cursor=Cursor(key="009", item_id=9),
    )
    assert [item.id for item in third.items] == [10, 11, 12, 13, 14]
    back = paginate_sequence(
        rows,
        limit=5,
        key_of=lambda r: r.key,
        id_of=lambda r: r.id,
        cursor=decode_cursor(third.prev_cursor),
    )
    assert [item.id for item in back.items] == [5, 6, 7, 8, 9]


def test_a_shared_sort_key_does_not_skip_rows_thanks_to_the_tiebreaker() -> None:
    """The pitfall the cursor exists to avoid: equal sort keys, distinct ids."""
    rows = [_Row("high", index) for index in range(6)]
    seen: list[int] = []
    cursor: Cursor | None = None
    while True:
        page = paginate_sequence(
            rows, limit=2, key_of=lambda r: r.key, id_of=lambda r: r.id, cursor=cursor
        )
        seen.extend(item.id for item in page.items)
        if page.next_cursor is None:
            break
        cursor = decode_cursor(page.next_cursor)
    assert seen == [0, 1, 2, 3, 4, 5]


# --------------------------------------------------------------------------- headers
def test_a_link_header_names_next_and_prev() -> None:
    from starlette.requests import Request

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/findings",
            "query_string": b"limit=5",
            "headers": [],
        }
    )
    header = link_header(request, next_cursor="AAA", prev_cursor="BBB")
    assert header is not None
    assert 'rel="next"' in header and 'rel="prev"' in header
    assert "cursor=AAA" in header and "cursor=BBB" in header


def test_the_page_headers_report_the_clamped_limit_and_the_next_cursor() -> None:
    from starlette.requests import Request
    from starlette.responses import Response

    request = Request(
        {"type": "http", "method": "GET", "path": "/x", "query_string": b"", "headers": []}
    )
    response = Response()
    page = _page([_Row(i, i) for i in range(6)], limit=5)
    apply_page(response, request, page)
    assert response.headers["X-Limit"] == "5"
    assert response.headers["X-Has-More"] == "true"
    assert response.headers["X-Next-Cursor"] == page.next_cursor
    assert 'rel="next"' in response.headers["Link"]


# --------------------------------------------------------------------------- vocabulary
class _Request:
    """The minimum ``Request`` surface the guard reads: ``query_params``."""

    def __init__(self, **params: str) -> None:
        self.query_params = params


def test_an_unknown_query_field_is_a_400_naming_it() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as info:
        reject_unknown_query_params(_Request(severiity="high"), {"severity"})
    assert info.value.status_code == 400
    assert "severiity" in info.value.detail


def test_the_pagination_and_tenant_parameters_are_always_allowed() -> None:
    reject_unknown_query_params(
        _Request(limit="5", cursor="x", sort="id", order="asc", offset="0", project="acme"),
        frozenset(),
    )


def test_a_declared_filter_is_allowed() -> None:
    reject_unknown_query_params(_Request(severity="high", q="env"), {"severity", "q"})


def test_an_unknown_sort_field_is_a_400_naming_it() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as info:
        resolve_sort_field("sev", ("id", "severity"), default="id")
    assert info.value.status_code == 400
    assert "sev" in info.value.detail
    assert resolve_sort_field(None, ("id", "severity"), default="id") == "id"
    assert resolve_sort_field("severity", ("id", "severity"), default="id") == "severity"
