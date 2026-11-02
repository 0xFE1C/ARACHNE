"""Integration: cursor pagination, the filter vocabulary and the shared cursor component.

Every assertion goes through ``fastapi.testclient`` against the assembled app, because the
contract is a property of the wire (the body, the ``Link`` header, the status code), not of
a handler.

The two that matter most:

* iterating every page of ``/findings`` returns exactly the unpaginated set — the cursor's
  ``id`` tiebreaker is what makes that true when two findings share a sort key;
* the same holds while another thread is inserting findings, which is the situation the
  naive ``LIMIT``/``OFFSET`` implementation silently broke.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest
from tests.helpers.api import VIEWER_KEY, ApiHarness, auth, make_api_harness

from arachne.api.pagination import MAX_LIMIT

pytestmark = pytest.mark.integration


@pytest.fixture
def harness(tmp_path) -> Iterator[ApiHarness]:  # type: ignore[no-untyped-def]
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


def _seed(harness: ApiHarness, count: int, *, severity: str | None = "high") -> list[int]:
    return [
        harness.seed_finding(title=f"finding {index}", severity=severity) for index in range(count)
    ]


def _page_all(client, headers, url: str, *, attribute: str = "X-Next-Cursor") -> list[int]:  # type: ignore[no-untyped-def]
    """Follow ``next`` until exhausted; return the ids of every row seen, in order."""
    seen: list[int] = []
    pages = 0
    while True:
        response = client.get(url, headers=headers)
        assert response.status_code == 200, response.text
        seen.extend(row["id"] for row in response.json())
        pages += 1
        cursor = response.headers.get(attribute)
        if cursor is None:
            break
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}cursor={cursor}"
        assert pages < 100, "the cursor did not terminate"
    return seen


# --------------------------------------------------------------------------- iteration
def test_iterating_every_page_of_findings_yields_exactly_the_unpaginated_set(
    harness: ApiHarness,
) -> None:
    planted = _seed(harness, 37)
    with harness.client() as client:
        unpaginated = [
            row["id"] for row in client.get("/api/v1/findings", headers=auth(VIEWER_KEY)).json()
        ]
        paged = _page_all(client, auth(VIEWER_KEY), "/api/v1/findings?limit=10")
    assert paged == unpaginated
    assert len(paged) == len(set(paged)) == len(planted)


def test_two_findings_with_the_same_sort_key_are_never_skipped(harness: ApiHarness) -> None:
    """The pitfall: without the id tiebreaker, a boundary can drop a row sharing a key."""
    planted = _seed(harness, 11, severity="high")
    with harness.client() as client:
        paged = _page_all(client, auth(VIEWER_KEY), "/api/v1/findings?sort=severity&limit=3")
    assert sorted(paged) == sorted(planted)


def test_pagination_holds_while_another_thread_inserts_findings(harness: ApiHarness) -> None:
    planted = _seed(harness, 30)
    stop = threading.Event()
    inserted: list[int] = []
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            index = 0
            while not stop.is_set():
                inserted.append(harness.seed_finding(title=f"concurrent {index}", severity="low"))
                index += 1
        except BaseException as exc:  # pragma: no cover - only on a real failure
            errors.append(exc)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        with harness.client() as client:
            paged = _page_all(client, auth(VIEWER_KEY), "/api/v1/findings?limit=6")
    finally:
        stop.set()
        thread.join(timeout=10)

    assert not errors, errors
    assert len(paged) == len(set(paged)), "a row was returned twice"
    assert set(planted) <= set(paged), "a pre-existing row was skipped under concurrent inserts"
    assert inserted, "the writer thread never inserted anything"


def test_the_link_header_walks_forwards_and_backwards(harness: ApiHarness) -> None:
    _seed(harness, 10)
    with harness.client() as client:
        first = client.get("/api/v1/findings?limit=4", headers=auth(VIEWER_KEY))
        assert first.headers["X-Has-More"] == "true"
        assert 'rel="next"' in first.headers["Link"]
        assert (
            "rel=" not in first.headers["Link"].split(",")[-1]
            or "prev" not in first.headers["Link"]
        )

        page_two = client.get(
            f"/api/v1/findings?limit=4&cursor={first.headers['X-Next-Cursor']}",
            headers=auth(VIEWER_KEY),
        )
        assert 'rel="prev"' in page_two.headers["Link"]
        previous = client.get(
            f"/api/v1/findings?limit=4&cursor={page_two.headers['X-Prev-Cursor']}",
            headers=auth(VIEWER_KEY),
        )
        assert [row["id"] for row in previous.json()] == [row["id"] for row in first.json()]


# --------------------------------------------------------------------------- clamp
def test_a_limit_above_the_documented_maximum_is_clamped(harness: ApiHarness) -> None:
    _seed(harness, 3)
    with harness.client() as client:
        response = client.get("/api/v1/findings?limit=100000", headers=auth(VIEWER_KEY))
        assert response.status_code == 200
        assert response.headers["X-Limit"] == str(MAX_LIMIT)
        scans = client.get("/api/v1/scans?limit=100000", headers=auth(VIEWER_KEY))
        assert scans.headers["X-Limit"] == str(MAX_LIMIT)


# --------------------------------------------------------------------------- vocabulary
def test_an_unknown_filter_field_is_a_400_naming_the_field(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.get("/api/v1/findings?severiity=high", headers=auth(VIEWER_KEY))
        assert response.status_code == 400
        assert "severiity" in response.json()["error"]["message"]
        scans = client.get("/api/v1/scans?sttatus=completed", headers=auth(VIEWER_KEY))
        assert scans.status_code == 400
        assert "sttatus" in scans.json()["error"]["message"]


def test_an_unknown_sort_field_is_refused(harness: ApiHarness) -> None:
    """``sort`` publishes its vocabulary as an enum, so a bad value is FastAPI's 422."""
    with harness.client() as client:
        response = client.get("/api/v1/findings?sort=nonsense", headers=auth(VIEWER_KEY))
    assert response.status_code == 422
    assert "nonsense" in response.text


def test_a_malformed_cursor_is_a_400_not_a_500(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.get("/api/v1/findings?cursor=not-a-cursor", headers=auth(VIEWER_KEY))
    assert response.status_code == 400


def test_an_unknown_severity_value_is_refused(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.get("/api/v1/findings?severity=apocalyptic", headers=auth(VIEWER_KEY))
    assert response.status_code == 422


def test_each_finding_filter_excludes_what_it_claims_to_exclude(harness: ApiHarness) -> None:
    high = harness.seed_finding(title="exposed .env", severity="high")
    low = harness.seed_finding(
        title="missing header",
        check_key="M3/security-headers@1.0",
        severity="low",
        asset=("url", "https://example.com/app"),
    )
    unanalysed = harness.seed_finding(title="unclassified", severity=None)
    with harness.client() as client:

        def ids(query: str) -> list[int]:
            return [
                row["id"]
                for row in client.get(f"/api/v1/findings?{query}", headers=auth(VIEWER_KEY)).json()
            ]

        assert ids("severity=high") == [high]
        assert ids("severity=low") == [low]
        assert ids("severity=unanalysed") == [unanalysed]
        assert ids("module=M3") == [low]
        assert ids("asset=/app") == [low]
        assert ids("q=header") == [low]
        assert ids("cwe=CWE-200") == sorted([high, low, unanalysed])
        assert ids("status=open") == sorted([high, low, unanalysed])


def test_sorting_is_totally_ordered(harness: ApiHarness) -> None:
    _seed(harness, 6, severity="high")
    _seed(harness, 4, severity="low")
    with harness.client() as client:
        rows = client.get(
            "/api/v1/findings?sort=severity&limit=20", headers=auth(VIEWER_KEY)
        ).json()
        assert [row["severity"] for row in rows] == ["high"] * 6 + ["low"] * 4
        descending = client.get(
            "/api/v1/findings?sort=severity&order=desc&limit=20", headers=auth(VIEWER_KEY)
        ).json()
        assert [row["severity"] for row in descending] == ["low"] * 4 + ["high"] * 6
        assert [row["id"] for row in rows] == sorted(row["id"] for row in rows)


# --------------------------------------------------------------------------- scans
def test_scans_paginate_and_accept_a_validated_status_filter(harness: ApiHarness) -> None:
    planted = [harness.seed_scan() for _ in range(5)]
    with harness.client() as client:
        paged = _page_all(client, auth(VIEWER_KEY), "/api/v1/scans?limit=2")
        assert sorted(paged) == sorted(planted)
        pending = client.get(
            "/api/v1/scans?status=pending&limit=2", headers=auth(VIEWER_KEY)
        ).json()
        assert len(pending) == 2
        assert all(row["status"] == "pending" for row in pending)
        completed = client.get("/api/v1/scans?status=completed", headers=auth(VIEWER_KEY)).json()
        assert completed == []
        by_target = client.get(f"/api/v1/scans?target_id={planted and 1}", headers=auth(VIEWER_KEY))
        assert by_target.status_code == 200


# --------------------------------------------------------------------------- OpenAPI
def test_the_cursor_parameter_is_documented_once_as_a_shared_component(harness: ApiHarness) -> None:
    with harness.client() as client:
        spec = client.get("/openapi.json").json()
    parameters = spec["components"]["parameters"]
    assert "Cursor" in parameters, "the cursor must be a shared component"
    assert parameters["Cursor"]["name"] == "cursor"
    assert parameters["Cursor"]["in"] == "query"

    inline = [
        f"{method.upper()} {path}"
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in {"get", "post", "put", "patch", "delete"}
        and isinstance(operation, dict)
        and any(
            isinstance(parameter, dict) and parameter.get("name") == "cursor"
            for parameter in operation.get("parameters") or []
        )
    ]
    assert inline == [], f"the cursor parameter is repeated inline on {inline}"

    paginated = sorted(
        f"{method.upper()} {path}"
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in {"get", "post", "put", "patch", "delete"}
        and isinstance(operation, dict)
        and operation.get("x-arachne-paginated")
    )
    assert len(paginated) == 8, paginated


def test_the_limit_maximum_is_documented(harness: ApiHarness) -> None:
    with harness.client() as client:
        spec = client.get("/openapi.json").json()
    findings = spec["paths"]["/api/v1/findings"]["get"]
    limit = next(p for p in findings["parameters"] if p.get("name") == "limit")
    assert limit["schema"].get("maximum") in (None, MAX_LIMIT)
    assert "clamped" in limit["description"]
