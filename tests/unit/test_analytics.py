"""k-anonymised cross-tenant aggregates (WP-21, REQ-DATA-008).

The exit criteria, one test each: a nine-tenant bucket is suppressed entirely, the suppression
is stated rather than silent, and two overlapping published queries cannot be differenced to
recover one tenant's value. The floor of k = 10 is enforced at the call site, not trusted.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.data.analytics import MIN_K, Observation, cross_tenant_aggregate


def _rows(query: str, tenants: int, *, value: float = 10.0) -> list[Observation]:
    return [
        Observation(tenant=f"tenant-{index}", query=query, value=value) for index in range(tenants)
    ]


def test_a_nine_tenant_bucket_is_suppressed_entirely() -> None:
    report = cross_tenant_aggregate(_rows("industry-median", 9))

    assert report.buckets == ()
    assert report.value_for("industry-median") is None
    assert len(report.suppressed) == 1
    entry = report.suppressed[0]
    assert entry.query == "industry-median"
    assert entry.tenants == 9
    assert "fewer than k=10" in entry.reason


def test_a_ten_tenant_bucket_is_published_as_a_mean() -> None:
    rows = [
        Observation(tenant=f"tenant-{index}", query="industry-median", value=float(index))
        for index in range(10)
    ]
    report = cross_tenant_aggregate(rows)

    assert report.value_for("industry-median") == pytest.approx(4.5)
    assert report.buckets[0].tenants == 10
    assert report.suppressed == ()


def test_duplicate_contributions_from_one_tenant_are_summed_not_counted_twice() -> None:
    """A tenant is one participant however many rows it contributes."""
    rows = _rows("bucket", 9, value=1.0) + _rows("bucket", 9, value=1.0)
    report = cross_tenant_aggregate(rows)
    # Eighteen rows, nine tenants: still below k, and the mean would be over nine values.
    assert report.value_for("bucket") is None
    assert report.suppressed[0].tenants == 9


def test_two_overlapping_queries_cannot_difference_out_one_tenant() -> None:
    """The complementary-suppression criterion: A minus B may not leave a sub-k remainder."""
    shared = [Observation(tenant=f"tenant-{index}", query="wide", value=5.0) for index in range(10)]
    # ``wide`` covers tenants 0..10; ``narrow`` covers tenants 0..9. Both are >= k on their
    # own, but wide minus narrow is exactly one tenant.
    wide = [*shared, Observation(tenant="tenant-10", query="wide", value=9.0)]
    narrow = [
        Observation(tenant=f"tenant-{index}", query="narrow", value=3.0) for index in range(10)
    ]

    report = cross_tenant_aggregate(wide + narrow)

    assert report.buckets == (), "a differenceable pair must not be published"
    suppressed = {item.query: item for item in report.suppressed}
    assert set(suppressed) == {"wide", "narrow"}
    assert all("differencing" in item.reason for item in suppressed.values())
    # The report says so, rather than returning an empty list of buckets with no explanation.
    document = report.to_dict()
    assert document["note"]
    assert {item["query"] for item in document["suppressed"]} == {"wide", "narrow"}


def test_a_suppressed_overlap_cannot_be_used_to_subtract_at_all() -> None:
    """The other shape of the attack: the small bucket is withheld, so there is nothing to
    subtract from the large one."""
    rows = _rows("wide", 11) + _rows("tiny", 2)
    report = cross_tenant_aggregate(rows)

    assert report.value_for("wide") is not None
    assert report.value_for("tiny") is None


def test_k_below_ten_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="k-anonymity needs k"):
        cross_tenant_aggregate(_rows("bucket", 20), k=9)
    # The module's own floor is the documented minimum.
    assert MIN_K == 10


def test_an_observation_without_a_tenant_or_query_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        cross_tenant_aggregate([Observation(tenant="", query="bucket", value=1.0)])
    with pytest.raises(ConfigurationError):
        cross_tenant_aggregate([Observation(tenant="t", query="  ", value=1.0)])


def test_disjoint_queries_are_both_published() -> None:
    """Complementary suppression must not silence comparisons that cannot be differenced."""
    rows = _rows("first", 10) + [
        Observation(tenant=f"other-{index}", query="second", value=2.0) for index in range(10)
    ]
    report = cross_tenant_aggregate(rows)
    assert set(report.queries) == {"first", "second"}
    assert report.suppressed == ()
