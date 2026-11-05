"""k-anonymised cross-tenant aggregates (WP-21, REQ-DATA-008).

An "industry comparison" or a benchmark shared between tenants is computed from *their* data,
and a small bucket is a re-identification: with nine tenants in a bucket, "the average is X"
plus a public fact about one of them is often the individual value. This module is the one
gate such a feature is allowed to compute through.

Two rules, and the second is the one naive k-anonymity misses:

**A bucket below k is suppressed entirely.** k is at least :data:`MIN_K` (10); a smaller value
is refused rather than quietly honoured. A suppressed bucket is *absent* from the result and
*named* in ``suppressed`` with its tenant count and reason — the suppression is stated, not
silent, because a user who sees four of five requested comparisons must be able to tell "there
is not enough data to show this" from "the feature is broken".

**Overlapping queries are suppressed when they could be differenced.** Showing query A (11
tenants) and query B (2 tenants) is safe bucket-by-bucket only if B is suppressed — but even
then, A minus B leaves nine tenants, which is below k. So complementary suppression runs too:
if two kept queries overlap and one's difference from the other has between one and k-1
tenants, *both* are suppressed (repeated to a fixpoint, since suppressing one can change what
another exposes). A tenant's individual contribution can therefore never be recovered by
subtracting two published aggregates.

The input is deliberately plain — ``(tenant, query, value)`` rows — so a caller cannot hand a
pre-aggregated bucket to this module and have the k-check applied to the wrong thing. Values
are summed per (query, tenant) first; the published figure is the mean over at least k
tenants, rounded to six decimals so two runs of the same data are byte-identical.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "MIN_K",
    "AggregateReport",
    "Bucket",
    "Observation",
    "Suppression",
    "cross_tenant_aggregate",
]

#: The smallest bucket this module will publish. The requirement says "k of at least 10"; a
#: caller asking for less is refused rather than trusted.
MIN_K: Final = 10

#: The statement every result carries. A consumer that renders only ``buckets`` still has this
#: in the document, so its output can say what was withheld.
_SUPPRESSION_NOTE: Final = (
    "buckets with fewer than k tenants are suppressed entirely; a query is also suppressed "
    "when differencing it against another published query would isolate fewer than k tenants"
)


@dataclass(frozen=True, slots=True)
class Observation:
    """One tenant's contribution to one query."""

    tenant: str
    query: str
    value: float


@dataclass(frozen=True, slots=True)
class Suppression:
    """Why one requested query has no published value."""

    query: str
    tenants: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"query": self.query, "tenants": self.tenants, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class Bucket:
    """One published comparison: the mean over at least ``k`` tenants."""

    query: str
    tenants: int
    value: float

    def to_dict(self) -> dict[str, Any]:
        return {"query": self.query, "tenants": self.tenants, "value": self.value}


@dataclass(frozen=True, slots=True)
class AggregateReport:
    """The whole answer: what could be published, and what was withheld and why."""

    k: int
    buckets: tuple[Bucket, ...] = ()
    suppressed: tuple[Suppression, ...] = ()
    note: str = _SUPPRESSION_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "k": self.k,
            "note": self.note,
            "buckets": [bucket.to_dict() for bucket in self.buckets],
            "suppressed": [item.to_dict() for item in self.suppressed],
        }

    def value_for(self, query: str) -> float | None:
        """The published value for ``query``, or ``None`` when it was suppressed."""
        for bucket in self.buckets:
            if bucket.query == query:
                return bucket.value
        return None

    @property
    def queries(self) -> tuple[str, ...]:
        return tuple(bucket.query for bucket in self.buckets)


def _group(
    observations: Iterable[Observation],
) -> dict[str, dict[str, float]]:
    grouped: dict[str, dict[str, float]] = {}
    for item in observations:
        tenant = str(item.tenant).strip()
        query = str(item.query).strip()
        if not tenant or not query:
            msg = "an aggregate observation needs both a tenant and a query"
            raise ConfigurationError(msg)
        per_tenant = grouped.setdefault(query, {})
        per_tenant[tenant] = per_tenant.get(tenant, 0.0) + float(item.value)
    return grouped


def cross_tenant_aggregate(
    observations: Iterable[Observation], *, k: int = MIN_K
) -> AggregateReport:
    """Aggregate per-query values across tenants, publishing nothing below ``k``.

    ``None`` (or anything below :data:`MIN_K`) is refused: the requirement's floor is not a
    default another feature may lower at the call site.
    """
    if k < MIN_K:
        msg = f"k-anonymity needs k >= {MIN_K}; the caller asked for {k}"
        raise ConfigurationError(msg)

    grouped = _group(observations)
    ordered = sorted(grouped)
    suppressed: dict[str, Suppression] = {}
    kept: dict[str, dict[str, float]] = {}

    for query in ordered:
        per_tenant = grouped[query]
        if len(per_tenant) < k:
            suppressed[query] = Suppression(
                query=query,
                tenants=len(per_tenant),
                reason=f"fewer than k={k} tenants contribute to this bucket",
            )
        else:
            kept[query] = per_tenant

    # Complementary suppression, to a fixpoint: a pair whose difference leaves between one
    # and k-1 tenants would let a holder of both aggregates subtract to a tiny set.
    changed = True
    while changed:
        changed = False
        for first in sorted(kept):
            for second in sorted(kept):
                if first >= second:
                    continue
                difference_a = set(kept[first]) - set(kept[second])
                difference_b = set(kept[second]) - set(kept[first])
                for difference, mine, other in (
                    (difference_a, first, second),
                    (difference_b, second, first),
                ):
                    if 0 < len(difference) < k:
                        for query in (mine, other):
                            against = other if query == mine else mine
                            suppressed[query] = Suppression(
                                query=query,
                                tenants=len(grouped[query]),
                                reason=(
                                    f"differencing this query against {against!r} "
                                    f"would isolate {len(difference)} tenant(s), "
                                    f"fewer than k={k}"
                                ),
                            )
                            kept.pop(query, None)
                        changed = True
                        break
                if changed:
                    break
            if changed:
                break

    buckets = tuple(
        Bucket(
            query=query,
            tenants=len(kept[query]),
            value=round(sum(kept[query].values()) / len(kept[query]), 6),
        )
        for query in sorted(kept)
    )
    withheld = tuple(suppressed[query] for query in sorted(suppressed))
    return AggregateReport(k=k, buckets=buckets, suppressed=withheld)
