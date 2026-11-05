"""Feed freshness: what the deployment's scanning is actually built on (REQ-INTEL-001).

Freshness is a *property of the toolchain*, not of the target, and a report that omits it is
quietly overconfident: "no KEV match" means something very different against a catalogue from
yesterday and one from last quarter. This module turns the feed store's contents into a small,
stable snapshot that

* the scan records in ``scans.stats["intel"]`` at admission, and
* the report renders in its freshness section (schema 1.4),

so the answer travels with the evidence instead of depending on when someone re-read the
database. The snapshot is deliberately boring: per feed kind, which artefact is active, its
upstream version, when it was imported, how old that is, whether the configured TTL makes it
stale, and whether it was verified (and how).

Nothing here contacts anything. It reads :class:`~arachne.data.feed_store.FeedStore`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arachne.core.config import (
    OPT_IN_OSINT_PROVIDERS,
    SEVERITY_FEED_KINDS,
    Settings,
)
from arachne.data.feed_store import FEED_KINDS, FeedRecord, FeedStore

__all__ = [
    "FeedObservation",
    "intel_snapshot",
    "observations_from_store",
    "sla_warnings",
]

#: How many decimal places an age is reported with (hours): one is plenty and keeps the
#: report stable across two renders of the same scan.
_AGE_PRECISION = 1


@dataclass(frozen=True, slots=True)
class FeedObservation:
    """One feed kind's current state: *is our data current, and do we trust it?*"""

    kind: str
    name: str
    version: str | None
    source: str | None
    imported_at: datetime | None
    age_hours: float | None
    ttl_hours: float
    stale: bool
    record_count: int
    verified: bool
    verification: str | None
    digest: str | None
    feed_id: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "imported_at": self.imported_at.isoformat() if self.imported_at else None,
            "age_hours": self.age_hours,
            "ttl_hours": self.ttl_hours,
            "stale": self.stale,
            "record_count": self.record_count,
            "verified": self.verified,
            "verification": self.verification,
            "digest": self.digest,
            "feed_id": self.feed_id,
        }


def _age_hours(imported_at: datetime | None, now: datetime) -> float | None:
    if imported_at is None:
        return None
    delta = now - imported_at
    return round(delta.total_seconds() / 3600.0, _AGE_PRECISION)


def observe(record: FeedRecord, *, ttl_hours: float, now: datetime) -> FeedObservation:
    """The observation for one active feed record."""
    meta = dict(record.meta or {})
    verification = meta.get("verification")
    mode = str(verification["mode"]) if isinstance(verification, Mapping) else None
    age = _age_hours(record.created_at, now)
    verified = bool(meta.get("verified"))
    # A feed is stale when it is older than its TTL *and* the deployment configured one: a
    # kind with no TTL is reported with ``stale=False`` rather than an invented threshold.
    stale = bool(ttl_hours) and (age is None or age > ttl_hours)
    return FeedObservation(
        kind=record.kind,
        name=record.name,
        version=record.version,
        source=record.source,
        imported_at=record.created_at,
        age_hours=age,
        ttl_hours=ttl_hours,
        stale=stale,
        record_count=record.record_count,
        verified=verified,
        verification=mode,
        digest=str(meta.get("sha256")) if meta.get("sha256") else None,
        feed_id=record.id,
    )


def observations_from_store(
    store: FeedStore,
    *,
    ttl_hours: Mapping[str, float] | Callable[[str], float] | None = None,
    now: datetime | None = None,
    kinds: Sequence[str] = FEED_KINDS,
) -> tuple[FeedObservation, ...]:
    """The active feed of every kind, as observations (missing kinds are included as empty).

    An operator cannot tell "no KEV feed, so no match" from "no KEV match" unless the absence
    is visible, so a kind with no import is reported too — with ``record_count=0`` and
    ``imported_at=None``, which the report renders as "not ingested".
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    configured: Mapping[str, float] = {} if callable(ttl_hours) else (ttl_hours or {})

    def ttl_for(kind: str) -> float:
        if callable(ttl_hours):
            return float(ttl_hours(kind))
        return float(configured.get(kind, 0.0))

    observations: list[FeedObservation] = []
    for kind in kinds:
        record = store.active(kind)
        if record is None:
            ttl = ttl_for(kind)
            observations.append(
                FeedObservation(
                    kind=kind,
                    name="",
                    version=None,
                    source=None,
                    imported_at=None,
                    age_hours=None,
                    ttl_hours=ttl,
                    stale=bool(ttl),
                    record_count=0,
                    verified=False,
                    verification=None,
                    digest=None,
                    feed_id=0,
                )
            )
            continue
        observations.append(observe(record, ttl_hours=ttl_for(kind), now=moment))
    return tuple(observations)


def sla_warnings(
    observations: Sequence[FeedObservation], severity_feeds: Sequence[str]
) -> tuple[str, ...]:
    """One visible warning per severity-contributing feed past its SLA (WP-21, REQ-INTEL-006).

    A warning, not an error: the scan completed and its report is valid — it just says that
    the data behind its severity ordering is old. A feed that was never ingested is *not*
    warned about here; it is named under ``missing``, because "absent" and "out of date" call
    for different operator action and conflating them would make the warning noise.
    """
    wanted = {kind.strip().lower() for kind in severity_feeds}
    warnings: list[str] = []
    for item in observations:
        if item.kind not in wanted or item.imported_at is None or not item.stale:
            continue
        age = f"{item.age_hours:.1f} h" if item.age_hours is not None else "unknown age"
        warnings.append(
            f"{item.kind} feed is {age} old, past its {item.ttl_hours:.0f} h freshness SLA; "
            f"severity enrichment for this scan may be understated"
        )
    return tuple(warnings)


def intel_snapshot(
    store: FeedStore | None,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The ``stats["intel"]`` snapshot for one scan.

    ``store=None`` (a deployment without a feed store, or a unit test) still produces a valid
    snapshot: every kind is reported as not ingested, so a report never has to special-case
    "intel section missing". Providers are listed by *name* only — which third-party indexes
    this deployment is allowed to consult — never with a key, a URL or a query.
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    intel = settings.intel if settings is not None else None
    ttl = dict(intel.freshness_ttl) if intel is not None else {}
    observations: tuple[FeedObservation, ...] = ()
    if store is not None:
        observations = observations_from_store(store, ttl_hours=ttl, now=moment)
    else:
        observations = tuple(
            FeedObservation(
                kind=kind,
                name="",
                version=None,
                source=None,
                imported_at=None,
                age_hours=None,
                ttl_hours=float(ttl.get(kind, 0.0)),
                stale=False,
                record_count=0,
                verified=False,
                verification=None,
                digest=None,
                feed_id=0,
            )
            for kind in FEED_KINDS
        )
    osint = settings.osint if settings is not None else None
    enabled_providers = list(osint.providers) if osint is not None and osint.enabled else []
    severity_feeds = (
        tuple(settings.intel.severity_feeds) if settings is not None else SEVERITY_FEED_KINDS
    )
    return {
        "generated_at": moment.isoformat(),
        # "Stale" is about data that exists and is old. A kind that was never ingested is
        # listed under "missing" instead: it is absent, not out of date, and the two call for
        # different operator action.
        "stale": any(item.stale for item in observations if item.imported_at is not None),
        "missing": [item.kind for item in observations if item.imported_at is None],
        "feeds": [item.to_dict() for item in observations],
        # WP-21 (REQ-INTEL-006): which kinds move severity, and the visible warnings that
        # follow when one of them is past its SLA. Both are recorded in the snapshot so the
        # report can state them without reaching back into a configuration that may have
        # changed since the scan ran.
        "severity_feeds": list(severity_feeds),
        "warnings": list(sla_warnings(observations, severity_feeds)),
        "providers": {
            "enabled": enabled_providers,
            # The providers this build can consume, so a report reader can tell an absent
            # finding from an unusable source (REQ-INTEL-005's graceful degradation).
            "opted_in": [name for name in enabled_providers if name in OPT_IN_OSINT_PROVIDERS],
        },
    }
