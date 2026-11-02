"""Scrape-time collection of the deployment-wide metrics (REQ-OPS-003).

The registry holds what *this process* did (counters) — the standard Prometheus scrape-target
semantics. Everything else an operator needs to act on is a property of the deployment, not of
one worker: how many scans are queued, which agents are alive, how stale the feeds are, how
much storage each project holds. Those are read from the database at scrape time, so a scrape
against any worker describes the whole fleet, and a metric cannot go stale because a process
restarted.

Two rules keep the endpoint safe and cheap:

* **Nothing target-identifying is exposed.** No host, asset, finding title or evidence payload
  reaches a label; the families are counts, depths, ages and ratios. ``/metrics`` is a public
  endpoint in the same sense ``/health`` is, so that is a privacy property, not a convention.
* **Gauge families are cleared before they are re-set.** A deleted project or a retired agent
  must stop being reported, not freeze at its last value.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from arachne.core.config import get_settings
from arachne.core.metrics import REGISTRY, MetricsRegistry
from arachne.data.models import ScanAgent, ScanQueue
from arachne.data.schema import LATEST_SCHEMA_REVISION

__all__ = ["collect_deployment_metrics", "gauge_families"]

#: The families whose series describe current state (cleared before each scrape).
_GAUGES = (
    "arachne_queue_depth",
    "arachne_queue_oldest_age_seconds",
    "arachne_queue_leases",
    "arachne_agents",
    "arachne_agent_heartbeat_age_seconds",
    "arachne_feed_age_hours",
    "arachne_feed_stale",
    "arachne_feed_records",
    "arachne_storage_used_bytes",
    "arachne_storage_quota_ratio",
    "arachne_build_info",
    "arachne_scans",
)


def gauge_families() -> tuple[str, ...]:
    """The families :func:`collect_deployment_metrics` owns."""
    return _GAUGES


def collect_deployment_metrics(
    services: Any = None,
    *,
    registry: MetricsRegistry = REGISTRY,
    now: datetime | None = None,
) -> None:
    """Refresh every deployment-wide gauge. Best-effort: one failing source is skipped."""
    moment = now or datetime.now(UTC)
    for name in _GAUGES:
        registry.clear_family(name)
    if services is None:
        return
    settings = getattr(services, "settings", None) or get_settings()
    factory = services.session_factory
    _scan_gauges(registry, factory)
    _queue_gauges(registry, services, factory, moment)
    _agent_gauges(registry, services, factory, moment)
    _feed_gauges(registry, services, settings)
    _storage_gauges(registry, services)
    from arachne import __version__

    registry.set(
        "arachne_build_info",
        1.0,
        {"version": __version__, "schema_revision": LATEST_SCHEMA_REVISION},
    )


def _scan_gauges(registry: MetricsRegistry, factory: Any) -> None:
    """Scan counts by status — the deployment's throughput and backlog at a glance.

    ``arachne_scans_total`` (a counter) is what *this process* finished; ``arachne_scans`` (a
    gauge, from the database) is what the deployment holds. Both are useful and they answer
    different questions, which is why the endpoint exposes both rather than conflating them.
    """
    from arachne.data.models import Scan

    try:
        with factory() as session:
            rows = session.execute(select(Scan.status, func.count()).group_by(Scan.status)).all()
    except Exception:
        return
    for status, count in rows:
        registry.set("arachne_scans", float(count), {"status": str(status)})


def _queue_gauges(registry: MetricsRegistry, services: Any, factory: Any, now: datetime) -> None:
    queue = getattr(services, "queue", None)
    stats: dict[str, int] = {}
    if queue is not None:
        try:
            stats = {str(key): int(value) for key, value in queue.stats().items()}
        except Exception:  # a queue read failure must not break a scrape
            stats = {}
    for status in ("queued", "leased", "done", "cancelled"):
        registry.set("arachne_queue_depth", float(stats.get(status, 0)), {"status": status})
    registry.set("arachne_queue_leases", float(stats.get("leased", 0)))
    oldest = None
    try:
        with factory() as session:
            oldest = session.scalar(
                select(func.min(ScanQueue.created_at)).where(ScanQueue.status == "queued")
            )
    except Exception:
        oldest = None
    registry.set("arachne_queue_oldest_age_seconds", _age_seconds(oldest, now) or 0.0)


def _agent_gauges(registry: MetricsRegistry, services: Any, factory: Any, now: datetime) -> None:
    agents = getattr(services, "agents", None)
    records: tuple[Any, ...] = ()
    if agents is not None:
        try:
            records = agents.list_agents()
        except Exception:
            records = ()
    counts: dict[str, int] = {}
    for record in records:
        counts[str(record.status)] = counts.get(str(record.status), 0) + 1
        registry.set(
            "arachne_agent_heartbeat_age_seconds",
            _age_seconds(record.last_heartbeat_at, now),
            {"agent": str(record.name)},
        )
    if not records:
        # Fall back to the table when the registry is not wired (a read-only worker).
        try:
            with factory() as session:
                rows = session.execute(
                    select(ScanAgent.status, func.count()).group_by(ScanAgent.status)
                ).all()
            counts = {str(status): int(count) for status, count in rows}
        except Exception:
            counts = {}
    for status, count in counts.items():
        registry.set("arachne_agents", float(count), {"status": status})


def _feed_gauges(registry: MetricsRegistry, services: Any, settings: Any) -> None:
    feeds = getattr(services, "feeds", None)
    if feeds is None:
        return
    try:
        from arachne.intel.freshness import observations_from_store

        observations = observations_from_store(feeds, ttl_hours=dict(settings.intel.freshness_ttl))
    except Exception:
        return
    for observation in observations:
        labels = {"feed": str(observation.kind)}
        age = observation.age_hours
        registry.set("arachne_feed_age_hours", -1.0 if age is None else float(age), labels)
        registry.set("arachne_feed_stale", 1.0 if observation.stale else 0.0, labels)
        registry.set("arachne_feed_records", float(observation.record_count), labels)


def _storage_gauges(registry: MetricsRegistry, services: Any) -> None:
    quota = getattr(services, "quota", None)
    if quota is None:
        return
    try:
        overview = quota.overview()
    except Exception:
        return
    for entry in overview:
        labels = {"project": str(entry["slug"])}
        registry.set("arachne_storage_used_bytes", float(entry["used_bytes"]), labels)
        registry.set("arachne_storage_quota_ratio", float(entry["ratio"]), labels)


def _age_seconds(value: datetime | None, now: datetime) -> float:
    """Seconds between ``value`` and ``now`` (``-1`` when the value is absent)."""
    if value is None:
        return -1.0
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return max(0.0, (now - aware).total_seconds())
