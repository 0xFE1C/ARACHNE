"""Prometheus metrics: the registry, the exposition format, and the metric contract.

REQ-OPS-003 needs one thing from this module — an endpoint whose *content* is a stable
contract — so the shape is driven by that rather than by a library:

* **No new dependency.** The exposition format is a page of text (``# HELP``/``# TYPE`` plus
  ``name{labels} value`` lines), and a metrics client library would be a build dependency in
  every deployment, including the air-gapped one. The AI layer already renders Prometheus text
  by hand (``ai/budget.py``); this module is the general form of it.
* **The families are declared, never discovered.** :data:`METRIC_FAMILIES` is the contract:
  a name, a type, a help string and its label names. ``tests/unit/test_metrics_contract.py``
  asserts that the endpoint exposes exactly these families and that each of REQ-OPS-003's six
  required signals is represented. A counter invented at a call site would not render a
  ``# TYPE`` line, so declaring first is also what keeps the output valid.
* **Label values are sanitised, not trusted.** A label value reaches the exposition format
  verbatim, so a value containing a quote or a newline would *inject* metrics lines (a target
  or agent name is attacker-influenced in the general case). Values are escaped per the
  format's rules and bounded in length, and labels are looked up from a fixed vocabulary.
* **Nothing here identifies a target.** Metric names and label sets are aggregate by
  construction: counts, durations, depths, ages. There is no label for a host, an asset, a
  finding title or an evidence payload — the endpoint is scrapeable without an API key, so a
  metric that named a target would be an information leak, not an observability win.

Counters are **process-local**: they count what this process did, which is what a Prometheus
scrape target means. The gauges are *collected from the database at scrape time* (queue depth,
agent health, feed freshness, scan counts), so they describe the whole deployment even when
several workers serve one database. The operator guide says which is which.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "CONTENT_TYPE",
    "DEFAULT_BUCKETS",
    "METRIC_FAMILIES",
    "REGISTRY",
    "MetricFamily",
    "MetricsRegistry",
    "render_metrics",
    "reset_metrics",
]

#: The Prometheus text exposition content type.
CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"

MetricKind = Literal["counter", "gauge", "histogram"]

#: Bucket bounds for a scan's wall-clock duration (seconds): a lab scan, a real one, a slow
#: one. Chosen wide and coarse — the question a scan-duration histogram answers is "did it
#: get slower", not "was it 3.1 s or 3.2 s".
SCAN_BUCKETS: Final[tuple[float, ...]] = (1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0)

#: Bucket bounds for API request latency (seconds), the usual web-service ladder.
API_BUCKETS: Final[tuple[float, ...]] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

DEFAULT_BUCKETS: Final[tuple[float, ...]] = SCAN_BUCKETS

#: Longest label value kept, and the character set an escaped value is truncated on.
_MAX_LABEL_VALUE: Final = 128


@dataclass(frozen=True, slots=True)
class MetricFamily:
    """The declared contract for one metric family."""

    name: str
    kind: MetricKind
    help: str
    label_names: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()

    @property
    def base_name(self) -> str:
        """``_total`` is part of a counter's name; Prometheus keeps it in the family name."""
        return self.name


def _family(
    name: str,
    kind: MetricKind,
    help_text: str,
    label_names: tuple[str, ...] = (),
    buckets: tuple[float, ...] = (),
) -> MetricFamily:
    return MetricFamily(name, kind, help_text, label_names, buckets)


#: Every family this build exposes (REQ-OPS-003). The six signals the requirement names are
#: marked below; the rest are the ones an operator needs to *act* on those six.
METRIC_FAMILIES: Final[tuple[MetricFamily, ...]] = (
    # --- scan counts and durations --------------------------------------------- (REQ-OPS-003)
    _family(
        "arachne_scans_total",
        "counter",
        "Scans observed by this process, by terminal or current state.",
        ("status",),
    ),
    _family(
        "arachne_scan_duration_seconds",
        "histogram",
        "Wall-clock duration of a completed scan, in seconds.",
        buckets=SCAN_BUCKETS,
    ),
    _family(
        "arachne_scan_steps_total",
        "counter",
        "Pipeline steps executed, by step and outcome.",
        ("step", "status"),
    ),
    _family(
        "arachne_scans",
        "gauge",
        "Scans held by the deployment, by status (read at scrape time).",
        ("status",),
    ),
    # --- queue depth and agent health ------------------------------------------ (REQ-OPS-003)
    _family(
        "arachne_queue_depth",
        "gauge",
        "Scans in the work queue, by queue state (deployment-wide, read at scrape time).",
        ("status",),
    ),
    _family(
        "arachne_queue_oldest_age_seconds",
        "gauge",
        "Age of the oldest queued scan in seconds (0 when the queue is empty).",
    ),
    _family(
        "arachne_agents",
        "gauge",
        "Registered agents, by status (deployment-wide, read at scrape time).",
        ("status",),
    ),
    _family(
        "arachne_agent_heartbeat_age_seconds",
        "gauge",
        "Seconds since an agent's last heartbeat (-1 when it never heartbeated).",
        ("agent",),
    ),
    _family(
        "arachne_queue_leases",
        "gauge",
        "Scans currently leased by an agent — the fleet's live work (REQ-SCALE-002).",
    ),
    # --- proof-level counters --------------------------------------------------- (REQ-OPS-003)
    _family(
        "arachne_proof_findings_total",
        "counter",
        "Proof-bearing findings recorded, by proof level (L0-L4, REQ-PROOF-001).",
        ("level",),
    ),
    _family(
        "arachne_proof_state_changes_total",
        "counter",
        "L4 state changes recorded, by cleanup status (restored / unrestored).",
        ("cleanup",),
    ),
    # --- API latency ------------------------------------------------------------ (REQ-OPS-003)
    _family(
        "arachne_api_requests_total",
        "counter",
        "HTTP requests answered, by method and status class.",
        ("method", "status"),
    ),
    _family(
        "arachne_api_request_duration_seconds",
        "histogram",
        "HTTP request latency in seconds, by method.",
        ("method",),
        API_BUCKETS,
    ),
    # --- feed freshness --------------------------------------------------------- (REQ-OPS-003)
    _family(
        "arachne_feed_age_hours",
        "gauge",
        "Hours since a feed kind was last imported (-1 when it has never been imported).",
        ("feed",),
    ),
    _family(
        "arachne_feed_stale",
        "gauge",
        "1 when a feed kind is older than its freshness TTL, else 0.",
        ("feed",),
    ),
    _family(
        "arachne_feed_records",
        "gauge",
        "Records in the active version of a feed kind.",
        ("feed",),
    ),
    # --- data lifecycle ---------------------------------------------------------
    _family(
        "arachne_retention_planned_total",
        "counter",
        "Rows a pruning run found eligible for deletion, by category (dry run or applied).",
        ("category",),
    ),
    _family(
        "arachne_retention_deleted_total",
        "counter",
        "Rows a pruning run actually deleted, by category.",
        ("category",),
    ),
    _family(
        "arachne_storage_used_bytes",
        "gauge",
        "Stored evidence bytes per project, read at scrape time (REQ-DATA-003).",
        ("project",),
    ),
    _family(
        "arachne_storage_quota_ratio",
        "gauge",
        "Used bytes divided by the project's quota (0 when no quota is configured).",
        ("project",),
    ),
    _family(
        "arachne_evidence_bytes_total",
        "counter",
        "Logical evidence bytes written through a backend, by backend.",
        ("backend",),
    ),
    _family(
        "arachne_evidence_stored_bytes_total",
        "counter",
        "Physical bytes written through a backend after compression and dedup.",
        ("backend",),
    ),
    _family(
        "arachne_evidence_dedup_hits_total",
        "counter",
        "Payloads already present in the backend, written once (REQ-DATA-004).",
        ("backend",),
    ),
    # --- process identity -------------------------------------------------------
    _family(
        "arachne_build_info",
        "gauge",
        "Always 1; the labels carry the running version and schema revision.",
        ("version", "schema_revision"),
    ),
)

_FAMILIES_BY_NAME: Final[dict[str, MetricFamily]] = {item.name: item for item in METRIC_FAMILIES}

#: Status-class labels keep API cardinality bounded (2xx/4xx/5xx), never a raw code.
_STATUS_CLASSES: Final[frozenset[str]] = frozenset({"1xx", "2xx", "3xx", "4xx", "5xx", "other"})


def _escape_label(value: str) -> str:
    """Escape a label value for the exposition format and bound its length.

    An unescaped ``"`` or newline in a label value would end the label list early and let the
    rest of the value land as *metric lines* — an injection into the scrape, not a cosmetic
    problem. Control characters are dropped rather than escaped because none of them are
    meaningful in a label.
    """
    cleaned = "".join(ch if ch >= " " else " " for ch in value)[:_MAX_LABEL_VALUE]
    return cleaned.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels_key(labels: Mapping[str, str] | None, family: MetricFamily) -> tuple[str, ...]:
    """Normalise a label mapping into the family's declared order."""
    if not family.label_names:
        if labels:
            msg = f"metric {family.name} takes no labels, got {sorted(labels)}"
            raise ValueError(msg)
        return ()
    if labels is not None and set(labels) != set(family.label_names):
        msg = (
            f"metric {family.name} wants labels {sorted(family.label_names)}, "
            f"got {sorted(labels or {})}"
        )
        raise ValueError(msg)
    return tuple(str((labels or {}).get(name, "")) for name in family.label_names)


def _render_labels(family: MetricFamily, values: tuple[str, ...]) -> str:
    if not family.label_names:
        return ""
    pairs = ", ".join(
        f'{name}="{_escape_label(value)}"'
        for name, value in zip(family.label_names, values, strict=True)
    )
    return "{" + pairs + "}"


class MetricsRegistry:
    """A tiny, thread-safe registry with a deterministic rendering order.

    The whole registry is one lock and three dictionaries. That is deliberate: metric updates
    happen on the request path (the API middleware, the evidence writer), so the cost has to be
    a dictionary write, and correctness matters more than contention at ARACHNE's scale.
    """

    def __init__(self, families: Iterable[MetricFamily] = METRIC_FAMILIES) -> None:
        self._lock = threading.Lock()
        self._families: dict[str, MetricFamily] = {item.name: item for item in families}
        self._counters: dict[tuple[str, tuple[str, ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[str, ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[str, ...]], tuple[list[float], float, int]] = {}

    # ------------------------------------------------------------------ writes
    def _family_for(self, name: str, kind: MetricKind) -> MetricFamily:
        family = self._families.get(name)
        if family is None:
            msg = f"undeclared metric {name!r}; add it to METRIC_FAMILIES first"
            raise ValueError(msg)
        if family.kind != kind:
            msg = f"metric {name!r} is a {family.kind}, not a {kind}"
            raise ValueError(msg)
        return family

    def increment(
        self, name: str, labels: Mapping[str, str] | None = None, value: float = 1.0
    ) -> None:
        """Add ``value`` to a counter (counters never decrease)."""
        family = self._family_for(name, "counter")
        key = (name, _labels_key(labels, family))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        """Set a gauge's value."""
        family = self._family_for(name, "gauge")
        key = (name, _labels_key(labels, family))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        """Record one histogram observation."""
        family = self._family_for(name, "histogram")
        key = (name, _labels_key(labels, family))
        with self._lock:
            entry = self._histograms.get(key)
            if entry is None:
                entry = ([0.0] * len(family.buckets), 0.0, 0)
                self._histograms[key] = entry
            counts, total, observed = entry
            for index, bound in enumerate(family.buckets):
                if value <= bound:
                    counts[index] += 1
            entry = (counts, total + value, observed + 1)
            self._histograms[key] = entry

    def clear_family(self, name: str, *, kinds: tuple[str, ...] = ("gauge",)) -> None:
        """Drop one family's series before a scrape re-populates it.

        Gauge families that describe *current* deployment state (queue depth, agents, feeds,
        storage) are re-set on every scrape, so a series must not survive the object it
        described: a retired agent or a deleted project would otherwise be reported for ever
        as a frozen value. Counters are never cleared — they are monotonic by definition.
        """
        with self._lock:
            if "gauge" in kinds:
                for key in [key for key in self._gauges if key[0] == name]:
                    del self._gauges[key]
            if "histogram" in kinds:
                for key in [key for key in self._histograms if key[0] == name]:
                    del self._histograms[key]
            if "counter" in kinds:
                for key in [key for key in self._counters if key[0] == name]:
                    del self._counters[key]

    def clear(self) -> None:
        """Drop every value (tests; not exposed on the endpoint)."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()

    # ------------------------------------------------------------------ reads
    def counter_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        family = self._family_for(name, "counter")
        with self._lock:
            return self._counters.get((name, _labels_key(labels, family)), 0.0)

    def gauge_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        family = self._family_for(name, "gauge")
        with self._lock:
            return self._gauges.get((name, _labels_key(labels, family)), 0.0)

    def histogram_count(self, name: str, labels: Mapping[str, str] | None = None) -> int:
        family = self._family_for(name, "histogram")
        with self._lock:
            entry = self._histograms.get((name, _labels_key(labels, family)))
        return entry[2] if entry is not None else 0

    def rendered_names(self) -> tuple[str, ...]:
        """Names that currently have at least one series (a family with no series is silent)."""
        with self._lock:
            present = {
                key[0]
                for key in (*self._counters.keys(), *self._gauges.keys(), *self._histograms.keys())
            }
        return tuple(sorted(present))

    def render(self) -> str:
        """The Prometheus text exposition for every family that has a series."""
        lines: list[str] = []
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = dict(self._histograms)

        for family in self._families.values():
            series = [
                (key, value)
                for key, value in (*counters.items(), *gauges.items())
                if key[0] == family.name
            ]
            buckets = [(key, value) for key, value in histograms.items() if key[0] == family.name]
            if not series and not buckets:
                continue
            lines.append(f"# HELP {family.name} {family.help}")
            lines.append(f"# TYPE {family.name} {family.kind}")
            for (_, label_values), value in sorted(series, key=lambda item: item[0][1]):
                rendered = _render_labels(family, label_values)
                lines.append(f"{family.name}{rendered} {_format(value)}")
            for (_, label_values), (counts, total, observed) in sorted(
                buckets, key=lambda item: item[0][1]
            ):
                cumulative = 0.0
                for bound, count in zip(family.buckets, counts, strict=True):
                    cumulative = max(cumulative, count)
                    labels = dict(zip(family.label_names, label_values, strict=True))
                    labels["le"] = _format(bound)
                    lines.append(
                        f"{family.name}_bucket{_render_bucket_labels(family, labels)} "
                        f"{_format(cumulative)}"
                    )
                labels = dict(zip(family.label_names, label_values, strict=True))
                labels["le"] = "+Inf"
                lines.append(
                    f"{family.name}_bucket{_render_bucket_labels(family, labels)} "
                    f"{_format(float(observed))}"
                )
                base = _render_labels(family, label_values)
                lines.append(f"{family.name}_sum{base} {_format(total)}")
                lines.append(f"{family.name}_count{base} {_format(float(observed))}")
        return "".join(f"{line}\n" for line in lines)


def _render_bucket_labels(family: MetricFamily, labels: Mapping[str, str]) -> str:
    """Bucket label sets are the family's labels plus ``le``, in a stable order."""
    names = (*family.label_names, "le")
    pairs = ", ".join(f'{name}="{_escape_label(str(labels.get(name, "")))}"' for name in names)
    return "{" + pairs + "}"


def _format(value: float) -> str:
    """Format a value the way the exposition format expects (no exponent surprises)."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


#: The process-wide registry every component writes to.
REGISTRY: Final = MetricsRegistry()


def render_metrics() -> str:
    """Render the process-wide registry."""
    return REGISTRY.render()


def reset_metrics() -> None:
    """Drop every value in the process-wide registry (tests)."""
    REGISTRY.clear()


def status_class(status: int | str) -> str:
    """Map an HTTP status to its class label (bounded cardinality by construction)."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "other"
    label = f"{code // 100}xx"
    return label if label in _STATUS_CLASSES else "other"
