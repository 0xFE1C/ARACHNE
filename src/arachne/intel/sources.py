"""Feed sources: what to fetch, where, and how to read it (REQ-INTEL-001).

One pair per source, in the same spirit as ``arachne.modules.providers.sources``: building
the URL and parsing the body is separated from deciding what it means, so the sync service
stays short enough to read and a provider changing its shape degrades to "nothing new"
instead of breaking an import.

Three sources, all published as machine-readable documents:

``nvd``
    NVD API 2.0 (``/rest/json/cves/2.0``). The only genuinely *incremental* source: the API
    takes a ``lastModStartDate``/``lastModEndDate`` window (at most 120 days) and a
    ``startIndex``/``resultsPerPage`` pair, so a sync continues from the previous one's
    cursor instead of re-reading a 300k-record corpus.
``kev``
    CISA's Known Exploited Vulnerabilities catalogue: a single JSON document with a
    ``catalogVersion``, so "incremental" means "changed upstream" and the sync is a no-op
    when the version is the one already stored.
``epss``
    FIRST's EPSS API (``/data/v1/epss``): a daily scoring run with a ``since`` parameter, so
    a sync asks only for scores updated since the last run.

Parsing is total by construction: a body that does not look like what the source documents
yields an empty result (or a clear ``ConfigurationError`` when the document is structurally
wrong), because a broken mirror is a normal event and must not take the deployment down
(```` §4 — errors are data).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlencode

from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_NVD_RESULTS_PER_PAGE",
    "NVD_MAX_WINDOW_DAYS",
    "SOURCES",
    "CpeRange",
    "FeedDocument",
    "FeedSource",
    "NvdRecord",
    "epss_url",
    "feed_version_label",
    "kev_url",
    "nvd_url",
    "nvd_window",
    "parse_source",
    "source_for",
]

_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

#: The API's documented maximum window for ``lastModStartDate``/``lastModEndDate``.
NVD_MAX_WINDOW_DAYS: Final = 120
#: The API's documented maximum page size.
DEFAULT_NVD_RESULTS_PER_PAGE: Final = 2000


@dataclass(frozen=True, slots=True)
class FeedSource:
    """Static description of one upstream feed."""

    name: str
    kind: str
    title: str
    description: str
    incremental: bool
    #: Configuration field carrying the API key, when the source wants one.
    credential: str | None = None
    #: Whether the source can be verified with a detached signature as well as a digest.
    supports_signature: bool = False


#: The three sources S18 syncs. ``kind`` is the :class:`~arachne.data.feed_store.FeedStore`
#: kind the parsed document is imported as, which is what makes an imported feed usable by
#: the very next scan with no further wiring.
SOURCES: dict[str, FeedSource] = {
    "nvd": FeedSource(
        name="nvd",
        kind="nvd",
        title="NVD CVE corpus (API 2.0)",
        description=(
            "The National Vulnerability Database's CVE records: description, CVSS, CWE, "
            "references and the CPE version ranges the CVE applies to. Fetched through the "
            "API 2.0 modification window so a sync continues where the last one stopped."
        ),
        incremental=True,
        credential="nvd_api_key",
        supports_signature=True,
    ),
    "kev": FeedSource(
        name="kev",
        kind="kev",
        title="CISA Known Exploited Vulnerabilities",
        description=(
            "The catalogue of CVEs CISA has confirmed as exploited in the wild. Arrives as "
            "one versioned JSON document, so a sync is a no-op while the catalogueVersion "
            "is unchanged."
        ),
        incremental=True,
        supports_signature=True,
    ),
    "epss": FeedSource(
        name="epss",
        kind="epss",
        title="FIRST EPSS scores",
        description=(
            "Exploit Prediction Scoring System probabilities. The API takes a 'since' "
            "date, so a sync asks only for the scores that moved since the last run."
        ),
        incremental=True,
        supports_signature=True,
    ),
}


def source_for(name: str) -> FeedSource:
    """The :class:`FeedSource` called ``name`` (a clear error when it is not one)."""
    try:
        return SOURCES[name.strip().lower()]
    except KeyError as exc:
        msg = f"unknown intel feed source {name!r}; known sources are {sorted(SOURCES)}"
        raise ConfigurationError(msg) from exc


# --------------------------------------------------------------------------- encoding
def _nvd_stamp(moment: datetime) -> str:
    """NVD's ISO-8601 spelling: milliseconds and a ``Z`` suffix.

    Not pre-encoded: the value goes through ``urlencode`` with the rest of the query string,
    so quoting here would double-encode it.
    """
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# --------------------------------------------------------------------------- NVD
def nvd_url(
    *,
    last_mod_start: datetime | None = None,
    last_mod_end: datetime | None = None,
    start_index: int = 0,
    results_per_page: int = DEFAULT_NVD_RESULTS_PER_PAGE,
) -> str:
    """The NVD API 2.0 URL for one page of a modification window.

    A window longer than :data:`NVD_MAX_WINDOW_DAYS` is refused here rather than by the API:
    the sync splits its work instead, and a clear local error is cheaper than a 404-shaped
    one.
    """
    if last_mod_start is not None and last_mod_end is not None:
        span = last_mod_end - last_mod_start
        if span > timedelta(days=NVD_MAX_WINDOW_DAYS):
            msg = (
                f"an NVD modification window is at most {NVD_MAX_WINDOW_DAYS} days, "
                f"got {span.days + 1}"
            )
            raise ConfigurationError(msg)
    params: dict[str, str] = {
        "resultsPerPage": str(max(1, min(results_per_page, DEFAULT_NVD_RESULTS_PER_PAGE))),
        "startIndex": str(max(0, start_index)),
    }
    if last_mod_start is not None:
        params["lastModStartDate"] = _nvd_stamp(last_mod_start)
    if last_mod_end is not None:
        params["lastModEndDate"] = _nvd_stamp(last_mod_end)
    return f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urlencode(params)}"


@dataclass(frozen=True, slots=True)
class CpeRange:
    """One ``cpeMatch`` node: which versions of which product a CVE affects."""

    vendor: str
    product: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    def is_versioned(self) -> bool:
        return any(
            value is not None
            for value in (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "version_start_including": self.version_start_including,
            "version_start_excluding": self.version_start_excluding,
            "version_end_including": self.version_end_including,
            "version_end_excluding": self.version_end_excluding,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CpeRange:
        return cls(
            vendor=str(data.get("vendor") or ""),
            product=str(data.get("product") or ""),
            version_start_including=_opt_str(data.get("version_start_including")),
            version_start_excluding=_opt_str(data.get("version_start_excluding")),
            version_end_including=_opt_str(data.get("version_end_including")),
            version_end_excluding=_opt_str(data.get("version_end_excluding")),
        )


@dataclass(frozen=True, slots=True)
class NvdRecord:
    """One CVE as the sync stores it (the vocabulary the baseline builder reads)."""

    cve: str
    title: str = ""
    published: str | None = None
    last_modified: str | None = None
    cvss: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    references: tuple[str, ...] = ()
    cpe_ranges: tuple[CpeRange, ...] = ()
    cpe_criteria: tuple[str, ...] = ()

    def to_entry(self) -> dict[str, Any]:
        """The normalised feed-entry vocabulary (JSON-safe, one row per CVE)."""
        return {
            "title": self.title,
            "published": self.published,
            "last_modified": self.last_modified,
            "cvss": self.cvss,
            "cvss_severity": self.cvss_severity,
            "cvss_vector": self.cvss_vector,
            "cwe": self.cwe,
            "references": list(self.references),
            "cpe_ranges": [item.to_dict() for item in self.cpe_ranges],
            "cpe_criteria": list(self.cpe_criteria),
        }

    @classmethod
    def from_entry(cls, cve: str, data: Mapping[str, Any]) -> NvdRecord:
        return cls(
            cve=cve,
            title=str(data.get("title") or ""),
            published=_opt_str(data.get("published")),
            last_modified=_opt_str(data.get("last_modified")),
            cvss=_opt_float(data.get("cvss")),
            cvss_severity=_opt_str(data.get("cvss_severity")),
            cvss_vector=_opt_str(data.get("cvss_vector")),
            cwe=_opt_str(data.get("cwe")),
            references=tuple(str(item) for item in _list(data.get("references"))),
            cpe_ranges=tuple(
                CpeRange.from_dict(item)
                for item in _list(data.get("cpe_ranges"))
                if isinstance(item, Mapping)
            ),
            cpe_criteria=tuple(str(item) for item in _list(data.get("cpe_criteria"))),
        )


@dataclass(frozen=True, slots=True)
class FeedDocument:
    """A parsed feed payload, ready to be verified, imported and reported on."""

    source: str
    kind: str
    version: str | None
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: What the upstream document says about itself (catalogue date, API timestamp).
    published_at: str | None = None
    #: Resume point for the next incremental sync.
    cursor: dict[str, Any] = field(default_factory=dict)
    total_results: int | None = None
    #: True when the document is byte-identical in meaning to the stored one; the sync then
    #: imports nothing and records the sync as an unchanged no-op.
    unchanged: bool = False

    @property
    def record_count(self) -> int:
        return len(self.entries)


def parse_source(source: str, payload: bytes | str) -> FeedDocument:
    """Parse one fetched payload into a :class:`FeedDocument`."""
    spec = source_for(source)
    text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
    if spec.name == "nvd":
        return _parse_nvd(text)
    if spec.name == "kev":
        return _parse_kev(text)
    return _parse_epss(text)


# --------------------------------------------------------------------------- NVD parsing
def _parse_nvd(text: str) -> FeedDocument:
    data = _load_json(text, source="nvd")
    rows = data.get("vulnerabilities")
    if not isinstance(rows, list):
        msg = "nvd: a CVE 2.0 document needs a 'vulnerabilities' list"
        raise ConfigurationError(msg)
    records: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = _nvd_record(row)
        if record is not None:
            records[record.cve] = record.to_entry()
    timestamp = _opt_str(data.get("timestamp"))
    total = data.get("totalResults")
    return FeedDocument(
        source="nvd",
        kind="nvd",
        # The API format version is a constant; the *timestamp* is what changes per window,
        # so it is the version an operator compares across syncs.
        version=timestamp or "2.0",
        entries=records,
        published_at=timestamp,
        cursor={"last_mod_end": timestamp} if timestamp else {},
        total_results=int(total) if isinstance(total, int) else None,
    )


def _nvd_record(row: Any) -> NvdRecord | None:
    if not isinstance(row, Mapping):
        return None
    container = row.get("cve")
    if not isinstance(container, Mapping):
        return None
    cve = _cve_id(container.get("id"))
    if cve is None:
        return None
    score, severity, vector = _nvd_cvss(container.get("metrics"))
    ranges, criteria = _nvd_cpe(container.get("configurations"))
    return NvdRecord(
        cve=cve,
        title=_nvd_description(container.get("descriptions")),
        published=_opt_str(container.get("published")),
        last_modified=_opt_str(container.get("lastModified")),
        cvss=score,
        cvss_severity=severity,
        cvss_vector=vector,
        cwe=_nvd_cwe(container.get("weaknesses")),
        references=_nvd_references(container.get("references")),
        cpe_ranges=ranges,
        cpe_criteria=criteria,
    )


def _nvd_description(value: Any) -> str:
    """The English description, bounded so one record cannot bloat the store."""
    for item in _list(value):
        if isinstance(item, Mapping) and str(item.get("lang", "")).lower().startswith("en"):
            return str(item.get("value") or "").strip()[:1024]
    return ""


def _nvd_cvss(value: Any) -> tuple[float | None, str | None, str | None]:
    """The best available CVSS base score: v4.0, then v3.1/v3.0, then v2."""
    if not isinstance(value, Mapping):
        return None, None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in _list(value.get(key)):
            if not isinstance(metric, Mapping):
                continue
            data = metric.get("cvssData")
            if not isinstance(data, Mapping):
                continue
            score = _opt_float(data.get("baseScore"))
            if score is None:
                continue
            severity = _opt_str(data.get("baseSeverity")) or _opt_str(metric.get("baseSeverity"))
            return score, severity, _opt_str(data.get("vectorString"))
    return None, None, None


def _nvd_cwe(value: Any) -> str | None:
    for weakness in _list(value):
        if not isinstance(weakness, Mapping):
            continue
        for description in _list(weakness.get("description")):
            if not isinstance(description, Mapping):
                continue
            candidate = _opt_str(description.get("value"))
            if candidate and candidate.upper().startswith("CWE-"):
                return candidate.upper()
    return None


def _nvd_references(value: Any) -> tuple[str, ...]:
    urls: dict[str, None] = {}
    for item in _list(value):
        if isinstance(item, Mapping):
            url = _opt_str(item.get("url"))
            if url:
                urls.setdefault(url, None)
    return tuple(urls)


def _nvd_cpe(value: Any) -> tuple[tuple[CpeRange, ...], tuple[str, ...]]:
    """Flatten the ``configurations`` tree into CPE version ranges and criteria."""
    ranges: list[CpeRange] = []
    criteria: dict[str, None] = {}
    for node in _walk_configurations(value):
        vendor, product, version = _split_cpe(str(node.get("criteria") or ""))
        if not product:
            continue
        if vendor and product and version:
            criteria.setdefault(f"cpe:2.3:*:{vendor}:{product}:{version}", None)
        if vendor and product:
            ranges.append(
                CpeRange(
                    vendor=vendor,
                    product=product,
                    version_start_including=_opt_str(node.get("versionStartIncluding")),
                    version_start_excluding=_opt_str(node.get("versionStartExcluding")),
                    version_end_including=_opt_str(node.get("versionEndIncluding")),
                    version_end_excluding=_opt_str(node.get("versionEndExcluding")),
                )
            )
    return tuple(ranges), tuple(criteria)


def _walk_configurations(value: Any) -> Iterable[Mapping[str, Any]]:
    """Yield every ``cpeMatch`` node of a (possibly nested) configurations tree."""
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, Mapping):
            matches = node.get("cpeMatch")
            if isinstance(matches, list):
                for item in matches:
                    if isinstance(item, Mapping):
                        yield item
            for child in node.get("nodes") or ():
                stack.append(child)
        elif isinstance(node, list):
            stack.extend(node)


def _split_cpe(criteria: str) -> tuple[str, str, str]:
    """``cpe:2.3:a:openbsd:openssh:9.3:*:...`` → ``(vendor, product, version)``."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return "", "", ""
    vendor = parts[3] if parts[3] not in {"", "*", "-"} else ""
    product = parts[4] if parts[4] not in {"", "*", "-"} else ""
    version = parts[5] if parts[5] not in {"", "*", "-"} else ""
    return vendor, product, version


# --------------------------------------------------------------------------- KEV parsing
def kev_url() -> str:
    """CISA's published KEV catalogue (one versioned JSON document)."""
    return "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_kev(text: str) -> FeedDocument:
    data = _load_json(text, source="kev")
    rows = data.get("vulnerabilities")
    if not isinstance(rows, list):
        msg = "kev: a KEV document needs a 'vulnerabilities' list"
        raise ConfigurationError(msg)
    entries: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        cve = _cve_id(row.get("cveID") or row.get("cve"))
        if cve is None:
            continue
        entries[cve] = {
            "epss": None,
            "percentile": None,
            "kev": True,
            "cvss": None,
            "kev_name": _opt_str(row.get("vulnerabilityName")),
            "kev_date_added": _opt_str(row.get("dateAdded")),
            "kev_ransomware": _opt_str(row.get("knownRansomwareCampaignUse")),
        }
    version = (
        _opt_str(data.get("catalogVersion"))
        or _opt_str(data.get("dateReleased"))
        or _opt_str(data.get("releaseDate"))
    )
    return FeedDocument(
        source="kev",
        kind="kev",
        version=version,
        entries=entries,
        published_at=_opt_str(data.get("dateReleased")) or version,
        total_results=len(entries),
    )


# --------------------------------------------------------------------------- EPSS parsing
def epss_url(
    *, since: str | None = None, date: str | None = None, offset: int = 0, limit: int = 5000
) -> str:
    """FIRST's EPSS API URL.

    ``since`` is the incremental form (scores updated on or after that date); ``date`` is the
    full daily snapshot. Only one of them may be given — the API refuses both, and guessing
    would quietly turn an incremental sync into a full one.
    """
    if since and date:
        msg = "epss: pass either 'since' (incremental) or 'date' (a daily snapshot), not both"
        raise ConfigurationError(msg)
    params: dict[str, str] = {"offset": str(max(0, offset)), "limit": str(max(1, limit))}
    if since:
        params["since"] = since
    elif date:
        params["date"] = date
    return f"https://api.first.org/data/v1/epss?{urlencode(params)}"


def _parse_epss(text: str) -> FeedDocument:
    data = _load_json(text, source="epss")
    rows = data.get("data")
    if not isinstance(rows, list):
        msg = "epss: an EPSS response needs a 'data' list"
        raise ConfigurationError(msg)
    entries: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        cve = _cve_id(row.get("cve"))
        if cve is None:
            continue
        entries[cve] = {
            "epss": _opt_float(row.get("epss")),
            "percentile": _opt_float(row.get("percentile")),
            "kev": False,
            "cvss": None,
        }
    version = _opt_str(data.get("date")) or _opt_str(data.get("score_date"))
    total = data.get("total")
    return FeedDocument(
        source="epss",
        kind="epss",
        version=version,
        entries=entries,
        published_at=version,
        cursor={"since": version} if version else {},
        total_results=int(total) if isinstance(total, int) else None,
    )


# --------------------------------------------------------------------------- helpers
def feed_version_label(document: FeedDocument) -> str:
    """The version string stored on the feed row (never empty, so a feed is comparable)."""
    base = f"{document.source}@{document.version}" if document.version else document.source
    return base[:64]


def _load_json(text: str, *, source: str) -> Mapping[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{source}: not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a JSON object at the top level"
        raise ConfigurationError(msg)
    return data


def _cve_id(value: Any) -> str | None:
    candidate = str(value or "").strip().upper()
    if candidate and _CVE_RE.match(candidate):
        return candidate
    return None


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def nvd_window(
    *, cursor: Mapping[str, Any] | None, now: datetime, overlap: timedelta = timedelta(days=1)
) -> tuple[datetime, datetime]:
    """The modification window for the next NVD sync: ``(start, end)``.

    The previous sync's cursor is the start (minus a one-day overlap, so a record modified
    while the last sync ran is not missed); without a cursor the window is the last
    :data:`NVD_MAX_WINDOW_DAYS` days, which is the API's own ceiling.
    """
    end = now.astimezone(UTC)
    raw = (cursor or {}).get("last_mod_end") if cursor else None
    start: datetime | None = None
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            start = parsed.astimezone(UTC) - overlap
    if start is None:
        start = end - timedelta(days=NVD_MAX_WINDOW_DAYS)
    if start > end:
        start = end - timedelta(days=1)
    return start, end
