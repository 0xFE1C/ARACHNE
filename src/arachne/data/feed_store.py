"""Ingested CVE/EPSS feeds: validation, normalisation and lookup (F-09-03).

"Offline-friendly" is the constraint that shapes this store. An operator brings a file —
a FIRST EPSS CSV, a CISA KEV JSON, or a CVE export — and ARACHNE:

1. **validates** it (a malformed header or JSON is refused with the reason, never half-read);
2. **normalises** it to the exact shape the M6 correlation check already consumes, and
   writes that artefact under the feeds directory;
3. **records** what was imported (kind, version, source, count, who) in ``feeds`` and each
   normalised row in ``feed_entries``.

Normalisation matters because it makes ingestion and correlation share one format: the file
:meth:`FeedStore.effective_path` returns is a valid ``ARACHNE_M6_EPSS_FEED`` /
``ARACHNE_M6_KEV_FEED`` value, so a scan uses the imported feed with no further wiring (the
composition root resolves the active feed automatically — see ``build_handlers``).

The store never contacts the network. A URL as ``source`` is recorded as provenance only;
fetching is the operator's job (``curl`` is a better fit than an HTTP client inside the
scanner, and it keeps F-08-*'s egress rules intact).
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ConfigurationError
from arachne.data.models import Feed, FeedEntry
from arachne.data.scan_store import as_utc

__all__ = [
    "FEED_KINDS",
    "FeedRecord",
    "FeedStore",
    "parse_feed",
]

#: The artefact shapes ingestion understands (F-09-03). ``nvd`` is S18's richer variant of
#: ``cve``: the same idea (one row per CVE) carrying what the NVD sync knows — CVSS, CWE,
#: references and the CPE version ranges a CVE applies to — which is what the generated
#: CVE-index baseline is built from.
FEED_KINDS: tuple[str, ...] = ("epss", "kev", "cve", "nvd")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FeedRecord:
    """One imported feed artefact."""

    id: int
    kind: str
    name: str
    version: str | None = None
    source: str | None = None
    path: str = ""
    record_count: int = 0
    imported_by: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "path": self.path,
            "record_count": self.record_count,
            "imported_by": self.imported_by,
            "meta": dict(self.meta),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def parse_feed(
    text: str, *, kind: str, source: str = "<text>", max_entries: int = 50_000
) -> dict[str, dict[str, Any]]:
    """Normalise ``text`` into ``{CVE: {"epss", "percentile", "kev", "cvss"}}``."""
    normalized_kind = kind.strip().lower()
    if normalized_kind == "epss":
        return _parse_epss(text, source=source, max_entries=max_entries)
    if normalized_kind == "kev":
        return _parse_kev(text, source=source, max_entries=max_entries)
    if normalized_kind == "cve":
        return _parse_cve(text, source=source, max_entries=max_entries)
    if normalized_kind == "nvd":
        return _parse_nvd(text, source=source, max_entries=max_entries)
    msg = f"unknown feed kind {kind!r}; expected one of {', '.join(FEED_KINDS)}"
    raise ConfigurationError(msg)


def detect_kind(path: Path, text: str) -> str:
    """Infer the feed kind from the file name/extension and the document shape."""
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "epss"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        if suffix in {".yaml", ".yml"}:
            return "cve"
        msg = f"{path}: cannot tell the feed kind; pass --kind epss|kev|cve"
        raise ConfigurationError(msg) from None
    if isinstance(parsed, dict) and "vulnerabilities" in parsed:
        return "kev"
    return "cve"


def _parse_epss(text: str, *, source: str, max_entries: int) -> dict[str, dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        msg = f"{source}: an EPSS CSV is empty"
        raise ConfigurationError(msg)
    lowered = {name.strip().lower(): name for name in reader.fieldnames}
    cve_col = lowered.get("cve")
    epss_col = lowered.get("epss")
    pct_col = lowered.get("percentile")
    if cve_col is None or epss_col is None:
        msg = f"{source}: an EPSS CSV needs 'cve' and 'epss' columns"
        raise ConfigurationError(msg)
    out: dict[str, dict[str, Any]] = {}
    for row in reader:
        cve = _cve(row.get(cve_col) or "", source=source)
        if cve is None:
            continue
        out[cve] = {
            "epss": _opt_float(row.get(epss_col)),
            "percentile": _opt_float(row.get(pct_col)) if pct_col else None,
            "kev": False,
            "cvss": None,
        }
        if len(out) >= max_entries:
            break
    if not out:
        msg = f"{source}: the EPSS CSV contained no CVE rows"
        raise ConfigurationError(msg)
    return out


def _parse_kev(text: str, *, source: str, max_entries: int) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{source}: not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc
    rows = data.get("vulnerabilities") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        msg = f"{source}: a KEV document needs a 'vulnerabilities' list"
        raise ConfigurationError(msg)
    out: dict[str, dict[str, Any]] = {}
    for row in rows[:max_entries]:
        raw = row.get("cveID") or row.get("cve") if isinstance(row, dict) else row
        cve = _cve(str(raw or ""), source=source)
        if cve is None:
            continue
        out[cve] = {"epss": None, "percentile": None, "kev": True, "cvss": None}
    if not out:
        msg = f"{source}: the KEV document contained no CVE rows"
        raise ConfigurationError(msg)
    return out


def _parse_cve(text: str, *, source: str, max_entries: int) -> dict[str, dict[str, Any]]:
    """A CVE/EPSS snapshot: ``{"entries": [{"cve", "epss", "percentile", "kev", "cvss"}]}``.

    A plain JSON/YAML list of the same objects is accepted, as is a list of bare CVE ids
    (useful for a hand-maintained allow list).
    """
    data: Any
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML/JSON: {exc}"
        raise ConfigurationError(msg) from exc
    if isinstance(data, dict):
        rows = data.get("entries") or data.get("vulnerabilities") or ()
    elif isinstance(data, list):
        rows = data
    else:
        msg = f"{source}: a CVE feed needs a list of entries"
        raise ConfigurationError(msg)
    out: dict[str, dict[str, Any]] = {}
    for row in list(rows)[:max_entries]:
        if isinstance(row, str):
            cve = _cve(row, source=source)
            if cve is None:
                continue
            out[cve] = {"epss": None, "percentile": None, "kev": False, "cvss": None}
            continue
        if not isinstance(row, dict):
            continue
        cve = _cve(str(row.get("cve") or row.get("id") or ""), source=source)
        if cve is None:
            continue
        out[cve] = {
            "epss": _opt_float(row.get("epss")),
            "percentile": _opt_float(row.get("percentile")),
            "kev": bool(row.get("kev", False)),
            "cvss": _opt_float(row.get("cvss")),
        }
    if not out:
        msg = f"{source}: the CVE feed contained no recognisable CVE ids"
        raise ConfigurationError(msg)
    return out


def _parse_nvd(text: str, *, source: str, max_entries: int) -> dict[str, dict[str, Any]]:
    """The normalised NVD snapshot ``arachne intel sync`` produces.

    Shape: ``{"version": ..., "entries": [{"cve", "title", "cvss", "cwe", "cpe_ranges", ...}]}``.
    It is deliberately *not* the NVD API's own document: the sync normalises once (in
    ``arachne.intel.sources``) and this reader consumes that artefact, which keeps the data
    layer free of a dependency on the intel layer and gives an operator one shape to bring in
    by hand. An API-shaped body is refused with a pointer to the right command rather than
    half-understood.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML/JSON: {exc}"
        raise ConfigurationError(msg) from exc
    if isinstance(data, dict) and "vulnerabilities" in data:
        msg = (
            f"{source}: this looks like a raw NVD API document; normalise it with "
            "`arachne intel sync --source nvd` (or convert it to the '{entries: [...]}' "
            "snapshot form)"
        )
        raise ConfigurationError(msg)
    rows = data.get("entries") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        msg = f"{source}: an NVD snapshot needs an 'entries' list"
        raise ConfigurationError(msg)
    out: dict[str, dict[str, Any]] = {}
    for row in rows[:max_entries]:
        if not isinstance(row, dict):
            continue
        cve = _cve(str(row.get("cve") or row.get("id") or ""), source=source)
        if cve is None:
            continue
        out[cve] = {
            "title": str(row.get("title") or "")[:1024],
            "published": row.get("published"),
            "last_modified": row.get("last_modified"),
            "cvss": _opt_float(row.get("cvss")),
            "epss": _opt_float(row.get("epss")),
            "kev": bool(row.get("kev", False)),
            "cwe": row.get("cwe"),
            "references": list(row.get("references") or ()),
            "cpe_ranges": list(row.get("cpe_ranges") or ()),
        }
    if not out:
        msg = f"{source}: the NVD snapshot contained no recognisable CVE ids"
        raise ConfigurationError(msg)
    return out


def _cve(raw: str, *, source: str) -> str | None:
    candidate = raw.strip().upper()
    if not candidate:
        return None
    if not _CVE_RE.match(candidate):
        msg = f"{source}: {raw!r} is not a CVE id (CVE-YYYY-NNNN)"
        raise ConfigurationError(msg)
    return candidate


def _opt_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class FeedStore:
    """``feeds``/``feed_entries`` access plus the normalised artefacts on disk."""

    def __init__(
        self, session_factory: sessionmaker[Session], *, directory: str | Path | None = None
    ) -> None:
        self._session_factory = session_factory
        self.directory = Path(directory).expanduser() if directory else Path("feeds")

    # ------------------------------------------------------------------ import
    def import_file(
        self,
        path: str | Path,
        *,
        kind: str | None = None,
        name: str | None = None,
        source: str | None = None,
        imported_by: str | None = None,
        max_entries: int = 50_000,
        meta: Mapping[str, Any] | None = None,
    ) -> FeedRecord:
        """Validate, normalise and persist one feed file."""
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"feed file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read feed file {resolved}: {exc}"
            raise ConfigurationError(msg) from exc
        normalized_kind = (kind or detect_kind(resolved, text)).strip().lower()
        entries = parse_feed(
            text, kind=normalized_kind, source=str(resolved), max_entries=max_entries
        )
        label = (name or resolved.stem).strip() or resolved.stem
        return self._persist(
            kind=normalized_kind,
            name=label,
            entries=entries,
            version=self._version_of(normalized_kind, text),
            source=source or str(resolved),
            imported_by=imported_by,
            extra_meta={"original_name": resolved.name, **dict(meta or {})},
        )

    def import_text(
        self,
        text: str,
        *,
        kind: str,
        name: str,
        source: str = "upload",
        imported_by: str | None = None,
        max_entries: int = 50_000,
        meta: Mapping[str, Any] | None = None,
    ) -> FeedRecord:
        """The same import from an uploaded document (the web UI's path)."""
        normalized_kind = kind.strip().lower()
        entries = parse_feed(text, kind=normalized_kind, source=name, max_entries=max_entries)
        return self._persist(
            kind=normalized_kind,
            name=name,
            entries=entries,
            version=self._version_of(normalized_kind, text),
            source=source,
            imported_by=imported_by,
            extra_meta=dict(meta or {}),
        )

    def import_entries(
        self,
        entries: Mapping[str, Mapping[str, Any]],
        *,
        kind: str,
        name: str,
        version: str | None = None,
        source: str | None = None,
        imported_by: str | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> FeedRecord:
        """Import **already normalised** rows.

        The S18 sync service's path: it parses and verifies a payload once (in
        ``arachne.intel``) and hands the normalised rows over, so a fetched feed and an
        operator's hand-imported file end up as the same artefact with the same provenance
        keys. ``meta`` carries what the sync knows and the store does not — the pinned digest,
        the verification result, the resume cursor and the upstream publication date — and is
        merged into the feed record's metadata.
        """
        if not entries:
            msg = f"{name}: refusing to import an empty {kind} feed"
            raise ConfigurationError(msg)
        normalized_kind = kind.strip().lower()
        if normalized_kind not in FEED_KINDS:
            msg = f"unknown feed kind {kind!r}; expected one of {', '.join(FEED_KINDS)}"
            raise ConfigurationError(msg)
        return self._persist(
            kind=normalized_kind,
            name=name,
            entries={str(key): dict(value) for key, value in entries.items()},
            version=version,
            source=source,
            imported_by=imported_by,
            extra_meta=dict(meta or {}),
        )

    def _persist(
        self,
        *,
        kind: str,
        name: str,
        entries: dict[str, dict[str, Any]],
        version: str | None,
        source: str | None,
        imported_by: str | None,
        extra_meta: dict[str, Any] | None = None,
    ) -> FeedRecord:
        """Write the normalised artefact and the ``feeds``/``feed_entries`` rows."""
        artefact = self._write_artefact(kind, name, entries, version=version)
        meta = {
            "effective_path": str(artefact),
            "format": artefact.suffix.lstrip("."),
            **dict(extra_meta or {}),
        }
        with self._session_factory() as session:
            feed = Feed(
                kind=kind,
                name=name,
                version=version,
                source=source,
                path=str(artefact),
                record_count=len(entries),
                imported_by=imported_by,
                meta_json=meta,
            )
            session.add(feed)
            session.commit()
            session.refresh(feed)
            feed_id = int(feed.id)
            session.add_all(
                FeedEntry(feed_id=feed_id, key=cve, data_json=dict(values))
                for cve, values in entries.items()
            )
            session.commit()
            session.refresh(feed)
            return _to_record(feed)

    # ------------------------------------------------------------------ reads
    def list_feeds(self, *, kind: str | None = None, limit: int = 100) -> tuple[FeedRecord, ...]:
        with self._session_factory() as session:
            query = select(Feed).order_by(Feed.id.desc()).limit(limit)
            if kind:
                query = query.where(Feed.kind == kind.strip().lower())
            rows = session.scalars(query).all()
            return tuple(_to_record(row) for row in rows)

    def get(self, feed_id: int) -> FeedRecord | None:
        with self._session_factory() as session:
            row = session.get(Feed, feed_id)
            return None if row is None else _to_record(row)

    def active(self, kind: str) -> FeedRecord | None:
        """The newest feed of ``kind`` (the one a scan consumes)."""
        with self._session_factory() as session:
            row = session.scalar(
                select(Feed).where(Feed.kind == kind.strip().lower()).order_by(Feed.id.desc())
            )
            return None if row is None else _to_record(row)

    def effective_path(self, kind: str) -> str | None:
        """The normalised artefact a check should read for ``kind`` (or ``None``)."""
        record = self.active(kind)
        if record is None:
            return None
        return record.path if Path(record.path).is_file() else None

    def entries(
        self, feed_id: int, *, limit: int = 100, offset: int = 0
    ) -> tuple[dict[str, Any], ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(FeedEntry)
                .where(FeedEntry.feed_id == feed_id)
                .order_by(FeedEntry.key)
                .limit(max(1, limit))
                .offset(max(0, offset))
            ).all()
            return tuple({"cve": str(row.key), **dict(row.data_json or {})} for row in rows)

    def lookup(self, cve: str, *, kind: str | None = None) -> dict[str, Any] | None:
        """Merge the active feed rows for ``cve`` (EPSS + KEV), newest row per kind."""
        wanted = cve.strip().upper()
        kinds = [kind.strip().lower()] if kind else ["epss", "cve", "kev"]
        merged: dict[str, Any] = {"cve": wanted}
        found = False
        for item_kind in kinds:
            record = self.active(item_kind)
            if record is None:
                continue
            with self._session_factory() as session:
                row = session.scalar(
                    select(FeedEntry).where(FeedEntry.feed_id == record.id, FeedEntry.key == wanted)
                )
                if row is None:
                    continue
                data = dict(row.data_json or {})
                found = True
                for key, value in data.items():
                    if value is not None and not merged.get(key):
                        merged[key] = value
                merged.setdefault("sources", []).append(
                    {"feed_id": record.id, "kind": record.kind, "name": record.name}
                )
        return merged if found else None

    def stats(self) -> dict[str, Any]:
        with self._session_factory() as session:
            rows = session.execute(
                select(Feed.kind, func.count(), func.sum(Feed.record_count)).group_by(Feed.kind)
            ).all()
        by_kind = {
            str(kind): {"feeds": int(count), "entries": int(total or 0)}
            for kind, count, total in rows
        }
        for kind in FEED_KINDS:
            by_kind.setdefault(kind, {"feeds": 0, "entries": 0})
        return {"by_kind": by_kind, "directory": str(self.directory)}

    # ------------------------------------------------------------------ delete
    def delete(self, feed_id: int, *, remove_file: bool = True) -> bool:
        record = self.get(feed_id)
        if record is None:
            return False
        with self._session_factory() as session:
            session.execute(delete(FeedEntry).where(FeedEntry.feed_id == feed_id))
            row = session.get(Feed, feed_id)
            if row is not None:
                session.delete(row)
            session.commit()
        if remove_file and record.path:
            # A permission problem unlinking the artefact must not abort the row delete.
            with contextlib.suppress(OSError):
                Path(record.path).unlink(missing_ok=True)
        return True

    # ------------------------------------------------------------------ helpers
    def _write_artefact(
        self,
        kind: str,
        label: str,
        entries: dict[str, dict[str, Any]],
        *,
        version: str | None,
    ) -> Path:
        """Write the normalised file the M6 checks read, and return its path."""
        self.directory.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9._-]+", "-", label.strip().lower()).strip("-") or kind
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        if kind == "epss":
            path = self.directory / f"epss-{slug}-{stamp}.csv"
            path.write_text(_epss_csv(entries), encoding="utf-8")
        elif kind == "kev":
            path = self.directory / f"kev-{slug}-{stamp}.json"
            path.write_text(_kev_json(entries), encoding="utf-8")
        elif kind == "nvd":
            path = self.directory / f"nvd-{slug}-{stamp}.yaml"
            path.write_text(_nvd_snapshot(entries, version=version or label), encoding="utf-8")
        else:
            path = self.directory / f"cve-{slug}-{stamp}.yaml"
            path.write_text(_cve_snapshot(entries, version=version or label), encoding="utf-8")
        return path.resolve()

    @staticmethod
    def _version_of(kind: str, text: str) -> str | None:
        if kind == "kev":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(data, dict):
                for key in ("catalogVersion", "version", "releaseDate"):
                    if data.get(key):
                        return str(data[key])
            return None
        if kind == "cve":
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                return None
            if isinstance(data, dict) and data.get("version"):
                return str(data["version"])
        return None


def _epss_csv(entries: dict[str, dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["cve", "epss", "percentile"])
    for cve, values in sorted(entries.items()):
        epss = values.get("epss")
        percentile = values.get("percentile")
        writer.writerow(
            [cve, "" if epss is None else epss, "" if percentile is None else percentile]
        )
    return buffer.getvalue()


def _kev_json(entries: dict[str, dict[str, Any]]) -> str:
    payload = {
        "vulnerabilities": [
            {"cveID": cve} for cve, values in sorted(entries.items()) if values.get("kev", True)
        ]
    }
    return json.dumps(payload, indent=2) + "\n"


def _cve_snapshot(entries: dict[str, dict[str, Any]], *, version: str) -> str:
    payload = {
        "version": version,
        "generated_at": datetime.now(UTC).isoformat(),
        "entries": [
            {
                "cve": cve,
                "epss": values.get("epss"),
                "percentile": values.get("percentile"),
                "kev": bool(values.get("kev", False)),
                "cvss": values.get("cvss"),
            }
            for cve, values in sorted(entries.items())
        ],
    }
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _nvd_snapshot(entries: dict[str, dict[str, Any]], *, version: str) -> str:
    """The normalised NVD artefact: one row per CVE with its ranges and references.

    This is the file the generated CVE-index baseline is built from, which is why it keeps
    the structure (``cpe_ranges``) rather than flattening it to the EPSS/KEV vocabulary.
    """
    payload = {
        "version": version,
        "generated_at": datetime.now(UTC).isoformat(),
        "entries": [{"cve": cve, **dict(values)} for cve, values in sorted(entries.items())],
    }
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _to_record(row: Feed) -> FeedRecord:
    return FeedRecord(
        id=int(row.id),
        kind=str(row.kind),
        name=str(row.name),
        version=row.version,
        source=row.source,
        path=str(row.path),
        record_count=int(row.record_count or 0),
        imported_by=row.imported_by,
        meta=dict(row.meta_json or {}),
        created_at=as_utc(row.created_at),
    )
