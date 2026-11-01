"""CMDB criticality import (S23, REQ-POSTURE-006, P2).

An estate's exposure only *ranks* correctly when business weight is part of the sort, so
an operator can import per-host criticality from the CMDB: a CSV (``host,tier[,name]``)
or a JSON list (``[{"host": ..., "tier": 1, "name": ..., "note": ...}]``). Tier 1 is the
most critical; ``*.example.com`` entries are wildcards that match any subdomain without
an exact row.

What the import feeds: attack-path *ranking and labelling* (``arachne.analyzer.paths``)
— a tier-1 host's path carries a business-impact floor, so "reachability on the payment
host" stops sorting under "medium on a build box". What it does **not** feed: the finding
severities themselves, which stay what the analyzer computed. Criticality is context,
not a re-score.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = ["CriticalityEntry", "CriticalityIndex", "parse_cmdb"]

_MAX_TIER: Final = 4
_MIN_TIER: Final = 1


@dataclass(frozen=True, slots=True)
class CriticalityEntry:
    """One imported row (see ``data.posture_store.CriticalityEntry``'s row shape)."""

    host: str
    tier: int
    name: str | None = None
    note: str | None = None
    source: str = "import"


class CriticalityIndex:
    """The lookup attack paths use: exact host first, then the longest wildcard."""

    def __init__(self, entries: Mapping[str, int]) -> None:
        self._exact: dict[str, int] = {}
        self._wildcards: dict[str, int] = {}
        for host, tier in entries.items():
            normalized = host.strip().lower()
            if normalized.startswith("*."):
                self._wildcards[normalized[2:]] = int(tier)
            else:
                self._exact[normalized] = int(tier)

    def lookup(self, host: str) -> int | None:
        """The tier for ``host``: exact row, else the matching wildcard, else ``None``."""
        candidate = (host or "").strip().lower()
        if not candidate:
            return None
        exact = self._exact.get(candidate)
        if exact is not None:
            return exact
        best: tuple[int, int] | None = None  # (label length, tier) — most specific wins
        for suffix, tier in self._wildcards.items():
            matched = candidate == suffix or candidate.endswith("." + suffix)
            if matched and (best is None or len(suffix) > best[0]):
                best = (len(suffix), tier)
        return best[1] if best else None

    def __bool__(self) -> bool:
        return bool(self._exact or self._wildcards)


def parse_cmdb(
    text: str, *, source: str = "<cmdb>", max_rows: int = 10_000
) -> tuple[CriticalityEntry, ...]:
    """Parse a CMDB export (CSV or JSON) into criticality entries.

    The format is inferred: a document starting with ``[`` or ``{`` is JSON, anything
    else CSV with a header row. Malformed rows are refused, never skipped — a silently
    missing tier-1 host is worse than a failed import.
    """
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        return _parse_json(stripped, source=source, max_rows=max_rows)
    return _parse_csv(text, source=source, max_rows=max_rows)


def _validate(entry: CriticalityEntry, source: str) -> CriticalityEntry:
    if not entry.host.strip():
        msg = f"{source}: a criticality row needs a host"
        raise ConfigurationError(msg)
    if not _MIN_TIER <= entry.tier <= _MAX_TIER:
        msg = (
            f"{source}: {entry.host!r} carries tier {entry.tier}; expected "
            f"{_MIN_TIER} (most critical) .. {_MAX_TIER}"
        )
        raise ConfigurationError(msg)
    return entry


def _parse_json(text: str, *, source: str, max_rows: int) -> tuple[CriticalityEntry, ...]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{source}: not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc
    rows: list[Any]
    if isinstance(data, Mapping):
        rows = [data]
    elif isinstance(data, list):
        rows = data
    else:
        msg = f"{source}: expected a JSON list of {{host, tier}} objects"
        raise ConfigurationError(msg)
    if len(rows) > max_rows:
        msg = f"{source}: {len(rows)} rows exceed the import cap ({max_rows})"
        raise ConfigurationError(msg)
    out: list[CriticalityEntry] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            msg = f"{source}: row {index} is not an object"
            raise ConfigurationError(msg)
        tier = row.get("tier")
        if isinstance(tier, bool) or not isinstance(tier, int):
            if isinstance(tier, str) and tier.strip().isdigit():
                tier = int(tier.strip())
            else:
                msg = f"{source}: row {index} carries tier {tier!r}; expected 1..4"
                raise ConfigurationError(msg)
        out.append(
            _validate(
                CriticalityEntry(
                    host=str(row.get("host") or ""),
                    tier=tier,
                    name=(str(row["name"]) if row.get("name") else None),
                    note=(str(row["note"]) if row.get("note") else None),
                ),
                source=f"{source} row {index}",
            )
        )
    return tuple(out)


def _parse_csv(text: str, *, source: str, max_rows: int) -> tuple[CriticalityEntry, ...]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        msg = f"{source}: CSV carries no header row (expected host,tier[,name,note])"
        raise ConfigurationError(msg)
    missing = {"host", "tier"} - {name.strip().lower() for name in reader.fieldnames if name}
    if missing:
        msg = f"{source}: CSV header is missing {', '.join(sorted(missing))} (expected host,tier)"
        raise ConfigurationError(msg)
    out: list[CriticalityEntry] = []
    for index, row in enumerate(reader):
        if len(out) >= max_rows:
            msg = f"{source}: more than {max_rows} rows exceed the import cap"
            raise ConfigurationError(msg)
        normalized = {
            (key or "").strip().lower(): (value or "").strip() for key, value in row.items()
        }
        tier_text = normalized.get("tier", "")
        if not tier_text.isdigit():
            msg = f"{source}: row {index + 1} carries tier {tier_text!r}; expected 1..4"
            raise ConfigurationError(msg)
        out.append(
            _validate(
                CriticalityEntry(
                    host=normalized.get("host", ""),
                    tier=int(tier_text),
                    name=normalized.get("name") or None,
                    note=normalized.get("note") or None,
                ),
                source=f"{source} row {index + 1}",
            )
        )
    return tuple(out)
