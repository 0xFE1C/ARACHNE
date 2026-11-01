"""The per-project analysis cache (F-04-07).

"Identical analysis requests hit the cache; the cache is per-project, bounded, and excluded
from cost accounting." The key is the hash of everything that can change the answer — the
stage, the prompt template version, the prompt text (which already carries the model-specific
scaffolding), the model — so a cached value can never be served to a different question.

The store is a bounded LRU in memory, optionally mirrored to a JSON file so a *second* scan in
the same project reuses the first one's answers (the "per-project" half of the requirement).
A cache hit is recorded on the ledger as a hit and never as spend, which is what keeps the
budget honest when a rule change causes a re-analysis of the same candidates.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from arachne.core.logging import get_logger

__all__ = ["RequestCache", "cache_key"]

_logger = get_logger("ai.cache")

#: Version of the cache key recipe. Bump it when the key inputs change shape, so an old file
#: cannot answer a new question.
CACHE_KEY_VERSION: Final = "1"


def cache_key(
    *,
    stage: str,
    template_version: str,
    model: str,
    prompt: str,
) -> str:
    """The stable identity of one analysis request ."""
    digest = hashlib.sha256()
    for part in (CACHE_KEY_VERSION, stage, template_version, model, prompt):
        digest.update(part.encode("utf-8"))
        digest.update(b"\x1f")
    return digest.hexdigest()


class RequestCache:
    """A bounded LRU of validated stage outputs, optionally persisted to one JSON file."""

    def __init__(self, *, max_entries: int = 256, path: str | None = None) -> None:
        if max_entries < 1:
            msg = "cache max_entries must be >= 1"
            raise ValueError(msg)
        self.max_entries = max_entries
        self.path = Path(path).expanduser() if path else None
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        if self.path is not None:
            self._load()

    # ------------------------------------------------------------------ interface
    def get(self, key: str) -> Mapping[str, Any] | None:
        with self._lock:
            value = self._entries.get(key)
            if value is None:
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return dict(value)

    def put(self, key: str, value: Mapping[str, Any]) -> None:
        with self._lock:
            self._entries[key] = dict(value)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
            if self.path is not None:
                self._save_locked()

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @property
    def size(self) -> int:
        return len(self._entries)

    def snapshot(self) -> dict[str, Any]:
        return {"entries": self.size, "hits": self.hits, "misses": self.misses}

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        assert self.path is not None  # guarded by the caller
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _logger.warning(
                "ai cache could not be read",
                extra={"event": "ai.cache_unreadable", "path": str(self.path), "error": str(exc)},
            )
            return
        entries = raw.get("entries") if isinstance(raw, dict) else None
        if not isinstance(entries, dict):
            return
        for key, value in dict(entries).items():
            if isinstance(value, dict):
                self._entries[str(key)] = value

    def _save_locked(self) -> None:
        assert self.path is not None
        payload = json.dumps({"version": CACHE_KEY_VERSION, "entries": self._entries})
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(payload, encoding="utf-8")
        except OSError as exc:  # a cache that cannot be written must not fail a scan
            _logger.warning(
                "ai cache could not be written",
                extra={"event": "ai.cache_unwritable", "path": str(self.path), "error": str(exc)},
            )
