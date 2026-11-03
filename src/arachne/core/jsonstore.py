"""A bounded JSON document on disk, with the path rules made explicit (WP-15).

One small thing, in ``core`` for one reason: the AI layer's request cache is mirrored to a JSON
file so a second scan in the same project reuses the first one's answers, and ``REQ-AGENT-011``
requires the AI package to import no filesystem-write primitive. The engine keeps the policy
(what is cached, how big, when it is bypassed) and asks this module to persist the document.

The path handling is the whole point of the module, so it is stated rather than assumed:

* the **directory** is the operator's configured cache directory, and it is used as given —
  it is the allowlist;
* the **filename** must be a bare name: a separator, a ``..`` segment or a drive letter is
  refused with :class:`ValueError`, so the document cannot be moved out of that directory by the
  value that names it;
* a **missing directory is not created**. ARACHNE does not create directories in a path it was
  pointed at by configuration; a deployment that wants the file mirror creates the directory. The
  caller learns the write did not happen (``save`` returns ``False``) rather than receiving an
  exception, because the cache is best-effort by design — a scan never fails because a cache
  could not be written.

Nothing here is a general-purpose file API: there is one ``save`` and one ``load``, both
JSON-only, both confined to the one directory.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

__all__ = ["JsonFileStore"]

#: Names that never name a file inside a directory.
_REJECTED_NAMES: Final[frozenset[str]] = frozenset({"", ".", ".."})


@dataclass(frozen=True, slots=True)
class JsonFileStore:
    """A JSON document at ``<directory>/<filename>``, with the path rules enforced."""

    directory: Path
    filename: str

    def __post_init__(self) -> None:
        if self.filename in _REJECTED_NAMES or Path(self.filename).name != self.filename:
            msg = (
                f"cache filename {self.filename!r} must be a bare name inside "
                f"{self.directory}; separators and '..' are refused"
            )
            raise ValueError(msg)

    @property
    def path(self) -> Path:
        """The document's location — always ``directory`` joined with a validated bare name."""
        return Path(self.directory) / self.filename

    def load(self) -> Mapping[str, Any]:
        """The stored document, or an empty mapping when it is absent or unreadable."""
        target = self.path
        if not target.is_file():
            return {}
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def save(self, payload: Mapping[str, Any]) -> bool:
        """Write ``payload`` as JSON; ``False`` when the directory is absent or unwritable."""
        target = self.path
        try:
            if not target.parent.is_dir():
                return False
            target.write_text(json.dumps(dict(payload)), encoding="utf-8")
        except OSError:
            return False
        return True
