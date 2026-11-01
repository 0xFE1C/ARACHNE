"""The plugin marketplace: a versioned catalogue of installable packages (F-09-01, S14).

The catalogue is **data** (``templates/marketplace/index.yaml`` by default), so an
air-gapped deployment points ``ARACHNE_MARKETPLACE`` at its own file and the whole
workflow stays offline. Nothing here installs or executes anything: the entry describes a
``source`` and the entry-point group it will register under, and
:mod:`arachne.plugins.installer` does the writing after an explicit operator action.

The ``installed`` flag in :meth:`MarketplaceCatalog.listing` is computed from the live
registries (module groups and report formats whose ``origin`` is not ``builtin``), so the
marketplace answers "what do I already have?" without trusting the catalogue's own claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError

__all__ = [
    "CATALOG_RESOURCE",
    "CHECK_ENTRY_POINT_GROUP",
    "FORMAT_ENTRY_POINT_GROUP",
    "MarketplaceCatalog",
    "MarketplaceEntry",
    "load_marketplace",
]

#: Bundled catalogue location, relative to ``templates/``.
CATALOG_RESOURCE: Final = ("marketplace", "index.yaml")

#: The entry-point group a check/module plugin registers under (mirrors the registry).
CHECK_ENTRY_POINT_GROUP: Final = "arachne.modules"
#: The entry-point group a report-format plugin registers under (mirrors the format registry).
FORMAT_ENTRY_POINT_GROUP: Final = "arachne.report_formats"

_KINDS: Final[frozenset[str]] = frozenset({"check", "report-format", "provider", "module"})


class MarketplaceEntry(BaseModel):
    """One catalogue row."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    kind: str = "check"
    description: str = ""
    version: str = ""
    source: str = Field(min_length=1, max_length=1024)
    entry_point_group: str | None = None
    homepage: str | None = None
    tags: tuple[str, ...] = ()
    verified: bool = False

    def model_post_init(self, __context: Any) -> None:
        if self.kind not in _KINDS:
            msg = f"marketplace entry {self.name!r} has unknown kind {self.kind!r}"
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "version": self.version,
            "source": self.source,
            "entry_point_group": self.entry_point_group,
            "homepage": self.homepage,
            "tags": list(self.tags),
            "verified": self.verified,
        }

    def matches(self, term: str) -> bool:
        needle = term.strip().lower()
        if not needle:
            return True
        haystack = " ".join([self.name, self.description, self.kind, *self.tags]).lower()
        return needle in haystack


@dataclass(frozen=True, slots=True)
class MarketplaceCatalog:
    """A loaded catalogue: its version, its entries and where it came from."""

    version: str = ""
    updated: str = ""
    source: str = "bundled"
    entries: tuple[MarketplaceEntry, ...] = field(default_factory=tuple)

    def search(self, term: str) -> tuple[MarketplaceEntry, ...]:
        return tuple(item for item in self.entries if item.matches(term))

    def get(self, name: str) -> MarketplaceEntry | None:
        wanted = name.strip().lower()
        for item in self.entries:
            if item.name.lower() == wanted:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "updated": self.updated,
            "source": self.source,
            "entries": [item.to_dict() for item in self.entries],
        }

    def listing(self, *, term: str | None = None) -> list[dict[str, Any]]:
        """Entries with an ``installed`` flag computed from the live environment."""
        installed = _installed_distributions()
        rows: list[dict[str, Any]] = []
        for item in self.search(term or ""):
            row = item.to_dict()
            row["installed"] = _normalize_distribution_name(item.name) in installed
            rows.append(row)
        return rows


def load_marketplace(path: str | Path | None = None) -> MarketplaceCatalog:
    """Load the catalogue from ``path`` (or the bundled index)."""
    if path is None or (isinstance(path, str) and not path.strip()):
        node = files("arachne.templates")
        for part in CATALOG_RESOURCE:
            node = node.joinpath(part)
        try:
            text = node.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled marketplace index is missing: {exc}"
            raise ConfigurationError(msg) from exc
        source = "bundled index.yaml"
    else:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"marketplace index {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read marketplace index {resolved}: {exc}"
            raise ConfigurationError(msg) from exc
        source = str(resolved)

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if data is None:
        return MarketplaceCatalog(source=source)
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    raw_entries = data.get("plugins") or ()
    if not isinstance(raw_entries, (list, tuple)):
        msg = f"{source}: 'plugins' must be a list"
        raise ConfigurationError(msg)
    entries: list[MarketplaceEntry] = []
    seen: set[str] = set()
    for raw in raw_entries:
        try:
            entry = MarketplaceEntry.model_validate(raw)
        except (ValidationError, ValueError) as exc:
            msg = f"{source}: invalid marketplace entry: {exc}"
            raise ConfigurationError(msg) from exc
        if entry.name in seen:
            msg = f"{source}: marketplace entry {entry.name!r} appears twice"
            raise ConfigurationError(msg)
        seen.add(entry.name)
        entries.append(entry)
    return MarketplaceCatalog(
        version=str(data.get("version", "")),
        updated=str(data.get("updated", "")),
        source=source,
        entries=tuple(entries),
    )


def _installed_distributions() -> set[str]:
    """Normalised names of every installed distribution (PEP 503 comparison).

    The catalogue's ``name`` is a **distribution** name, so this is the honest test of
    "installed" — unlike the entry-point names a registry records. A package that is
    importable but has no distribution metadata (a stray directory on ``PYTHONPATH``) is
    still reported by :func:`arachne.plugins.installed_plugins`; the marketplace flag is a
    convenience, not an authorization signal.
    """
    from importlib.metadata import distributions

    names: set[str] = set()
    for distribution in distributions():
        try:
            raw = distribution.metadata["Name"]
        except (KeyError, TypeError):  # pragma: no cover - broken metadata
            continue
        if raw:
            names.add(_normalize_distribution_name(str(raw)))
    return names


def _normalize_distribution_name(name: str) -> str:
    """PEP 503 normalisation: ``Arachne_Example.Report`` → ``arachne-example-report``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())
