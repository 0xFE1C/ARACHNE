"""The CWE → OWASP Top-10 map for the report's classification block (docs/spec/06- §1).

The spec's finding schema has an ``owasp_2025`` category beside the CWE. ARACHNE's scoring
model already computes an OWASP-style *risk* (likelihood x impact), but a Top-10 category
is a different fact: which class of weakness this is. That mapping is data (F-09-04), so an
organisation can point it at its own edition without a code change.

An unmapped CWE yields ``None`` rather than a guess: a report that claims a category it
cannot justify is worse than one that leaves the field empty.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Final

import yaml

from arachne.core.errors import ConfigurationError

__all__ = ["OwaspMap", "load_owasp_map"]

DEFAULT_OWASP_RESOURCE: Final = ("report", "owasp-map.yaml")


@dataclass(frozen=True, slots=True)
class OwaspMap:
    """CWE → category label, with the edition the labels belong to."""

    version: str
    edition: str
    categories: Mapping[str, str]
    by_cwe: Mapping[str, str]

    def category_for(self, cwe: str | None) -> str | None:
        if not cwe:
            return None
        key = self.by_cwe.get(cwe)
        if key is None:
            return None
        return self.categories.get(key)


def load_owasp_map(path: str | None = None) -> OwaspMap:
    """Load the map from ``path``, or the shipped default."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"OWASP map {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return _parse(text, source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_OWASP_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled OWASP map is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return _parse(text, source="/".join(DEFAULT_OWASP_RESOURCE))


def _parse(text: str, *, source: str) -> OwaspMap:
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{source}: expected a mapping")
    categories = data.get("categories") or {}
    by_cwe = data.get("by_cwe") or {}
    if not isinstance(categories, dict) or not isinstance(by_cwe, dict):
        raise ConfigurationError(f"{source}: categories and by_cwe must be mappings")
    unknown = sorted({str(key) for key in by_cwe.values()} - {str(key) for key in categories})
    if unknown:
        raise ConfigurationError(f"{source}: unknown OWASP category key(s) {unknown}")
    return OwaspMap(
        version=str(data.get("version") or "unknown"),
        edition=str(data.get("edition") or ""),
        categories={str(key): str(value) for key, value in categories.items()},
        by_cwe={str(key): str(value) for key, value in by_cwe.items()},
    )
