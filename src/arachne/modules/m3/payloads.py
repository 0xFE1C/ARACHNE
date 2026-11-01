"""Load the M3 probe corpus (``templates/m3/payloads.yaml``, F-09-04).

The corpus is *data*: what an M3 check sends, what it matches a response against, and the
parameter-name hints that decide where a family is tried. Modelling it here (rather than
inlining strings in each check) keeps the "detection-only, differential" contract of
 reviewable in one file, and gives an operator a documented override
(``ARACHNE_WEB_PAYLOADS``).

The loader validates the shape it depends on and raises :class:`ConfigurationError` with the
path of the missing key, so a hand-edited corpus fails at load time with an actionable
message instead of producing a check that silently probes nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_PAYLOADS_RESOURCE",
    "BooleanProbe",
    "TimeProbe",
    "UploadExtension",
    "WebPayloads",
    "load_payloads",
    "load_wordlist",
    "parse_payloads",
]

#: Where the shipped M3 corpus lives inside the package.
DEFAULT_PAYLOADS_RESOURCE: Final = ("m3", "payloads.yaml")

#: Hard cap on a wordlist an M3 check will read, so a project-supplied list cannot turn an
#: inventory probe into a content-discovery sweep.
MAX_WORDLIST_ENTRIES: Final = 500


@dataclass(frozen=True, slots=True)
class BooleanProbe:
    """One half of a boolean-differential pair (``1=1`` vs ``1=2``)."""

    name: str
    payload: str
    truth: bool


@dataclass(frozen=True, slots=True)
class TimeProbe:
    """A blocking-sleep payload and the DB family it targets."""

    family: str
    payload: str


@dataclass(frozen=True, slots=True)
class UploadExtension:
    """One extension/content-type pair of the upload validation matrix."""

    ext: str
    content_type: str


@dataclass(frozen=True, slots=True)
class WebPayloads:
    """The parsed M3 corpus, with typed accessors for what the checks consume."""

    version: str
    source: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookup helpers
    def section(self, name: str) -> Mapping[str, Any]:
        value = self.raw.get(name)
        if not isinstance(value, Mapping):
            raise ConfigurationError(f"{self.source}: section {name!r} is missing or not a mapping")
        return value

    def strings(self, *path: str) -> tuple[str, ...]:
        """A list of strings at ``path`` (each element stringified), or ``()``."""
        value = self._get(*path)
        if value is None:
            return ()
        if not isinstance(value, (list, tuple)):
            raise ConfigurationError(
                f"{self.source}: {'/'.join(path)} must be a list, got {type(value).__name__}"
            )
        return tuple(str(item) for item in value)

    def string(self, *path: str, default: str = "") -> str:
        value = self._get(*path)
        return default if value is None else str(value)

    def pattern(self, *path: str) -> re.Pattern[str] | None:
        """A compiled regex at ``path`` (``None`` when absent), validated at load time."""
        value = self._get(*path)
        if value is None:
            return None
        return compile_pattern(str(value), source=self.source, path="/".join(path))

    def mapping(self, *path: str) -> Mapping[str, Any]:
        value = self._get(*path)
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ConfigurationError(
                f"{self.source}: {'/'.join(path)} must be a mapping, got {type(value).__name__}"
            )
        return value

    def entries(self, *path: str) -> tuple[Mapping[str, Any], ...]:
        """The mapping entries of a list at ``path`` (empty when the key is absent/not a list).

        The extended families (S10) store their probes as ``{name, ...}`` lists; this is the
        typed accessor for them, so a check never reaches into the raw mapping.
        """
        value = self._get(*path)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(item for item in value if isinstance(item, Mapping))

    def number(self, *path: str, default: float = 0.0) -> float:
        value = self._get(*path)
        try:
            return default if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"{self.source}: {'/'.join(path)} must be a number") from exc

    def _get(self, *path: str) -> Any:
        node: Any = self.raw
        for segment in path:
            if not isinstance(node, Mapping) or segment not in node:
                return None
            node = node[segment]
        return node

    # ------------------------------------------------------------------ typed views
    def sqli_error_signatures(self) -> Mapping[str, re.Pattern[str]]:
        raw = self.mapping("sqli", "error_signatures")
        compiled: dict[str, re.Pattern[str]] = {}
        for family, expression in raw.items():
            compiled[str(family)] = compile_pattern(
                str(expression), source=self.source, path=f"sqli/error_signatures/{family}"
            )
        if not compiled:
            raise ConfigurationError(f"{self.source}: sqli/error_signatures is empty")
        return compiled

    def sql_error_regex(self) -> re.Pattern[str]:
        """One alternation of every family's signature (used for a single pass per body)."""
        parts = [pattern.pattern for pattern in self.sqli_error_signatures().values()]
        return re.compile("|".join(parts), re.IGNORECASE)

    def boolean_probes(self) -> tuple[BooleanProbe, ...]:
        value = self._get("sqli", "boolean")
        if not isinstance(value, (list, tuple)) or not value:
            raise ConfigurationError(f"{self.source}: sqli/boolean is empty")
        probes: list[BooleanProbe] = []
        for entry in value:
            if not isinstance(entry, Mapping):
                raise ConfigurationError(f"{self.source}: sqli/boolean entry is not a mapping")
            probes.append(
                BooleanProbe(
                    name=str(entry.get("name", "boolean")),
                    payload=str(entry["payload"]),
                    truth=bool(entry.get("truth", False)),
                )
            )
        return tuple(probes)

    def time_probes(self) -> tuple[TimeProbe, ...]:
        value = self._get("sqli", "time")
        if not isinstance(value, (list, tuple)):
            return ()
        probes: list[TimeProbe] = []
        for entry in value:
            if isinstance(entry, Mapping) and "payload" in entry:
                probes.append(
                    TimeProbe(
                        family=str(entry.get("family", "unknown")),
                        payload=str(entry["payload"]),
                    )
                )
        return tuple(probes)

    def upload_extensions(self) -> tuple[UploadExtension, ...]:
        value = self._get("upload", "extensions")
        if not isinstance(value, (list, tuple)) or not value:
            raise ConfigurationError(f"{self.source}: upload/extensions is empty")
        extensions: list[UploadExtension] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "ext" not in entry:
                raise ConfigurationError(f"{self.source}: upload/extensions entry needs 'ext'")
            extensions.append(
                UploadExtension(
                    ext=str(entry["ext"]),
                    content_type=str(entry.get("content_type", "application/octet-stream")),
                )
            )
        return tuple(extensions)

    def traversal_markers(self) -> tuple[tuple[str, re.Pattern[str], str], ...]:
        """``(name, regex, file)`` triples that confirm a traversal read."""
        value = self._get("traversal", "markers")
        if not isinstance(value, (list, tuple)) or not value:
            raise ConfigurationError(f"{self.source}: traversal/markers is empty")
        markers: list[tuple[str, re.Pattern[str], str]] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "regex" not in entry:
                raise ConfigurationError(f"{self.source}: traversal/markers entry needs 'regex'")
            markers.append(
                (
                    str(entry.get("name", "marker")),
                    compile_pattern(
                        str(entry["regex"]), source=self.source, path="traversal/markers"
                    ),
                    str(entry.get("file", "unknown")),
                )
            )
        return tuple(markers)

    def header_baseline(self, *, https: bool) -> tuple[str, ...]:
        key = "https" if https else "http"
        return tuple(name.lower() for name in self.strings("headers", key))

    def session_cookie_names(self) -> frozenset[str]:
        return frozenset(name.lower() for name in self.strings("headers", "session_cookie_names"))


def compile_pattern(expression: str, *, source: str, path: str) -> re.Pattern[str]:
    if len(expression) > 500:
        raise ConfigurationError(f"{source}: {path} pattern is longer than 500 characters")
    try:
        return re.compile(expression, re.IGNORECASE)
    except re.error as exc:
        raise ConfigurationError(f"{source}: {path} is not a valid regex: {exc}") from exc


def parse_payloads(data: Any, *, source: str = "<memory>") -> WebPayloads:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ConfigurationError(f"{source}: 'version' is required")
    payloads = WebPayloads(version=version, source=source, raw=data)
    # Touch the sections the checks require, so a broken corpus fails here, not mid-scan.
    for section in ("sqli", "xss", "traversal", "upload", "auth", "csrf", "cors", "redirect"):
        payloads.section(section)
    payloads.sqli_error_signatures()
    payloads.boolean_probes()
    payloads.upload_extensions()
    payloads.traversal_markers()
    return payloads


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


def _resolve(override: str | None) -> tuple[Path | None, str]:
    """``(path, source)`` — the operator's file when set, else the packaged resource."""
    if override:
        resolved = Path(override).expanduser()
        if resolved.is_dir():
            candidate = resolved / "payloads.yaml"
            if candidate.is_file():
                return candidate, str(candidate)
            raise ConfigurationError(f"no payloads.yaml under {resolved}")
        if not resolved.is_file():
            raise ConfigurationError(f"M3 payload corpus {resolved} does not exist")
        return resolved, str(resolved)
    return None, "/".join(DEFAULT_PAYLOADS_RESOURCE)


def load_payloads(path: str | None = None) -> WebPayloads:
    """Load the M3 corpus from ``path`` (a file or a directory), or the shipped one."""
    resolved, source = _resolve(path)
    if resolved is not None:
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - unreadable file
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_payloads(_safe_yaml(text, source=source), source=source)
    resource = files("arachne.templates")
    for part in DEFAULT_PAYLOADS_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled M3 payload corpus is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_payloads(_safe_yaml(text, source=source), source=source)


def load_wordlist(
    name: str,
    *,
    override_dir: str | None = None,
    limit: int = MAX_WORDLIST_ENTRIES,
) -> tuple[str, ...]:
    """Load an M3 wordlist: an operator directory first, then the packaged one.

    ``name`` is the corpus value (``templates/m3/wordlists/hidden-paths.txt``); an operator's
    ``override_dir`` may hold the same relative path. Comments and blank lines are ignored.
    """
    cap = min(limit, MAX_WORDLIST_ENTRIES)
    relative = Path(name)
    text: str | None = None
    if override_dir:
        candidate = Path(override_dir).expanduser()
        if candidate.is_dir():
            candidate = candidate / relative
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8")
    if text is None:
        resource = files("arachne.templates") / "m3" / relative
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):  # pragma: no cover - packaging failure
            return ()
    return _lines(text)[:cap]


def _lines(text: str) -> tuple[str, ...]:
    entries: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            entries.append(stripped)
    return tuple(dict.fromkeys(entries))


def _sequence(value: Any) -> Sequence[Any]:  # pragma: no cover - convenience for callers
    return value if isinstance(value, (list, tuple)) else ()
