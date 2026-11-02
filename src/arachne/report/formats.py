"""Report formats as a registry, so a third party can add one without a core change (F-09-01).

Before S14 "which formats exist" was an ``if`` chain and a tuple constant: adding a format
meant editing :mod:`arachne.report` and its callers. This module turns that into the same
shape the check registry already uses — a **name → renderer** table with entry-point
discovery — so a report-format plugin is an installed package, not a patch.

A format is described by :class:`ReportFormat`:

* ``name`` — the CLI/API vocabulary (``md``, ``html``, ``json``, ``pdf``, ``csv``, ...);
* ``render`` — ``ReportData -> str | bytes``. It receives the *same* immutable DTO every
  built-in renderer does, so a plugin cannot invent a finding;
* ``media_type`` and ``binary`` — how the API sets ``Content-Type`` and whether the CLI
  writes text or bytes;
* ``aliases`` — extra spellings (``markdown`` for ``md``);
* ``origin`` — ``builtin`` or the entry point that supplied it.

Discovery uses the ``arachne.report_formats`` entry-point group. A plugin's entry point may
resolve to a :class:`ReportFormat`, a bare renderer callable, or a sequence of either. A
broken plugin is a loud :class:`~arachne.core.errors.ReportError` naming it, never a silent
format that renders nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Final

from arachne.core.errors import ReportError
from arachne.report.model import ReportData

__all__ = [
    "ENTRY_POINT_GROUP",
    "ReportFormat",
    "ReportFormatRegistry",
    "default_registry",
    "discover_formats",
    "reset_format_cache",
]

#: Entry-point group a third-party report-format plugin registers under (F-09-01).
ENTRY_POINT_GROUP: Final = "arachne.report_formats"

#: Renderers are synchronous: a report is assembled from an in-memory DTO, so no I/O.
Renderer = Callable[[ReportData], str | bytes]


@dataclass(frozen=True, slots=True)
class ReportFormat:
    """One renderable format."""

    name: str
    render: Renderer
    media_type: str = "text/plain; charset=utf-8"
    binary: bool = False
    aliases: tuple[str, ...] = ()
    description: str = ""
    origin: str = "builtin"

    def __post_init__(self) -> None:
        normalized = self.name.strip().lower()
        if not normalized:
            msg = "a report format needs a name"
            raise ReportError(msg)
        object.__setattr__(self, "name", normalized)

    @property
    def spellings(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)

    def to_bytes(self, report: ReportData) -> bytes:
        """Render to bytes, encoding text formats as UTF-8."""
        rendered = self.render(report)
        return rendered if isinstance(rendered, bytes) else rendered.encode("utf-8")

    def to_text(self, report: ReportData) -> str:
        if self.binary:
            msg = (
                f"report format {self.name!r} is binary; use report_bytes() or "
                "ReportFormat.to_bytes()"
            )
            raise ReportError(msg)
        rendered = self.render(report)
        return rendered.decode("utf-8") if isinstance(rendered, bytes) else rendered

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "aliases": list(self.aliases),
            "media_type": self.media_type,
            "binary": self.binary,
            "description": self.description,
            "origin": self.origin,
        }


class ReportFormatRegistry:
    """An ordered set of formats with alias resolution and entry-point discovery."""

    def __init__(self, formats: Iterable[ReportFormat] = ()) -> None:
        self._formats: dict[str, ReportFormat] = {}
        self._by_spelling: dict[str, str] = {}
        for item in formats:
            self.register(item)

    # ------------------------------------------------------------------ construction
    def register(self, report_format: ReportFormat) -> None:
        """Register a format, refusing a name/alias that is already taken.

        Refusing (rather than overriding) is deliberate: a plugin that claims ``md`` would
        silently replace the spec's default renderer, and a report whose format depends on
        which packages happen to be installed is not reproducible.
        """
        from dataclasses import replace

        if report_format.name in self._formats:
            msg = f"report format {report_format.name!r} is registered twice"
            raise ReportError(msg)
        for spelling in report_format.spellings:
            key = spelling.strip().lower()
            if key in self._by_spelling:
                msg = (
                    f"report format spelling {spelling!r} is already used by "
                    f"{self._by_spelling[key]!r}"
                )
                raise ReportError(msg)
            self._by_spelling[key] = report_format.name
        self._formats[report_format.name] = replace(
            report_format, aliases=tuple(alias.lower() for alias in report_format.aliases)
        )

    @classmethod
    def discover(
        cls,
        *,
        include_entry_points: bool = True,
        extra: Sequence[ReportFormat] = (),
    ) -> ReportFormatRegistry:
        """Built-ins, then ``extra``, then installed ``arachne.report_formats`` plugins."""
        registry = cls(_builtin_formats())
        for item in extra:
            registry.register(item)
        if include_entry_points:
            for item in _load_entry_point_formats():
                registry.register(item)
        return registry

    # ------------------------------------------------------------------ queries
    @property
    def formats(self) -> tuple[ReportFormat, ...]:
        return tuple(self._formats.values())

    def names(self) -> tuple[str, ...]:
        """Every accepted spelling, in registration order (``md`` first)."""
        return tuple(self._by_spelling)

    def canonical(self, name: str) -> str | None:
        """The canonical name for ``name``/an alias, or ``None`` when unknown."""
        return self._by_spelling.get(name.strip().lower())

    def get(self, name: str) -> ReportFormat | None:
        canonical = self.canonical(name)
        return None if canonical is None else self._formats[canonical]

    def require(self, name: str) -> ReportFormat:
        found = self.get(name)
        if found is None:
            msg = (
                f"unknown report format {name!r}; this build ships "
                f"{', '.join(item.name for item in self.formats)}"
            )
            raise ReportError(msg)
        return found

    def media_type(self, name: str) -> str:
        found = self.get(name)
        return found.media_type if found is not None else "application/octet-stream"

    def summary(self) -> list[dict[str, Any]]:
        return [item.summary() for item in self.formats]


# --------------------------------------------------------------------------- built-ins
def _builtin_formats() -> list[ReportFormat]:
    """The formats the engine names; imports are local to avoid an import cycle.

    ``report/__init__`` imports this module, so a module-level import of the renderers
    would import the package mid-initialisation.
    """
    from arachne.report.defectdojo import render_defectdojo
    from arachne.report.html_render import render_html
    from arachne.report.json_render import render_json
    from arachne.report.markdown import render_markdown
    from arachne.report.pdf import render_pdf
    from arachne.report.sarif import render_sarif

    def _pdf(report: ReportData) -> bytes:
        return render_pdf(report).data

    return [
        ReportFormat(
            name="md",
            render=render_markdown,
            media_type="text/markdown; charset=utf-8",
            aliases=("markdown",),
            description="Markdown skeleton (the default).",
        ),
        ReportFormat(
            name="html",
            render=render_html,
            media_type="text/html; charset=utf-8",
            description="Standalone HTML document.",
        ),
        ReportFormat(
            name="json",
            render=render_json,
            media_type="application/json; charset=utf-8",
            description="Machine-readable, versioned report schema.",
        ),
        ReportFormat(
            name="pdf",
            render=_pdf,
            media_type="application/pdf",
            binary=True,
            description="PDF via the built-in paginator or a headless browser backend.",
        ),
        ReportFormat(
            name="defectdojo",
            render=render_defectdojo,
            media_type="application/json; charset=utf-8",
            description=(
                "DefectDojo import-scan document (S22, REQ-OPS-001): the offline "
                "handoff for `arachne report --format defectdojo`."
            ),
        ),
        ReportFormat(
            name="sarif",
            render=render_sarif,
            media_type="application/sarif+json; charset=utf-8",
            description=(
                "SARIF 2.1.0 for CI code scanning and pull-request annotations (S26, REQ-ECOS-003)."
            ),
        ),
    ]


# --------------------------------------------------------------------------- discovery
def _load_entry_point_formats() -> list[ReportFormat]:
    formats: list[ReportFormat] = []
    for entry_point in _entry_points():
        try:
            loaded = entry_point.load()
        except Exception as exc:  # a broken plugin must be loud, not a silent gap
            raise ReportError(
                f"report-format plugin {entry_point.name!r} failed to load: "
                f"{exc.__class__.__name__}: {exc}"
            ) from exc
        formats.extend(_formats_from_object(loaded, name=entry_point.name))
    return formats


def _entry_points() -> tuple[EntryPoint, ...]:
    return tuple(entry_points(group=ENTRY_POINT_GROUP))


def _formats_from_object(loaded: object, *, name: str) -> list[ReportFormat]:
    if isinstance(loaded, ReportFormat):
        return [_with_origin(loaded, origin=name)]
    if callable(loaded):
        return [_from_callable(loaded, name=name)]
    if isinstance(loaded, (list, tuple)):
        out: list[ReportFormat] = []
        for item in loaded:
            out.extend(_formats_from_object(item, name=name))
        return out
    msg = (
        f"report-format plugin {name!r} must resolve to a ReportFormat, a renderer callable, "
        f"or a sequence of those; got {type(loaded).__name__}"
    )
    raise ReportError(msg)


def _with_origin(item: ReportFormat, *, origin: str) -> ReportFormat:
    from dataclasses import replace

    return replace(item, origin=origin)


def _from_callable(renderer: Callable[..., object], *, name: str) -> ReportFormat:
    """A bare callable becomes a text format named after its entry point."""
    binary = name.lower() in {"pdf"}
    media = "application/octet-stream" if binary else "text/plain; charset=utf-8"

    def render(report: ReportData) -> str | bytes:
        result = renderer(report)
        if not isinstance(result, (str, bytes)):
            msg = f"report-format plugin {name!r} returned {type(result).__name__}, not str/bytes"
            raise ReportError(msg)
        return result

    return ReportFormat(
        name=name,
        render=render,
        media_type=media,
        binary=binary,
        origin=name,
    )


# --------------------------------------------------------------------------- cache
_default: ReportFormatRegistry | None = None


def default_registry() -> ReportFormatRegistry:
    """The process-wide registry: built-ins plus installed plugins, discovered once."""
    global _default
    if _default is None:
        _default = ReportFormatRegistry.discover()
    return _default


def discover_formats(
    *, include_entry_points: bool = True, extra: Sequence[ReportFormat] = ()
) -> ReportFormatRegistry:
    """A fresh registry (tests and the ``arachne plugin`` commands use this)."""
    return ReportFormatRegistry.discover(include_entry_points=include_entry_points, extra=extra)


def reset_format_cache() -> None:
    """Drop the cached registry (tests, and after installing a plugin in-process)."""
    global _default
    _default = None


#: Field kept for callers that used the old constant; the registry is the source of truth.
BUILTIN_FORMAT_NAMES: Final[tuple[str, ...]] = (
    "md",
    "markdown",
    "html",
    "json",
    "pdf",
    "defectdojo",
    "sarif",
)
