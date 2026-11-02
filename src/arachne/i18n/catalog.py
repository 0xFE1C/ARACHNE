"""Catalog loading and the :class:`Translator` lookup (S14 i18n skeleton).

The catalogue is **committed data** (``templates/i18n/<locale>.yaml``), loaded through
:mod:`importlib.resources` exactly like every other shipped corpus (rules, narrative
templates, the OWASP map), so an installed package finds it without a path. The English
catalogue is the reference: its values are byte-identical to the strings the renderers used
to hold inline, which is what lets ``translate()`` be wired in without changing any rendered
output.

The lookup is deliberately forgiving, because it sits on a *scan/report path* where an
exception is worse than a missing word:

* an unknown key returns the key itself (with any ``{params}`` interpolated), never raises;
* a locale with no bundled catalogue degrades to English rather than failing the render;
* a malformed catalogue is caught and treated as empty, so a bad translation file cannot
  break a report.

Interpolation is a hand-written ``{name}`` substitution, not :meth:`str.format` — the same
choice :mod:`arachne.analyzer.narrative` makes, so a placeholder can only name a supplied
parameter and can never reach into an object graph.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_I18N_DIR",
    "DEFAULT_LOCALE",
    "LOCALE_ENV_VAR",
    "PLURAL_FORMS",
    "Translator",
    "load_catalog",
    "parse_catalog",
    "plural_form",
    "resolve_locale",
]

_LOGGER: Final = logging.getLogger("arachne.i18n")

#: The locale used when nothing else is configured, and the fallback for every other locale.
DEFAULT_LOCALE: Final = "en"

#: Environment variable a deployment sets to pick the default locale (F-08-01, env-only).
LOCALE_ENV_VAR: Final = "ARACHNE_LOCALE"

#: The catalogue directory, relative to the ``arachne.templates`` package.
DEFAULT_I18N_DIR: Final = "i18n"

#: ``{name}`` — a placeholder naming one of the ``**params``. Deliberately name-only:
#: no ``{0.__class__}`` formatter access, no ``{}`` positional fields.
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def resolve_locale(explicit: str | None = None) -> str:
    """The locale to use: an explicit value, else ``ARACHNE_LOCALE``, else ``en``."""
    if explicit is not None and explicit.strip():
        return explicit.strip()
    return os.environ.get(LOCALE_ENV_VAR, "").strip() or DEFAULT_LOCALE


#: The plural categories a catalogue may carry. This is the CLDR **cardinal** subset the shipped
#: languages need; a locale's rule below maps a count onto one of these, and the catalogue holds
#: ``<key>.one`` / ``<key>.other``.
PLURAL_FORMS: Final[tuple[str, ...]] = ("one", "other")

#: The plural rule per locale (CLDR cardinal). A locale with no entry uses :func:`_default_plural`.
#: English is "exactly one"; French counts zero as singular ("0 constat", not "0 constats"), which
#: is the rule a French-speaking operator expects and the reason this is a table, not ``n == 1``.
_PLURAL_RULES: Final[Mapping[str, Callable[[float], str]]] = {
    "en": lambda count: "one" if count == 1 else "other",
    "fr": lambda count: "one" if int(count) in (0, 1) else "other",
}


def _default_plural(count: float) -> str:
    return "one" if count == 1 else "other"


def plural_form(locale: str, count: float) -> str:
    """The plural category ``count`` falls into in ``locale`` (one of :data:`PLURAL_FORMS`)."""
    rule = _PLURAL_RULES.get((locale or DEFAULT_LOCALE).split("-")[0].split("_")[0].lower())
    return (rule or _default_plural)(count)


#: How a catalogue names a number separator. The catalogue cannot carry the character itself —
#: the French group separator is a narrow no-break space, and ``parse_catalog`` refuses a value
#: that is blank once stripped — so it carries the **name** of the glyph and the glyph lives
#: here, once, with the rest of the formatting rules.
_NUMBER_GLYPHS: Final[Mapping[str, str]] = {
    "comma": ",",
    "point": ".",
    "space": " ",
    "nbsp": "\u00a0",
    "narrow_nbsp": "\u202f",
}


def _separator(catalog: Mapping[str, str], key: str, default: str) -> str:
    """The glyph a catalogue names for ``key`` (see :data:`_NUMBER_GLYPHS`)."""
    return _NUMBER_GLYPHS.get(catalog.get(key, default), _NUMBER_GLYPHS[default])


# --------------------------------------------------------------------------- locale formatting
def _as_datetime(value: object) -> datetime | None:
    """``value`` as an aware UTC datetime, or ``None`` when it is not a date at all.

    An ISO-8601 string is what the API, the stores and the DTOs carry, so that is the shape this
    accepts; a naive datetime is read as UTC because every timestamp ARACHNE records is.
    """
    moment: datetime | None = None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if moment is None:
        return None
    return moment.astimezone(UTC) if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def parse_catalog(data: Any, *, source: str = "<memory>") -> dict[str, str]:
    """Validate an already-parsed catalogue document into flat ``dotted.key -> text``."""
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    strings = data.get("strings")
    if not isinstance(strings, dict):
        msg = f"{source}: 'strings' must be a mapping of dotted keys to text"
        raise ConfigurationError(msg)
    catalog: dict[str, str] = {}
    for key, value in strings.items():
        if not isinstance(key, str) or not key.strip():
            msg = f"{source}: catalogue key {key!r} must be a non-empty string"
            raise ConfigurationError(msg)
        if not isinstance(value, str) or not value.strip():
            msg = f"{source}: value for {key!r} must be a non-empty string"
            raise ConfigurationError(msg)
        catalog[key] = value
    if not catalog:
        msg = f"{source}: catalogue contains no strings"
        raise ConfigurationError(msg)
    return catalog


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


def load_catalog(locale: str = DEFAULT_LOCALE, *, path: str | Path | None = None) -> dict[str, str]:
    """Load one locale's catalogue from ``path`` (file or directory), or the bundled one.

    ``path`` is the managed-data override (F-09-04): a file is read directly, a directory is
    searched for ``<locale>.yaml``. With ``path`` unset the packaged
    ``templates/i18n/<locale>.yaml`` is read. A missing or invalid catalogue raises
    :class:`~arachne.core.errors.ConfigurationError`; :class:`Translator` is the forgiving
    caller that degrades to English instead.
    """
    if path is not None:
        resolved = Path(path).expanduser()
        if resolved.is_dir():
            resolved = resolved / f"{locale}.yaml"
        if not resolved.is_file():
            msg = f"i18n catalogue {resolved} does not exist or is not a file"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read i18n catalogue {resolved}: {exc}") from exc
        return parse_catalog(_safe_yaml(text, source=str(resolved)), source=str(resolved))

    resource = files("arachne.templates").joinpath(DEFAULT_I18N_DIR, f"{locale}.yaml")
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled i18n catalogue for locale {locale!r} is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = f"{DEFAULT_I18N_DIR}/{locale}.yaml"
    return parse_catalog(_safe_yaml(text, source=source), source=source)


def interpolate(text: str, params: Mapping[str, object]) -> str:
    """Substitute ``{name}`` from ``params``; an unknown placeholder is left untouched."""
    if not params:
        return text

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        return str(params[name]) if name in params else match.group(0)

    return _PLACEHOLDER.sub(replace, text)


class Translator:
    """A catalogue-backed lookup that always returns a string.

    ``catalogs`` injects in-memory catalogues by locale (tests, and a deployment that ships
    its own); any locale not supplied is loaded on first use from the packaged data. Every
    load failure is absorbed: the lookup degrades to ``fallback_locale`` and finally to the
    key itself, so it never raises on a scan/report path.
    """

    def __init__(
        self,
        catalogs: Mapping[str, Mapping[str, str]] | None = None,
        *,
        fallback_locale: str = DEFAULT_LOCALE,
    ) -> None:
        self._fallback_locale = fallback_locale
        self._catalogs: dict[str, dict[str, str]] = {
            locale: dict(strings) for locale, strings in (catalogs or {}).items()
        }

    def _catalog(self, locale: str) -> Mapping[str, str]:
        cached = self._catalogs.get(locale)
        if cached is not None:
            return cached
        try:
            loaded = load_catalog(locale)
        except ConfigurationError:
            loaded = {}  # a missing/malformed catalogue must not break a scan
        self._catalogs[locale] = loaded
        return loaded

    def translate(self, key: str, /, *, locale: str | None = None, **params: object) -> str:
        """Return the string for ``key`` in ``locale`` (or the resolved default).

        Resolution: the requested locale, then the fallback (English), then the key itself;
        the result always has ``**params`` interpolated and is never an exception.

        A key found in **neither** catalogue is a defect — it renders as its own dotted name —
        so it is logged at WARNING (REQ-UIX-008: "renders the key and logs a warning"). The
        lookup still returns a string: this sits on a scan/report path, where raising would turn
        a missing word into a failed scan.
        """
        target = resolve_locale(locale)
        text = self._catalog(target).get(key)
        if text is None and target != self._fallback_locale:
            text = self._catalog(self._fallback_locale).get(key)
        if text is None:
            _LOGGER.warning("missing translation for %r (locale %s)", key, target)
            text = key
        return interpolate(text, params)

    def pluralize(
        self, key: str, count: float, /, *, locale: str | None = None, **params: object
    ) -> str:
        """The plural form of ``key`` for ``count``: ``<key>.one`` / ``<key>.other``.

        A catalogue carrying only ``<key>.other`` serves every count, so a language with one
        plural form needs no ``.one`` entry; a key with neither is logged and rendered like any
        other missing key. ``count`` is interpolated as ``{count}``.
        """
        target = resolve_locale(locale)
        form = plural_form(target, count)
        text = self._catalog(target).get(f"{key}.{form}")
        if text is None:
            text = self._catalog(target).get(f"{key}.other")
        if text is None and target != self._fallback_locale:
            text = self._catalog(self._fallback_locale).get(
                f"{key}.{plural_form(self._fallback_locale, count)}"
            )
        if text is None and target != self._fallback_locale:
            text = self._catalog(self._fallback_locale).get(f"{key}.other")
        if text is None:
            _LOGGER.warning("missing plural translation for %r (locale %s)", key, target)
            text = key
        return interpolate(text, {"count": count, **params})

    def format_number(
        self, value: object, decimals: int = 0, /, *, locale: str | None = None
    ) -> str:
        """``value`` grouped and decimal-separated the way ``locale`` writes numbers.

        The separators come from the catalogue (``i18n.number.thousands`` /
        ``i18n.number.decimal``), which is what makes this the catalogue's formatting rather
        than a hard-coded anglo convention. A non-numeric value is returned unchanged, so a
        template can format a field it is not sure about without a guard.
        """
        target = resolve_locale(locale)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            try:
                numeric = float(str(value))
            except (TypeError, ValueError):
                return str(value)
        else:
            numeric = float(value)
        catalog = self._catalog(target)
        grouped = f"{numeric:,.{decimals}f}"
        return (
            grouped.replace(",", "\x00")
            .replace(".", _separator(catalog, "i18n.number.decimal", "point"))
            .replace("\x00", _separator(catalog, "i18n.number.thousands", "comma"))
        )

    def format_datetime(self, value: object, /, *, locale: str | None = None) -> str:
        """``value`` (a datetime or an ISO-8601 string) in ``locale``'s date/time form.

        The pattern and the month names come from the catalogue, and every rendering carries its
        zone (``06-ui-ux.md`` §10: "timestamps are always shown with a timezone"). A value that
        is not a date is returned unchanged rather than raising on a render path.
        """
        target = resolve_locale(locale)
        moment = _as_datetime(value)
        if moment is None:
            return "" if value is None else str(value)
        catalog = self._catalog(target)
        pattern = catalog.get("i18n.datetime.pattern", "{day} {month} {year}, {time} {zone}")
        return interpolate(
            pattern,
            {
                "day": str(moment.day),
                "month": catalog.get(f"i18n.month.{moment.month}", str(moment.month)),
                "year": str(moment.year),
                "time": f"{moment.hour:02d}:{moment.minute:02d}",
                "zone": catalog.get("i18n.timezone.utc", "UTC"),
            },
        )
