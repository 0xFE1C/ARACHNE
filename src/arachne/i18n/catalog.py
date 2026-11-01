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

import os
import re
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_I18N_DIR",
    "DEFAULT_LOCALE",
    "LOCALE_ENV_VAR",
    "Translator",
    "load_catalog",
    "parse_catalog",
    "resolve_locale",
]

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
        """
        target = resolve_locale(locale)
        text = self._catalog(target).get(key)
        if text is None and target != self._fallback_locale:
            text = self._catalog(self._fallback_locale).get(key)
        if text is None:
            text = key
        return interpolate(text, params)
