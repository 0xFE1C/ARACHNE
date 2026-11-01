"""Internationalisation (i18n) skeleton — externalizable report/prompt text (S14).

This is a **minimal, English-default** framework, not a translation. It exists so
user-visible strings *can* be moved into committed catalogues without changing a single byte
of today's output, and so a second locale can be added later without touching renderers.

Public surface:

* :func:`translate` — ``translate("report.section.executive_summary") -> "Executive summary"``.
  The default is the packaged English catalogue; a missing key returns the key itself (with
  any ``**params`` interpolated), and a locale without a catalogue degrades to English. It
  never raises on a scan/report path.
* :class:`~arachne.i18n.catalog.Translator` — the loader/lookup behind it; construct one with
  in-memory catalogues or let it load ``templates/i18n/<locale>.yaml`` on demand.
* Locale resolution follows the deployment's env-only settings pattern (F-08-01):
  ``ARACHNE_LOCALE`` selects the default locale, an explicit ``locale=`` argument overrides
  it, and the fallback is ``en``.

Scope note — honest about what is and is not externalized today:

* **Externalized now** (English values byte-identical, so no test changes behaviour): the
  Markdown renderer's section titles (executive summary, scope, asset inventory,
  low-confidence observations, appendix) and three per-finding labels (evidence,
  description, remediation) — the ``report.*`` keys in ``templates/i18n/en.yaml``.
* **Still inline** (deliberately not rewired — a mechanical pass, not a correctness one):
  everything else. The HTML and PDF renderers keep their own headings; the Markdown renderer
  still writes "Verification of fix", "Provenance", "Classification", the severity labels and
  the per-row table text inline; the JSON renderer emits schema keys; the analyzer narrative
  and executive-summary prose live in their own corpora (``templates/narrative/``,
  ``templates/report/executive-summary.yaml``); and CLI/API/web text is untouched. Those are
  the natural next entries for the English catalogue, one renderer at a time.
"""

from __future__ import annotations

from arachne.i18n.catalog import (
    DEFAULT_I18N_DIR,
    DEFAULT_LOCALE,
    LOCALE_ENV_VAR,
    Translator,
    load_catalog,
    parse_catalog,
    resolve_locale,
)

__all__ = [
    "DEFAULT_I18N_DIR",
    "DEFAULT_LOCALE",
    "LOCALE_ENV_VAR",
    "Translator",
    "get_translator",
    "load_catalog",
    "parse_catalog",
    "reset_translator",
    "resolve_locale",
    "set_translator",
    "translate",
]

#: The process-wide translator, built lazily with the packaged catalogues.
_default_translator: Translator | None = None


def get_translator() -> Translator:
    """Return the process translator, creating it on first use."""
    global _default_translator
    if _default_translator is None:
        _default_translator = Translator()
    return _default_translator


def set_translator(translator: Translator | None) -> None:
    """Install a process translator (tests, and a deployment shipping its own catalogues)."""
    global _default_translator
    _default_translator = translator


def reset_translator() -> None:
    """Drop the process translator so the next :func:`translate` rebuilds the default."""
    set_translator(None)


def translate(key: str, /, *, locale: str | None = None, **params: object) -> str:
    """Look up ``key`` in ``locale`` (default: the resolved process locale).

    ``locale`` overrides ``ARACHNE_LOCALE`` for this call. An unknown key returns the key
    itself with ``**params`` interpolated; a locale without a catalogue falls back to
    English. Never raises on a scan/report path.
    """
    return get_translator().translate(key, locale=locale, **params)
