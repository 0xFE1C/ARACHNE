"""The i18n skeleton: English-default lookup, graceful fallback, locale override (S14).

These tests pin the contract the renderers rely on: a known key returns the exact English
string, a missing key returns the key itself (never an exception) with ``**params``
interpolated, an explicit ``locale`` can select another catalogue, and the committed English
catalogue loads with no empty values.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.i18n import (
    DEFAULT_LOCALE,
    LOCALE_ENV_VAR,
    Translator,
    load_catalog,
    reset_translator,
    resolve_locale,
    translate,
)
from arachne.i18n.catalog import parse_catalog


def test_a_known_key_returns_the_english_string() -> None:
    assert translate("report.section.executive_summary") == "Executive summary"
    assert translate("report.section.scope") == "Scope & methodology"
    assert translate("report.finding.remediation") == "Remediation"


def test_a_missing_key_returns_the_key_without_raising() -> None:
    assert translate("report.section.does_not_exist") == "report.section.does_not_exist"


def test_a_missing_key_interpolates_params() -> None:
    assert translate("missing.{count}.key", count=3) == "missing.3.key"
    # A placeholder with no matching parameter is left intact rather than raising.
    assert translate("missing.{absent}", count=1) == "missing.{absent}"


def test_a_locale_without_a_catalogue_falls_back_to_english() -> None:
    # No bundled ``zz`` catalogue exists; the lookup still returns the English string.
    assert translate("report.section.appendix", locale="zz") == "Appendix"


def test_locale_resolution_prefers_explicit_then_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(LOCALE_ENV_VAR, raising=False)
    assert resolve_locale() == DEFAULT_LOCALE
    monkeypatch.setenv(LOCALE_ENV_VAR, "fr")
    assert resolve_locale() == "fr"
    assert resolve_locale("de") == "de"  # explicit wins over the environment
    assert resolve_locale("  ") == "fr"  # blank explicit falls through to the environment


def test_the_environment_selects_the_default_locale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_translator()
    monkeypatch.setenv(LOCALE_ENV_VAR, "zz")
    # Unknown bundled locale: the process lookup degrades to English, not an exception.
    assert translate("report.section.assets") == "Asset inventory"


def test_a_second_catalog_is_selected_by_locale(tmp_path: Path) -> None:
    catalog_file = tmp_path / "fr.yaml"
    catalog_file.write_text(
        'version: "1.0"\nlocale: fr\nstrings:\n'
        '  report.section.executive_summary: "Résumé exécutif"\n',
        encoding="utf-8",
    )
    french = load_catalog("fr", path=catalog_file)
    translator = Translator({"fr": french})

    # The overridden key comes from the French catalogue...
    assert (
        translator.translate("report.section.executive_summary", locale="fr") == "Résumé exécutif"
    )
    # ...and a key the French catalogue omits falls back to English.
    assert translator.translate("report.section.scope", locale="fr") == "Scope & methodology"


def test_the_bundled_english_catalog_loads_with_non_empty_values() -> None:
    catalog = load_catalog("en")
    assert catalog
    for key, value in catalog.items():
        assert isinstance(key, str) and key.strip()
        assert isinstance(value, str) and value.strip(), key
    # The keys wired into the renderer must all be present in the committed catalogue.
    for key in (
        "report.section.executive_summary",
        "report.section.scope",
        "report.section.assets",
        "report.section.attack_paths",
        "report.section.low_confidence",
        "report.section.appendix",
        "report.finding.evidence",
        "report.finding.description",
        "report.finding.remediation",
    ):
        assert key in catalog, key


def test_a_malformed_catalog_is_a_clean_error() -> None:
    with pytest.raises(ConfigurationError):
        parse_catalog({"not_strings": {}})
    with pytest.raises(ConfigurationError):
        parse_catalog({"strings": {"key": ""}})
    with pytest.raises(ConfigurationError):
        parse_catalog({"strings": {}})


# --------------------------------------------------------------------- S26 (REQ-ECOS-005)
#: The second language the report can be delivered in (S26). A locale is "supported" when its
#: catalogue exists and its key set matches English, so this list is the definition of "at
#: least two languages" that the requirement asks for.
SECOND_LOCALES: tuple[str, ...] = ("fr",)

#: The renderers whose catalogue keys this test scans. A `report.*` string literal in one of
#: these must exist in the catalogue — that is what keeps a renamed key from silently
#: rendering its own name.
_LOCALISED_RENDERERS: tuple[str, ...] = ("report/markdown.py", "report/html_render.py")


def _catalog_path(locale: str) -> Path:
    # Resolve through the real package location: `arachne.templates` is a *namespace*
    # package, so `importlib.resources.files()` yields an object whose str() is a repr, not a
    # path, and a writing/reading test needs a path. `DEFAULT_I18N_DIR` is relative to
    # `templates/`.
    import arachne
    from arachne.i18n import DEFAULT_I18N_DIR

    base = Path(arachne.__file__).resolve().parent / "templates"

    return base / DEFAULT_I18N_DIR / f"{locale}.yaml"


def test_every_second_locale_mirrors_the_english_key_set() -> None:
    """A locale that is missing a key would fall back to English silently (S26).

    That reads as a half-translated report rather than a caught defect, so key-set parity is
    asserted rather than left to the runtime fallback.
    """
    english = load_catalog("en")
    assert english
    for locale in SECOND_LOCALES:
        catalog = load_catalog(locale)
        assert catalog, locale
        missing = sorted(set(english) - set(catalog))
        extra = sorted(set(catalog) - set(english))
        assert not missing, f"{locale} is missing keys: {missing[:5]}"
        assert not extra, f"{locale} has keys English does not: {extra[:5]}"


def test_the_second_locale_actually_translates() -> None:
    """The French catalogue is not a copy of the English one."""
    from arachne.i18n import Translator

    translator = Translator()
    for key in ("report.section.executive_summary", "report.finding.remediation"):
        assert translator.translate(key, locale="fr") != translator.translate(key, locale="en")


def test_every_report_key_a_renderer_names_exists_in_every_catalogue() -> None:
    """Scans the renderers for `report.*` literals and checks them against each catalogue.

    The renderers route every label through the catalogue; a key that does not exist would
    render as its own dotted name in the output, which a golden test would catch but only for
    the paths it exercises. This catches all of them, including a key added to one locale file
    and forgotten in the other.
    """
    import ast

    import arachne

    root = Path(arachne.__file__).resolve().parent
    keys: set[str] = set()
    for relative in _LOCALISED_RENDERERS:
        source = root / relative
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            # A key is a complete dotted name. `f"report.severity.{severity}"` contributes the
            # prefix `"report.severity."` as its own constant in 3.12+, which is not a key —
            # the assembled names it produces are covered by the rendering tests.
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("report.")
                and not node.value.endswith(".")
            ):
                keys.add(node.value)
    assert keys, "no report.* catalogue keys found in the renderers — did the scan break?"
    for locale in ("en", *SECOND_LOCALES):
        catalog = load_catalog(locale)
        unknown = sorted(key for key in keys if key not in catalog)
        assert not unknown, f"{locale} catalogue is missing renderer keys: {unknown}"


def test_the_french_catalogue_is_a_real_file_of_the_expected_shape() -> None:
    text = _catalog_path("fr").read_text(encoding="utf-8")
    assert 'locale: fr' in text
    parsed = load_catalog("fr")
    assert parsed["report.severity.critical"] == "Critique"
