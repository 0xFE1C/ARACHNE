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
    assert "locale: fr" in text
    parsed = load_catalog("fr")
    assert parsed["report.severity.critical"] == "Critique"


# ---------------------------------------------------------- WP-06: the UI (REQ-UIX-008)
#: Every key whose English and French values are identical, with the value as a comment. Each
#: one is a cognate, an acronym, a machine example or an identifier — the words a French
#: security team also writes in English — so an entry here is a *decision*, and a value that
#: joins this set without a line here is a translation somebody forgot.
IDENTICAL_BY_DESIGN: dict[str, str] = {
    "i18n.timezone.utc": "UTC",
    "report.finding.classification": "Classification",
    "report.finding.description": "Description",
    "report.finding.provenance": "Provenance",
    "ui.app.name": "ARACHNE",
    "ui.detail.cvss": "CVSS",
    "ui.detail.evidence_ref": "E{number}",
    "ui.detail.sha256": "sha256",
    "ui.display.compact": "Compact",
    "ui.feeds.document_label": "Document",
    "ui.feeds.name_placeholder": "epss-2026-10-29",
    "ui.filter.asset_placeholder": "example.com",
    "ui.filter.cwe": "CWE",
    "ui.filter.cwe_placeholder": "CWE-200",
    "ui.filter.module": "Module",
    "ui.filter.module_placeholder": "m3",
    "ui.findings.confidence_abbrev": "conf",
    "ui.modules.api_rate_value": "{rate}/min",
    "ui.modules.heading": "Modules & configuration",
    "ui.modules.version_short": "v{version}",
    "ui.modules.webhooks": "Webhooks",
    "ui.nav.api": "API",
    "ui.nav.modules": "Modules",
    "ui.nav.posture": "Posture",
    "ui.quality.asset_pattern_placeholder": "https://app.example/*",
    "ui.quality.check_id_placeholder": "m3.xss-oracle",
    "ui.report.json": "JSON",
    "ui.scan.pipeline_heading": "Pipeline",
    "ui.table.artefact": "Artefact",
    "ui.table.cron": "Cron",
    "ui.table.cwe": "CWE",
    "ui.table.id": "Id",
    "ui.table.justification": "Justification",
    "ui.table.module": "Module",
    "ui.table.service": "Service",
    "ui.table.source": "Source",
    "ui.table.version": "Version",
    "ui.title.finding": "{title} · ARACHNE",
    "ui.title.modules": "Modules · ARACHNE",
    "ui.title.posture": "Posture — {project}",
    "ui.workspace.bulkbar_aria": "Triage",
    "ui.workspace.owner_placeholder": "jane.operator@example.com",
    "ui.workspace.undo_chord": "⌘Z",
}


def test_a_missing_key_renders_the_key_and_logs_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """REQ-UIX-008: "a missing translation renders the key and logs a warning"."""
    import logging

    from arachne.i18n import Translator

    with caplog.at_level(logging.WARNING, logger="arachne.i18n"):
        rendered = Translator().translate("ui.no.such.key")
    assert rendered == "ui.no.such.key"
    assert any("ui.no.such.key" in record.getMessage() for record in caplog.records)
    # A key that exists logs nothing: the warning has to mean something.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="arachne.i18n"):
        assert Translator().translate("ui.login.heading") == "ARACHNE sign in"
    assert not caplog.records


def test_only_the_pinned_values_are_identical_across_the_two_locales() -> None:
    """The one list of values that may stay English in French, and nothing else."""
    english = load_catalog("en")
    french = load_catalog("fr")
    identical = {key for key in english if english[key] == french.get(key)}
    assert identical == set(IDENTICAL_BY_DESIGN), sorted(identical ^ set(IDENTICAL_BY_DESIGN))
    for key, value in IDENTICAL_BY_DESIGN.items():
        assert english[key] == value, (key, english[key])


def test_every_ui_value_is_non_empty_and_stays_a_string() -> None:
    for locale in ("en", "fr"):
        for key, value in load_catalog(locale).items():
            if key.startswith(("ui.", "i18n.")):
                assert isinstance(value, str) and value.strip(), (locale, key)


def test_the_plural_rule_follows_the_locale() -> None:
    """French counts zero as singular; English does not. This is a rule, not a translation."""
    from arachne.i18n import Translator, plural_form

    assert plural_form("en", 0) == "other"
    assert plural_form("en", 1) == "one"
    assert plural_form("fr", 0) == "one"
    assert plural_form("fr", 1) == "one"
    assert plural_form("fr", 2) == "other"
    translator = Translator()
    assert translator.pluralize("ui.common.findings", 0, locale="fr") == "0 constat"
    assert translator.pluralize("ui.common.findings", 0, locale="en") == "0 findings"
    assert translator.pluralize("ui.common.findings", 1) == "1 finding"


def test_numbers_and_dates_come_from_the_catalogue() -> None:
    """§10: "Dates and numbers use the locale formatter", and both are catalogue-driven."""
    from arachne.i18n import Translator

    translator = Translator()
    assert translator.format_number(1234567) == "1,234,567"
    assert translator.format_number(1234567, locale="fr") == "1\u202f234\u202f567"
    assert translator.format_number(3.0, 1) == "3.0"
    assert translator.format_number(3.0, 1, locale="fr") == "3,0"
    # A timestamp always carries its zone (§10), in both locales.
    assert translator.format_datetime("2026-11-01T12:00:00+00:00") == "1 Nov 2026, 12:00 UTC"
    assert translator.format_datetime("2026-11-01T12:00:00+00:00", locale="fr") == (
        "1 nov. 2026 à 12:00 UTC"
    )
    # A value that is not a date is passed through rather than raising on a render path.
    assert translator.format_datetime("not a date") == "not a date"
    assert translator.format_datetime(None) == ""
    assert translator.format_number("not a number") == "not a number"


def test_every_closed_vocabulary_a_template_builds_a_key_from_is_translated() -> None:
    """The half of REQ-UIX-008 a static scan of the templates cannot see."""
    from arachne.i18n.audit import _has_key, _vocabulary_prefixes, referenced_keys

    _, prefixes = referenced_keys()
    vocabularies = _vocabulary_prefixes()
    assert prefixes, "no dynamic key prefix found — did the templates change shape?"
    for prefix in prefixes:
        assert prefix in vocabularies, f"{prefix!r} has no declared vocabulary"
        for value in vocabularies[prefix]:
            for locale in ("en", "fr"):
                assert _has_key(load_catalog(locale), f"{prefix}{value}"), (locale, prefix, value)


def test_no_template_carries_a_user_visible_literal() -> None:
    """REQ-UIX-008's first acceptance criterion, as the audit enforces it in CI."""
    from arachne.i18n import audit as i18n_audit

    findings = i18n_audit.audit()
    assert findings == [], "\n".join(str(item) for item in findings)
    assert len(i18n_audit.template_sources()) == 18


def test_the_template_audit_is_not_vacuous() -> None:
    """A gate nobody has seen fail is not a gate: every rule is driven over a plant."""
    from arachne.i18n import audit as i18n_audit

    assert i18n_audit.self_test() == []
    findings, keys, prefixes = i18n_audit.scan_template(
        Path("planted.html"),
        '<h1>Sign in</h1>\n<p aria-label="Display controls"></p>\n'
        '<p>{{ "a phrase in English" }}</p>\n'
        "<p>{{ t('ui.planted.' ~ kind) }}</p>",
    )
    assert {item.rule for item in findings} == {"T1", "T2", "T3"}
    assert prefixes == {"ui.planted."}
    assert not keys


def test_the_template_audit_notices_a_key_that_exists_in_no_catalogue() -> None:
    from arachne.i18n import audit as i18n_audit

    findings, keys, _ = i18n_audit.scan_template(
        Path("planted.html"), "{{ t('ui.not.in.any.catalogue') }}"
    )
    assert findings == []
    assert keys == {"ui.not.in.any.catalogue"}
    assert "ui.not.in.any.catalogue" not in load_catalog("en")
