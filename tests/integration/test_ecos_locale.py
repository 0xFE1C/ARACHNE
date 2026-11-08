"""Per-report and per-tenant report languages (S26, REQ-ECOS-005).

REQ-ECOS-005 is "at least two languages, with per-report locale selection". The catalogue
existence and the renderer wiring are covered in `tests/unit/test_i18n.py` and the goldens;
this file is the *selection* behaviour end to end: the tenant's stored default, the per-report
override, and the operator's command for setting either.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import plain
from tests.helpers.api import ADMIN_KEY, VIEWER_KEY, ApiHarness, auth, make_api_harness
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import reset_settings_cache

pytestmark = pytest.mark.integration

runner = CliRunner()


@pytest.fixture
def harness(tmp_path: Path) -> ApiHarness:
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


def test_a_tenant_can_be_created_with_a_default_report_language(harness: ApiHarness) -> None:
    with harness.client() as client:
        created = client.post(
            "/api/v1/projects",
            headers=auth(ADMIN_KEY),
            json={"slug": "acme", "name": "Acme Corp", "report_locale": "fr"},
        )
        assert created.status_code == 201, created.text
        assert created.json()["report_locale"] == "fr"
        listed = client.get("/api/v1/projects", headers=auth(VIEWER_KEY))
        assert listed.status_code == 200
        assert listed.json()[0]["report_locale"] == "fr"


def test_a_report_can_be_rendered_in_either_language(harness: ApiHarness) -> None:
    """The same scan, two languages, one request apart — the point of per-report selection."""
    with harness.client() as client:
        client.post(
            "/api/v1/projects",
            headers=auth(ADMIN_KEY),
            json={"slug": "acme", "name": "Acme Corp", "report_locale": "fr"},
        )
        scan_id = harness.seed_scan(project="acme")
        english = client.get(
            f"/api/v1/scans/{scan_id}/report?locale=en",
            headers={**auth(VIEWER_KEY), "X-Project": "acme"},
        )
        assert english.status_code == 200, english.text
        assert "## 1. Executive summary" in english.text

        french = client.get(
            f"/api/v1/scans/{scan_id}/report?locale=fr",
            headers={**auth(VIEWER_KEY), "X-Project": "acme"},
        )
        assert french.status_code == 200, french.text
        assert "## 1. Synthèse pour la direction" in french.text

        # With no override, the tenant's stored default applies.
        default = client.get(
            f"/api/v1/scans/{scan_id}/report", headers={**auth(VIEWER_KEY), "X-Project": "acme"}
        )
        assert "## 1. Synthèse pour la direction" in default.text


def test_an_unknown_locale_falls_back_to_english_rather_than_failing(harness: ApiHarness) -> None:
    with harness.client() as client:
        scan_id = harness.seed_scan()
        response = client.get(f"/api/v1/scans/{scan_id}/report?locale=zz", headers=auth(VIEWER_KEY))
        assert response.status_code == 200, response.text
        assert "## 1. Executive summary" in response.text


def test_the_html_report_declares_the_language_it_was_rendered_in(harness: ApiHarness) -> None:
    with harness.client() as client:
        scan_id = harness.seed_scan()
        french = client.get(
            f"/api/v1/scans/{scan_id}/report?format=html&locale=fr", headers=auth(VIEWER_KEY)
        )
        assert french.status_code == 200
        assert '<html lang="fr">' in french.text
        english = client.get(
            f"/api/v1/scans/{scan_id}/report?format=html", headers=auth(VIEWER_KEY)
        )
        assert '<html lang="en">' in english.text


def test_the_json_report_carries_its_locale(harness: ApiHarness) -> None:
    with harness.client() as client:
        scan_id = harness.seed_scan()
        response = client.get(
            f"/api/v1/scans/{scan_id}/report?format=json&locale=fr", headers=auth(VIEWER_KEY)
        )
        assert response.status_code == 200
        document = json.loads(response.text)
        assert document["locale"] == "fr"
        # WP-21 moved the report schema to 1.14 (the feed-freshness SLA fields, REQ-INTEL-006);
        # the locale itself is unchanged by that additive bump.
        assert document["schema_version"] == "1.14"


def test_the_locale_is_audited_with_the_report(harness: ApiHarness) -> None:
    """A report is delivered to a reader in a language; the trail records which."""
    from arachne.core.audit import AuditAction

    with harness.client() as client:
        scan_id = harness.seed_scan()
        response = client.get(f"/api/v1/scans/{scan_id}/report?locale=fr", headers=auth(VIEWER_KEY))
        assert response.status_code == 200
    events = harness.events_of(AuditAction.REPORT_GENERATED)
    assert events
    assert events[-1].meta["locale"] == "fr"


# --------------------------------------------------------------------------- the operator's verb
def test_the_project_locale_command_sets_and_clears_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'locale.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_REPORT_LOCALE", "en")
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    assert runner.invoke(app, ["project", "create", "acme", "--name", "Acme Corp"]).exit_code == 0

    set_locale = runner.invoke(app, ["project", "locale", "--project", "acme", "--locale", "fr"])
    assert set_locale.exit_code == 0, set_locale.output
    payload = json.loads(set_locale.output)
    assert payload["report_locale"] == "fr"
    assert payload["deployment_locale"] == "en"

    cleared = runner.invoke(app, ["project", "locale", "--project", "acme", "--clear"])
    assert cleared.exit_code == 0, cleared.output
    assert json.loads(cleared.output)["report_locale"] is None


def test_the_project_locale_command_refuses_a_contradiction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'locale2.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    result = runner.invoke(
        app, ["project", "locale", "--project", "acme", "--locale", "fr", "--clear"]
    )
    assert result.exit_code != 0
    assert "--clear cannot be combined with --locale" in plain(result.output)


def test_a_malformed_language_tag_is_refused_by_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo must fail loudly rather than silently fall back to English.

    The CLI lets an unknown-but-well-formed tag through (a deployment may be about to ship that
    catalogue), but a value that is not a language tag at all is a mistake with no reading.
    """
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'locale3.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    assert runner.invoke(app, ["project", "create", "acme"]).exit_code == 0
    result = runner.invoke(
        app, ["project", "locale", "--project", "acme", "--locale", "not a language!"]
    )
    assert result.exit_code == 2, result.output
    assert "not a language tag" in result.output
