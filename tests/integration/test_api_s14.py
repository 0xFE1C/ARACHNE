"""Integration: multi-tenancy, feed management and the plugin endpoints (S14, F-07-06/09-01/03).

Drives the real app through ``fastapi.testclient``: project isolation is a property of the
assembled interface (dependency + query filters + ownership checks), which is exactly what a
tenant boundary has to survive.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from tests.helpers.api import (
    ADMIN_KEY,
    SCANNER_KEY,
    VIEWER_KEY,
    ApiHarness,
    auth,
    make_api_harness,
    wait_for_scan,
)

from arachne.core.config import ApiSettings, PluginsSettings, Settings

pytestmark = pytest.mark.integration

TARGET: dict[str, object] = {
    "name": "tenant-target",
    "targets": [{"kind": "url", "value": "https://example.com/"}],
    "attestation": {
        "attested_by": "tenant test",
        "attested_at": "2026-10-01T00:00:00Z",
        "scope_statement": "integration-test authorization covering example.com",
        "allowed_targets": ["example.com"],
    },
}

#: A key bound to the ``globex`` tenant (the 4th field of the entry, F-07-06).
GLOBEX_KEY = "globex-viewer-secret"


@pytest.fixture
def harness(tmp_path) -> Iterator[ApiHarness]:  # type: ignore[no-untyped-def]
    built = make_api_harness(
        tmp_path,
        settings=Settings(
            database_url=f"sqlite:///{tmp_path / 'api.db'}",
            log_level="CRITICAL",
            log_json=False,
            actor="pytest",
            api=ApiSettings(
                keys=(
                    f"admin:admin:{ADMIN_KEY}",
                    f"scanner:scanner:{SCANNER_KEY}",
                    f"viewer:viewer:{VIEWER_KEY}",
                    f"globex:viewer:{GLOBEX_KEY}:globex",
                ),
                require_tls=False,
                rate_limit_per_minute=100_000,
                rate_limit_burst=100_000,
                docs_enabled=True,
            ),
            plugins=PluginsSettings(allow_install=True),
        ),
    )
    try:
        yield built
    finally:
        built.close()


def _create_project(client, slug: str, **body) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/projects", headers=auth(ADMIN_KEY), json={"slug": slug, **body})
    assert response.status_code == 201, response.text


def _start_scan(client, project: str) -> int:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/scans",
        headers={**auth(SCANNER_KEY), "X-Project": project},
        json={"target": TARGET},
    )
    assert response.status_code == 202, response.text
    scan_id = int(response.json()["scan_id"])
    wait_for_scan(client, {**auth(VIEWER_KEY), "X-Project": project}, scan_id)
    return scan_id


# --------------------------------------------------------------------------- projects
def test_project_crud_through_the_api(harness: ApiHarness) -> None:
    with harness.client() as client:
        _create_project(
            client,
            "acme",
            name="Acme Corp",
            scope={"domains": ["example.com"]},
            branding={"company_name": "Acme Security", "classification": "CONFIDENTIAL"},
        )
        listed = client.get("/api/v1/projects", headers=auth(VIEWER_KEY))
        assert listed.status_code == 200
        slugs = {row["slug"] for row in listed.json()}
        assert {"acme", "default"} <= slugs
        shown = client.get("/api/v1/projects/acme", headers=auth(VIEWER_KEY))
        assert shown.json()["branding"]["company_name"] == "Acme Security"
        assert client.get("/api/v1/projects/nope", headers=auth(VIEWER_KEY)).status_code == 404
        # Only an admin may create one.
        assert (
            client.post(
                "/api/v1/projects", headers=auth(VIEWER_KEY), json={"slug": "x"}
            ).status_code
            == 403
        )


def test_the_default_project_cannot_be_deleted(harness: ApiHarness) -> None:
    with harness.client() as client:
        client.get("/api/v1/projects", headers=auth(VIEWER_KEY))  # ensure_default
        response = client.delete("/api/v1/projects/default", headers=auth(ADMIN_KEY))
        assert response.status_code == 404
        assert "default project" in response.json()["error"]["message"]


# --------------------------------------------------------------------------- isolation
def test_scans_and_targets_are_isolated_between_projects(harness: ApiHarness) -> None:
    with harness.client() as client:
        _create_project(client, "acme")
        _create_project(client, "globex")
        scan_id = _start_scan(client, "acme")
        created_target = client.post(
            "/api/v1/targets",
            headers={**auth(ADMIN_KEY), "X-Project": "acme"},
            json={**TARGET},
        )
        assert created_target.status_code == 201, created_target.text

        acme_scans = client.get(
            "/api/v1/scans", headers={**auth(VIEWER_KEY), "X-Project": "acme"}
        ).json()
        assert [row["id"] for row in acme_scans] == [scan_id]
        globex_scans = client.get(
            "/api/v1/scans", headers={**auth(VIEWER_KEY), "X-Project": "globex"}
        ).json()
        assert globex_scans == []

        # A scan in another tenant is a 404, not a 403: its existence is not disclosed.
        assert (
            client.get(
                f"/api/v1/scans/{scan_id}", headers={**auth(VIEWER_KEY), "X-Project": "globex"}
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/scans/{scan_id}/report?format=md",
                headers={**auth(VIEWER_KEY), "X-Project": "globex"},
            ).status_code
            == 404
        )
        acme_targets = client.get(
            "/api/v1/targets", headers={**auth(VIEWER_KEY), "X-Project": "acme"}
        ).json()
        globex_targets = client.get(
            "/api/v1/targets", headers={**auth(VIEWER_KEY), "X-Project": "globex"}
        ).json()
        assert len(acme_targets) == 1
        assert globex_targets == []


def test_a_key_bound_to_a_project_cannot_name_another(harness: ApiHarness) -> None:
    with harness.client() as client:
        _create_project(client, "acme")
        _create_project(client, "globex")
        forbidden = client.get("/api/v1/scans", headers={**auth(GLOBEX_KEY), "X-Project": "acme"})
        assert forbidden.status_code == 403
        assert "bound to project" in forbidden.json()["error"]["message"]
        # Without a header the bound key operates on its own tenant.
        own = client.get("/api/v1/scans", headers=auth(GLOBEX_KEY))
        assert own.status_code == 200
        assert own.json() == []


def test_a_finding_in_another_project_is_not_readable(harness: ApiHarness) -> None:
    with harness.client() as client:
        _create_project(client, "acme")
        _create_project(client, "globex")
        scan_id = _start_scan(client, "acme")
        finding_id = harness.seed_finding(scan_id=scan_id, severity="high")
        assert (
            client.get(
                f"/api/v1/findings/{finding_id}",
                headers={**auth(VIEWER_KEY), "X-Project": "globex"},
            ).status_code
            == 404
        )
        found = client.get(
            f"/api/v1/findings/{finding_id}",
            headers={**auth(VIEWER_KEY), "X-Project": "acme"},
        )
        assert found.status_code == 200


def test_a_pre_s14_scan_is_visible_in_the_default_workspace(harness: ApiHarness) -> None:
    """Rows written before multi-tenancy (``project_id`` NULL) belong to ``default``."""
    finding_id = harness.seed_finding(severity="medium")
    with harness.client() as client:
        listed = client.get("/api/v1/findings", headers=auth(VIEWER_KEY)).json()
        assert [row["id"] for row in listed] == [finding_id]


# --------------------------------------------------------------------------- branding
def test_a_tenant_report_carries_its_branding(harness: ApiHarness) -> None:
    with harness.client() as client:
        _create_project(
            client,
            "acme",
            branding={
                "company_name": "Acme Security",
                "classification": "CONFIDENTIAL",
                "show_arachne_branding": False,
            },
        )
        scan_id = _start_scan(client, "acme")
        response = client.get(
            f"/api/v1/scans/{scan_id}/report?format=md",
            headers={**auth(VIEWER_KEY), "X-Project": "acme"},
        )
        assert response.status_code == 200
        assert response.text.startswith("**CONFIDENTIAL**")
        assert "Acme Security" in response.text


# --------------------------------------------------------------------------- feeds
def test_feed_import_lookup_and_delete(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/feeds",
            headers=auth(SCANNER_KEY),
            json={
                "kind": "epss",
                "name": "api-epss",
                "content": "cve,epss,percentile\nCVE-2021-44228,0.97,0.999\n",
            },
        )
        assert response.status_code == 201, response.text
        feed = response.json()
        assert feed["kind"] == "epss" and feed["record_count"] == 1

        listed = client.get("/api/v1/feeds", headers=auth(VIEWER_KEY)).json()
        assert [row["id"] for row in listed["feeds"]] == [feed["id"]]
        assert listed["stats"]["by_kind"]["epss"]["entries"] == 1

        lookup = client.get("/api/v1/feeds/lookup/CVE-2021-44228", headers=auth(VIEWER_KEY))
        assert lookup.status_code == 200
        assert lookup.json()["epss"] == pytest.approx(0.97)
        assert (
            client.get("/api/v1/feeds/lookup/CVE-0000-0000", headers=auth(VIEWER_KEY)).status_code
            == 404
        )

        shown = client.get(f"/api/v1/feeds/{feed['id']}", headers=auth(VIEWER_KEY))
        assert shown.json()["entries"][0]["cve"] == "CVE-2021-44228"

        assert (
            client.delete(f"/api/v1/feeds/{feed['id']}", headers=auth(VIEWER_KEY)).status_code
            == 403
        )
        assert (
            client.delete(f"/api/v1/feeds/{feed['id']}", headers=auth(ADMIN_KEY)).status_code == 204
        )


def test_a_malformed_feed_is_a_400_with_the_reason(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/feeds",
            headers=auth(SCANNER_KEY),
            json={"kind": "epss", "name": "bad", "content": "no,columns\n1,2\n"},
        )
        assert response.status_code == 400
        assert "needs 'cve' and 'epss'" in response.json()["error"]["message"]


# --------------------------------------------------------------------------- plugins
def test_plugin_inventory_and_marketplace(harness: ApiHarness) -> None:
    with harness.client() as client:
        inventory = client.get("/api/v1/plugins", headers=auth(VIEWER_KEY)).json()
        assert set(inventory) >= {"checks", "report_formats", "install_enabled"}
        assert inventory["install_enabled"] is True
        formats = client.get("/api/v1/plugins/formats", headers=auth(VIEWER_KEY)).json()
        names = {item["name"] for item in formats["formats"]}
        assert {"md", "html", "json", "pdf"} <= names
        marketplace = client.get(
            "/api/v1/plugins/marketplace?search=example", headers=auth(VIEWER_KEY)
        ).json()
        assert any(row["name"] == "arachne-example-check-plugin" for row in marketplace["entries"])


def test_plugin_install_is_a_dry_run_over_the_api(harness: ApiHarness, tmp_path) -> None:  # type: ignore[no-untyped-def]
    wheel = _build_example_wheel(tmp_path)
    with harness.client() as client:
        response = client.post(
            "/api/v1/plugins/install",
            headers=auth(ADMIN_KEY),
            json={"source": str(wheel), "dry_run": True},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["install"]["executed"] is False
        assert "pip install" in " ".join(payload["install"]["argv"])


def test_plugin_install_is_refused_when_disabled(harness: ApiHarness, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    wheel = _build_example_wheel(tmp_path)
    with harness.client() as client:
        harness.context.settings = replace(
            harness.context.settings,
            plugins=PluginsSettings(allow_install=False),
        )
        response = client.post(
            "/api/v1/plugins/install",
            headers=auth(ADMIN_KEY),
            json={"source": str(wheel)},
        )
        assert response.status_code == 403
        assert "ARACHNE_PLUGIN_INSTALL" in response.json()["error"]["message"]


def _build_example_wheel(tmp_path) -> object:  # type: ignore[no-untyped-def]
    from pathlib import Path

    from tests.helpers.plugin_wheel import build_wheel

    root = Path(__file__).resolve().parents[2]
    return build_wheel(
        tmp_path / "wheels",
        name="arachne-example-plugin",
        version="0.1.0",
        package_dir=root
        / "examples"
        / "plugins"
        / "arachne_example_plugin"
        / "src"
        / "arachne_example_plugin",
        entry_points={
            "arachne.modules": {"example-version-banner": "arachne_example_plugin:PLUGIN_GROUP"}
        },
    )


# Keep the json import meaningful: a feed's provenance is JSON round-trippable.
def test_feed_metadata_is_json_serialisable(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/feeds",
            headers=auth(SCANNER_KEY),
            json={
                "kind": "kev",
                "name": "kev",
                "content": json.dumps({"vulnerabilities": [{"cveID": "CVE-2017-0144"}]}),
            },
        )
        assert response.status_code == 201, response.text
        json.dumps(response.json())  # no non-serialisable values leak into the response


def test_the_feeds_and_plugins_pages_render(harness: ApiHarness) -> None:
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        feeds = client.get("/ui/feeds")
        assert feeds.status_code == 200, feeds.text
        assert "CVE / EPSS feeds" in feeds.text
        assert "Import a feed" in feeds.text
        plugins = client.get("/ui/plugins")
        assert plugins.status_code == 200, plugins.text
        assert "Marketplace" in plugins.text
        assert "Report formats" in plugins.text


def test_the_dashboard_is_scoped_to_the_selected_project(harness: ApiHarness) -> None:
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        _create_project(client, "acme")
        _create_project(client, "globex")
        _start_scan(client, "acme")
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        acme = client.get("/ui/?project=acme")
        assert acme.status_code == 200
        assert "tenant-target" in acme.text
        globex = client.get("/ui/?project=globex")
        assert globex.status_code == 200
        assert "tenant-target" not in globex.text
