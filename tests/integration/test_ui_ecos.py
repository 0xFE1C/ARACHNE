"""The product-grade UI's pages and their golden snapshots (S26, REQ-ECOS-004).

REQ-ECOS-004 asks for the attack-path graph, the executive dashboard (posture trend and control
coverage) and tenant self-service for the FP/risk-acceptance workflow, and its accept criterion
is "UI integration tests; golden screenshots at the gate".

The pages are driven through the real app (``make_api_harness``) with a real scan, and the
snapshots are committed under ``tests/report_qa/golden/`` after :func:`~tests.helpers.golden.
normalize` collapses the two things that legitimately differ between runs (the render timestamp
and the operator label). Everything else — structure, labels, tables, the inline SVG — is
compared verbatim, which is what makes the snapshot a gate rather than a smoke test.

Tenant self-service is asserted as a *behaviour*, not a snapshot: which rule a tenant sees is
the property under test, and a golden would only pin the rendering of whichever rule happened to
be seeded.
"""

from __future__ import annotations

import pytest
from tests.helpers.api import ADMIN_KEY, SCANNER_KEY, VIEWER_KEY, ApiHarness, auth, make_api_harness
from tests.helpers.golden import assert_golden, normalize

pytestmark = pytest.mark.integration


@pytest.fixture
def harness(tmp_path) -> ApiHarness:  # type: ignore[no-untyped-def]
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


def _create_project(client, slug: str, **body: object) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/projects", headers=auth(ADMIN_KEY), json={"slug": slug, **body})
    assert response.status_code == 201, response.text


def _suppress(client, *, project: str, reason: str) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/suppressions",
        headers={**auth(SCANNER_KEY), "X-Project": project},
        json={"kind": "rule", "check_id": f"m3.rule-for-{project}", "reason": reason},
    )
    assert response.status_code == 201, response.text


# --------------------------------------------------------------------------- golden snapshots
def test_the_executive_dashboard_matches_its_golden(harness: ApiHarness) -> None:
    """The dashboard renders from stored rows and its snapshot is committed."""
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        # The default workspace is asserted here because it includes scans that predate any
        # project (``project_id IS NULL``); the tenant-scoped rendering is covered by
        # `test_the_posture_page_is_scoped_to_the_selected_tenant`.
        scan_id = harness.seed_scan()
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get("/ui/posture")
        assert page.status_code == 200, page.text
        assert_golden("ui-posture-page.html", normalize(page.text))
        assert "Executive dashboard" in page.text
        assert "Posture trend" in page.text
        assert "Control coverage" in page.text
        assert f"/ui/scans/{scan_id}" in page.text


def test_the_attack_paths_page_matches_its_golden(harness: ApiHarness) -> None:
    """The attack-path page renders for a scan (the populated graph is a separate SVG golden)."""
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        scan_id = harness.seed_scan()
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get(f"/ui/scans/{scan_id}/attack-paths")
        assert page.status_code == 200, page.text
        assert_golden("ui-attack-paths-page.html", normalize(page.text))
        assert "Attack paths" in page.text
        assert "cheapest breaking remediation" in page.text


def test_the_quality_page_matches_its_golden(harness: ApiHarness) -> None:
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        _create_project(client, "acme", name="Acme Corp")
        _suppress(client, project="acme", reason="hardened at the WAF for this tenant")
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get("/ui/quality?project=acme")
        assert page.status_code == 200, page.text
        assert_golden("ui-quality-page.html", normalize(page.text))


# --------------------------------------------------------------------------- tenant self-service
def test_the_quality_page_shows_only_the_selected_tenants_rules(harness: ApiHarness) -> None:
    """REQ-ECOS-004's self-service half: a tenant sees its own decisions, and no one else's."""
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        _create_project(client, "acme", name="Acme Corp")
        _create_project(client, "globex", name="Globex")
        _suppress(client, project="acme", reason="acme accepted this on its own estate")
        _suppress(client, project="globex", reason="globex has its own decision")
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)

        acme = client.get("/ui/quality?project=acme")
        assert acme.status_code == 200
        assert "acme accepted this on its own estate" in acme.text
        assert "globex has its own decision" not in acme.text

        globex = client.get("/ui/quality?project=globex")
        assert "globex has its own decision" in globex.text
        assert "acme accepted this on its own estate" not in globex.text

        # The MSSP audit view sees both, which is the operator's cross-customer question.
        every = client.get("/ui/quality?scope=all")
        assert "acme accepted this on its own estate" in every.text
        assert "globex has its own decision" in every.text


def test_a_rules_tenant_cannot_be_forged_through_the_form(harness: ApiHarness) -> None:
    """The tenant a rule is recorded in comes from the request, never from the form body.

    Otherwise a scanner in one tenant could file a suppression against another by editing the
    HTML — the same class of bug as trusting a project id from a body.
    """
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        _create_project(client, "acme", name="Acme Corp")
        _create_project(client, "globex", name="Globex")
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        response = client.post(
            "/ui/quality/suppressions",
            headers={"hx-request": "true"},
            data={
                "kind": "rule",
                "check_id": "m3.forged",
                "reason": "filed against the wrong tenant",
                "project_id": "1",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        stored = harness.services.quality.list_suppressions(active_only=False)
        assert len(stored) == 1
        # The default project owns them; the form's project_id was ignored.
        default = harness.services.projects.resolve(None)
        assert harness.services.quality.list_suppressions(
            active_only=False, project_id=default.id
        )
        assert not harness.services.quality.list_suppressions(
            active_only=False, project_id=harness.services.projects.resolve("globex").id
        )


def test_the_new_pages_require_authentication(harness: ApiHarness) -> None:
    with harness.client() as client:
        for path in ("/ui/posture", "/ui/quality", "/ui/scans/1/attack-paths"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["location"].startswith("/ui/login")


def test_the_navigation_links_the_new_pages(harness: ApiHarness) -> None:
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get("/ui/")
        assert page.status_code == 200
        assert 'href="/ui/posture"' in page.text


def test_the_posture_page_is_scoped_to_the_selected_tenant(harness: ApiHarness) -> None:
    """A dashboard that mixed tenants would be a data leak, not a convenience."""
    from arachne.api.auth import API_KEY_COOKIE

    with harness.client() as client:
        _create_project(client, "acme", name="Acme Corp")
        _create_project(client, "globex", name="Globex")
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        acme = client.get("/ui/posture?project=acme")
        assert acme.status_code == 200
        assert "Acme Corp" in acme.text
        assert "Globex" not in acme.text
