"""Integration: the FP workflow end to end — a suppression survives a re-scan (REQ-QUAL-001/002).

Two halves, both against the real stack:

* **The diff** is computed over a real lab report plus one finding a re-scan added, with the
  rule read from the *quality store* (not passed in by the test). The second re-scan reads the
  same store and suppresses the same finding again — that is what "suppression survives a
  re-scan" means, and it is why the rule lives in the store rather than in a report's input.
* **The API and the UI** are driven through ``fastapi.testclient``: the same rule can be
  recorded, listed and revoked over HTTP, an acceptance can be created and expired, and the
  kill switch writes the directive a running scan reads.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from tests.helpers.api import (
    ADMIN_KEY,
    SCANNER_KEY,
    VIEWER_KEY,
    ApiHarness,
    auth,
    make_api_harness,
)
from tests.helpers.report import make_analysis, make_candidate, make_inputs

from arachne.core.config import ApiSettings, HypothesisSettings, Settings
from arachne.data.quality_store import MemoryQualityStore, SqlQualityStore
from arachne.quality.acceptance import RiskAcceptance
from arachne.quality.suppressions import Suppression, SuppressionSet
from arachne.report import build_report_data
from arachne.report.diff import build_diff, diff_from_payload, diff_payload

pytestmark = pytest.mark.integration


def _reports():
    """A base report and a re-scan that found one more thing (the same asset, a new check)."""
    base = make_candidate(
        number=1,
        title="Reflected cross-site scripting",
        asset_value="https://app.example/search",
        module="M3",
        check="xss-oracle",
        severity="medium",
        evidence_start=1,
    )
    new = make_candidate(
        number=2,
        title="Missing HTTP security headers",
        asset_value="https://app.example/",
        module="M3",
        check="security-headers",
        severity="low",
        evidence_start=20,
    )
    first = build_report_data(
        make_inputs(
            candidates=[base],
            analyses=[make_analysis(base, severity="medium", confidence=88, cwe="CWE-79")],
        )
    )
    second = build_report_data(
        make_inputs(
            candidates=[base, new],
            analyses=[
                make_analysis(base, severity="medium", confidence=88, cwe="CWE-79"),
                make_analysis(new, severity="low", confidence=70, cwe="CWE-693"),
            ],
        )
    )
    return first, second


def _rule() -> Suppression:
    return Suppression(
        kind="rule",
        check_id="m3.security-headers",
        reason="the reverse proxy sets the headers; the scanner sees the origin",
        actor="alice",
    )


@pytest.mark.parametrize("store_kind", ["memory", "sql"])
def test_a_suppression_survives_a_rescan_and_the_diff_states_the_count(
    tmp_path, store_kind: str
) -> None:
    if store_kind == "memory":
        store = MemoryQualityStore()
    else:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from arachne.data.models import Base

        engine = create_engine(f"sqlite:///{tmp_path / 'quality.db'}")
        Base.metadata.create_all(engine)
        store = SqlQualityStore(sessionmaker(bind=engine))
    store.add_suppression(_rule())

    first, second = _reports()
    rules = store.active_suppressions()
    assert isinstance(rules, SuppressionSet) and len(rules) == 1

    rescan_one = build_diff(
        first.findings, second.findings, scan_a="scan_1", scan_b="scan_2", suppressions=rules
    )
    assert rescan_one.suppressed == ("m3.security-headers|https://app.example/",)
    assert rescan_one.new == ()
    assert rescan_one.counts["suppressed"] == 1
    assert rescan_one.suppression_version == 1

    # The second re-scan reads the same rule from the same store: still suppressed, still
    # counted, and the persisted document carries it (a stored diff is not silently smaller).
    rescan_two = build_diff(
        first.findings, second.findings, scan_a="scan_1", scan_b="scan_3",
        suppressions=store.active_suppressions(),
    )
    assert rescan_two.suppressed == rescan_one.suppressed
    restored = diff_from_payload(diff_payload(rescan_two))
    assert restored is not None
    assert restored.suppressed == rescan_one.suppressed
    assert restored.suppression_version == 1


def test_a_revoked_suppression_stops_suppressing_the_next_rescan(tmp_path) -> None:
    store = MemoryQualityStore()
    stored = store.add_suppression(_rule())
    assert stored.id is not None
    store.revoke_suppression(stored.id, actor="bob")
    first, second = _reports()
    diff = build_diff(
        first.findings,
        second.findings,
        scan_a="scan_1",
        scan_b="scan_2",
        suppressions=store.active_suppressions(),
    )
    assert diff.suppressed == ()
    assert diff.new == ("m3.security-headers|https://app.example/",)


# --------------------------------------------------------------------------- API


@pytest.fixture
def harness(tmp_path) -> Iterator[ApiHarness]:
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
                ),
                require_tls=False,
                rate_limit_per_minute=100_000,
                rate_limit_burst=1_000,
            ),
            # The kill switch writes a file; keep it inside the test's directory so the suite
            # never touches the working tree.
            hypotheses=HypothesisSettings(control_path=str(tmp_path / "control.json")),
        ),
    )
    try:
        yield built
    finally:
        built.services.close()


def test_the_quality_workflow_over_http(harness: ApiHarness) -> None:
    """REQ-QUAL-001: FP workflow from the API — record, list, revoke, accept, expire."""
    with harness.client() as client:
        created = client.post(
            "/api/v1/suppressions",
            headers=auth(SCANNER_KEY),
            json={
                "kind": "rule",
                "check_id": "m3.security-headers",
                "reason": "the proxy sets the headers, the origin does not",
            },
        )
        assert created.status_code == 201, created.text
        rule = created.json()
        assert rule["version"] == 1 and rule["actor"] == "scanner"

        second = client.post(
            "/api/v1/suppressions",
            headers=auth(SCANNER_KEY),
            json={
                "kind": "pattern",
                "check_id": "m3.xss-oracle",
                "asset_pattern": "https://app.example/*",
                "reason": "reflected input is escaped by the front end",
            },
        )
        assert second.status_code == 201
        assert second.json()["version"] == 2  # versioned, monotonic

        listed = client.get("/api/v1/suppressions", headers=auth(VIEWER_KEY))
        assert listed.status_code == 200
        assert len(listed.json()) == 2

        # A suppression without a reason is refused at the edge (and the model refuses it too).
        refused = client.post(
            "/api/v1/suppressions",
            headers=auth(SCANNER_KEY),
            json={"kind": "rule", "check_id": "m3.xss-oracle", "reason": "x"},
        )
        assert refused.status_code == 422

        revoked = client.delete(
            f"/api/v1/suppressions/{rule['id']}", headers=auth(SCANNER_KEY)
        )
        assert revoked.status_code == 204
        still_there = client.get(
            "/api/v1/suppressions", params={"include_revoked": "true"},
            headers=auth(VIEWER_KEY),
        )
        assert any(not item["active"] for item in still_there.json())

        # An acceptance needs an owner, a justification and a window.
        accepted = client.post(
            "/api/v1/acceptances",
            headers=auth(SCANNER_KEY),
            json={
                "check_id": "m3.security-headers",
                "owner": "platform-team",
                "justification": "compensated by the network control",
                "ttl_days": 30,
            },
        )
        assert accepted.status_code == 201, accepted.text
        assert accepted.json()["owner"] == "platform-team"
        # An acceptance on a finding that does not exist is a clean 404, not a database error.
        unknown = client.post(
            "/api/v1/acceptances",
            headers=auth(SCANNER_KEY),
            json={
                "finding_id": 9999,
                "owner": "platform-team",
                "justification": "compensated by the network control",
                "ttl_days": 30,
            },
        )
        assert unknown.status_code == 404
        listed_acceptances = client.get("/api/v1/acceptances", headers=auth(VIEWER_KEY))
        assert len(listed_acceptances.json()) == 1

        # Nothing has expired yet, so the expire verb is a clean no-op.
        expired = client.post("/api/v1/acceptances/expire", headers=auth(SCANNER_KEY))
        assert expired.status_code == 200
        assert expired.json()["reopened"] == []


def test_the_kill_switch_is_reachable_over_http(harness: ApiHarness) -> None:
    """REQ-AGENT-007: the operator's pause/abort reaches a running scan through a file."""
    import json
    from pathlib import Path

    control_path = Path(harness.settings.hypotheses.control_path or "")
    with harness.client() as client:
        response = client.post(
            "/api/v1/scans/42/hypotheses/control",
            headers=auth(SCANNER_KEY),
            json={"directive": "abort"},
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"scan_id": 42, "directive": "abort"}
        document = json.loads(control_path.read_text(encoding="utf-8"))
        assert document["scans"]["42"] == "abort"

        cleared = client.post(
            "/api/v1/scans/42/hypotheses/control",
            headers=auth(SCANNER_KEY),
            json={"directive": "none"},
        )
        assert cleared.status_code == 200
        assert "42" not in json.loads(control_path.read_text(encoding="utf-8")).get("scans", {})

        # A scan that recorded no journal answers 404 rather than an empty document.
        missing = client.get("/api/v1/scans/999/hypotheses", headers=auth(VIEWER_KEY))
        assert missing.status_code == 404


def test_the_ui_lists_and_records_a_suppression(harness: ApiHarness) -> None:
    """REQ-QUAL-001's UI half: the quality page renders, and its form records a rule."""
    with harness.client() as client:
        # The interface signs in with a key, exactly as a browser does (S12/S17).
        login = client.post(
            "/ui/login", data={"key": SCANNER_KEY, "next": "/ui/quality"}, follow_redirects=False
        )
        assert login.status_code == 303, login.text
        page = client.get("/ui/quality", headers={"hx-request": "true"})
        assert page.status_code == 200
        assert "Suppression rules" in page.text

        created = client.post(
            "/ui/quality/suppressions",
            headers={"hx-request": "true", **auth(SCANNER_KEY)},
            data={
                "kind": "rule",
                "check_id": "m3.security-headers",
                "reason": "the proxy sets the headers",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303, created.text
        assert harness.services.quality is not None
        rows = harness.services.quality.list_suppressions()
        assert rows and rows[0].check_id == "m3.security-headers"
        assert rows[0].actor == "scanner"

        # Without the interface header a state change is refused (the CSRF guard).
        refused = client.post(
            "/ui/quality/suppressions",
            headers=auth(SCANNER_KEY),
            data={"kind": "rule", "check_id": "m3.x", "reason": "no hx header"},
        )
        assert refused.status_code == 403


def test_an_expired_acceptance_reopens_through_the_store(tmp_path) -> None:
    """REQ-QUAL-003 at the store level, with a seeded finding (the API's expire verb calls this)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from arachne.data.models import Asset, Base, Finding, Scan, Target

    engine = create_engine(f"sqlite:///{tmp_path / 'expire.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        target = Target(name="expire-target", scope_json={})
        session.add(target)
        session.commit()
        scan = Scan(target_id=target.id, engine="heuristic", plan_json={}, stats_json={})
        session.add(scan)
        session.commit()
        asset = Asset(scan_id=scan.id, kind="url", value="https://app.example/")
        session.add(asset)
        session.commit()
        finding = Finding(scan_id=scan.id, asset_id=asset.id, title="accepted", status="open")
        session.add(finding)
        session.commit()
        finding_id = int(finding.id)

    store = SqlQualityStore(factory)
    store.add_acceptance(
        RiskAcceptance(
            finding_id=finding_id,
            owner="platform-team",
            justification="compensated by the network control",
            accepted_at=datetime.now(UTC) - timedelta(days=30),
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    with factory() as session:
        row = session.get(Finding, finding_id)
        assert row is not None
        row.status = "accepted"
        session.commit()

    decisions = store.reopen_expired()
    assert [item.finding_id for item in decisions] == [finding_id]
    with factory() as session:
        row = session.get(Finding, finding_id)
        assert row is not None and row.status == "open"
