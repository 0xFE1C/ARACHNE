"""Live threat intel end to end: feed sync → the scan's snapshot → the report (S18).

What this file proves, in one flow:

* a scan admitted by a deployment with synced, verified feeds records the freshness snapshot
  the report needs (``scans.stats["intel"]``), and
* the rendered report states its own data freshness — Markdown section and JSON block,
  validated against the 1.4 schema — which is REQ-INTEL-001's accept criterion, and
* a feed that failed verification is *not* silently absent: the report says "not ingested",
  so a reader can tell "no KEV match" from "no KEV data".

The scan is admitted with ``launch`` (the API's deferred path), so no check runs and no
request leaves the process: the property under test is the wiring from the feed store to the
evidence, not the checks.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import validate
from tests.conftest import build_scan_request

from arachne.core.config import FeedsSettings, IntelSettings, Settings
from arachne.core.planner import ScanStep
from arachne.data.db import create_all, create_sqlite_engine
from arachne.data.services import build_orchestrator, build_services
from arachne.intel.sync import build_sync_service
from arachne.report.builder import build_report_for_scan
from arachne.report.json_render import load_report_schema, render_json
from arachne.report.markdown import render_markdown
from arachne.report.model import REPORT_SCHEMA_VERSION

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intel"
PINS: dict[str, str] = json.loads((FIXTURES / "checksums.json").read_text(encoding="utf-8"))


@pytest.fixture
def intel_stack(tmp_path: Path) -> Iterator[Any]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'intel-e2e.db'}",
        log_level="CRITICAL",
        feeds=FeedsSettings(dir=str(tmp_path / "feeds")),
    )
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    services = build_services(settings, check_schema=False)
    try:
        yield services
    finally:
        services.close()
        engine.dispose()


def _sync(services: Any, *, fixtures: Path = FIXTURES) -> None:
    import asyncio

    settings = replace(
        services.settings.intel,
        enabled=True,
        fixtures_dir=str(fixtures),
        checksums=tuple(PINS.items()),
        request_delay_s=0.0,
    )
    service = build_sync_service(
        services.feeds, settings, auditor=services.auditor, imported_by="pytest"
    )
    asyncio.run(service.sync())
    asyncio.run(service.aclose())


def _admit(services: Any) -> int:
    import asyncio

    orchestrator = build_orchestrator(services, pipeline=(ScanStep.RECON,))
    session = asyncio.run(orchestrator.launch(build_scan_request()))
    assert session.scan_id is not None
    return int(session.scan_id)


def _age_feeds(services: Any, *, days: int) -> None:
    """Back-date the imported feeds, i.e. "the operator last synced a month ago"."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update

    from arachne.data.models import Feed

    with services.session_factory() as session:
        session.execute(
            update(Feed).values(created_at=datetime.now(UTC) - timedelta(days=days))
        )
        session.commit()


def _report(services: Any, scan_id: int) -> Any:
    return build_report_for_scan(
        scan_id=scan_id,
        scans=services.store,
        findings=services.findings,
        analyses=services.analyses,
        settings=services.settings,
        arachne_version="test",
    )


def test_an_admitted_scan_records_the_feed_freshness_it_was_planned_against(
    intel_stack: Any,
) -> None:
    _sync(intel_stack)
    scan_id = _admit(intel_stack)
    record = intel_stack.store.get_scan(scan_id)
    assert record is not None
    snapshot = record.stats["intel"]
    assert snapshot["stale"] is False
    by_kind = {feed["kind"]: feed for feed in snapshot["feeds"]}
    assert by_kind["kev"]["version"] == "kev@2026.10.29"
    assert by_kind["kev"]["verified"] is True
    assert by_kind["kev"]["verification"] == "checksum"
    assert by_kind["nvd"]["record_count"] == 5
    assert by_kind["epss"]["record_count"] == 3
    # The feed a deployment never loaded is reported as missing, not as fresh.
    assert "cve" in snapshot["missing"]


def test_the_report_surfaces_feed_freshness_in_markdown_and_json(intel_stack: Any) -> None:
    _sync(intel_stack)
    report = _report(intel_stack, _admit(intel_stack))
    assert report.intel is not None
    assert report.intel.stale is False
    assert "cve" in report.intel.missing

    markdown = render_markdown(report)
    assert "### G. Threat-intel freshness" in markdown
    assert "kev@2026.10.29" in markdown
    assert "verified (checksum)" in markdown
    assert "not ingested" in markdown

    document = json.loads(render_json(report))
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    validate(document, load_report_schema())
    assert document["intel"]["feeds"]
    assert document["intel"]["stale"] is False
    assert document["intel"]["missing"] == ["cve"]


def test_a_stale_feed_is_visible_in_the_report(intel_stack: Any) -> None:
    """An old feed is *stated*, not hidden: the TTL is part of the deployment's config."""
    import asyncio

    from arachne.core.orchestrator import Orchestrator
    from arachne.intel.freshness import intel_snapshot

    _sync(intel_stack)
    _age_feeds(intel_stack, days=30)
    # A deployment whose feeds must be a week old at most, over the same store: the snapshotter
    # reads the configured TTL, so the scan records staleness.
    stale = replace(
        intel_stack.settings,
        intel=IntelSettings(
            freshness_ttl=(("nvd", 168.0), ("kev", 168.0), ("epss", 48.0), ("cve", 720.0))
        ),
    )
    orchestrator = Orchestrator(
        settings=stale,
        store=intel_stack.store,
        target_store=intel_stack.target_store,
        auditor=intel_stack.auditor,
        bus=intel_stack.bus,
        registry=intel_stack.registry,
        pipeline=(ScanStep.RECON,),
        intel_snapshot=lambda: intel_snapshot(intel_stack.feeds, settings=stale),
    )
    session = asyncio.run(orchestrator.launch(build_scan_request()))
    assert session.scan_id is not None
    report = _report(intel_stack, int(session.scan_id))
    assert report.intel is not None
    assert report.intel.stale is True
    assert "an ingested feed is past its freshness TTL" in render_markdown(report)


def test_a_rejected_feed_is_reported_as_missing_not_as_clean(
    intel_stack: Any, tmp_path: Path
) -> None:
    """The tampered-feed path, seen from the report: KEV data is absent and says so."""
    tampered = tmp_path / "tampered"
    tampered.mkdir()
    for name in ("nvd.json", "kev.json", "epss.json"):
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        if name == "kev.json":
            payload["body"] = payload["body"].replace("Log4Shell", "Log4Shel1")
        (tampered / name).write_text(json.dumps(payload), encoding="utf-8")
    _sync(intel_stack, fixtures=tampered)
    assert intel_stack.feeds.active("kev") is None
    report = _report(intel_stack, _admit(intel_stack))
    assert report.intel is not None
    assert "kev" in report.intel.missing
    markdown = render_markdown(report)
    assert "`kev`" in markdown
    assert "kev@" not in markdown


def test_the_report_omits_the_section_when_no_snapshot_was_recorded(intel_stack: Any) -> None:
    """A scan from before S18 (or a deployment without a feed store) has no block at all —
    an empty table would be a claim, and there is nothing to claim."""
    scan_id = _admit(intel_stack)
    record = intel_stack.store.get_scan(scan_id)
    assert record is not None
    stats = {key: value for key, value in record.stats.items() if key != "intel"}
    intel_stack.store.update_scan(scan_id, stats=stats)
    report = _report(intel_stack, scan_id)
    assert report.intel is None
    assert "Threat-intel freshness" not in render_markdown(report)
    document = json.loads(render_json(report))
    validate(document, load_report_schema())
    assert document["intel"] is None
