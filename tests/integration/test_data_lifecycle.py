"""The data lifecycle on a real scan: offload, dedup, retrieval, quota, pruning (S20).

Everything here runs the *offline demo scan* (``docker/demo`` fixtures, replayed responses,
no socket — the same sequence ``docker compose up`` runs, established in
``tests/integration/test_s14_e2e.py``) against a temporary database, and then asserts what
happened to the data it produced:

* REQ-DATA-002/004 — evidence above the configured threshold lands in the configured backend,
  content-addressed, once per distinct payload, and reads back byte-identical.
* REQ-DATA-003 — a quota crossing warns, then hard-stops the scan with an audit line and a
  *resumable* scan, which ``arachne scan --resume`` continues once the quota is raised.
* REQ-DATA-001 — a pruning run removes an expired scan, its findings and evidence *and the
  objects those rows pointed at*, and a dry run removes nothing.
* REQ-OPS-003/004 — the metrics endpoint reflects the scan, and a real scan produces a span
  tree (orchestrator step → HTTP client request).
"""

from __future__ import annotations

import hashlib
import json
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.audit import AuditAction
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.metrics import render_metrics, reset_metrics
from arachne.core.tracing import InMemoryExporter, configure_tracing, reset_tracer
from arachne.data.metrics_source import collect_deployment_metrics
from arachne.data.retention import RetentionPruner
from arachne.data.services import build_evidence_backend, build_services

CODE_ROOT = Path(__file__).resolve().parents[2]
DEMO = CODE_ROOT / "docker" / "demo"
TARGET = DEMO / "target.yaml"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"

runner = CliRunner()


#: The harness's viewer key, as a header dict (every read needs one).
def _viewer_auth() -> dict[str, str]:
    from tests.helpers.api import VIEWER_KEY, auth

    return auth(VIEWER_KEY)


VIEWER_AUTH = _viewer_auth()


def _scan_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    offload_threshold: int = 256,
    preview_chars: int = 16,
    quota_bytes: int | None = None,
) -> Path:
    """The demo scan's environment plus the S20 evidence switches.

    The bundled demo target's responses are a few hundred bytes each — that is the point of a
    fixture you can read — so the offload threshold here is set *below* what a real deployment
    would use (the default is 16 KiB). The service refuses to offload a payload whose stub
    would be larger than the payload itself, so this configuration exercises both branches:
    the 400-500 byte rows offload, the ~120 byte ones stay inline.``preview_chars`` is dropped
    to 16 for the same reason: the reference metadata costs ~230 bytes, and a 2 KiB preview
    would make every stub bigger than the payload it replaces.
    """
    evidence_dir = tmp_path / "evidence"
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'lifecycle.db'}")
    monkeypatch.setenv("ARACHNE_HTTP_FIXTURES", str(DEMO / "http"))
    monkeypatch.setenv("ARACHNE_OSINT_ENABLED", "true")
    monkeypatch.setenv("ARACHNE_OSINT_FIXTURES", str(DEMO / "osint"))
    monkeypatch.setenv("ARACHNE_OSINT_PROVIDERS", "crtsh,circl,wayback,commoncrawl,internetdb")
    monkeypatch.setenv("ARACHNE_OSINT_SEARCH_URL", SEARCH_URL)
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("ARACHNE_EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("ARACHNE_EVIDENCE_OFFLOAD_THRESHOLD_BYTES", str(offload_threshold))
    monkeypatch.setenv("ARACHNE_EVIDENCE_PREVIEW_CHARS", str(preview_chars))
    if quota_bytes is not None:
        monkeypatch.setenv("ARACHNE_EVIDENCE_DEFAULT_QUOTA_BYTES", str(quota_bytes))
    reset_settings_cache()
    upgraded = runner.invoke(app, ["db", "upgrade"])
    assert upgraded.exit_code == 0, upgraded.output
    return evidence_dir


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Nothing in this file may open a socket: the demo scan is a replay."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


@pytest.fixture(autouse=True)
def _clean_process_state() -> Iterator[None]:
    reset_metrics()
    reset_tracer()
    yield
    reset_metrics()
    reset_tracer()


def _run_scan(extra: list[str] | None = None) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["scan", "--target", str(TARGET), "--json", *(extra or [])])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("{") :])
    return int(payload["scan_id"]), payload


def _object_files(evidence_dir: Path) -> list[Path]:
    return sorted(
        path for path in evidence_dir.rglob("*") if path.is_file() and path.parent.name != ".tmp"
    )


# --------------------------------------------------------------- REQ-DATA-002 / 004
def test_the_scan_offloads_large_evidence_content_addressed_and_compressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Offload, dedup and compression, asserted against what is actually on disk."""
    evidence_dir = _scan_env(tmp_path, monkeypatch)
    scan_id, _ = _run_scan()

    services = build_services(get_settings())
    try:
        candidates = services.findings.list_candidates(scan_id)
        offloaded = [
            record for candidate in candidates for record in candidate.evidence if record.offloaded
        ]
        assert offloaded, "nothing was offloaded: the threshold did not bite"
        assert all(record.storage == "local" for record in offloaded)
        # The stub keeps a bounded preview so a report can still show the capture.
        first = offloaded[0]
        assert first.payload["offloaded"] is True
        assert first.payload["key"] == first.storage_key
        assert first.payload["backend"] == "local"
        assert int(first.payload["size"]) == int(first.size_bytes or 0)
        assert len(json.dumps(first.payload)) < int(first.size_bytes or 0)
        strings = [
            value
            for value in first.payload.values()
            if isinstance(value, str) and not value.startswith("{")
        ]
        assert all(len(value) <= 2048 for value in strings)

        # The sizes the payloads would have occupied inline are still recorded, so the
        # arithmetic below is real rather than derived from the stubs.
        inline = [
            record
            for candidate in candidates
            for record in candidate.evidence
            if not record.offloaded
        ]
        assert inline, "every payload was offloaded; the inline branch is untested here"

        files = _object_files(evidence_dir)
        logical = sum(int(record.size_bytes or 0) for record in offloaded)
        stored = sum(path.stat().st_size for path in files)
        assert files, "no evidence object was written"
        assert stored < logical, f"stored {stored} of {logical} logical bytes"

        # The object reads back byte-identical to the digest recorded with the row.
        backend = build_evidence_backend(get_settings())
        for record in offloaded:
            payload = __import__("asyncio").run(backend.get(str(record.storage_key)))
            assert hashlib.sha256(payload).hexdigest() == record.storage_key

        # REQ-DATA-004: writing the *same* payload again costs no new object — content
        # addressing is the dedup mechanism, so the ratio is exact rather than statistical.
        stage = __import__("asyncio").run
        first = stage(_stage_repeat(services, scan_id))
        after_first = len(_object_files(evidence_dir))
        assert after_first == len(files) + 1, "the first copy should have cost one object"
        again = stage(_stage_repeat(services, scan_id))
        assert len(_object_files(evidence_dir)) == after_first, "a duplicate payload was stored"
        assert first.evidence[0].payload["key"] == again.evidence[0].payload["key"]
        stats = services.evidence.stats()
        assert stats["dedup_hits"] >= 1, stats
        assert stats["logical_bytes"] > stats["stored_bytes"], stats
    finally:
        services.close()


def _stage_repeat(services: object, scan_id: int) -> object:
    """Stage the same oversized payload twice, through the real service."""
    from arachne.core.results import CheckResult, Evidence

    result = CheckResult(
        module="m3",
        check="m3.sqli-oracle",
        title="repeat",
        status="vulnerable",
        detail="repeat",
        confidence=0.9,
        evidence=(Evidence.of("http_response", {"body": "B" * 4096}),),
    )
    return services.evidence.stage(result, scan_id=scan_id, project_id=None)  # type: ignore[attr-defined]


def test_an_offloaded_payload_is_served_by_the_download_route(tmp_path: Path) -> None:
    """The API hands back the stored object (presigned when the backend can mint one)."""
    from tests.helpers.api import make_api_harness

    database = tmp_path / "lifecycle.db"
    evidence_dir = tmp_path / "evidence"
    harness = make_api_harness(
        tmp_path,
        settings=_download_settings(tmp_path, database, evidence_dir),
    )
    try:
        from arachne.core.results import CheckResult, Evidence

        # Write one oversized payload through the real store + service, as the checks step
        # would, then read it back through the route.
        scan_id = harness.seed_scan()
        staged = __import__("asyncio").run(
            harness.services.evidence.stage(
                CheckResult(
                    module="m3",
                    check="m3.sqli-oracle",
                    title="planted",
                    status="vulnerable",
                    detail="d",
                    confidence=0.9,
                    evidence=(
                        Evidence.of("http_response", {"body": "A" * 5000, "status_code": 200}),
                    ),
                ),
                scan_id=scan_id,
                project_id=None,
            )
        )
        record = harness.services.findings.record_candidate(
            scan_id, result=staged, check_id=None, asset_id=None
        )
        offloaded = [item for item in record.evidence if item.offloaded]
        assert offloaded, "the payload was not offloaded"
        client = harness.client(headers=VIEWER_AUTH)
        response = client.get(f"/api/v1/evidence/{offloaded[0].id}/download")
        assert response.status_code == 200
        assert len(response.content) > 5000
        assert response.headers["content-disposition"].startswith("attachment")
        body = json.loads(response.content)
        assert body["body"] == "A" * 5000
        # An unknown id is a 404, not a 500; and the route needs a key like every read.
        assert client.get("/api/v1/evidence/999999/download").status_code == 404
        anonymous = harness.client().get(f"/api/v1/evidence/{offloaded[0].id}/download")
        assert anonymous.status_code == 401
    finally:
        harness.close()


def _download_settings(tmp_path: Path, database: Path, evidence_dir: Path) -> object:
    from tests.helpers.api import build_api_settings

    from arachne.core.config import EvidenceSettings

    settings = build_api_settings(
        tmp_path, evidence=EvidenceSettings(offload_threshold_bytes=64, dir=str(evidence_dir))
    )
    object.__setattr__(settings, "database_url", f"sqlite:///{database}")
    return settings


# --------------------------------------------------------------- REQ-DATA-003
def test_a_quota_crossing_warns_then_hard_stops_and_the_scan_is_resumable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The accept criterion: a clear audited error, nothing written, and a resume that works."""
    _scan_env(tmp_path, monkeypatch, quota_bytes=50)
    result = runner.invoke(app, ["scan", "--target", str(TARGET), "--json"])
    assert result.exit_code != 0, "the scan completed despite a 50-byte quota"

    services = build_services(get_settings())
    try:
        scans = services.store.list_scans(limit=5)
        assert scans, "the scan row was not created"
        failed = next(record for record in scans if record.status.value == "failed")

        # The hard stop is audited twice: the soft warning and the refusal.
        rows = __import__("asyncio").run(_audit_actions(services))
        assert AuditAction.QUOTA_WARNING.value in rows
        assert AuditAction.QUOTA_EXCEEDED.value in rows
        # Nothing was stored for the refused candidate.
        assert services.findings.count_candidates(failed.id) == 0

        # Raise the quota and resume: the failed step is re-run, and the scan completes.
        monkeypatch.setenv("ARACHNE_EVIDENCE_DEFAULT_QUOTA_BYTES", str(50 * 1024 * 1024))
        reset_settings_cache()
        resumed = runner.invoke(
            app, ["scan", "--target", str(TARGET), "--resume", str(failed.id), "--json"]
        )
        assert resumed.exit_code == 0, resumed.output
        payload = json.loads(resumed.output[resumed.output.index("{") :])
        assert payload["status"] == "completed"
        assert payload["scan_id"] == failed.id
    finally:
        services.close()


async def _audit_actions(services: object) -> set[str]:
    from sqlalchemy import select

    from arachne.data.models import AuditLog

    with services.session_factory() as session:  # type: ignore[attr-defined]
        return {str(value) for value in session.scalars(select(AuditLog.action).distinct()).all()}


# --------------------------------------------------------------- REQ-DATA-001
def test_retention_prunes_an_expired_scan_its_rows_and_its_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _scan_env(tmp_path, monkeypatch)
    scan_id, _ = _run_scan()
    files_before = _object_files(evidence_dir)
    assert files_before, "the scan stored no evidence objects"

    monkeypatch.setenv("ARACHNE_RETENTION_SCANS_DAYS", "1")
    monkeypatch.setenv("ARACHNE_RETENTION_FINDINGS_DAYS", "1")
    monkeypatch.setenv("ARACHNE_RETENTION_EVIDENCE_DAYS", "1")
    reset_settings_cache()

    services = build_services(get_settings())
    try:
        # Age the scan past its retention (the alternative is waiting a day).
        with services.session_factory() as session:
            from sqlalchemy import update

            from arachne.data.models import Scan

            session.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(created_at=datetime.now(UTC) - timedelta(days=3))
            )
            session.commit()

        pruner = RetentionPruner(
            services.session_factory,
            settings=services.settings,
            auditor=services.auditor,
            quota=services.quota,
            evidence=services.evidence_backend,
        )
        plan = pruner.plan()
        assert plan.category("scans").rows == 1
        assert plan.category("scans").cascaded_rows > 0

        # A dry run deletes nothing at all.
        __import__("asyncio").run(pruner.prune(dry_run=True))
        assert len(_object_files(evidence_dir)) == len(files_before)
        assert services.store.get_scan(scan_id) is not None

        applied = __import__("asyncio").run(pruner.prune(dry_run=False))
        assert applied.category("scans").rows == 1
        assert services.store.get_scan(scan_id) is None
        # The objects those rows referenced are gone too: rows and blobs are one unit.
        assert _object_files(evidence_dir) == []
    finally:
        services.close()


# --------------------------------------------------------------- REQ-OPS-003 / 004
def test_the_metrics_endpoint_reflects_a_real_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scan_env(tmp_path, monkeypatch)
    _run_scan()
    services = build_services(get_settings())
    try:
        collect_deployment_metrics(services)
        body = render_metrics()
        assert 'arachne_scans{status="completed"} 1' in body
        assert 'arachne_queue_depth{status="queued"} 0' in body
        assert "arachne_build_info" in body

        # The proof counter is checked against the database rather than assumed: the metric
        # must equal the number of proof-bearing evidence rows the scan actually wrote.
        from sqlalchemy import func, select

        from arachne.data.models import Evidence

        with services.session_factory() as session:
            proof_rows = int(
                session.scalar(
                    select(func.count()).select_from(Evidence).where(Evidence.kind == "proof")
                )
                or 0
            )
        if proof_rows:
            assert "arachne_proof_findings_total" in body
        else:
            assert "arachne_proof_findings_total" not in body
    finally:
        services.close()


def test_a_real_scan_produces_a_span_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _scan_env(tmp_path, monkeypatch)
    exporter = InMemoryExporter()
    configure_tracing(get_settings(), exporter=exporter, sample_ratio=1.0)
    _run_scan()
    names = [span.name for span in exporter.spans]
    assert any(name.startswith("scan.step.") for name in names), names
    assert "scan.step.checks" in names
    http_spans = [span for span in exporter.spans if span.name.startswith("http.")]
    assert http_spans, "the HTTP client emitted no span"
    steps = [span for span in exporter.spans if span.name.startswith("scan.step.")]
    # Each HTTP span belongs to the trace of the step it was made from, and names that step
    # as its parent — the orchestrator-to-client chain REQ-OPS-004 asks for.
    assert {span.trace_id for span in http_spans} <= {span.trace_id for span in steps}
    step_ids = {span.span_id for span in steps}
    assert {span.parent_span_id for span in http_spans} <= step_ids
    assert any(span.attributes.get("http.status_code") for span in http_spans)
    assert any(span.attributes.get("http.url") for span in http_spans)
