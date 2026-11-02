"""Per-project quotas and the offload seam (REQ-DATA-003, with REQ-DATA-002/004).

REQ-DATA-003's accept criterion is "warn and then hard-stop with a clear audited error and a
resumable scan". The unit-level half of that is here: the ledger arithmetic, the two
thresholds, the error's *message* (which is the operator's whole diagnosis, so it has to name
the limit and the way out), and the fact that a refusal writes nothing. The scan-level half —
a refused scan that ``--resume`` continues — is
``tests/integration/test_data_lifecycle.py::test_a_quota_crossing_warns_then_hard_stops_and_the_scan_is_resumable``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from arachne.core.audit import AuditAction, MemoryAuditSink
from arachne.core.config import EvidenceSettings, Settings
from arachne.core.errors import ConfigurationError, StorageQuotaError
from arachne.core.results import CheckResult, Evidence
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.evidence_backend import LocalEvidenceBackend
from arachne.data.evidence_service import EvidenceService, serialized_size
from arachne.data.models import Evidence as EvidenceRow
from arachne.data.models import Project, Scan, Target
from arachne.data.quota import StorageQuota


@pytest.fixture
def factory(tmp_path: Path) -> Any:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'quota.db'}")
    create_all(engine)
    yield create_session_factory(engine)
    engine.dispose()


def _project(factory: Any, *, quota: int | None = None) -> int:
    with factory() as session:
        project = Project(
            slug="acme",
            name="Acme",
            scope_json={},
            branding_json={},
            quota_bytes=quota,
            used_bytes=0,
        )
        session.add(project)
        session.commit()
        return int(project.id)


def _scan(factory: Any, project_id: int) -> int:
    with factory() as session:
        target = Target(project_id=project_id, name="t", scope_json={}, auth_attestation={})
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            project_id=project_id,
            status="running",
            plan_json={},
            engine="heuristic",
            stats_json={},
        )
        session.add(scan)
        session.commit()
        return int(scan.id)


def _big_result(size: int = 8000) -> CheckResult:
    return CheckResult(
        module="m3",
        check="m3.sqli-oracle",
        title="planted",
        status="vulnerable",
        detail="d",
        confidence=0.9,
        evidence=(Evidence.of("http_response", {"body": "A" * size, "status_code": 200}),),
    )


# --------------------------------------------------------------------- the ledger
def test_without_a_limit_nothing_is_enforced(factory: Any) -> None:
    quota = StorageQuota(factory)
    project_id = _project(factory)
    state = quota.enforce(project_id, 10**12)
    assert state.has_limit is False
    assert state.ratio == 0.0 and state.headroom is None
    assert quota.state(project_id).exceeded is False


def test_usage_is_tracked_in_the_caller_transaction_and_recomputed_on_demand(factory: Any) -> None:
    quota = StorageQuota(factory)
    project_id = _project(factory, quota=1_000_000)
    scan_id = _scan(factory, project_id)
    with factory() as session:
        finding_id = 1
        row = EvidenceRow(
            finding_id=None,
            kind="http_response",
            payload_json={},
            sha256="0" * 64,
            size_bytes=1234,
            storage="inline",
        )
        session.add(row)
        from arachne.data.models import Finding

        finding = Finding(
            scan_id=scan_id,
            check_id=None,
            asset_id=None,
            title="t",
            status="open",
            evidence_refs_json=[],
        )
        session.add(finding)
        session.flush()
        row.finding_id = finding.id
        StorageQuota.add_usage(session, project_id, 1234)
        session.commit()
        del finding_id
    assert quota.usage(project_id) == 1234
    # A cached total that has drifted is corrected by the recomputation the pruner runs.
    with factory() as session:
        session.execute(
            Project.__table__.update().where(Project.id == project_id).values(used_bytes=999)
        )
        session.commit()
    assert quota.recompute(project_id) == 1234
    assert quota.usage(project_id) == 1234


def test_the_two_thresholds_and_the_error_message(factory: Any) -> None:
    quota = StorageQuota(factory, warn_ratio=0.8)
    project_id = _project(factory, quota=1000)

    warning = quota.state(project_id, 850)
    assert warning.warning is True and warning.exceeded is False
    assert warning.ratio == pytest.approx(0.85)

    with factory() as session:
        session.execute(
            Project.__table__.update().where(Project.id == project_id).values(used_bytes=950)
        )
        session.commit()
    over = quota.state(project_id, 100)
    assert over.exceeded is True
    with pytest.raises(StorageQuotaError) as caught:
        quota.enforce(project_id, 100, context="scan 7")
    message = str(caught.value)
    # The message is the diagnosis: what is stored, what was refused, the limit, and the way
    # out (raise the quota, then resume — nothing has to be rescanned).
    assert "950 bytes stored" in message
    assert "limit 1000 bytes" in message
    assert "scan 7" in message
    assert "arachne scan --resume" in message


def test_a_zero_quota_means_no_quota_not_zero_bytes(factory: Any) -> None:
    quota = StorageQuota(factory)
    project_id = _project(factory, quota=0)
    assert quota.limit_for(project_id) is None


def test_the_overview_reports_every_project(factory: Any) -> None:
    quota = StorageQuota(factory, default_limit_bytes=5000)
    _project(factory, quota=1000)
    overview = quota.overview()
    assert [entry["slug"] for entry in overview] == ["acme"]
    assert overview[0]["limit_bytes"] == 1000
    assert overview[0]["used_bytes"] == 0


def test_a_negative_limit_is_refused(factory: Any) -> None:
    quota = StorageQuota(factory)
    project_id = _project(factory)
    with pytest.raises(ConfigurationError):
        quota.set_limit(project_id, -1)
    assert quota.set_limit(project_id, 4096) == 4096
    assert quota.set_limit(project_id, None) is None


# --------------------------------------------------------------------- the service
def _service(
    tmp_path: Path, factory: Any, *, quota: StorageQuota, threshold: int = 256, preview: int = 32
) -> tuple[EvidenceService, LocalEvidenceBackend, MemoryAuditSink]:
    backend = LocalEvidenceBackend(tmp_path / "evidence")
    sink = MemoryAuditSink()
    from arachne.core.audit import Auditor

    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'quota.db'}",
        evidence=EvidenceSettings(
            offload_threshold_bytes=threshold,
            preview_chars=preview,
            dir=str(tmp_path / "evidence"),
        ),
    )
    service = EvidenceService(backend, settings=settings, quota=quota, auditor=Auditor(sink=sink))
    return service, backend, sink


async def test_a_small_payload_stays_inline_because_its_stub_would_be_bigger(
    tmp_path: Path, factory: Any
) -> None:
    quota = StorageQuota(factory)
    service, backend, _sink = _service(tmp_path, factory, quota=quota, threshold=0)
    staged = await service.stage(
        CheckResult(
            module="m4",
            check="m4.env-file-probe",
            title="tiny",
            status="vulnerable",
            detail="d",
            confidence=0.5,
            evidence=(Evidence.of("http_response", {"status_code": 200}),),
        ),
        scan_id=1,
        project_id=None,
    )
    assert staged.evidence[0].payload.get("offloaded") is None
    assert (
        await backend.exists(  # nothing was uploaded
            "0" * 64
        )
    ) is False
    assert backend.stats()["objects_written"] == 0


async def test_a_large_payload_is_offloaded_and_audited(tmp_path: Path, factory: Any) -> None:
    quota = StorageQuota(factory)
    service, backend, sink = _service(tmp_path, factory, quota=quota)
    staged = await service.stage(_big_result(), scan_id=11, project_id=None)
    payload = staged.evidence[0].payload
    assert payload["offloaded"] is True
    assert payload["size"] == serialized_size(_big_result().evidence[0].payload)
    assert len(payload["body"]) <= 32
    assert backend.stats()["objects_written"] == 1
    assert [event.action for event in sink.events] == [AuditAction.EVIDENCE_STORED]
    # The digest recorded with the row is the digest of the object, not of the stub.
    assert staged.evidence[0].sha256 == await _digest(backend, payload["key"])


async def _digest(backend: LocalEvidenceBackend, key: str) -> str:
    import hashlib

    return hashlib.sha256(await backend.get(key)).hexdigest()


async def test_a_refused_write_uploads_nothing_and_warns_first(
    tmp_path: Path, factory: Any
) -> None:
    project_id = _project(factory, quota=64)
    quota = StorageQuota(factory, warn_ratio=0.8)
    service, backend, sink = _service(tmp_path, factory, quota=quota)
    with pytest.raises(StorageQuotaError):
        await service.stage(_big_result(), scan_id=5, project_id=project_id)
    actions = [event.action for event in sink.events]
    # The soft warning is recorded by the service, before it refuses. The refusal's own audit
    # line (``quota.exceeded``) is written by the checks step, which knows the check and the
    # asset — see tests/integration/test_data_lifecycle.py for the end-to-end pair.
    assert actions == [AuditAction.QUOTA_WARNING]
    assert backend.stats()["objects_written"] == 0, "a refused payload reached the backend"
    assert backend.stats()["logical_bytes"] == 0


async def test_the_warning_is_recorded_once_per_scan(tmp_path: Path, factory: Any) -> None:
    """A scan that keeps writing past the soft threshold warns once, not once per candidate."""
    project_id = _project(factory, quota=200_000)
    quota = StorageQuota(factory, warn_ratio=0.01)  # the soft threshold is 2 KB
    with factory() as session:
        session.execute(
            Project.__table__.update().where(Project.id == project_id).values(used_bytes=4_000)
        )
        session.commit()
    service, _backend, sink = _service(tmp_path, factory, quota=quota)
    for _ in range(3):
        await service.stage(_big_result(), scan_id=9, project_id=project_id)
    warnings = [event for event in sink.events if event.action is AuditAction.QUOTA_WARNING]
    assert len(warnings) == 1
    # A different scan gets its own warning.
    await service.stage(_big_result(), scan_id=10, project_id=project_id)
    assert len([e for e in sink.events if e.action is AuditAction.QUOTA_WARNING]) == 2


def test_the_settings_refuse_an_insane_quota_configuration() -> None:
    with pytest.raises(ConfigurationError):
        EvidenceSettings(quota_warn_ratio=0.0)
    with pytest.raises(ConfigurationError):
        EvidenceSettings(quota_warn_ratio=1.5)
    with pytest.raises(ConfigurationError):
        EvidenceSettings(default_quota_bytes=-1)
    with pytest.raises(ConfigurationError):
        EvidenceSettings(preview_chars=-1)
    with pytest.raises(ConfigurationError):
        EvidenceSettings(compress_level=12)


def test_a_scan_with_no_project_reports_no_usage(factory: Any) -> None:
    """``project_id IS NULL`` is the implicit workspace: it has no ledger row to update."""
    with factory() as session:
        assert StorageQuota.project_for_scan(session, 4242) is None
    assert StorageQuota(factory).usage(None) == 0
    with factory() as session:
        assert session.scalar(select(Project.used_bytes).where(Project.slug == "acme")) is None
