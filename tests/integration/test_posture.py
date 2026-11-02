"""The continuous exposure management cycle, end to end (S23, REQ-POSTURE-001/003/005).

Three acceptance demonstrations, each against the real cloud lab and the real services
stack (SQL store, analyzer, admission through the orchestrator):

1. **Drift (REQ-POSTURE-001):** the lab's cloud-config snapshot is watched by
   ``m5.cloud-posture``; the first run establishes the baseline (and reports the one
   standing policy breach), a later run — after the lab's estate drifts — emits a delta
   finding whose artifact carries **before/after**.
2. **Fix → regress (REQ-POSTURE-003):** a finding is closed by a targeted re-scan of
   *only the affected checks* (verified absence), then re-opened when a later scan sees
   it again — with both acts' evidence linked to the original finding.
3. **Admission (REQ-POSTURE-005):** the webhook route allows a deliberately bad manifest
   in monitor mode (the default) and denies it in enforce mode with the namespace staged.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tests.helpers.api import SCANNER_KEY, auth, make_api_harness
from tests.lab.cloud_lab import CloudLab, start_cloud_lab

from arachne.core.audit import AuditAction
from arachne.core.config import (
    ApiSettings,
    PostureSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.target import ModuleSelection, ScanOptions, ScanRequest, TargetDefinition
from arachne.data.models import Base
from arachne.data.models import Evidence as EvidenceRow
from arachne.data.models import Finding as FindingRow
from arachne.data.services import build_orchestrator
from arachne.posture.verify import FixVerificationService


@pytest.fixture(scope="module")
def cloud() -> Iterator[CloudLab]:
    with start_cloud_lab() as running:
        yield running


def _settings(tmp_path: Path, db_name: str = "posture.db", **posture: object) -> Settings:
    """Offline-friendly settings: loopback in scope, generous rate limits, posture knobs."""
    from arachne.core.safety import UrlSafetyPolicy

    return Settings(
        database_url=f"sqlite:///{tmp_path / db_name}",
        log_level="CRITICAL",
        log_json=False,
        actor="pytest",
        api=ApiSettings(
            keys=("admin:admin:rootsecret", "scanner:scanner:scansecret"),
            require_tls=False,
            rate_limit_per_minute=100_000,
            rate_limit_burst=100_000,
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        # A live scan over loopback: the lab is a private address, covered by the
        # fixture's attestation.
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        posture=PostureSettings(**posture),  # type: ignore[arg-type]
    )


def _attestation(cloud: CloudLab) -> dict[str, object]:
    return {
        "attested_by": "S23 integration test",
        "attested_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        "scope_statement": "the lab cloud estate, watched continuously for the test",
        "allowed_targets": (cloud.base_url, "endpoint:*"),
        "authorization_ref": "test-s23",
        "active_checks_authorized": True,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }


def _definition(cloud: CloudLab, *, path: str, name: str) -> TargetDefinition:
    # A URL target (not an endpoint: cloud reference): a cloud ref alone names no host,
    # so the requests the check is allowed to make are exactly this declared prefix.
    return TargetDefinition.model_validate(
        {
            "name": name,
            "targets": [{"kind": "url", "value": f"{cloud.base_url.rstrip('/')}{path}"}],
            "attestation": _attestation(cloud),
        }
    )


def _posture_request(cloud: CloudLab) -> ScanRequest:
    return ScanRequest(
        target=_definition(cloud, path="/posture/snapshot", name="lab-estate"),
        options=ScanOptions(
            engine="heuristic",
            active_checks=True,
            modules=ModuleSelection(only=("m5.cloud-posture",)),
        ),
    )


def _bucket_request(cloud: CloudLab) -> ScanRequest:
    return ScanRequest(
        target=_definition(cloud, path="/storage/backup", name="lab-storage"),
        options=ScanOptions(
            engine="heuristic",
            active_checks=True,
            modules=ModuleSelection(enabled=("M5",)),
        ),
    )


def _confirmed(harness: Any, scan_id: int) -> list[Any]:
    """The scan's confirmed findings (analyzed, not fp/merged) — the report's set."""
    return [
        candidate
        for candidate in harness.services.findings.list_candidates(scan_id)
        if candidate.status not in {"fp", "merged"} and candidate.severity is not None
    ]


# ------------------------------------------------------------------ 1. drift
@pytest.mark.asyncio
async def test_the_estate_drifts_and_the_delta_finding_carries_before_and_after(
    cloud: CloudLab, tmp_path: Path
) -> None:
    """REQ-POSTURE-001's acceptance: the fixture drifts; the delta carries before/after."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    orchestrator = build_orchestrator(harness.services)
    request = _posture_request(cloud)

    try:
        # Run 1: the baseline. One standing breach (the unencrypted archive bucket), no
        # drift (nothing to compare against), baseline committed.
        first = await orchestrator.scan(request)
        assert first.scan_id is not None
        findings = _confirmed(harness, first.scan_id)
        assert [candidate.check_key for candidate in findings] == ["M5/cloud-posture@1.0"]
        blob = str(findings[0].to_dict())
        assert "storage-unencrypted" in blob
        assert "aws:storage/logs-archive" in blob
        saved = harness.sink.of_action(AuditAction.POSTURE_BASELINE_SAVED)
        assert len(saved) == 1 and saved[0].meta["resources"] == 5

        # Run 2, unchanged: no delta, the same point-in-time breach.
        second = await orchestrator.scan(request)
        assert second.scan_id is not None
        assert _confirmed(harness, second.scan_id)[0].check_key.endswith("cloud-posture@1.0")
        assert harness.sink.of_action(AuditAction.POSTURE_DRIFT) == []

        # The estate drifts: the application bucket becomes public.
        resources = cloud.posture_state["resources"]
        app_assets = next(item for item in resources if item["id"] == "app-assets")
        app_assets["config"]["public"] = True

        third = await orchestrator.scan(request)
        assert third.scan_id is not None
        drift_events = harness.sink.of_action(AuditAction.POSTURE_DRIFT)
        assert len(drift_events) == 1
        assert drift_events[0].meta["changes"] == [
            {"resource": "aws:storage/app-assets", "change": "modified"}
        ]
        deltas = _confirmed(harness, third.scan_id)
        artifacts = [
            item.payload
            for candidate in deltas
            for item in candidate.evidence
            if item.kind == "artifact"
        ]
        drift = next(item for item in artifacts if item.get("signal") == "cloud-config-drift")
        assert drift["change"] == "modified"
        assert drift["resource"] == "aws:storage/app-assets"
        assert drift["before"] == {"public": False, "encrypted": True}
        assert drift["after"] == {"public": True, "encrypted": True}
        assert drift["changed_keys"] == ["public"]
        assert drift["policies_after"] == ["storage-public"]
    finally:
        harness.close()


# ------------------------------------------------------------------ 2. fix → regress
@pytest.mark.asyncio
async def test_the_fix_then_regress_cycle_closes_and_reopens_with_linked_evidence(
    cloud: CloudLab, tmp_path: Path
) -> None:
    """REQ-POSTURE-003's acceptance: close on verified absence, reopen on regression."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    orchestrator = build_orchestrator(harness.services)

    try:
        # The finding: the lab's public backup bucket.
        first = await orchestrator.scan(_bucket_request(cloud))
        assert first.scan_id is not None
        candidates = _confirmed(harness, first.scan_id)
        finding = next(c for c in candidates if c.check_key == "M5/bucket-enumerator@1.0")
        original_finding_id = int(finding.id)

        # The "fix": the bucket stops granting anonymous access.
        cloud.public_buckets.clear()
        service = FixVerificationService(harness.services)
        result = await service.verify(original_finding_id)
        assert result.outcome == "verified"
        assert result.closed
        verification_scan_id = result.verification_scan_id
        assert verification_scan_id is not None

        # The finding is closed, and the verification scan planned *only* the affected check.
        record = harness.services.store.get_scan(verification_scan_id)
        planned = [check for check in record.plan["checks"] if check.get("included")]
        assert [f"{check['module']}/{check['name']}@{check['version']}" for check in planned] == [
            "M5/bucket-enumerator@1.0"
        ]
        with harness.services.session_factory() as session:
            row = session.get(FindingRow, original_finding_id)
            assert row is not None and row.status == "closed"
            linked = [
                ref for ref in row.evidence_refs_json if session.get(EvidenceRow, ref) is not None
            ]
            assert linked
        verifications = harness.services.posture.verifications_for(original_finding_id)
        assert [item.outcome for item in verifications] == ["verified"]
        audit = harness.sink.of_action(AuditAction.POSTURE_FIX_VERIFIED)
        assert len(audit) == 1

        # The regression: the bucket is public again, a later scan sees it.
        cloud.public_buckets.add("backup")
        regression = await orchestrator.scan(_bucket_request(cloud))
        assert regression.scan_id is not None
        reopens = service.reconcile(int(regression.scan_id))
        assert [item.finding_id for item in reopens] == [original_finding_id]
        with harness.services.session_factory() as session:
            row = session.get(FindingRow, original_finding_id)
            assert row is not None and row.status == "open"
        assert [
            item.outcome for item in harness.services.posture.verifications_for(original_finding_id)
        ] == ["verified", "reopened"]
        assert len(harness.sink.of_action(AuditAction.POSTURE_FIX_REGRESSED)) == 1
        # Both acts linked their evidence to the original finding (two evidence rows now).
        with harness.services.session_factory() as session:
            row = session.get(FindingRow, original_finding_id)
            assert row is not None
            assert len(row.evidence_refs_json) >= 2
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_verification_that_still_finds_the_issue_keeps_it_open(
    cloud: CloudLab, tmp_path: Path
) -> None:
    """The honest branch: no fix landed, the act is recorded, the finding stays open."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    orchestrator = build_orchestrator(harness.services)

    try:
        first = await orchestrator.scan(_bucket_request(cloud))
        assert first.scan_id is not None
        candidates = _confirmed(harness, first.scan_id)
        finding = next(c for c in candidates if c.check_key == "M5/bucket-enumerator@1.0")

        # No fix: the bucket is still public, so the targeted re-scan reports it again.
        service = FixVerificationService(harness.services)
        result = await service.verify(int(finding.id))
        assert result.outcome == "still-open"
        assert not result.closed
        with harness.services.session_factory() as session:
            row = session.get(FindingRow, int(finding.id))
            assert row is not None and row.status == "open"
        verifications = harness.services.posture.verifications_for(int(finding.id))
        assert [item.outcome for item in verifications] == ["still-open"]
        # The act's evidence is still linked to the original finding.
        with harness.services.session_factory() as session:
            row = session.get(FindingRow, int(finding.id))
            assert row is not None and len(row.evidence_refs_json) >= 1
        assert len(harness.sink.of_action(AuditAction.POSTURE_FIX_STILL_OPEN)) == 1
    finally:
        harness.close()


# ------------------------------------------------------------------ 3. admission
_BAD_REVIEW: dict[str, Any] = {
    "request": {
        "uid": "admission-uid-1",
        "kind": {"kind": "Deployment", "version": "v1"},
        "name": "payments",
        "namespace": "prod",
        "operation": "CREATE",
        "object": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "payments", "namespace": "prod"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "image": "registry.local/payments:latest",
                                "securityContext": {"privileged": True},
                            }
                        ]
                    }
                }
            },
        },
    }
}


def _admission_client(tmp_path: Path, name: str, **posture: object) -> tuple[Any, Any]:
    from fastapi.testclient import TestClient

    from arachne.api.app import create_app

    harness = make_api_harness(
        tmp_path / name, settings=_settings(tmp_path, db_name=f"{name}.db", **posture)
    )
    app = create_app(harness.services, settings=harness.settings, context=harness.context)
    return TestClient(app), harness


def test_admission_monitor_allows_and_enforce_denies_a_bad_manifest(tmp_path: Path) -> None:
    """REQ-POSTURE-005's acceptance: monitor default, enforce opt-in with staging."""
    # Monitor (the deployment default): the findings are named, the deploy proceeds.
    client, harness = _admission_client(tmp_path, "monitor")
    try:
        response = client.post("/api/v1/admission", json=_BAD_REVIEW, headers=auth(SCANNER_KEY))
        assert response.status_code == 200
        body = response.json()
        assert body["response"]["allowed"] is True
        assert "k8s-privileged" in body["response"]["status"]["message"]
        events = harness.sink.of_action(AuditAction.ADMISSION_REVIEWED)
        assert len(events) == 1 and events[0].meta["mode"] == "monitor"
    finally:
        harness.close()

    # Enforce, staged to the prod namespace: the same manifest is denied.
    client, harness = _admission_client(
        tmp_path, "enforce", admission_mode="enforce", admission_enforce_namespaces=("prod",)
    )
    try:
        response = client.post("/api/v1/admission", json=_BAD_REVIEW, headers=auth(SCANNER_KEY))
        assert response.status_code == 200
        body = response.json()
        assert body["response"]["allowed"] is False
        assert "k8s-privileged" in body["response"]["status"]["reason"]
        events = harness.sink.of_action(AuditAction.ADMISSION_REVIEWED)
        assert events[-1].outcome.value == "blocked"
    finally:
        harness.close()

    # Enforce, but the namespace is not in the rollout: monitor-only behaviour.
    client, harness = _admission_client(
        tmp_path, "staged", admission_mode="enforce", admission_enforce_namespaces=("staging",)
    )
    try:
        response = client.post("/api/v1/admission", json=_BAD_REVIEW, headers=auth(SCANNER_KEY))
        assert response.json()["response"]["allowed"] is True
    finally:
        harness.close()


# The unused SQL helpers are imported for the seeded-database variants other suites may
# build on; keep them referenced so lint stays honest about the intent.
_ENGINE_HELPERS = (create_engine, sessionmaker, Base)
