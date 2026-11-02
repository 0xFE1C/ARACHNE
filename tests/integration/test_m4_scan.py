"""Acceptance: M4 runs against a deliberately misconfigured web root.

The S7 definition of done is qualitative in shape and quantitative in outcome:

1. **Every planted exposure is detected with evidence** — the lab publishes the planted set
   (``M4_GROUND_TRUTH``) and the hardened controls that must not be reported
   (``M4_FALSE_POSITIVE_TRAPS``), and this module runs a *live* scan through the real
   pipeline (crawl, checks, analyzer, correlation) and scores it against both.
2. **The two opt-in checks respect their gates** — with the shipped defaults neither
   ``m4.metadata-ssrf`` nor ``m4.default-credentials`` runs, and the lab sees no SSRF or
   authentication attempt. Named explicitly (``--check``) with their switches on, both run.
3. **Secrets stay redacted and the ledger stays encrypted** — the ``.env`` credentials never
   appear in a candidate, the audit trail or the manifest's bytes, and the manifest
   decrypts to masked fingerprints only.
4. **The M3/M4 overlap is deduplicated** — one CWE-942 finding survives for the permissive
   CORS endpoint however many modules and probe origins reported it
   ("Deduplication & overlap rules").

The numbers are recorded in ``docs/adr/120-stage-7-m4-misconfiguration-exposure.md``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from tests.lab.web_lab import (
    M4_FALSE_POSITIVE_TRAPS,
    M4_GROUND_TRUTH,
    WebLab,
    start_web_lab,
)

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import (
    M4Settings,
    RateLimitSettings,
    SafetySettings,
    SecretsSettings,
    Settings,
)
from arachne.core.events import EventBus
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.safety import UrlSafetyPolicy
from arachne.core.secrets import load_manifest
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry

PASSPHRASE = "s7-lab-manifest-passphrase"
#: The raw credentials the lab serves in ``/.env``; none may survive into evidence.
ENV_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sup3rs3cr3t-db-password",
    "mailgun-not-really-a-password",
)


@dataclass
class Measurement:
    """One scan's outcome, scored against the lab's declared M4 ground truth."""

    detection: float
    true_positives: int
    planted: int
    fp_rate: float
    false_positives: int
    candidates: int
    fp_examples: list[str]
    missed: list[str]

    def record(self) -> str:
        return (
            f"M4 detection {self.true_positives}/{self.planted} ({self.detection:.0%}); "
            f"FP {self.false_positives}/{self.candidates} ({self.fp_rate:.0%})"
            + (f"; missed: {self.missed}" if self.missed else "")
            + (f"; FP examples: {self.fp_examples}" if self.fp_examples else "")
        )


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def build_definition(lab: WebLab) -> TargetDefinition:
    bucket = f"endpoint:{lab.base_url}storage/backup"
    return TargetDefinition(
        name="m4-misconfigured-lab",
        targets=(
            TargetSelector(kind="url", value=lab.base_url),
            TargetSelector(kind="cloud", value=bucket),
        ),
        attestation={
            "attested_by": "S7 builder <s7@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": (
                "Local vulnerable-by-design lab fixture on loopback, owned by the test suite"
            ),
            "allowed_targets": [lab.base_url, "127.0.0.1", "endpoint:*"],
            "authorization_ref": "TEST-M4",
            "active_checks_authorized": True,
        },
    )


def build_settings(
    definition: TargetDefinition,
    *,
    m4: M4Settings | None = None,
    manifest: Path | None = None,
) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        # A live scan over loopback: the lab is a private address, and the scan is
        # covered by the fixture's attestation.
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=definition.compile_scope(),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        m4=m4 or M4Settings(),
        secrets=(
            SecretsSettings(manifest_path=str(manifest), manifest_key=SecretStr(PASSPHRASE))
            if manifest is not None
            else SecretsSettings()
        ),
    )


async def run_scan(
    lab: WebLab,
    *,
    modules: tuple[str, ...] = ("M4",),
    checks: tuple[str, ...] = (),
    m4: M4Settings | None = None,
    manifest: Path | None = None,
) -> tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings, MemoryAuditSink]:
    definition = build_definition(lab)
    settings = build_settings(definition, m4=m4, manifest=manifest)
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=registry,
            findings=findings,
            analyses=analyses,
            auditor=auditor,
        ),
        registry=registry,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(enabled=modules, checks=checks),
        ),
    )
    session = await orchestrator.scan(request)
    return findings, analyses, session, settings, sink


def score(findings: MemoryFindingStore, scan_id: int) -> Measurement:
    """Score the M4 candidates against the lab's declared ground truth.

    Only M4 candidates participate: the M3 checks run in the same acceptance scan and are
    scored by ``test_m3_scan.py``; counting their (correct) findings as M4 false positives
    would measure the wrong thing.
    """
    candidates = [record for record in findings.list_candidates(scan_id) if record.module == "M4"]
    matched: set[tuple[str, str]] = set()
    false_positives: list[str] = []
    for record in candidates:
        check = (record.check_key or "").split("/")[-1].split("@")[0]
        blob = " ".join(
            f"{key}={value}" for item in record.evidence for key, value in item.payload.items()
        )
        check_id = f"m4.{check}"
        hits = [
            (planted_check, marker)
            for planted_check, marker in M4_GROUND_TRUTH
            if planted_check == check_id and marker in blob
        ]
        if hits:
            matched.update(hits)
            continue
        trap = [marker for planted_check, marker in M4_FALSE_POSITIVE_TRAPS if marker in blob]
        false_positives.append(f"{check_id}:{record.title[:50]!r} trap={trap}")
    total = len(candidates)
    return Measurement(
        detection=round(len(matched) / len(M4_GROUND_TRUTH), 3),
        true_positives=len(matched),
        planted=len(M4_GROUND_TRUTH),
        fp_rate=round(len(false_positives) / total, 3) if total else 0.0,
        false_positives=len(false_positives),
        candidates=total,
        fp_examples=sorted(false_positives)[:6],
        missed=[
            f"{check}:{marker}"
            for check, marker in M4_GROUND_TRUTH
            if (check, marker) not in matched
        ],
    )


# --------------------------------------------------------------------------- the acceptance run
@pytest.fixture(scope="module")
def base_scan(
    lab: WebLab,
) -> tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings, MemoryAuditSink]:
    """One default-configuration M4 scan shared by the tests that read its result.

    A full M4 scan costs about fifteen seconds and three acceptance tests read the *same*
    result, so it runs once (runtime budget, REQ-QUAL-007). ``run_scan`` is driven in its own
    event loop and the tests only read the returned in-memory stores.
    """
    return asyncio.run(run_scan(lab))


async def test_m4_scan_detects_every_planted_exposure(
    base_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings, MemoryAuditSink],
) -> None:
    """DONE criterion 1: the planted exposures are found, and the controls are not."""
    findings, analyses, session, _settings, _sink = base_scan
    assert session.status is ScanStatus.COMPLETED, session
    measurement = score(findings, session.scan_id or 0)
    print(f"\nM4 lab scan: {measurement.record()}")
    assert measurement.detection >= 0.9, measurement.record()
    assert measurement.fp_rate <= 0.15, measurement.record()
    # The analysed findings exist too: the acceptance scan is the whole pipeline.
    assert analyses.list_analyses(session.scan_id or 0)


async def test_every_m4_candidate_carries_request_evidence_and_an_artifact(
    base_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings, MemoryAuditSink],
) -> None:
    """F-02-08: a candidate cites what was asked and what answered, plus machine facts."""
    findings, _analyses, session, _settings, _sink = base_scan
    candidates = [
        record for record in findings.list_candidates(session.scan_id or 0) if record.module == "M4"
    ]
    assert candidates
    for record in candidates:
        assert record.severity is None, "the module layer must not score (ADR-02)"
        kinds = {item.kind for item in record.evidence}
        assert "artifact" in kinds, record.title
        # Every M4 finding cites the request and the response that proved it. The review
        # checks cite the representative crawled page; the probes cite their own exchange.
        assert {"http_request", "http_response"} <= kinds, record.title


async def test_opt_in_checks_are_inert_and_then_run_when_enabled(
    base_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings, MemoryAuditSink],
    lab: WebLab,
) -> None:
    """DONE criterion 2: both switches gate their check, and the target sees nothing until on."""
    findings, _analyses, session, settings, _sink = base_scan
    assert session.status is ScanStatus.COMPLETED
    default_ids = {
        (record.check_key or "").split("/")[-1].split("@")[0]
        for record in findings.list_candidates(session.scan_id or 0)
        if record.module == "M4"
    }
    assert "default-credentials" not in default_ids
    assert "metadata-ssrf" not in default_ids
    # No authentication attempt and no metadata URL was ever sent by the target.
    assert not [entry for entry in lab.requests if entry.startswith("POST /jenkins")]
    assert not [entry for entry in lab.requests if "169.254.169.254" in entry]
    assert settings.m4.default_credentials is False
    assert settings.m4.metadata_ssrf_probe is False

    opted_in = M4Settings(
        metadata_ssrf_probe=True, default_credentials=True, default_credentials_pacing_s=0.0
    )
    findings, _analyses, session, _settings, _sink = await run_scan(
        lab,
        checks=("m4.default-credentials", "m4.metadata-ssrf"),
        m4=opted_in,
    )
    assert session.status is ScanStatus.COMPLETED
    opted_ids = {
        (record.check_key or "").split("/")[-1].split("@")[0]
        for record in findings.list_candidates(session.scan_id or 0)
        if record.module == "M4"
    }
    assert {"default-credentials", "metadata-ssrf"} <= opted_ids
    jenkins_posts = [entry for entry in lab.requests if entry.startswith("POST /jenkins")]
    assert len(jenkins_posts) == 1, "exactly one vendor-default attempt per product"
    assert [entry for entry in lab.requests if "169.254.169.254" in entry]


async def test_secrets_never_reach_evidence_and_the_manifest_is_encrypted(
    lab: WebLab, tmp_path: Path
) -> None:
    """DONE criterion 3 and F-08-04: redaction at capture time, ledger encrypted at rest."""
    manifest_path = tmp_path / "secrets.enc"
    findings, _analyses, session, _settings, sink = await run_scan(lab, manifest=manifest_path)
    assert session.status is ScanStatus.COMPLETED

    candidates = json.dumps(
        [record.to_dict() for record in findings.list_candidates(session.scan_id or 0)],
        default=str,
    )
    audit = json.dumps([event.to_dict() for event in sink.events], default=str)
    for secret in ENV_SECRETS:
        assert secret not in candidates, secret
        assert secret not in audit, secret

    assert manifest_path.exists()
    blob = manifest_path.read_bytes()
    assert blob.startswith(b"ARACHNE-SM-1")
    for secret in ENV_SECRETS:
        assert secret.encode() not in blob, secret
    records = load_manifest(manifest_path, PASSPHRASE)
    kinds = {item["kind"] for item in records}
    assert "aws-access-key-id" in kinds
    assert all("masked" in item and item["masked"] for item in records)


async def test_m3_and_m4_cors_findings_are_deduplicated_by_cwe_and_asset(lab: WebLab) -> None:
    """dedupe: one root cause, one finding, whichever module saw it first."""
    findings, analyses, session, _settings, _sink = await run_scan(lab, modules=("M3", "M4"))
    assert session.status is ScanStatus.COMPLETED
    scan_id = session.scan_id or 0

    def cors_check(record: Any) -> bool:
        return (record.check_key or "").split("/")[-1].split("@")[0] in {
            "cors-audit",
            "cors-config-review",
        }

    cors_candidates = [record for record in findings.list_candidates(scan_id) if cors_check(record)]
    assert len(cors_candidates) >= 2, "M3 and M4 both see the permissive CORS endpoint"
    cors_analyses = [row for row in analyses.list_analyses(scan_id) if row.cwe == "CWE-942"]
    # The analysis step logs each candidate; the correlation step logs the deduped result.
    # Group by finding id, so "one surviving finding" means one *finding*, not one log row.
    merged_ids = {row.finding_id for row in cors_analyses if row.verdict == "merged"}
    surviving = {
        row.finding_id
        for row in cors_analyses
        if row.verdict != "merged" and row.finding_id not in merged_ids
    }
    assert len(surviving) == 1, sorted(surviving)
    assert len(merged_ids) >= 2, sorted(merged_ids)
    # The duplicates are recorded as merged with their reason, never silently dropped.
    assert any(
        "same CWE and asset" in str(row.payload.get("drop_reason"))
        for row in cors_analyses
        if row.verdict == "merged"
    )
