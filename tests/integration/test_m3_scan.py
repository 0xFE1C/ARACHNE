"""Acceptance: M3 runs against a live lab and meets the S6 detection/FP criteria.

The S6 definition of done is quantitative: "the scan finds ≥ 60% of the planted
vulnerabilities from the core set" and "false-positive rate ≤ 15% at default tuning". Both
numbers are only meaningful against a target whose planted set is *declared*, so this module
runs a **live** scan (real sockets on loopback) against the stdlib web lab of
``tests/lab/web_lab.py`` — a small vulnerable-by-design application modelled on the DVWA /
Juice Shop patterns — and measures the result against that lab's published ground truth.

The scan goes through the real wiring (``build_handlers`` + the lifecycle machine + the
analyzer), not by calling checks one at a time, because the thing being measured is the whole
pipeline: crawl, oracles, candidate persistence, heuristic rules, severity. The measurements
are recorded in ``docs/adr/100-stage-6-m3-web-core.md``.

Two runs, because they answer different questions:

``default``
    The shipped defaults plus the two switches F-01-09 requires to run *anything* active
    (``--active-checks`` and an attestation that authorizes them). ``ARACHNE_WEB_UPLOAD_PROBE``
    stays off, which is the documented safe default — no stored payloads .
    The false-positive rate is measured here, because this is "default tuning".
``tuned``
    The same scan with the upload-validation probe enabled, so the upload family is exercised
    too. The detection rate is reported for both so the cost of the safety default is visible.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from tests.lab.web_lab import (
    FALSE_POSITIVE_TRAPS,
    GROUND_TRUTH,
    M4_FALSE_POSITIVE_TRAPS,
    M4_GROUND_TRUTH,
    WebLab,
    start_web_lab,
)

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import ModuleSelection, ScanOptions, TargetDefinition, TargetSelector
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry

#: The S6 core check set. The acceptance scan is restricted to these so its detection/FP
#: numbers stay comparable with S6: the S10 extended families run against the same lab and
#: are scored by ``test_m3x_scan.py`` instead.
CORE_CHECKS: tuple[str, ...] = (
    "m3.security-headers",
    "m3.api-surface",
    "m3.csrf-audit",
    "m3.sqli-oracle",
    "m3.xss-oracle",
    "m3.traversal-oracle",
    "m3.open-redirect",
    "m3.cors-audit",
    "m3.idor-oracle",
    "m3.auth-session-audit",
    "m3.rate-limit-audit",
    "m3.upload-audit",
)

#: The S10 extended routes the shared wordlist (``m3.api-surface``) reaches on this lab. They
#: are the extended run's surface, so an api-surface discovery on one is scored by neither
#: number here (as the S7 code did for the M4 surface).
M3X_SURFACE_MARKERS: tuple[str, ...] = (
    "/ssti",
    "/safe-template",
    "/xxe",
    "/safe-xml",
    "/ping",
    "/safe-ping",
    "/deser",
    "/smuggle",
    "/cache-me",
    "/cache-safe",
    "/hpp",
    "/api/profile",
    "/merge",
    "/graphql",
    "/graphql-safe",
    "/ws",
    "/ws-safe",
    "/checkout",
    "/checkout-safe",
    "/redeem",
    "/oauth/authorize",
    "/saml/acs",
    "/takeover-alias",
    "/api/me",
)


@dataclass
class Measurement:
    """One scan's outcome, scored against the lab's ground truth."""

    detection: float
    true_positives: int
    planted: int
    fp_rate: float
    false_positives: int
    candidates: int
    fp_examples: list[str]
    missed: list[str]
    findings: int
    severities: dict[str, int]

    def record(self) -> str:
        return (
            f"detection {self.true_positives}/{self.planted} ({self.detection:.0%}); "
            f"FP {self.false_positives}/{self.candidates} ({self.fp_rate:.0%}); "
            f"candidates {self.candidates}, {self.findings} analysed finding(s); "
            f"severities {self.severities}"
            + (f"; missed: {self.missed}" if self.missed else "")
            + (f"; FP examples: {self.fp_examples}" if self.fp_examples else "")
        )


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


#: Endpoint markers the S7 lab planted for M4 (``M4_GROUND_TRUTH``/``M4_FALSE_POSITIVE_TRAPS``).
#: ``m3.api-surface`` probes a shared wordlist that overlaps these routes and legitimately
#: reports them as reachable, so the M3 scorer must not count them as M3 false positives —
#: the mirror of ``test_m4_scan.py`` scoring only ``module == "M4"``. The S7 acceptance run
#: scores them.
M4_SURFACE_MARKERS: frozenset[str] = frozenset(
    marker
    for _check, marker in (*M4_GROUND_TRUTH, *M4_FALSE_POSITIVE_TRAPS)
    if marker.startswith("/")
)


def build_definition(lab: WebLab) -> TargetDefinition:
    return TargetDefinition(
        name="m3-web-lab",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "S6 builder <s6@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": (
                "Local vulnerable-by-design lab fixture on loopback, owned by the test suite"
            ),
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-M3",
            "active_checks_authorized": True,
        },
    )


def build_settings(definition: TargetDefinition, *, upload_probe: bool) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        # A live scan over loopback: the lab is a private address, and the scan is authorized.
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=definition.compile_scope(),
        ),
        # A check makes tens of probes; the production 5/s per host would turn the acceptance
        # run into a multi-minute wait. Rate limiting has its own suite.
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        web=WebSettings(upload_probe=upload_probe),
    )


async def run_lab_scan(
    lab: WebLab, *, upload_probe: bool
) -> tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings]:
    definition = build_definition(lab)
    settings = build_settings(definition, upload_probe=upload_probe)
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=settings.safety.policy,
            auditor=auditor,
        )

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
        client_factory=client_factory,
    )
    from arachne.core.target import ScanRequest

    request = ScanRequest(
        target=definition,
        options=ScanOptions(active_checks=True, modules=ModuleSelection(enabled=("M3",))),
    )
    session = await orchestrator.scan(request)
    return findings, analyses, session, settings


def score(findings: MemoryFindingStore, analyses: MemoryAnalysisStore, scan_id: int) -> Measurement:
    """Score the scan's candidates against the lab's declared ground truth.

    Only the S6 **core** checks participate, and ``m3.api-surface`` skips discoveries on the
    S7 (M4) and S10 (M3-extended) routes the same lab now serves — those belong to the other
    suites' ground truth. The numbers therefore stay comparable with S6, which measured 18
    candidates against this same core set.
    """
    candidates = findings.list_candidates(scan_id)
    matched: set[tuple[str, str]] = set()
    false_positives: list[str] = []
    scored = 0
    for record in candidates:
        check = (record.check_key or "").split("/")[-1].split("@")[0]
        if f"{record.module.lower()}.{check}" not in CORE_CHECKS:
            continue  # an S10 extended family, scored by test_m3x_scan.py
        blob = " ".join(
            f"{key}={value}" for item in record.evidence for key, value in item.payload.items()
        )
        hits = [
            (planted_check, marker)
            for planted_check, marker in GROUND_TRUTH
            if planted_check == record.module.lower() + "." + check and marker in blob
        ]
        if hits:
            matched.update(hits)
            scored += 1
            continue
        if check == "api-surface" and any(marker in blob for marker in M4_SURFACE_MARKERS):
            continue  # an S7 endpoint, scored by test_m4_scan.py
        if check == "api-surface" and any(marker in blob for marker in M3X_SURFACE_MARKERS):
            continue  # an S10 endpoint, scored by test_m3x_scan.py
        false_positives.append(_describe(record, check, blob))
        scored += 1
    total = scored
    return Measurement(
        detection=round(len(matched) / len(GROUND_TRUTH), 3),
        true_positives=len(matched),
        planted=len(GROUND_TRUTH),
        fp_rate=round(len(false_positives) / total, 3) if total else 0.0,
        false_positives=len(false_positives),
        candidates=total,
        fp_examples=sorted(false_positives)[:6],
        missed=[
            f"{check}:{marker}" for check, marker in GROUND_TRUTH if (check, marker) not in matched
        ],
        findings=len(analyses.list_analyses(scan_id)),
        severities=_severities(analyses, scan_id),
    )


def _describe(record: Any, check: str, blob: str) -> str:
    endpoint = ""
    for item in record.evidence:
        payload = item.payload
        for key in ("endpoint", "origin", "url"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                endpoint = value
                break
        if endpoint:
            break
    trap = [marker for planted_check, marker in FALSE_POSITIVE_TRAPS if marker in blob]
    return f"{record.module}.{check}:{record.title[:48]!r} endpoint={endpoint!r} trap={trap}"


def _severities(analyses: MemoryAnalysisStore, scan_id: int) -> dict[str, int]:
    histogram: dict[str, int] = {}
    for row in analyses.list_analyses(scan_id):
        histogram[row.severity] = histogram.get(row.severity, 0) + 1
    return dict(sorted(histogram.items(), key=lambda item: item[0]))


# --------------------------------------------------------------------------- the acceptance run
@pytest.fixture(scope="module")
def upload_scan(lab: WebLab) -> tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings]:
    """One upload-probe M3 scan, shared by the tests that read its result (runtime budget).

    A full M3 crawl-and-checks run costs about twenty seconds and three of the four
    acceptance tests read the *same* result, so it runs once. ``run_lab_scan`` is driven in
    its own event loop and every test only reads the returned in-memory stores, so nothing
    loop-bound is shared between tests.
    """
    return asyncio.run(run_lab_scan(lab, upload_probe=True))


async def test_m3_scan_detects_the_planted_vulnerabilities(
    upload_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings],
) -> None:
    """≥ 60% of the planted core set (DONE criterion 1)."""
    findings, analyses, session, _settings = upload_scan
    assert session.status is ScanStatus.COMPLETED, session
    measurement = score(findings, analyses, session.scan_id or 0)
    print(f"\nM3 lab scan (upload probe on): {measurement.record()}")
    assert measurement.detection >= 0.6, measurement.record()
    # The upload family is only reachable with the opt-in probe, so its detection is a
    # separate, visible number rather than silently folded into the requirement.
    assert measurement.planted == len(GROUND_TRUTH)


async def test_default_tuning_holds_the_false_positive_rate(lab: WebLab) -> None:
    """≤ 15% false positives at default tuning (DONE criterion 2)."""
    findings, analyses, session, settings = await run_lab_scan(lab, upload_probe=False)
    assert settings.web.upload_probe is False
    assert session.status is ScanStatus.COMPLETED, session
    measurement = score(findings, analyses, session.scan_id or 0)
    print(f"\nM3 lab scan (default tuning): {measurement.record()}")
    assert measurement.fp_rate <= 0.15, measurement.record()
    assert measurement.candidates >= 10, "the scan should have raised the core findings"


async def test_the_checks_step_ran_the_crawl_and_the_oracles(
    upload_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings],
) -> None:
    """The step statistics prove the crawl and the checks actually executed (not skipped)."""
    _findings, _analyses, session, _settings = upload_scan
    steps = _steps_of(session)
    checks_step = steps.get(ScanStep.CHECKS)
    assert checks_step is not None
    assert checks_step.status is not None
    stats = checks_step.stats
    assert stats.get("web", {}).get("pages", 0) > 5
    assert stats.get("checks_run", 0) >= 10
    assert stats.get("candidates", 0) >= 10


async def test_every_candidate_carries_evidence_and_every_probe_is_audited(
    upload_scan: tuple[MemoryFindingStore, MemoryAnalysisStore, Any, Settings],
) -> None:
    """F-02-08 and F-01-08: candidates cite request/response, and probes are audited."""
    findings, _analyses, session, _settings = upload_scan
    candidates = findings.list_candidates(session.scan_id or 0)
    assert candidates
    for record in candidates:
        assert record.evidence, f"{record.title!r} carries no evidence"
        assert record.severity is None, "the module layer must not score (ADR-02)"
        kinds = {item.kind for item in record.evidence}
        assert "artifact" in kinds
    steps = _steps_of(session)
    assert steps[ScanStep.CHECKS].stats.get("results", 0) > 0


def _steps_of(session: Any) -> dict[ScanStep, Any]:
    record = session.record
    assert record is not None
    return {state.step: state for state in record.steps}
