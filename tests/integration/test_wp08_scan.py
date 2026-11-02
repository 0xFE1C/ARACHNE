"""WP-08 acceptance: CWE Top 25 gap closure and the five missing injection families.

Two requirement ids meet here, and the tests are shaped to their acceptance criteria rather
than to the implementation:

REQ-DET-004
    The registry's CWE set is a superset of the eighteen in-scope CWE Top 25 (2025) ids, each
    of the four new emitters has a lab positive and a false-positive trap, every new check is
    L1, and the ledger reports ``cwe_top25.in_scope.covered = 18 / 18``.
REQ-DET-009
    Five new injection checks exist, all L1, all WSTG+CWE mapped, each with a lab positive and
    a decoy that produces no finding; ``CWE-90``, ``CWE-643`` and ``CWE-644`` are in the
    registry's CWE set; and none of the five changes server state.

The read-only claim is checked two ways: at the source (the two check modules construct no
non-GET request) and on the wire (every request the lab answered during the full scan was a
``GET``). The report criterion builds a real report from those findings and validates it
against the shipped JSON schema.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import make_m5_harness
from tests.lab.web_lab import (
    WP08_FALSE_POSITIVE_TRAPS,
    WP08_GROUND_TRUTH,
    WebLab,
    start_web_lab,
)

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore
from arachne.core.orchestrator import Orchestrator
from arachne.core.proof import ProofLevel
from arachne.core.safety import UrlSafetyPolicy
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.coverage import build_ledger
from arachne.modules.handlers import build_handlers
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.registry import ModuleRegistry
from arachne.report.builder import build_report_for_scan
from arachne.report.json_render import load_report_schema, render_json

WP08_CHECKS: tuple[str, ...] = tuple(check_id for check_id, _ in WP08_GROUND_TRUTH)

#: The one crawl root per family's positive and its hardened twin. Running each family over
#: both is what makes "the decoy produces no finding" a measured statement.
ROOTS: dict[str, tuple[str, ...]] = {
    "m3.ldap-injection": ("/directory?uid=alice", "/directory-safe?uid=alice"),
    "m3.xpath-injection": ("/xpath?q=alice", "/xpath-safe?q=alice"),
    "m3.code-injection-oracle": ("/calc?expr=1", "/calc-safe?expr=1"),
    "m3.argument-injection": (
        "/tools/lookup?host=127.0.0.1",
        "/tools/lookup-safe?host=127.0.0.1",
    ),
    "m3.host-header-injection": ("/reset", "/reset-safe"),
    "m3.email-header-injection": (
        "/subscribe?email=alice@example.com",
        "/subscribe-safe?email=alice@example.com",
    ),
    "m3.cache-deception": ("/account", "/account-hardened"),
    "m3.authz-bypass": ("/secure/reports", "/secure/hardened"),
    "m3.input-validation-audit": ("/api/quote?amount=100", "/api/quote-safe?amount=100"),
}

M3_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M3_CHECKS}


def _blob(result: object) -> str:
    evidence = getattr(result, "evidence", ())
    return " ".join(f"{key}={value}" for item in evidence for key, value in item.payload.items())


async def _run(lab: WebLab, check_id: str) -> list:
    check = _by_id()[check_id]
    roots = [f"{lab.base_url.rstrip('/')}{path}" for path in ROOTS[check_id]]
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=60))
    try:
        await harness.prepare(roots)
        return [result async for result in check().run(harness.context(check()))]
    finally:
        await harness.aclose()


# --------------------------------------------------------------------------- positives / decoys
@pytest.mark.parametrize(("check_id", "marker"), WP08_GROUND_TRUTH)
async def test_each_new_check_reports_its_positive_and_not_its_decoy(
    lab: WebLab, check_id: str, marker: str
) -> None:
    """REQ-DET-004/009: a planted signal is found, and its hardened twin is silent."""
    trap = dict(WP08_FALSE_POSITIVE_TRAPS)[check_id]
    results = await _run(lab, check_id)
    vulnerable = [result for result in results if result.status == "vulnerable"]
    found = [result for result in vulnerable if marker in _blob(result)]
    assert found, f"{check_id} did not report {marker!r}: {[r.title for r in results]}"
    offenders = [result.title for result in vulnerable if trap in _blob(result)]
    assert not offenders, f"{check_id} reported the hardened control {trap}: {offenders}"


# --------------------------------------------------------------------------- level and shape
def test_every_new_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-004/009: all nine are L1, read-only, and carry WSTG and CWE mappings."""
    by_id = _by_id()
    registry = ModuleRegistry.discover()
    for check_id in WP08_CHECKS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is ProofLevel.L1, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True and metadata.type == "active", check_id
        assert metadata.requires_active_checks is True, check_id
        assert registry.get(check_id) is not None, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith("WSTG-") for item in metadata.framework), check_id


def test_the_new_modules_construct_only_get_requests() -> None:
    """The read-only claim at the source: no non-GET verb and no ``method=`` argument."""
    for name in ("injection_families.py", "surface_families.py"):
        source = (M3_SOURCE / name).read_text(encoding="utf-8")
        for verb in (
            '"POST"',
            "'POST'",
            '"PUT"',
            "'PUT'",
            '"PATCH"',
            "'PATCH'",
            '"DELETE"',
            "'DELETE'",
        ):
            assert verb not in source, f"{name} names a non-GET verb: {verb}"
        assert "method=" not in source, f"{name} can choose a request method"


# --------------------------------------------------------------------------- CWE coverage
TOP25_IN_SCOPE: frozenset[str] = frozenset(
    {
        "CWE-79",
        "CWE-89",
        "CWE-352",
        "CWE-862",
        "CWE-22",
        "CWE-78",
        "CWE-434",
        "CWE-502",
        "CWE-284",
        "CWE-200",
        "CWE-306",
        "CWE-918",
        "CWE-639",
        "CWE-770",
        "CWE-94",
        "CWE-863",
        "CWE-20",
        "CWE-77",
    }
)


def test_the_registry_cwe_set_covers_all_eighteen_in_scope_ids() -> None:
    """REQ-DET-004: the registry emits every in-scope CWE Top 25 (2025) id."""
    emitted = {
        metadata.cwe
        for metadata in ModuleRegistry.discover().metadata()
        if metadata.cwe is not None
    }
    assert emitted >= TOP25_IN_SCOPE, sorted(TOP25_IN_SCOPE - emitted)
    # REQ-DET-009 names three ids explicitly; they are not Top 25 items, so check them here.
    assert {"CWE-90", "CWE-643", "CWE-644"} <= emitted


def test_the_ledger_reports_eighteen_of_eighteen_in_scope() -> None:
    """REQ-DET-004: ``cwe_top25.in_scope.covered = 18 / 18``, with the 25 visible."""
    document = build_ledger(generated_at="2026-11-03").to_dict()
    tally = document["cwe_top25"]
    assert tally["version"] == "2025"
    assert tally["in_scope"] == {"covered": 18, "total": 18, "percent": 100.0}
    assert tally["all"]["total"] == 25
    in_scope = [item for item in tally["items"] if item["in_scope"]]
    assert len(in_scope) == 18
    assert all(item["covered"] for item in in_scope)
    # The seven memory-safety classes remain in the denominator, out of scope with a reason.
    out_of_scope = [item for item in tally["items"] if not item["in_scope"]]
    assert {item["id"] for item in out_of_scope} == {
        "CWE-787",
        "CWE-416",
        "CWE-125",
        "CWE-120",
        "CWE-476",
        "CWE-121",
        "CWE-122",
    }
    assert all(item["reason"] and not item["covered"] for item in out_of_scope)


# --------------------------------------------------------------------------- report
def _definition(lab: WebLab) -> TargetDefinition:
    return TargetDefinition(
        name="wp08-lab",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "WP-08 builder <wp08@arachne.test>",
            "attested_at": "2026-11-01T00:00:00Z",
            "scope_statement": (
                "Local vulnerable-by-design lab fixture on loopback, owned by the test suite"
            ),
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-WP08",
            "active_checks_authorized": True,
        },
    )


def _settings(definition: TargetDefinition) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
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
        web=WebSettings(max_pages=120),
    )


async def _scan(lab: WebLab) -> tuple[Any, Any, Any, Any]:
    definition = _definition(lab)
    settings = _settings(definition)
    registry = ModuleRegistry.discover()
    store = MemoryScanStateStore()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    orchestrator = Orchestrator(
        settings=settings,
        store=store,
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
        client_factory=lambda scope: ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=settings.safety.policy,
            auditor=auditor,
        ),
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(enabled=("M3",), only=WP08_CHECKS),
        ),
    )
    session = await orchestrator.scan(request)
    return session, store, findings, analyses


async def test_a_report_with_the_new_findings_renders_and_validates(lab: WebLab) -> None:
    """REQ-DET-004/009: the findings reach a report that validates against the schema."""
    before = len(lab.requests)
    session, store, findings, analyses = await _scan(lab)
    answered = lab.requests[before:]
    assert answered, "the scan sent no request"
    assert all(request.startswith("GET ") for request in answered), sorted(
        {request.split()[0] for request in answered}
    )

    report = build_report_for_scan(
        scan_id=session.scan_id or 0,
        scans=store,
        findings=findings,
        analyses=analyses,
        settings=_settings(_definition(lab)),
    )
    document = json.loads(render_json(report))
    jsonschema.validate(document, load_report_schema())

    emitted = {
        (finding["check_id"], finding["classification"]["cwe"]) for finding in document["findings"]
    }
    expected = {(check_id, _by_id()[check_id].metadata.cwe) for check_id in WP08_CHECKS}
    assert expected <= emitted, sorted(expected - emitted)
