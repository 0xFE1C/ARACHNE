"""Acceptance for area AGENT: a live lab scan that reasons, and records every decision.

The two hard rules of S21 are quantitative or structural, and neither can be shown by a unit
test:

* **Heuristic-only parity** — "heuristic-only mode must meet the lab ground-truth thresholds".
  So this module runs the *same* live lab scan as S6's acceptance run, with agentic reasoning
  **on** in ``heuristic`` mode (no provider anywhere), and scores it against the lab's declared
  ground truth with the same scorer.
* **The cage** — hypotheses execute only through the planner/orchestrator, under a per-scan
  budget, and every decision is recorded. So the same run's journal is replayed offline, its
  budget is checked, and a paused run is resumed.

The scan is live (real sockets on loopback) and goes through the real wiring — the lifecycle
machine, the checks engine, the analyzer, the correlation step and then the hypothesis step —
because what is being measured is the whole loop, not a check called in isolation.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from tests.helpers.agentic import hypothesis_factory
from tests.integration.test_m3_scan import build_definition, build_settings, score
from tests.lab.web_lab import GROUND_TRUTH, WebLab, start_web_lab

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.errors import ScanStateError
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
)
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry
from arachne.reasoning.control import MemoryHypothesisControl
from arachne.reasoning.model import (
    HypothesisBudget,
    HypothesisJournal,
    HypothesisJournalState,
    HypothesisMode,
    HypothesisOutcome,
)
from arachne.reasoning.replay import replay_journal


@dataclass
class Harness:
    """One agentic scan's wiring, kept so a test can resume it."""

    settings: Settings
    definition: TargetDefinition
    registry: ModuleRegistry
    findings: MemoryFindingStore
    analyses: MemoryAnalysisStore
    sink: MemoryAuditSink
    store: MemoryScanStateStore
    orchestrator: Orchestrator
    control: MemoryHypothesisControl
    factory: Any
    session: Any = None
    request: ScanRequest | None = None

    @property
    def scan_id(self) -> int:
        assert self.session is not None and self.session.scan_id is not None
        return int(self.session.scan_id)

    def journal(self) -> HypothesisJournal:
        record = self.store.get_scan(self.scan_id)
        assert record is not None
        journal = HypothesisJournal.from_document((record.stats or {}).get("hypotheses"))
        assert journal is not None, "the scan recorded no hypothesis journal"
        return journal

    def actions(self) -> list[str]:
        return [event.action.value for event in self.sink.events]


def make_harness(
    lab: WebLab,
    *,
    mode: HypothesisMode = HypothesisMode.HEURISTIC,
    max_hypotheses: int = 3,
    max_probes: int = 40,
    approved: tuple[str, ...] = (),
    control: MemoryHypothesisControl | None = None,
) -> Harness:
    """Build the full agentic stack against ``lab`` (no provider, no fixtures)."""
    definition = build_definition(lab)
    settings = build_settings(definition, upload_probe=False)
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    store = MemoryScanStateStore()
    control = control if control is not None else MemoryHypothesisControl()
    factory = hypothesis_factory(
        findings=findings,
        analyses=analyses,
        settings=settings,
        registry=registry,
        control=control,
    )

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings, scope=scope, policy=settings.safety.policy, auditor=auditor
        )

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
        client_factory=client_factory,
        hypothesis_factory=factory,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(enabled=("M3",)),
            hypotheses=mode,
            proof_approved=approved,
            hypothesis_budget=HypothesisBudget(
                max_hypotheses=max_hypotheses, max_probes=max_probes
            ),
        ),
    )
    return Harness(
        settings=settings,
        definition=definition,
        registry=registry,
        findings=findings,
        analyses=analyses,
        sink=sink,
        store=store,
        orchestrator=orchestrator,
        control=control,
        factory=factory,
        request=request,
    )


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


# --------------------------------------------------------------------------- the loop


async def test_the_agentic_step_runs_inside_the_scan_pipeline(lab: WebLab) -> None:
    """The step is part of the scan: it executes, and its journal is persisted with the scan."""
    harness = make_harness(lab, max_hypotheses=3)
    harness.session = await harness.orchestrator.scan(harness.request)
    assert harness.session.status is ScanStatus.COMPLETED, harness.session
    executed = [step.value for step in harness.session.outcome.executed]
    assert ScanStep.HYPOTHESIS.value in executed
    journal = harness.journal()
    assert journal.state is HypothesisJournalState.COMPLETED
    assert journal.proposed >= 1, "the M3 lab should offer something to reason about"
    assert journal.cursor == len(journal.proposals)
    assert (
        len(journal.executed) + len(journal.refused) + _deferred(journal) == journal.cursor
    ), "every proposal must have exactly one decision"
    assert AuditAction.HYPOTHESIS_PROPOSED.value in harness.actions()
    assert AuditAction.HYPOTHESIS_COMPLETED.value in harness.actions()


async def test_a_probe_runs_through_the_planner_and_produces_findings(lab: WebLab) -> None:
    """An approved L2 sibling is planned, executed, and its candidates land on the scan."""
    harness = make_harness(lab, max_hypotheses=3, approved=("m3.sqli-oob", "m3.sqli-oracle"))
    harness.session = await harness.orchestrator.scan(harness.request)
    assert harness.session.status is ScanStatus.COMPLETED, harness.session
    journal = harness.journal()
    assert journal.executed, f"nothing executed: {[d.reason for d in journal.decisions]}"
    executed_checks = {decision.check_id for decision in journal.executed}
    assert executed_checks <= set(harness.factory.index.ids())
    for decision in journal.executed:
        assert decision.probes > 0, "an executed probe must consume budget"
        assert decision.engine == journal.engine
    assert AuditAction.HYPOTHESIS_EXECUTED.value in harness.actions()
    # The probe wrote its candidates to the same scan (no second scan, no shadow store).
    written = {record.id for record in harness.findings.list_candidates(harness.scan_id)}
    for decision in journal.executed:
        assert set(decision.produced) <= written


async def test_heuristic_only_mode_meets_the_lab_ground_truth(lab: WebLab) -> None:
    """REQ-AGENT-001's accept criterion: parity with no AI provider anywhere (hard rule)."""
    harness = make_harness(lab, max_hypotheses=3)
    assert harness.orchestrator.handlers.get(ScanStep.HYPOTHESIS) is not None
    assert harness.factory.ai_engine is None  # nothing to call: this is heuristic-only mode
    harness.session = await harness.orchestrator.scan(harness.request)
    assert harness.session.status is ScanStatus.COMPLETED, harness.session
    measured = score(harness.findings, harness.analyses, harness.scan_id)
    print(f"\nagentic (heuristic-only) lab scan: {measured.record()}")
    assert measured.detection >= 0.6, measured.record()
    assert measured.fp_rate <= 0.15, measured.record()
    assert measured.planted == len(GROUND_TRUTH)
    # The scan reasoned: a run with proposals is the difference from the baseline pipeline.
    assert harness.journal().proposed >= 1


async def test_the_budget_bounds_what_runs(lab: WebLab) -> None:
    """REQ-AGENT-001/005: the per-scan budget is hard, and what does not fit is *recorded*."""
    harness = make_harness(lab, max_hypotheses=1, max_probes=30)
    harness.session = await harness.orchestrator.scan(harness.request)
    assert harness.session.status is ScanStatus.COMPLETED, harness.session
    journal = harness.journal()
    assert len(journal.executed) <= 1
    assert journal.budget.hypotheses_spent <= 1
    assert journal.budget.probes_spent <= 30
    assert journal.budget.hypotheses_spent + journal.budget.deferred <= journal.proposed


async def test_every_decision_replays_offline(lab: WebLab) -> None:
    """REQ-AGENT-002: the journal alone reproduces the run's decisions."""
    harness = make_harness(lab, max_hypotheses=3)
    harness.session = await harness.orchestrator.scan(harness.request)
    journal = harness.journal()
    report = replay_journal(journal, index=harness.factory.index)
    assert report.ok, report.problems
    assert report.hash_matches
    assert report.proposals_reproduced, (report.missing_probes, report.extra_probes)
    assert report.decisions == journal.cursor
    assert report.executed == len(journal.executed)


async def test_the_kill_switch_leaves_a_resumable_scan(lab: WebLab) -> None:
    """REQ-AGENT-007: an operator abort mid-expansion stops it and a resume continues it."""
    control = MemoryHypothesisControl(global_directive="abort")
    harness = make_harness(lab, max_hypotheses=3, control=control)
    with pytest.raises(ScanStateError, match="agentic expansion aborted"):
        await harness.orchestrator.scan(harness.request)
    assert harness.session is None
    record = _only_scan(harness)
    assert record.status is ScanStatus.FAILED
    journal = _journal_of(harness, record.id)
    assert journal.state is HypothesisJournalState.ABORTED
    assert journal.cursor == 0
    assert journal.proposals, "the proposals are recorded before anything runs"
    assert AuditAction.HYPOTHESIS_ABORTED.value in harness.actions()

    # The resume clears the directive (a stop applies to one run, not to every later one).
    control.clear(None)
    resumed = await harness.orchestrator.resume(record.id, harness.request)
    assert resumed.status is ScanStatus.COMPLETED, resumed
    after = _journal_of(harness, record.id)
    assert after.state is HypothesisJournalState.COMPLETED
    assert after.cursor == len(after.proposals)
    assert AuditAction.HYPOTHESIS_RESUMED.value in harness.actions()


# --------------------------------------------------------------------------- helpers


def _deferred(journal: HypothesisJournal) -> int:
    return sum(1 for item in journal.decisions if item.outcome is HypothesisOutcome.DEFERRED)


def _only_scan(harness: Harness) -> Any:
    scans = harness.store.list_scans(limit=10)
    assert scans, "the failed scan should still exist"
    return scans[0]


def _journal_of(harness: Harness, scan_id: int) -> HypothesisJournal:
    record = harness.store.get_scan(scan_id)
    assert record is not None
    journal = HypothesisJournal.from_document((record.stats or {}).get("hypotheses"))
    assert journal is not None
    return journal


@dataclass
class _Unused:
    """Kept for symmetry with the other lab suites; no state of its own."""

    values: tuple[int, ...] = field(default_factory=tuple)
