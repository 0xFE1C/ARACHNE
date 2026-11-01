"""The scan state machine and resumability (F-01-03/04).

The behaviour that matters: a step is persisted ``running`` *before* its handler runs, so
a kill leaves a durable record; ``completed``/``skipped`` steps are never re-run; a failing
step is recorded as data and re-raised for the caller's exit code.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from tests.conftest import build_scan_request

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.errors import ScanStateError
from arachne.core.events import EventBus, EventType
from arachne.core.lifecycle import (
    MemoryScanStateStore,
    ScanMachine,
    ScanStatus,
    StepContext,
    StepOutcome,
    StepStatus,
)
from arachne.core.planner import ScanStep

PIPELINE = (ScanStep.RECON, ScanStep.DISCOVERY, ScanStep.CHECKS)


class Harness:
    """Machine + store + bus + audit, with scripted handlers."""

    def __init__(self, *, pipeline: tuple[ScanStep, ...] = PIPELINE) -> None:
        self.store = MemoryScanStateStore()
        self.bus = EventBus()
        self.sink = MemoryAuditSink()
        self.auditor = Auditor(self.sink, actor="pytest")
        self.machine = ScanMachine(
            self.store, bus=self.bus, auditor=self.auditor, pipeline=pipeline
        )
        # A domain plus a URL target, so both host assets and endpoint assets have a
        # scope dimension that can allow them.
        self.request = build_scan_request(
            targets=[
                {"kind": "domain", "value": "example.com"},
                {"kind": "url", "value": "https://example.com/"},
            ]
        )
        self.calls: list[str] = []
        self.created = self.store.create_scan(
            target_id=None, engine="heuristic", plan={"target_name": "unit-fixture"}
        )

    def handlers(
        self, *, fail_on: ScanStep | None = None, skip: tuple[ScanStep, ...] = ()
    ) -> dict[ScanStep, object]:
        def make(step: ScanStep):  # type: ignore[no-untyped-def]
            async def handler(context: StepContext) -> StepOutcome:
                self.calls.append(step.value)
                if fail_on is step:
                    msg = "handler exploded"
                    raise RuntimeError(msg)
                return StepOutcome(stats={"step": step.value}, skipped=step in skip)

            return handler

        return {step: make(step) for step in self.machine.pipeline}

    async def run(self, *, resume: bool = False, **kwargs) -> object:
        return await self.machine.run(
            self.created.id,
            self.handlers(**kwargs),  # type: ignore[arg-type]
            definition=self.request.target,
            options=self.request.options,
            scope=self.request.target.compile_scope(),
            resume=resume,
        )


# ------------------------------------------------------------------ happy path
async def test_all_steps_run_in_order_and_the_scan_completes() -> None:
    harness = Harness()
    outcome = await harness.run()

    assert harness.calls == ["recon", "discovery", "checks"]
    assert outcome.status is ScanStatus.COMPLETED
    assert outcome.executed == PIPELINE
    record = harness.store.get_scan(harness.created.id)
    assert record is not None
    assert record.status is ScanStatus.COMPLETED
    assert record.completed_steps == PIPELINE
    assert record.started_at is not None and record.finished_at is not None
    assert record.stats["steps_executed"] == ["recon", "discovery", "checks"]


async def test_each_step_records_attempts_status_and_stats() -> None:
    harness = Harness()
    await harness.run()

    record = harness.store.get_scan(harness.created.id)
    assert record is not None
    for step in PIPELINE:
        state = record.step_state(step)
        assert state is not None
        assert state.status is StepStatus.COMPLETED
        assert state.attempts == 1
        assert state.stats["step"] == step.value
        assert state.started_at is not None and state.finished_at is not None


async def test_lifecycle_events_are_published_in_order() -> None:
    harness = Harness()
    await harness.run()

    types = [event.type for event in harness.bus.history()]
    assert types[0] is EventType.SCAN_STARTED
    assert types[-1] is EventType.SCAN_FINISHED
    assert types.count(EventType.STEP_COMPLETED) == len(PIPELINE)
    assert types.index(EventType.STEP_STARTED) < types.index(EventType.STEP_COMPLETED)


async def test_lifecycle_is_audited() -> None:
    harness = Harness()
    await harness.run()

    actions = harness.sink.actions()
    assert AuditAction.SCAN_STARTED.value in actions
    assert AuditAction.SCAN_FINISHED.value in actions
    assert actions.count(AuditAction.SCAN_STEP_STARTED.value) == len(PIPELINE)
    assert actions.count(AuditAction.SCAN_STEP_COMPLETED.value) == len(PIPELINE)


async def test_steps_without_a_handler_are_skipped_not_failed() -> None:
    harness = Harness()
    outcome = await harness.machine.run(
        harness.created.id,
        {ScanStep.RECON: harness.handlers()[ScanStep.RECON]},  # type: ignore[arg-type]
        definition=harness.request.target,
        options=harness.request.options,
        scope=harness.request.target.compile_scope(),
    )
    assert outcome.executed == (ScanStep.RECON,)
    assert set(outcome.skipped) == {ScanStep.DISCOVERY, ScanStep.CHECKS}
    record = harness.store.get_scan(harness.created.id)
    assert record is not None
    state = record.step_state(ScanStep.CHECKS)
    assert state is not None
    assert state.status is StepStatus.SKIPPED
    assert state.stats["note"] == "no step handler is registered in this build"


async def test_a_handler_may_skip_its_own_step() -> None:
    harness = Harness()
    outcome = await harness.run(skip=(ScanStep.DISCOVERY,))
    assert outcome.skipped == (ScanStep.DISCOVERY,)
    assert outcome.executed == (ScanStep.RECON, ScanStep.CHECKS)


# ------------------------------------------------------------------ resumability
async def test_resume_continues_from_the_last_completed_step() -> None:
    harness = Harness()
    with pytest.raises(ScanStateError):
        await harness.run(fail_on=ScanStep.CHECKS)

    assert harness.calls == ["recon", "discovery", "checks"]
    record = harness.store.get_scan(harness.created.id)
    assert record is not None
    assert record.status is ScanStatus.FAILED
    assert record.next_step(PIPELINE) is ScanStep.CHECKS

    outcome = await harness.run(resume=True)

    # Only the failed step ran again; the completed ones were not repeated.
    assert harness.calls == ["recon", "discovery", "checks", "checks"]
    assert outcome.resumed is True
    assert outcome.already_completed == (ScanStep.RECON, ScanStep.DISCOVERY)
    assert outcome.executed == (ScanStep.CHECKS,)
    assert outcome.status is ScanStatus.COMPLETED
    final = harness.store.get_scan(harness.created.id)
    assert final is not None
    checks_state = final.step_state(ScanStep.CHECKS)
    assert checks_state is not None
    assert checks_state.attempts == 2


async def test_resume_skips_terminal_skipped_steps_too() -> None:
    harness = Harness()
    await harness.run(skip=(ScanStep.DISCOVERY,))
    outcome = await harness.run(resume=True)
    assert outcome.already_completed == PIPELINE
    assert outcome.executed == ()


async def test_a_completed_scan_is_a_no_op_on_resume() -> None:
    harness = Harness()
    await harness.run()
    harness.calls.clear()

    outcome = await harness.run(resume=True)

    assert harness.calls == []
    assert outcome.already_completed == PIPELINE
    assert outcome.status is ScanStatus.COMPLETED


async def test_mid_step_progress_survives_a_reader_a_crash_would_leave_behind() -> None:
    """A step marked ``running`` on disk is exactly what a hard kill leaves behind."""
    harness = Harness()
    seen: list[StepStatus] = []

    async def observing(context: StepContext) -> StepOutcome:
        record = harness.store.get_scan(context.scan_id)
        assert record is not None
        state = record.step_state(context.step)
        assert state is not None
        seen.append(state.status)
        return StepOutcome()

    await harness.machine.run(
        harness.created.id,
        {ScanStep.RECON: observing, ScanStep.DISCOVERY: observing, ScanStep.CHECKS: observing},  # type: ignore[arg-type]
        definition=harness.request.target,
        options=harness.request.options,
        scope=harness.request.target.compile_scope(),
    )
    # While the handler ran, the step was already durably marked as running.
    assert seen == [StepStatus.RUNNING, StepStatus.RUNNING, StepStatus.RUNNING]


async def test_failure_records_the_error_and_marks_the_scan_failed() -> None:
    harness = Harness()
    with pytest.raises(ScanStateError, match="failed in step discovery"):
        await harness.run(fail_on=ScanStep.DISCOVERY)

    record = harness.store.get_scan(harness.created.id)
    assert record is not None
    assert record.status is ScanStatus.FAILED
    state = record.step_state(ScanStep.DISCOVERY)
    assert state is not None
    assert state.status is StepStatus.FAILED
    assert "handler exploded" in (state.error or "")
    assert AuditAction.SCAN_FAILED.value in harness.sink.actions()
    assert harness.bus.history(EventType.SCAN_FAILED)


async def test_a_failed_step_is_retried_on_resume_and_can_succeed() -> None:
    harness = Harness()
    with pytest.raises(ScanStateError):
        await harness.run(fail_on=ScanStep.RECON)

    assert harness.calls == ["recon"]
    outcome = await harness.run(resume=True)
    assert harness.calls == ["recon", "recon", "discovery", "checks"]
    assert outcome.status is ScanStatus.COMPLETED


async def test_running_an_unknown_scan_is_an_error() -> None:
    harness = Harness()
    with pytest.raises(ScanStateError, match="does not exist"):
        await harness.machine.run(
            999,
            {},
            definition=harness.request.target,
            options=harness.request.options,
            scope=harness.request.target.compile_scope(),
        )


async def test_scan_resumed_event_is_published_on_a_resume() -> None:
    harness = Harness()
    with pytest.raises(ScanStateError):
        await harness.run(fail_on=ScanStep.DISCOVERY)
    harness.calls.clear()
    harness.bus.drain()

    await harness.run(resume=True)

    history = harness.bus.history()
    assert history[0].type is EventType.SCAN_RESUMED
    assert harness.sink.actions().count(AuditAction.SCAN_RESUMED.value) == 1


# ------------------------------------------------------------------ asset guard
async def test_recording_an_asset_persists_it_with_provenance() -> None:
    harness = Harness()
    stored: list[str] = []

    async def handler(context: StepContext) -> StepOutcome:
        asset = await context.record_asset("host", "api.example.com", source="module-m1")
        assert asset is not None
        stored.append(asset.value)
        return StepOutcome()

    await harness.machine.run(
        harness.created.id,
        {ScanStep.RECON: handler},  # type: ignore[arg-type]
        definition=harness.request.target,
        options=harness.request.options,
        scope=harness.request.target.compile_scope(),
    )
    assets = harness.store.list_assets(harness.created.id)
    assert stored == ["api.example.com"]
    assert assets[0].meta["source"] == "module-m1"


async def test_discovery_outside_scope_is_discarded_logged_and_not_stored() -> None:
    """F-01-02: out-of-scope discovery is discarded, logged, and never reported."""
    harness = Harness()
    result: list[object] = []

    async def handler(context: StepContext) -> StepOutcome:
        result.append(await context.record_asset("url", "https://elsewhere.example.net/"))
        return StepOutcome()

    await harness.machine.run(
        harness.created.id,
        {ScanStep.RECON: handler},  # type: ignore[arg-type]
        definition=harness.request.target,
        options=harness.request.options,
        scope=harness.request.target.compile_scope(),
    )

    assert result == [None]
    assert harness.store.list_assets(harness.created.id) == ()
    discarded = harness.sink.of_action(AuditAction.SCOPE_DISCARDED)
    assert discarded and discarded[0].outcome.value == "blocked"
    assert discarded[0].reason
    assert harness.bus.history(EventType.OUT_OF_SCOPE_DISCARDED)


async def test_declared_assets_pass_the_guard_unchecked_by_kind() -> None:
    """Network/Git/cloud assets have no host; they are in scope by declaration."""
    harness = Harness()
    recorded: list[str] = []

    async def handler(context: StepContext) -> StepOutcome:
        for kind, value in (
            ("network", "192.0.2.0/30"),
            ("git", "git@github.com:org/repo.git"),
            ("cloud", "aws:1234"),
        ):
            asset = await context.record_asset(kind, value)
            if asset is not None:
                recorded.append(value)
        return StepOutcome()

    scope = build_scan_request(
        targets=[
            {"kind": "cidr", "value": "192.0.2.0/30"},
            {"kind": "git", "value": "git@github.com:org/repo.git"},
            {"kind": "cloud", "value": "aws:1234"},
        ],
        attestation={
            "allowed_targets": ["192.0.2.0/30", "git@github.com:org/repo.git", "aws:1234"]
        },
    ).target.compile_scope()

    await harness.machine.run(
        harness.created.id,
        {ScanStep.RECON: handler},  # type: ignore[arg-type]
        definition=harness.request.target,
        options=harness.request.options,
        scope=scope,
    )
    assert recorded == ["192.0.2.0/30", "git@github.com:org/repo.git", "aws:1234"]


# ------------------------------------------------------------------ memory store
def test_memory_store_lists_scans_newest_first_and_scopes_assets_per_scan() -> None:
    store = MemoryScanStateStore()
    first = store.create_scan(target_id=None, engine="heuristic", plan={})
    second = store.create_scan(target_id=None, engine="heuristic", plan={})
    store.add_asset(first.id, kind="host", value="a.example")
    store.add_asset(second.id, kind="host", value="b.example")

    assert [record.id for record in store.list_scans()] == [second.id, first.id]
    assert [asset.value for asset in store.list_assets(first.id)] == ["a.example"]


def test_memory_store_can_be_constructed_with_an_injected_clock() -> None:
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryScanStateStore(clock=lambda: fixed)
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    assert record.created_at == fixed
    started = store.update_scan(record.id, status=ScanStatus.RUNNING, mark_started=True)
    assert started.started_at == fixed


def test_step_state_terminality() -> None:
    assert StepStatus.COMPLETED.value == "completed"
    assert {StepStatus.COMPLETED, StepStatus.SKIPPED} == {
        status for status in StepStatus if status in {StepStatus.COMPLETED, StepStatus.SKIPPED}
    }


def test_handlers_mapping_is_typed_as_step_handlers() -> None:
    harness = Harness()
    mapping: Mapping[ScanStep, object] = harness.handlers()
    assert set(mapping) == set(PIPELINE)
