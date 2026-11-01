"""The checks engine: selection, isolation, persistence and step statistics (F-01-03).

``run_checks`` is the seam where the framework meets the checks, so these tests are about its
guarantees rather than about any one check:

* selection honours the scan's module choices and the two active-check switches (F-02-09);
* a check that raises becomes one ``error`` result and the step continues;
* a candidate is persisted with its evidence and announced as an event, and an ``info``
  result is not persisted as a finding (ADR-02);
* the step's statistics describe exactly what happened, because that is what a resume and an
  operator both read (F-01-04).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from tests.helpers.checks import asset_for, make_step_context

from arachne.core.audit import AuditAction
from arachne.core.config import Settings
from arachne.core.events import EventType
from arachne.core.lifecycle import StepOutcome
from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult
from arachne.core.target import ModuleSelection, TargetKind
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.handlers import build_handlers, make_checks_handler, run_checks
from arachne.modules.registry import ModuleGroup, ModuleRegistry


class Collecting(Module):
    """A real check (the contract is enforced at class creation) that yields canned results."""

    metadata = CheckMetadata(
        id="m1.collecting",
        module="M1",
        name="collecting",
        version="1.0",
        title="Collecting check",
        description="Yields canned results for the checks-engine tests.",
        research_ref="ch01#3",
        target_kinds=(TargetKind.DOMAIN,),
        estimated_requests=1,
    )
    results: tuple[CheckResult, ...] = ()
    seen: list[str] = []
    raise_with: BaseException | None = None

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        Collecting.seen.append(ctx.asset.key)
        if Collecting.raise_with is not None:
            raise Collecting.raise_with
        for result in Collecting.results:
            yield result


@pytest.fixture(autouse=True)
def _reset_collecting() -> None:
    Collecting.results = ()
    Collecting.seen = []
    Collecting.raise_with = None


def registry_with(*checks: type[Module]) -> ModuleRegistry:
    return ModuleRegistry(
        [ModuleGroup(id="M1", title="M1", description="d", version="1.0", checks=tuple(checks))]
    )


def settings(**overrides: object) -> Settings:
    return Settings(database_url="sqlite:///:memory:", log_level="CRITICAL", **overrides)


# ------------------------------------------------------------------ selection
async def test_only_declared_assets_are_checked_by_default() -> None:
    """A check that fed on its own discoveries would multiply its own request count."""
    step, _memory = make_step_context(seed=[("domain", "example.com")])
    step.store.add_asset(step.scan_id, kind="host", value="discovered.example.com")
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert Collecting.seen == ["domain:example.com"]
    assert stats["checks_run"] == 1


async def test_a_deselected_module_runs_nothing() -> None:
    step, _memory = make_step_context(seed=[("domain", "example.com")])
    step.options = step.options.model_copy(update={"modules": ModuleSelection(disabled=("M1",))})
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert stats["checks_selected"] == 0
    assert Collecting.seen == []


async def test_a_check_that_does_not_support_the_asset_is_skipped() -> None:
    step, _memory = make_step_context(seed=[("host", "93.184.216.34")])
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert stats["checks_selected"] == 1
    assert stats["checks_run"] == 0
    assert Collecting.seen == []


async def test_active_checks_need_both_switches() -> None:
    active = type(
        "Active",
        (Collecting,),
        {
            "metadata": CheckMetadata(
                id="m1.active",
                module="M1",
                name="active",
                version="1.0",
                title="Active",
                description="An active check for the switch test.",
                research_ref="ch01#4",
                target_kinds=(TargetKind.DOMAIN,),
                type="active",
                requires_active_checks=True,
                estimated_requests=1,
            )
        },
    )
    # Opted in by the scan, not authorized by the attestation (the fixture says false).
    step, _memory = make_step_context(seed=[("domain", "example.com")])
    step.options = step.options.model_copy(update={"active_checks": True})
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(active),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert stats["checks_selected"] == 0


# ------------------------------------------------------------------ isolation
async def test_a_raising_check_becomes_one_error_result_and_the_step_continues() -> None:
    Collecting.raise_with = RuntimeError("check blew up")
    step, memory = make_step_context(seed=[("domain", "example.com")])
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert stats["checks_failed"] == 1
    assert stats["candidates"] == 0
    assert AuditAction.CHECK_FAILED.value in memory.actions()
    assert memory.actions().count(AuditAction.CHECK_STARTED.value) == 1


# ------------------------------------------------------------------ persistence
async def test_a_candidate_is_persisted_and_announced() -> None:
    Collecting.results = (
        CheckResult(
            status="vulnerable",
            title="exposed .env",
            detail="200 with secrets",
            cwe="CWE-200",
            confidence=0.8,
            evidence=(),
            check="M1/collecting@1.0",
            module="M1",
        ),
    )
    findings = MemoryFindingStore()
    step, memory = make_step_context(seed=[("domain", "example.com")])
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=findings,
        osint=None,
    )
    assert stats["candidates"] == 1
    records = findings.list_candidates(step.scan_id)
    assert len(records) == 1
    assert records[0].severity is None  # ADR-02
    assert memory.store.list_assets(step.scan_id)  # the seeded asset
    assert AuditAction.CANDIDATE_RECORDED.value in memory.actions()
    types = {event.type for event in memory.bus.history()}
    assert EventType.FINDING_RAISED in types
    assert EventType.CHECK_COMPLETED in types


async def test_an_info_result_is_not_a_finding() -> None:
    Collecting.results = (
        CheckResult(
            status="info", title="3 hosts discovered", check="M1/collecting@1.0", module="M1"
        ),
    )
    findings = MemoryFindingStore()
    step, memory = make_step_context(seed=[("domain", "example.com")])
    stats = await run_checks(
        step, step=ScanStep.RECON, registry=registry_with(Collecting), findings=findings, osint=None
    )
    assert stats["candidates"] == 0
    assert findings.list_candidates(step.scan_id) == ()
    assert AuditAction.CHECK_COMPLETED.value in memory.actions()


async def test_a_skipped_result_is_counted_separately() -> None:
    step, memory = make_step_context(seed=[("domain", "example.com")])
    collecting = type(
        "Skipping",
        (Collecting,),
        {
            "metadata": CheckMetadata(
                id="m1.skipping",
                module="M1",
                name="skipping",
                version="1.0",
                title="Skipping",
                description="A check that always reports itself not run.",
                research_ref="ch01#6",
                target_kinds=(TargetKind.DOMAIN,),
                estimated_requests=1,
            ),
            "run": lambda self, ctx: _skip(ctx),
        },
    )
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(collecting),
        findings=MemoryFindingStore(),
        osint=None,
    )
    assert stats["checks_skipped"] == 1
    assert AuditAction.CHECK_SKIPPED.value in memory.actions()


async def _skip(ctx: CheckContext) -> AsyncIterator[CheckResult]:
    yield ctx.skipped("no source configured")


async def test_a_store_failure_does_not_lose_the_scan() -> None:
    class Exploding(MemoryFindingStore):
        def record_candidate(self, *args: object, **kwargs: object) -> object:
            raise RuntimeError("database gone")

    Collecting.results = (
        CheckResult(status="vulnerable", title="x", check="M1/collecting@1.0", module="M1"),
    )
    step, _memory = make_step_context(seed=[("domain", "example.com")])
    stats = await run_checks(
        step,
        step=ScanStep.RECON,
        registry=registry_with(Collecting),
        findings=Exploding(),
        osint=None,
    )
    assert stats["candidates"] == 1  # counted, even though persistence failed


# ------------------------------------------------------------------ handlers
async def test_the_recon_handler_seeds_then_runs_module_checks() -> None:
    handlers = build_handlers(settings=settings(), registry=registry_with(Collecting))
    assert set(handlers) == {
        ScanStep.RECON,
        ScanStep.DISCOVERY,
        ScanStep.CHECKS,
        # S5 wires the analyzer into the scan: analysis and correlation are pipeline steps, so
        # their handlers are part of the default set.
        ScanStep.ANALYSIS,
        ScanStep.CORRELATION,
    }
    step, _memory = make_step_context()
    outcome = await handlers[ScanStep.RECON](step)
    assert isinstance(outcome, StepOutcome)
    assert outcome.stats["seeded_assets"] == 4  # the fixture's four declared targets
    assert outcome.stats["checks_selected"] == 1


async def test_the_checks_handler_reports_itself_skipped_when_nothing_is_implemented() -> None:
    handler = make_checks_handler(
        registry=registry_with(), findings=MemoryFindingStore(), osint=None
    )
    step, memory = make_step_context(seed=[("domain", "example.com")])
    outcome = await handler(step)
    assert outcome.skipped is True
    assert outcome.note == "no implemented check targets this step in this build"
    assert outcome.stats["checks_selected"] == 0
    assert memory  # the context was real


async def test_handlers_default_to_the_installed_registry_and_offline_osint() -> None:
    """With no arguments the handler set is the built-in one and OSINT stays off (F-02-09)."""
    handlers = build_handlers()
    assert ScanStep.RECON in handlers and ScanStep.CHECKS in handlers
    step, memory = make_step_context(definition=_definition_with_m1(), options=None)
    outcome = await handlers[ScanStep.RECON](step)
    # No OSINT client exists, so the M1 checks report skips; nothing was queried.
    assert outcome.stats["checks_skipped"] >= 8
    assert not [event for event in memory.sink.events if event.action is AuditAction.OSINT_QUERY]


def _definition_with_m1():  # type: ignore[no-untyped-def]
    from tests.helpers.checks import DEFAULT_DEFINITION

    from arachne.core.target import load_scan_request

    return load_scan_request(DEFAULT_DEFINITION).target


def test_asset_helper_is_declared() -> None:
    assert asset_for("domain", "example.com").declared is True
