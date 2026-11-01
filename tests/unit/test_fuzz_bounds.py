"""The hard bounds (S30, area FUZZ, REQ-FUZZ-001).

"Bounded" is the whole requirement, so these tests are about the arithmetic of stopping: every
budget axis refuses the request that would exceed it, a plan can tighten a ceiling but never
raise one, and the clock is injectable so the wall-clock bound is provable without sleeping.
"""

from __future__ import annotations

import pytest

from arachne.core.config import FuzzSettings
from arachne.core.errors import ConfigurationError, FuzzBudgetExhaustedError
from arachne.fuzz.bounds import BudgetLedger, FuzzBudget


class FakeClock:
    """A monotonic clock a test advances by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_a_budget_rejects_a_bound_that_cannot_bound_anything() -> None:
    with pytest.raises(ConfigurationError):
        FuzzBudget(max_cases=0)
    with pytest.raises(ConfigurationError):
        FuzzBudget(max_requests=0)
    with pytest.raises(ConfigurationError):
        FuzzBudget(max_seconds=0)
    with pytest.raises(ConfigurationError):
        FuzzBudget(batch_size=0)


def test_the_deployment_ceiling_is_what_a_budget_defaults_to() -> None:
    settings = FuzzSettings(max_cases=11, max_requests=22, max_seconds=33.0, batch_size=4)
    budget = FuzzBudget.from_settings(settings)
    assert (budget.max_cases, budget.max_requests, budget.max_seconds, budget.batch_size) == (
        11,
        22,
        33.0,
        4,
    )


def test_a_plan_may_tighten_a_ceiling_but_never_raise_one() -> None:
    ceiling = FuzzBudget(max_cases=100, max_requests=120, max_seconds=10.0, batch_size=25)
    tightened = ceiling.narrowed(max_cases=10, max_requests=20, max_seconds=2.0, batch_size=5)
    assert tightened.max_cases == 10
    assert tightened.max_requests == 20
    assert tightened.max_seconds == 2.0
    assert tightened.batch_size == 5

    asked = FuzzBudget(max_cases=10_000, max_requests=10_000, max_seconds=999.0, batch_size=25)
    raised = ceiling.narrowed(
        max_cases=asked.max_cases, max_requests=asked.max_requests, max_seconds=asked.max_seconds
    )
    assert raised.max_cases == 100, "a request above the ceiling is clamped, never granted"
    assert raised.max_requests == 120
    assert raised.max_seconds == 10.0
    assert ceiling.clamped_fields(asked) == ("max_cases", "max_requests", "max_seconds")
    smallest = FuzzBudget(max_cases=1, max_requests=1, max_seconds=1.0)
    assert ceiling.clamped_fields(smallest) == ()


def test_the_ledger_spends_and_refuses_the_spend_that_would_exceed_a_bound() -> None:
    ledger = BudgetLedger(FuzzBudget(max_cases=2, max_requests=3, max_seconds=60.0))
    ledger.spend(requests=1)
    ledger.spend(requests=2)
    assert (ledger.cases, ledger.requests) == (2, 3)
    assert ledger.spent
    assert "request budget spent (3 of 3)" in (ledger.exhausted_reason() or "")
    with pytest.raises(FuzzBudgetExhaustedError):
        ledger.spend(requests=1)


def test_a_refused_spend_leaves_the_ledger_exactly_as_it_was() -> None:
    ledger = BudgetLedger(FuzzBudget(max_cases=5, max_requests=2, max_seconds=60.0))
    ledger.spend(requests=2)
    for _ in range(3):
        with pytest.raises(FuzzBudgetExhaustedError):
            ledger.spend(requests=1)
    assert (ledger.cases, ledger.requests) == (1, 2), (
        "a repeated refusal must not walk past a bound"
    )


def test_a_health_probe_costs_a_request_but_no_case() -> None:
    ledger = BudgetLedger(FuzzBudget(max_cases=1, max_requests=10, max_seconds=60.0))
    ledger.spend(requests=1, cases=0)
    ledger.spend(requests=1, cases=0)
    assert ledger.cases == 0
    assert ledger.requests == 2
    assert not ledger.spent, "probes must not consume the case budget a run was granted"


def test_the_time_bound_is_enforced_without_sleeping() -> None:
    clock = FakeClock()
    ledger = BudgetLedger(FuzzBudget(max_cases=100, max_requests=100, max_seconds=5.0), clock=clock)
    ledger.spend(requests=1)
    clock.advance(5.0)
    assert ledger.spent
    assert "wall-clock budget spent" in (ledger.exhausted_reason() or "")
    with pytest.raises(FuzzBudgetExhaustedError):
        ledger.spend(requests=1)


def test_the_reported_reason_is_stable_when_two_bounds_run_out_together() -> None:
    """Time, then requests, then cases — a fixed order, so the reason is reproducible."""
    cases_only = BudgetLedger(FuzzBudget(max_cases=1, max_requests=9, max_seconds=9.0))
    cases_only.spend(requests=1)
    assert "case budget spent (1 of 1)" in (cases_only.exhausted_reason() or "")

    both = BudgetLedger(FuzzBudget(max_cases=1, max_requests=1, max_seconds=9.0))
    both.spend(requests=1)
    assert "request budget spent" in (both.exhausted_reason() or ""), (
        "requests are checked before cases, so the reason does not depend on which bound tied"
    )

    clock = FakeClock()
    every = BudgetLedger(
        FuzzBudget(max_cases=1, max_requests=1, max_seconds=1.0), clock=clock
    )
    every.spend(requests=1)
    clock.advance(2.0)
    assert "wall-clock budget spent" in (every.exhausted_reason() or "")


def test_a_discarded_payload_is_counted_apart_from_the_work_done() -> None:
    ledger = BudgetLedger(FuzzBudget(max_cases=5, max_requests=5, max_seconds=60.0))
    ledger.spend(requests=1)
    ledger.note_refused_payload()
    ledger.note_refused_payload()
    assert ledger.cases == 1, "a payload the table refused is not a case that ran"
    assert ledger.payloads_refused == 2
    assert ledger.to_dict()["payloads_refused"] == 2


def test_the_ledger_reads_out_every_axis() -> None:
    clock = FakeClock()
    ledger = BudgetLedger(
        FuzzBudget(max_cases=10, max_requests=20, max_seconds=30.0), clock=clock
    )
    ledger.spend(requests=4)
    clock.advance(2.5)
    payload = ledger.to_dict()
    assert payload["cases"] == 1
    assert payload["requests"] == 4
    assert payload["elapsed_seconds"] == 2.5
    assert payload["remaining_cases"] == 9
    assert payload["remaining_requests"] == 16
    assert payload["remaining_seconds"] == 27.5
    assert payload["budget"]["max_cases"] == 10


def test_affords_answers_for_a_case_that_will_cost_more_than_one_request() -> None:
    ledger = BudgetLedger(FuzzBudget(max_cases=10, max_requests=3, max_seconds=60.0))
    assert ledger.affords(requests=3)
    assert not ledger.affords(requests=4)
    ledger.spend(requests=3)
    assert not ledger.affords(requests=1)
