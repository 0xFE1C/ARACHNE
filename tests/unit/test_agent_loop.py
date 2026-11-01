"""The agent loop's protocol behaviour (S16): lease, heartbeat, ack — and the exceptions.

These tests run the loop against a scripted fake control plane, so each rule is exact:

* the loop acks finished scans and acks *failed* ones too (a failure is terminal data,
  never a hidden retry);
* a lost lease renewal cancels the local execution and never acks;
* a cancelled execution (an agent kill) never acks — the abandoned lease is what makes
  the scan re-leasable on another node (REQ-SCALE-003);
* ``--once`` draining stops when the queue is empty or ``max_scans`` is reached.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from arachne.agent.control import AgentLease
from arachne.agent.runner import AgentLoop, ExecutionResult

# --------------------------------------------------------------------------- fake plane


class FakeControlPlane:
    """Scripted leases + a record of every call the loop made."""

    def __init__(self, leases: list[list[AgentLease]], *, renewals: dict[int, bool] | None = None):
        self._leases = list(leases)
        self.renewals = renewals or {}
        self.registered: str | None = None
        self.lease_calls: list[int] = []
        self.heartbeats = 0
        self.completed: list[int] = []

    async def register(
        self,
        name: str,
        *,
        node: str | None = None,
        version: str | None = None,
        concurrency: int | None = None,
    ) -> dict[str, Any]:
        self.registered = name
        return {"name": name, "concurrency": concurrency or 1}

    async def heartbeat(self, name: str) -> dict[int, bool]:
        self.heartbeats += 1
        return dict(self.renewals)

    async def lease(self, name: str, *, cap: int, ttl_s: float) -> tuple[AgentLease, ...]:
        self.lease_calls.append(cap)
        if not self._leases:
            return ()
        return tuple(self._leases.pop(0))

    async def complete(self, name: str, scan_id: int) -> bool:
        self.completed.append(scan_id)
        return True

    async def close(self) -> None:
        return None


def instant_sleep() -> Any:
    """A sleep that returns immediately but lets other tasks run."""

    async def sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    return sleep


def executor_of(results: dict[int, ExecutionResult | BaseException]) -> Any:
    async def execute(lease: AgentLease) -> ExecutionResult:
        outcome = results.get(lease.scan_id)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, asyncio.CancelledError):
            raise asyncio.CancelledError()
        return outcome or ExecutionResult(scan_id=lease.scan_id, status="completed")

    return execute


# --------------------------------------------------------------------------- tests
async def test_the_loop_registers_then_drains_and_acks_every_scan() -> None:
    control = FakeControlPlane(
        [[AgentLease(scan_id=1)], [AgentLease(scan_id=2)], []],
    )
    loop = AgentLoop(
        control,
        name="a",
        executor=executor_of({}),
        concurrency=1,
        sleep=instant_sleep(),
    )
    assert await loop.run_until_drained() == 2
    assert control.registered == "a"  # draining registers first (--once needs it)
    assert control.completed == [1, 2]
    assert control.lease_calls == [1, 1, 1]  # the cap rides on every lease call


async def test_run_until_drained_stops_at_max_scans() -> None:
    control = FakeControlPlane(
        [[AgentLease(scan_id=1)], [AgentLease(scan_id=2)], [AgentLease(scan_id=3)]],
    )
    loop = AgentLoop(
        control, name="a", executor=executor_of({}), concurrency=1, sleep=instant_sleep()
    )
    assert await loop.run_until_drained(max_scans=2) == 2
    assert control.completed == [1, 2]


async def test_a_failed_scan_is_acked_like_a_finished_one() -> None:
    control = FakeControlPlane([[AgentLease(scan_id=7)], []])
    loop = AgentLoop(
        control,
        name="a",
        executor=executor_of({7: RuntimeError("step blew up")}),
        concurrency=1,
        sleep=instant_sleep(),
    )
    await loop.run_until_drained()
    assert control.completed == [7]  # a failure is a terminal ack, not a retry


async def test_a_lost_lease_cancels_the_execution_and_never_acks() -> None:
    control = FakeControlPlane([[AgentLease(scan_id=5)]], renewals={5: False})
    started = asyncio.Event()

    async def slow_execute(lease: AgentLease) -> ExecutionResult:
        started.set()
        await asyncio.sleep(3600)
        return ExecutionResult(scan_id=lease.scan_id, status="completed")  # pragma: no cover

    loop = AgentLoop(
        control,
        name="a",
        executor=slow_execute,
        concurrency=1,
        heartbeat_interval_s=0.0,  # the first renewal fires immediately
        sleep=instant_sleep(),
    )
    await loop.run_one()
    assert control.completed == []  # no ack: the lease was lost, the scan aborted locally
    # The loop survives a lost lease — it is an operational event, not an agent death.
    assert loop.name == "a"


async def test_a_cancelled_execution_never_acks() -> None:
    """The agent-kill shape: the executor dies; the lease must stay abandoned."""
    control = FakeControlPlane([[AgentLease(scan_id=9)]])
    loop = AgentLoop(
        control,
        name="a",
        executor=executor_of({9: asyncio.CancelledError()}),
        concurrency=1,
        sleep=instant_sleep(),
    )
    with pytest.raises(asyncio.CancelledError):
        await loop.run_one()
    assert control.completed == []


async def test_a_cap_above_one_runs_the_leases_concurrently() -> None:
    control = FakeControlPlane(
        [[AgentLease(scan_id=1), AgentLease(scan_id=2)], []],
    )
    running: set[int] = set()
    max_concurrent = 0

    async def execute(lease: AgentLease) -> ExecutionResult:
        nonlocal max_concurrent
        running.add(lease.scan_id)
        max_concurrent = max(max_concurrent, len(running))
        await asyncio.sleep(0)
        running.discard(lease.scan_id)
        return ExecutionResult(scan_id=lease.scan_id, status="completed")

    loop = AgentLoop(control, name="a", executor=execute, concurrency=2, sleep=instant_sleep())
    await loop.run_until_drained()
    assert max_concurrent == 2
    assert sorted(control.completed) == [1, 2]


async def test_the_forever_loop_sleeps_when_the_queue_is_empty() -> None:
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= 2:  # stop the loop after two idle polls
            raise KeyboardInterrupt

    control = FakeControlPlane([[], []])
    loop = AgentLoop(
        control, name="a", executor=executor_of({}), concurrency=1, poll_interval_s=0.5, sleep=sleep
    )
    with pytest.raises(KeyboardInterrupt):
        await loop.run_forever()
    assert control.registered == "a"
    assert sleeps == [0.5, 0.5]
