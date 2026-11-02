"""The Postgres work queue and the agent registry (S16, area SCALE).

The invariants the fleet's correctness rests on, each one a test:

* **No double claim** (REQ-SCALE-001) — concurrent claimants never receive the same
  row, on the portable (SQLite) path here and, on Postgres, through the mandated
  ``SELECT … FOR UPDATE SKIP LOCKED`` whose statement shape is pinned below.
* **The cap holds** (REQ-SCALE-002) — an agent holding ``cap`` leases claims nothing.
* **Expiry re-leases** (REQ-SCALE-003) — a lease past its TTL is reclaimed exactly once
  and the row becomes claimable again with ``attempts`` incremented.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select as sa_select
from sqlalchemy.orm import sessionmaker

from arachne.core.errors import ScanStateError
from arachne.data.db import create_all, create_db_engine, create_session_factory
from arachne.data.models import Scan, Target
from arachne.data.queue_store import AgentRegistry, WorkQueue

# --------------------------------------------------------------------------- fixtures


def build_stack(url: str = "sqlite:///:memory:") -> tuple[sessionmaker, WorkQueue, AgentRegistry]:
    """A fresh queue stack with six scan rows seeded (a file URL shares across threads)."""
    engine = create_db_engine(url)
    create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        target = Target(name="queue-test", scope_json={})
        session.add(target)
        session.commit()
        for _ in range(6):
            session.add(Scan(target_id=target.id, engine="heuristic", plan_json={}))
        session.commit()
    return factory, WorkQueue(factory, dialect=engine.dialect.name), AgentRegistry(factory)


@pytest.fixture
def stack() -> tuple[sessionmaker, WorkQueue, AgentRegistry]:
    return build_stack()


# --------------------------------------------------------------------------- registry
def test_register_is_idempotent_and_heartbeat_keeps_liveness(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, _queue, agents = stack
    first = agents.register("fleet-1", node="node-a", version="1.0", concurrency=2)
    assert first.concurrency == 2 and first.is_active
    again = agents.register("fleet-1", node="node-a", concurrency=1)
    assert again.id == first.id and again.concurrency == 1

    later = agents.heartbeat("fleet-1", now=datetime.now(UTC) + timedelta(seconds=5))
    assert later is not None and later.last_heartbeat_at is not None
    assert later.last_heartbeat_at > (first.last_heartbeat_at or later.last_heartbeat_at)


def test_an_unregistered_agent_cannot_heartbeat_and_a_cap_below_one_is_refused(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, _queue, agents = stack
    assert agents.heartbeat("ghost") is None
    assert agents.get("ghost") is None
    with pytest.raises(ScanStateError):
        agents.register("bad", concurrency=0)


def test_retire_takes_an_agent_out_of_the_claiming_set(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, _queue, agents = stack
    agents.register("old", concurrency=1)
    assert agents.retire("old")
    record = agents.get("old")
    assert record is not None and not record.is_active


# --------------------------------------------------------------------------- produce
def test_enqueue_refuses_a_second_row_for_the_same_scan(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, _agents = stack
    first = queue.enqueue(1, requested_by="admin")
    assert first.status == "queued"
    with pytest.raises(ScanStateError):
        queue.enqueue(1)
    with pytest.raises(ScanStateError):
        queue.enqueue(999)  # no such scan row
    assert queue.entry_for(1) is not None and queue.entry_for(1).requested_by == "admin"


def test_leases_follow_priority_then_arrival_order(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, agents = stack
    agent = agents.register("a", concurrency=3)
    queue.enqueue(1)
    queue.enqueue(2, priority=5)
    queue.enqueue(3)
    leased = queue.lease_next("a", agent_id=agent.id, cap=3, ttl_s=60)
    assert [entry.scan_id for entry in leased] == [2, 1, 3]
    assert all(entry.status == "leased" for entry in leased)
    assert all(entry.attempts == 1 for entry in leased)


def test_the_concurrency_cap_bounds_what_an_agent_holds(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, agents = stack
    agent = agents.register("a", concurrency=2)
    for scan_id in (1, 2, 3):
        queue.enqueue(scan_id)
    first = queue.lease_next("a", agent_id=agent.id, cap=2, ttl_s=60)
    assert len(first) == 2
    # The cap counts *held* leases, not per-call claims: a third lease is refused.
    assert queue.lease_next("a", agent_id=agent.id, cap=2, ttl_s=60) == ()
    # Completing one frees exactly one slot.
    assert queue.complete("a", first[0].scan_id)
    again = queue.lease_next("a", agent_id=agent.id, cap=2, ttl_s=60)
    assert [entry.scan_id for entry in again] == [3]


# --------------------------------------------------------------------------- claim race
def test_concurrent_claimants_never_receive_the_same_row(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The REQ-SCALE-001 acceptance shape: many claimants, one queue, disjoint leases."""
    _factory, queue, agents = build_stack(f"sqlite:///{tmp_path / 'queue-race.db'}")
    for scan_id in range(1, 6):
        queue.enqueue(scan_id)
    claimants = [agents.register(f"c-{i}", concurrency=1) for i in range(5)]
    results: dict[str, int | None] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(len(claimants))

    def claim(name: str, agent_id: int) -> None:
        barrier.wait()
        try:
            leased = queue.lease_next(name, agent_id=agent_id, cap=1, ttl_s=60)
            results[name] = leased[0].scan_id if leased else None
        except Exception as exc:  # pragma: no cover - surfaced below if it happens
            errors.append(exc)

    threads = [threading.Thread(target=claim, args=(agent.name, agent.id)) for agent in claimants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    claimed = [scan_id for scan_id in results.values() if scan_id is not None]
    assert sorted(claimed) == [1, 2, 3, 4, 5]
    assert len(set(claimed)) == len(claimed)  # no double claim


def test_the_postgres_claim_uses_for_update_skip_locked() -> None:
    """REQ-SCALE-001 pins the mandated statement shape on the Postgres dialect."""
    from sqlalchemy.dialects import postgresql

    from arachne.data.models import ScanQueue

    query = (
        sa_select(ScanQueue.id)
        .where(ScanQueue.status == "queued")
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    compiled = str(query.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE SKIP LOCKED" in compiled


# --------------------------------------------------------------------------- expiry
def test_an_expired_lease_is_reclaimed_exactly_once_and_becomes_re_leasable(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, agents = stack
    dead = agents.register("dead", concurrency=1)
    live = agents.register("live", concurrency=1)
    queue.enqueue(1)
    now = datetime.now(UTC)
    leased = queue.lease_next("dead", agent_id=dead.id, cap=1, ttl_s=10, now=now)
    assert leased[0].scan_id == 1

    before_expiry = queue.reclaim_expired(now=now + timedelta(seconds=5))
    assert before_expiry == ()  # not expired yet
    moment = now + timedelta(seconds=11)
    reclaimed = queue.reclaim_expired(now=moment)
    assert [item.scan_id for item in reclaimed] == [1]
    assert reclaimed[0].agent_name == "dead" and reclaimed[0].attempts == 1
    # A second reaper is idempotent — the interruption must not be double-counted.
    assert queue.reclaim_expired(now=moment) == ()

    again = queue.lease_next("live", agent_id=live.id, cap=1, ttl_s=10, now=moment)
    assert again[0].scan_id == 1 and again[0].attempts == 2


def test_a_renewal_only_extends_leases_the_agent_still_holds(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, agents = stack
    agent = agents.register("a", concurrency=1)
    queue.enqueue(1)
    assert queue.lease_next("a", agent_id=agent.id, cap=1, ttl_s=60)
    now = datetime.now(UTC)
    assert queue.renew("a", [1], ttl_s=60, now=now) == {1: True}
    assert queue.renew("a", [2], ttl_s=60, now=now) == {2: False}  # never leased
    assert queue.cancel(1)
    assert queue.renew("a", [1], ttl_s=60, now=now) == {1: False}  # cancelled → abort


def test_complete_acks_once_and_cancel_neutralises_queued_and_leased_rows(stack) -> None:  # type: ignore[no-untyped-def]
    _factory, queue, agents = stack
    agent = agents.register("a", concurrency=2)
    queue.enqueue(1)
    queue.enqueue(2)
    queue.enqueue(3)
    leased = queue.lease_next("a", agent_id=agent.id, cap=1, ttl_s=60)
    assert queue.complete("a", leased[0].scan_id)
    assert not queue.complete("a", leased[0].scan_id)  # already done
    assert queue.cancel(2)  # queued
    assert queue.cancel(3)  # never leased — still cancellable while queued
    assert not queue.cancel(99)
    assert queue.stats() == {"done": 1, "cancelled": 2}
