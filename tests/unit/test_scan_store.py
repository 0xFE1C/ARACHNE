"""The SQLite-backed scan store (F-01-04, F-09-02)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from tests.conftest import build_scan_request

from arachne.core.errors import ScanStateError
from arachne.core.lifecycle import ScanStatus, StepState, StepStatus
from arachne.core.planner import ScanStep
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import Target
from arachne.data.scan_store import SqlScanStateStore, as_utc
from arachne.data.target_store import SqlTargetStore


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    created = create_sqlite_engine(f"sqlite:///{tmp_path / 'store.db'}")
    create_all(created)
    try:
        yield created
    finally:
        created.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def store(factory: sessionmaker[Session]) -> SqlScanStateStore:
    return SqlScanStateStore(factory)


@pytest.fixture
def target_id(factory: sessionmaker[Session]) -> int:
    """A persisted target row: the schema requires every scan to reference one."""
    with factory() as session:
        target = Target(name="t", scope_json={}, auth_attestation=None)
        session.add(target)
        session.commit()
        return int(target.id)


def test_create_and_read_a_scan(store: SqlScanStateStore, target_id: int) -> None:
    created = store.create_scan(
        target_id=target_id, engine="heuristic", plan={"target_name": "t"}, stats={"a": 1}
    )
    assert created.id
    assert created.status is ScanStatus.PENDING
    assert created.target_id == target_id

    loaded = store.get_scan(created.id)
    assert loaded is not None
    assert loaded.plan == {"target_name": "t"}
    assert loaded.stats == {"a": 1}
    assert loaded.created_at is not None and loaded.created_at.tzinfo is UTC


def test_get_scan_returns_none_for_an_unknown_id(store: SqlScanStateStore) -> None:
    assert store.get_scan(999) is None


def test_update_scan_sets_status_and_timestamps(store: SqlScanStateStore, target_id: int) -> None:
    created = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    started = store.update_scan(created.id, status=ScanStatus.RUNNING, mark_started=True)
    assert started.status is ScanStatus.RUNNING
    assert started.started_at is not None
    assert started.finished_at is None

    finished = store.update_scan(created.id, status=ScanStatus.COMPLETED, mark_finished=True)
    assert finished.finished_at is not None
    assert finished.started_at == started.started_at  # start is not overwritten


def test_step_state_is_upserted_per_step(store: SqlScanStateStore, target_id: int) -> None:
    created = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    store.save_step(
        created.id,
        StepState(step=ScanStep.RECON, status=StepStatus.RUNNING, attempts=1, stats={"n": 1}),
    )
    store.save_step(
        created.id,
        StepState(
            step=ScanStep.RECON,
            status=StepStatus.COMPLETED,
            attempts=1,
            stats={"n": 2},
            finished_at=datetime.now(UTC),
        ),
    )

    loaded = store.get_scan(created.id)
    assert loaded is not None
    assert len(loaded.steps) == 1  # updated, not appended
    state = loaded.step_state(ScanStep.RECON)
    assert state is not None
    assert state.status is StepStatus.COMPLETED
    assert state.stats == {"n": 2}


def test_multiple_steps_keep_their_pipeline_identity(
    store: SqlScanStateStore, target_id: int
) -> None:
    created = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    for step in (ScanStep.RECON, ScanStep.DISCOVERY, ScanStep.CHECKS):
        store.save_step(created.id, StepState(step=step, status=StepStatus.COMPLETED, attempts=1))
    loaded = store.get_scan(created.id)
    assert loaded is not None
    assert loaded.completed_steps == (ScanStep.RECON, ScanStep.DISCOVERY, ScanStep.CHECKS)
    assert loaded.next_step() is ScanStep.ANALYSIS


def test_assets_are_stored_and_listed_in_insertion_order(
    store: SqlScanStateStore, target_id: int
) -> None:
    created = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    store.add_asset(created.id, kind="host", value="a.example")
    store.add_asset(created.id, kind="url", value="https://a.example/", meta={"source": "recon"})

    assets = store.list_assets(created.id)
    assert [asset.value for asset in assets] == ["a.example", "https://a.example/"]
    assert assets[1].meta == {"source": "recon"}


def test_operations_on_an_unknown_scan_raise(store: SqlScanStateStore) -> None:
    with pytest.raises(ScanStateError):
        store.update_scan(999, status=ScanStatus.RUNNING)
    with pytest.raises(ScanStateError):
        store.save_step(999, StepState(step=ScanStep.RECON))
    with pytest.raises(ScanStateError):
        store.add_asset(999, kind="host", value="x")


def test_deleting_a_scan_cascades_to_its_steps_and_assets(
    store: SqlScanStateStore, factory: sessionmaker[Session], target_id: int
) -> None:
    from sqlalchemy import select

    from arachne.data.models import Asset, Scan, ScanStepRecord

    created = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    store.save_step(created.id, StepState(step=ScanStep.RECON, status=StepStatus.RUNNING))
    store.add_asset(created.id, kind="host", value="a.example")

    with factory() as session:
        session.delete(session.get(Scan, created.id))
        session.commit()
        assert session.scalars(select(ScanStepRecord)).all() == []
        assert session.scalars(select(Asset)).all() == []


def test_list_scans_returns_the_newest_first(store: SqlScanStateStore, target_id: int) -> None:
    first = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    second = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    assert [record.id for record in store.list_scans()] == [second.id, first.id]
    assert [record.id for record in store.list_scans(limit=1)] == [second.id]


def test_naive_database_timestamps_are_re_attached_to_utc() -> None:
    """ADR-050.6/060.4: SQLite returns naive values; the repository boundary fixes it."""
    assert as_utc(None) is None
    naive = datetime(2026, 1, 1, 12, 0)
    assert as_utc(naive) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    aware = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert as_utc(aware) is aware


# ------------------------------------------------------------------ target store
def test_target_store_saves_and_reuses_the_same_definition(
    factory: sessionmaker[Session],
) -> None:
    store = SqlTargetStore(factory)
    request = build_scan_request()
    first = store.save(request.target)
    second = store.save(request.target)

    assert first == second  # same name + scope reuses the row
    with factory() as session:
        assert len(session.query(Target).all()) == 1


def test_target_store_keeps_distinct_scopes_apart(factory: sessionmaker[Session]) -> None:
    store = SqlTargetStore(factory)
    one = store.save(build_scan_request(name="same").target)
    two = store.save(
        build_scan_request(name="same", targets=[{"kind": "domain", "value": "example.com"}]).target
    )
    assert one != two
    with factory() as session:
        assert len(session.query(Target).all()) == 2


def test_target_store_round_trips_the_attestation(factory: sessionmaker[Session]) -> None:
    store = SqlTargetStore(factory)
    store.save(build_scan_request().target)
    with factory() as session:
        target = session.query(Target).one()
        assert target.auth_attestation is not None
        assert target.auth_attestation["authorization_ref"] == "TEST-1"
        assert target.auth_attestation["attested_at"].startswith("2026-10-01")
        assert target.scope_json["targets"][0]["kind"] == "url"
