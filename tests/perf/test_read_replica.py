"""Read-replica failover (REQ-SCALE-011).

The requirement is a behaviour, not a diagram: killing a replica must be **transparent to a
``GET`` endpoint**, the fallback must be logged and counted, and the consistency model must
be stated so a stale read is a documented choice rather than a surprise.

These tests cover all three. The first proves a healthy replica actually serves the read (a
router that silently used the primary would pass a "it still works" test while proving
nothing). The second kills the replica at the driver level — its database directory does not
exist, so opening a connection raises — and asserts the read still succeeds through the
primary, that the failure is counted and logged, and that a read-only endpoint built on the
router still answers 200.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.metrics import REGISTRY
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import Check
from arachne.data.replica import FAILOVER_METRIC, ReadReplicaRouter, ReplicaState


def _engine_with_schema(path: Path) -> Engine:
    engine = create_sqlite_engine(f"sqlite:///{path}")
    create_all(engine)
    return engine


def _dead_factory(tmp_path: Path) -> tuple[sessionmaker[Session], Engine]:
    """A replica that cannot answer: its database directory does not exist."""
    missing = tmp_path / "gone" / "replica.db"
    engine = create_engine(
        f"sqlite:///{missing}", connect_args={"check_same_thread": False}, future=True
    )
    return create_session_factory(engine), engine


def _metric_value(label: str) -> float:
    """The rendered value of the failover counter for one replica label (0 when absent)."""
    pattern = re.compile(rf'^{FAILOVER_METRIC}\{{replica="{re.escape(label)}"\}} (\S+)$', re.M)
    match = pattern.search(REGISTRY.render())
    return float(match.group(1)) if match else 0.0


def test_a_healthy_replica_serves_the_read(tmp_path: Path) -> None:
    primary_engine = _engine_with_schema(tmp_path / "primary.db")
    replica_engine = _engine_with_schema(tmp_path / "replica.db")
    primary = create_session_factory(primary_engine)
    replica = create_session_factory(replica_engine)
    with replica() as session:
        session.add(Check(module="M3", name="only-on-the-replica", version="1.0"))
        session.commit()

    router = ReadReplicaRouter(primary=primary, replicas=(ReplicaState("r1", replica),))
    with router.read_session() as session:
        assert session.get_bind() is replica_engine
        assert session.scalars(select(Check)).all()[0].name == "only-on-the-replica"
    assert router.stats()["degraded"] is False
    assert _metric_value("r1") == 0.0
    primary_engine.dispose()
    replica_engine.dispose()


def test_a_dead_replica_falls_back_to_the_primary_logged_and_counted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    primary_engine = _engine_with_schema(tmp_path / "primary.db")
    primary = create_session_factory(primary_engine)
    with primary() as session:
        session.add(Check(module="M3", name="only-on-the-primary", version="1.0"))
        session.commit()
    dead, dead_engine = _dead_factory(tmp_path)
    before = _metric_value("r1")

    router = ReadReplicaRouter(primary=primary, replicas=(ReplicaState("r1", dead),))
    with caplog.at_level("WARNING"):
        with router.read_session() as session:
            # Killing the replica is transparent: the caller gets a working session.
            assert session.get_bind() is primary_engine
            assert session.scalars(select(Check)).all()[0].name == "only-on-the-primary"

    stats = router.stats()
    assert stats["degraded"] is True
    assert stats["replicas"][0]["failures"] == 1
    assert "unable to open" in (stats["replicas"][0]["last_error"] or "")
    # Counted in metrics (the degradation is visible to a scrape).
    assert _metric_value("r1") == before + 1
    # Logged, with the replica named and the event a log query can find.
    assert any(
        record.message == "read replica unavailable; falling back to the primary"
        and getattr(record, "replica", None) == "r1"
        for record in caplog.records
    )
    primary_engine.dispose()
    dead_engine.dispose()


def test_a_dead_replica_is_not_reprobed_on_every_read(tmp_path: Path) -> None:
    primary_engine = _engine_with_schema(tmp_path / "primary.db")
    primary = create_session_factory(primary_engine)
    dead, dead_engine = _dead_factory(tmp_path)
    now = [100.0]
    state = ReplicaState("r1", dead)
    router = ReadReplicaRouter(
        primary=primary, replicas=(state,), cooldown_s=30.0, clock=lambda: now[0]
    )

    for _ in range(5):
        with router.read_session() as session:
            assert session.get_bind() is primary_engine
    assert state.failures == 1, "the cooldown must stop a dead replica being probed per read"

    now[0] += 31.0  # past the cooldown: try it again, once
    with router.read_session() as session:
        assert session.get_bind() is primary_engine
    assert state.failures == 2
    primary_engine.dispose()
    dead_engine.dispose()


def test_a_recovered_replica_is_used_again(tmp_path: Path) -> None:
    primary_engine = _engine_with_schema(tmp_path / "primary.db")
    replica_engine = _engine_with_schema(tmp_path / "replica.db")
    primary = create_session_factory(primary_engine)
    replica = create_session_factory(replica_engine)
    dead, dead_engine = _dead_factory(tmp_path)
    now = [0.0]
    state = ReplicaState("r1", dead)
    router = ReadReplicaRouter(
        primary=primary, replicas=(state,), cooldown_s=10.0, clock=lambda: now[0]
    )

    with router.read_session() as session:  # trips over the dead replica
        assert session.get_bind() is primary_engine
    assert state.healthy is False

    state.factory = replica  # the replica comes back
    now[0] += 11.0
    with router.read_session() as session:
        assert session.get_bind() is replica_engine
    assert state.healthy is True
    assert router.stats()["degraded"] is False
    primary_engine.dispose()
    replica_engine.dispose()
    dead_engine.dispose()


def test_a_read_only_endpoint_survives_a_killed_replica(tmp_path: Path) -> None:
    """``GET /api/v1/modules`` answers 200 with its read store backed by a dead replica."""
    from tests.helpers.api import ADMIN_KEY, auth, make_api_harness

    from arachne.data.api_store import ApiQueryStore

    harness = make_api_harness(tmp_path)
    dead, dead_engine = _dead_factory(tmp_path)
    router = ReadReplicaRouter(
        primary=harness.services.session_factory,
        replicas=(ReplicaState("r1", dead),),
    )
    try:
        harness.context.read_queries = ApiQueryStore(router)
        response = harness.client().get("/api/v1/modules", headers=auth(ADMIN_KEY))
        assert response.status_code == 200
        # The catalogue came from the primary and is complete.
        assert any(item["checks"] for item in response.json())
        assert router.stats()["degraded"] is True
        assert _metric_value("r1") >= 1
    finally:
        harness.close()
        dead_engine.dispose()


def test_a_replica_naming_the_primary_is_a_configuration_error(tmp_path: Path) -> None:
    from arachne.core.config import Settings
    from arachne.core.errors import ConfigurationError
    from arachne.data.services import _build_read_replicas

    url = f"sqlite:///{tmp_path / 'db.sqlite'}"
    settings = Settings(database_url=url, database_replica_urls=(url,))
    engine = create_sqlite_engine(url)
    factory = create_session_factory(engine)
    with pytest.raises(ConfigurationError, match="primary database"):
        _build_read_replicas(settings, factory)
    engine.dispose()


def test_the_router_with_no_replicas_is_the_primary(tmp_path: Path) -> None:
    engine = _engine_with_schema(tmp_path / "primary.db")
    factory = create_session_factory(engine)
    router = ReadReplicaRouter(primary=factory)
    with router.read_session() as session:
        assert session.get_bind() is engine
    assert router.stats()["degraded"] is False
    engine.dispose()


def test_a_broken_replica_raises_a_database_error_not_something_else(tmp_path: Path) -> None:
    """Guard: the dead fixture really is a driver-level failure, not a test artefact."""
    dead, dead_engine = _dead_factory(tmp_path)
    with pytest.raises(SQLAlchemyError):
        with dead() as session:
            session.connection()
    dead_engine.dispose()


def test_a_configured_replica_url_builds_a_router_and_is_disposed(tmp_path: Path) -> None:
    """The service-construction path: `ARACHNE_DATABASE_REPLICA_URLS` becomes a router."""
    from arachne.core.config import Settings
    from arachne.data.db import create_sqlite_engine
    from arachne.data.services import _build_read_replicas

    primary_url = f"sqlite:///{tmp_path / 'primary.db'}"
    replica_url = f"sqlite:///{tmp_path / 'replica.db'}"
    settings = Settings(database_url=primary_url, database_replica_urls=(replica_url, "", "  "))
    engine = create_sqlite_engine(primary_url)
    factory = create_session_factory(engine)
    try:
        router, replica_engines = _build_read_replicas(settings, factory)
        assert router is not None
        assert len(router.replicas) == 1, "blank entries must be skipped, not become replicas"
        assert router.replicas[0].name == "replica-1"
        assert len(replica_engines) == 1
        with router.read_session() as session:
            assert session.get_bind() in replica_engines
    finally:
        engine.dispose()
        for replica_engine in replica_engines:
            replica_engine.dispose()
