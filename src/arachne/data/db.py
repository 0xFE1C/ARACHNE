"""Engine/session plumbing for the evidence store (F-09-02).

The database URL comes from :mod:`arachne.core.config` (env var
``ARACHNE_DATABASE_URL``, default: a SQLite file in the working directory). Session
handling is deliberately explicit — callers get a session from a factory and own its
transaction — so the orchestrator (S2) can keep scan state out of globals
(docs/spec/07- §4, "orchestration state lives in the store").
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.config import Settings, get_settings
from arachne.data.models import Base

__all__ = [
    "create_db_engine",
    "create_session_factory",
    "create_sqlite_engine",
    "session_scope",
]


def create_db_engine(
    url: str | None = None,
    *,
    echo: bool = False,
    settings: Settings | None = None,
) -> Engine:
    """Create an engine for ``url`` (defaults to the configured database URL)."""
    resolved = url or (settings or get_settings()).database_url
    if resolved.startswith("sqlite"):
        return create_sqlite_engine(resolved, echo=echo)
    return create_engine(resolved, echo=echo, pool_pre_ping=True, future=True)


def create_sqlite_engine(url: str, *, echo: bool = False) -> Engine:
    """Create a SQLite engine with the pragmas ARACHNE relies on.

    ``foreign_keys=ON`` is required for ``ondelete`` rules to work at all in SQLite;
    without it the FK constraints are decorative. ``check_same_thread=False`` is needed
    because the async HTTP client and workers may touch the store from another thread.
    """
    _ensure_sqlite_directory(url)
    engine = create_engine(
        url,
        echo=echo,
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
        finally:
            cursor.close()

    return engine


def _ensure_sqlite_directory(url: str) -> None:
    _, _, raw_path = url.partition("///")
    if not raw_path or raw_path == ":memory:":
        return
    parent = Path(raw_path).expanduser().parent
    if str(parent) not in {"", "."}:
        parent.mkdir(parents=True, exist_ok=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on failure."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine) -> None:
    """Create the schema directly from the models.

    Test-only convenience: production and CI use Alembic migrations
    (``alembic upgrade head``), which is the single source of truth for the schema.
    """
    Base.metadata.create_all(engine)
