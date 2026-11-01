"""Alembic environment (F-09-02).

Two deliberate choices:

* The database URL comes from :mod:`arachne.core.config` (env var
  ``ARACHNE_DATABASE_URL``) unless the caller overrides ``sqlalchemy.url``
  programmatically — which is how tests point Alembic at a temporary file.
* ``target_metadata`` is the application's declarative metadata, so ``alembic revision
  --autogenerate`` and the drift test in ``tests/unit/test_migrations.py`` both compare
  against the real models rather than a copy.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from arachne.core.config import get_settings
from arachne.data.models import Base

config = context.config

if config.config_file_name is not None:
    # ``disable_existing_loggers=False`` matters: ``fileConfig`` defaults to disabling
    # every logger it does not mention, which silences ARACHNE's own loggers for the rest
    # of the process. ``arachne db upgrade`` exits immediately, but a long-lived host (the
    # API of a later stage migrating at startup) would lose its logs. The Alembic sections
    # of alembic.ini still configure Alembic's loggers as intended.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured
    return get_settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade head --sql``)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    # The engine is disposed explicitly: ``NullPool`` still hands the DBAPI connection to
    # the garbage collector, and an unclosed SQLite connection raises "Exception ignored
    # while finalizing database connection" at an unpredictable later moment (which a test
    # run turns into a warning attributed to an unrelated test).
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                compare_server_default=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
