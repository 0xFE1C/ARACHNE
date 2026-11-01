"""Migration tests (F-09-02): migrations apply, reverse, and match the models.

``alembic upgrade head`` on a fresh SQLite file is a documented acceptance criterion for
this stage, so it is asserted here rather than only in CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from arachne.data.models import Base
from arachne.data.schema import ALEMBIC_VERSION_TABLE, LATEST_SCHEMA_REVISION, TABLE_NAMES

CODE_ROOT = Path(__file__).resolve().parents[2]


def alembic_config(database_url: str) -> Config:
    config = Config(str(CODE_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(CODE_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'migrated.db'}"


@pytest.fixture
def migrated(database_url: str) -> str:
    command.upgrade(alembic_config(database_url), "head")
    return database_url


def test_upgrade_head_creates_the_spec_schema(migrated: str) -> None:
    engine = create_engine(migrated)
    try:
        tables = set(inspect(engine).get_table_names())
        assert set(TABLE_NAMES) <= tables
        assert ALEMBIC_VERSION_TABLE in tables
    finally:
        engine.dispose()


def test_upgrade_head_records_the_expected_revision(migrated: str) -> None:
    engine = create_engine(migrated)
    try:
        with engine.connect() as connection:
            applied = MigrationContext.configure(connection).get_current_revision()
    finally:
        engine.dispose()

    head = ScriptDirectory.from_config(alembic_config(migrated)).get_current_head()
    assert applied == LATEST_SCHEMA_REVISION
    assert head == LATEST_SCHEMA_REVISION


def test_migrations_can_be_reversed(migrated: str) -> None:
    command.downgrade(alembic_config(migrated), "base")

    engine = create_engine(migrated)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert not (set(TABLE_NAMES) & tables)


def test_applied_schema_matches_the_models(migrated: str) -> None:
    """No drift between the migration and ``Base.metadata`` (the autogenerate gate)."""
    engine = create_engine(migrated)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True, "compare_server_default": True}
            )
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], f"migration/model drift detected: {diff}"


def test_upgrade_is_idempotent(migrated: str) -> None:
    command.upgrade(alembic_config(migrated), "head")  # second run must be a no-op
    engine = create_engine(migrated)
    try:
        assert set(TABLE_NAMES) <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_foreign_keys_are_declared_with_cascades(migrated: str) -> None:
    engine = create_engine(migrated)
    try:
        inspector = inspect(engine)
        scan_fks = inspector.get_foreign_keys("scans")
        assert any(fk["referred_table"] == "targets" for fk in scan_fks)
        assert scan_fks[0]["options"].get("ondelete") == "CASCADE"
    finally:
        engine.dispose()
