"""Migration tests (F-09-02): migrations apply, reverse, and match the models.

``alembic upgrade head`` on a fresh SQLite file is a documented acceptance criterion for
this stage, so it is asserted here rather than only in CI.

WP-18 (REQ-OPS-008) adds the upgrade-safety half: every migration declares whether it is
reversible and the declaration is *tested* against the downgrade; ``db upgrade --dry-run``
prints the SQL and changes nothing; a migration that does not declare itself reversible is
refused without an explicit acknowledgement; and an upgrade from two versions back succeeds
on a database that already holds rows.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.data.models import AuditLog, Base, Finding, Scan, Target
from arachne.data.schema import ALEMBIC_VERSION_TABLE, LATEST_SCHEMA_REVISION, TABLE_NAMES
from arachne.resil.migrations import (
    MigrationDeclaration,
    declarations,
    dry_run_sql,
    irreversible,
    pending_declarations,
)

#: The tables the populated-upgrade test seeds and counts.
MODELS = (Target, Scan, Finding, AuditLog)

CODE_ROOT = Path(__file__).resolve().parents[2]
VERSIONS = CODE_ROOT / "migrations" / "versions"
#: The fixture tree holding a migration that declares itself non-reversible and one that
#: declares nothing, so the refusal path is exercised on real files rather than on a stub.
NON_REVERSIBLE_FIXTURE = CODE_ROOT / "tests" / "fixtures" / "migrations-nonreversible" / "versions"

#: The release before the two most recent migrations: the "two versions back" starting point
#: of the populated upgrade.
TWO_VERSIONS_BACK = "0016"

runner = CliRunner()


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


# ------------------------------------------------------- reversibility declarations (WP-18)
def schema_fingerprint(database_url: str) -> set[tuple[str, tuple[str, ...]]]:
    """Every table and its column names — the shape a downgrade has to restore."""
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        return {
            (name, tuple(sorted(column["name"] for column in inspector.get_columns(name))))
            for name in inspector.get_table_names()
            if name != ALEMBIC_VERSION_TABLE
        }
    finally:
        engine.dispose()


def test_every_migration_declares_whether_it_is_reversible() -> None:
    """REQ-OPS-008: the declaration is mandatory, not optional prose."""
    config = alembic_config("sqlite://")
    scripted = list(ScriptDirectory.from_config(config).walk_revisions())
    items = declarations(VERSIONS)
    assert len(items) == len(scripted), "the declaration reader missed a migration"
    undeclared = [item.revision for item in items if not item.declared]
    assert undeclared == [], f"migrations with no `reversible:` line: {undeclared}"


def test_every_declaration_is_backed_by_a_downgrade() -> None:
    missing = [item.revision for item in declarations(VERSIONS) if not item.has_downgrade]
    assert missing == [], f"migrations that declare reversibility with no downgrade(): {missing}"


def test_the_reversible_declarations_reflect_reality(tmp_path: Path) -> None:
    """The declaration is a claim about the downgrade; this is where the claim is tested.

    For every revision that declares itself reversible, the downgrade is *run* and the
    resulting schema is compared with a fresh upgrade to the parent revision. A migration
    that declared reversibility optimistically fails here, in CI, instead of during a
    rollback — which is the only moment a downgrade ever matters.
    """
    items = declarations(VERSIONS)
    order = [item.revision for item in items]
    claimed = {item.revision for item in items if item.reversible}
    assert order, "no migrations found"
    for index, revision in enumerate(order):
        if revision not in claimed:
            continue
        parent = order[index - 1] if index else None
        rolled_back = f"sqlite:///{tmp_path / f'rolled-{revision}.db'}"
        command.upgrade(alembic_config(rolled_back), revision)
        command.downgrade(alembic_config(rolled_back), parent or "base")
        expected = f"sqlite:///{tmp_path / f'expected-{revision}.db'}"
        if parent:
            command.upgrade(alembic_config(expected), parent)
        assert schema_fingerprint(rolled_back) == schema_fingerprint(expected), (
            f"{revision} declares reversible: true but its downgrade does not restore the "
            f"{parent or 'empty'} schema"
        )


def test_a_non_reversible_migration_is_detected_in_a_real_tree() -> None:
    """The fixture tree declares one non-reversible migration and one that declares nothing."""
    items = {item.revision: item for item in declarations(NON_REVERSIBLE_FIXTURE)}
    assert items["9001"].reversible is False
    assert items["9002"].reversible is None
    pending = pending_declarations(NON_REVERSIBLE_FIXTURE, current=None)
    assert [item.revision for item in pending] == ["9001", "9002"]
    # An *absent* declaration counts as non-reversible: the safe default is to ask.
    assert [item.revision for item in irreversible(pending)] == ["9001", "9002"]


def test_an_empty_pending_range_blocks_nothing() -> None:
    assert irreversible(pending_declarations(VERSIONS, current=LATEST_SCHEMA_REVISION)) == ()


def _blocking_pair() -> tuple[MigrationDeclaration, ...]:
    """The fixture's two declarations, reached through the same reader the CLI uses."""
    return irreversible(pending_declarations(NON_REVERSIBLE_FIXTURE, current=None))


def test_db_upgrade_refuses_a_non_reversible_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQ-OPS-008: no acknowledgement, no upgrade — and nothing is attempted.

    The declarations are the fixture's (real files, real parsing); only the directory lookup
    is substituted, because the shipped tree has no non-reversible migration to refuse.
    """
    monkeypatch.setattr("arachne.cli.main.pending_declarations", lambda *a, **k: _blocking_pair())
    calls: list[Any] = []
    monkeypatch.setattr("arachne.cli.main.command.upgrade", lambda *a, **k: calls.append(a))
    result = runner.invoke(
        app, ["db", "upgrade", "--database-url", f"sqlite:///{tmp_path / 'x.db'}"]
    )
    assert result.exit_code == 1, result.output
    assert "REFUSED" in result.output
    assert "9001" in result.output
    assert calls == [], "the upgrade was attempted despite the refusal"


def test_db_upgrade_proceeds_with_allow_destructive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("arachne.cli.main.pending_declarations", lambda *a, **k: _blocking_pair())
    calls: list[Any] = []
    monkeypatch.setattr("arachne.cli.main.command.upgrade", lambda *a, **k: calls.append(a))
    result = runner.invoke(
        app,
        [
            "db",
            "upgrade",
            "--allow-destructive",
            "--database-url",
            f"sqlite:///{tmp_path / 'x.db'}",
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1, "the upgrade did not run with the acknowledgement given"


def test_db_migrations_check_reports_every_declaration() -> None:
    result = runner.invoke(app, ["db", "migrations", "--check"])
    assert result.exit_code == 0, result.output
    assert f"ok: {len(declarations(VERSIONS))} migration(s)" in result.output


# ---------------------------------------------------------------------- the dry run (WP-18)
def test_the_dry_run_prints_sql_and_changes_nothing(database_url: str) -> None:
    """REQ-OPS-008: `db upgrade --dry-run` prints the SQL that would run."""
    command.upgrade(alembic_config(database_url), TWO_VERSIONS_BACK)
    before = schema_fingerprint(database_url)
    result = runner.invoke(
        app, ["db", "upgrade", "--dry-run", "--json", "--database-url", database_url]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    printed = "\n".join(payload["statements"])
    assert "provenance" in printed, printed
    assert "provisioned_principals" in printed, printed
    assert [item["revision"] for item in payload["pending"]] == ["0017", "0018"]
    # Nothing ran: the schema and the applied revision are exactly what they were.
    assert schema_fingerprint(database_url) == before
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision() == TWO_VERSIONS_BACK
            )
    finally:
        engine.dispose()


def test_the_dry_run_is_empty_at_head(migrated: str) -> None:
    run = dry_run_sql(migrated)
    assert run.statements == ()
    assert run.sql == ""


def test_the_dry_run_says_how_the_sql_was_obtained(database_url: str) -> None:
    """An operator must be able to tell a rendering from an execution."""
    command.upgrade(alembic_config(database_url), TWO_VERSIONS_BACK)
    run = dry_run_sql(database_url)
    assert run.method in {"offline", "scratch-snapshot"}
    if run.method == "scratch-snapshot":
        assert "not modified" in run.method_note()
    assert run.current == TWO_VERSIONS_BACK


def test_the_dry_run_reports_reversibility_per_migration(database_url: str) -> None:
    result = runner.invoke(
        app, ["db", "upgrade", "--dry-run", "--json", "--database-url", database_url]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["current"] is None
    assert [item["revision"] for item in payload["pending"]] == [
        item.revision for item in declarations(VERSIONS)
    ]
    assert all(item["reversible"] is True for item in payload["pending"])
    assert payload["requires_allow_destructive"] is False
    assert payload["statements"], "the dry run printed no SQL for an empty database"


# ------------------------------------------------- the populated upgrade (WP-18, REQ-OPS-008)
def _seed(database_url: str, *, name: str) -> dict[str, int]:
    """Write a small estate through the ORM: a target, a scan, a finding and audit rows."""
    engine = create_engine(database_url)
    factory = sessionmaker(bind=engine)
    try:
        with factory.begin() as session:
            target = Target(name=name, scope_json={"hosts": ["legacy.example.net"]})
            session.add(target)
            session.flush()
            scan = Scan(target_id=target.id, status="completed")
            session.add(scan)
            session.flush()
            session.add(Finding(scan_id=scan.id, title="legacy finding", status="open"))
            for action in ("scan.admitted", "scan.completed"):
                session.add(
                    AuditLog(
                        ts=datetime.now(UTC),
                        actor="legacy-operator",
                        action=action,
                        meta_json={"scan_id": scan.id},
                    )
                )
        with factory() as session:
            return {
                model.__tablename__: len(list(session.scalars(select(model)))) for model in MODELS
            }
    finally:
        engine.dispose()


def _rows(database_url: str) -> dict[str, int]:
    engine = create_engine(database_url)
    factory = sessionmaker(bind=engine)
    try:
        with factory() as session:
            return {
                model.__tablename__: len(list(session.scalars(select(model)))) for model in MODELS
            }
    finally:
        engine.dispose()


def test_an_upgrade_from_two_versions_back_succeeds_on_a_populated_database(
    database_url: str,
) -> None:
    """The expensive incident class: a real upgrade on a database that already holds rows.

    The estate is written at the current release, the schema is rolled back to the revision
    two steps behind head, and the upgrade then runs against rows that are already there —
    which is the shape of a release rollout, not of a fresh install.
    """
    command.upgrade(alembic_config(database_url), "head")
    before = _seed(database_url, name="legacy-estate")

    command.downgrade(alembic_config(database_url), TWO_VERSIONS_BACK)
    engine = create_engine(database_url)
    try:
        # The rollback really did contract the schema the upgrade is about to expand: the two
        # additive changes above this revision are gone.
        assert "provenance" not in {c["name"] for c in inspect(engine).get_columns("analysis_log")}
        assert "provisioned_principals" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()

    command.upgrade(alembic_config(database_url), "head")

    engine = create_engine(database_url)
    try:
        columns = {c["name"] for c in inspect(engine).get_columns("scans")}
        assert {"residue_hash", "residue_attestation"} <= columns
        assert "provenance" in {c["name"] for c in inspect(engine).get_columns("analysis_log")}
        assert {"provisioned_principals", "provisioned_groups"} <= set(
            inspect(engine).get_table_names()
        )
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == LATEST_SCHEMA_REVISION
            )
        assert _rows(database_url) == before, "the upgrade lost or duplicated rows"
        factory = sessionmaker(bind=engine)
        with factory() as session:
            names = list(session.scalars(select(Target.name)))
        assert "legacy-estate" in names, "the pre-upgrade rows were not preserved"
    finally:
        engine.dispose()
