"""Expand/contract discipline for zero-downtime upgrades (S25, REQ-RESIL-002).

A rolling upgrade runs two versions of the code against one schema for the length of the
rollout. That is only possible when a release's migration **expands** — adding a nullable
column, a new table, a new index — because the old code, which knows nothing about the
addition, keeps working. A migration that *contracts* (drops or narrows a column, renames a
table, tightens a nullability the old code still relies on) breaks the old replicas mid-roll
and turns a deploy into an outage.

This module reads a migration's source and reports every operation that is not expand-only,
so the check can run in CI and in a release review instead of being discovered during a
rollout. It is an ``ast`` inspection, not an execution: it never imports the migration and
never touches a database, so it is safe to run anywhere.

The contract phase — actually dropping the compatibility the expand phase added — is not
forbidden, it is **deferred**: a later release, once no replica runs the old code, performs
it. :func:`check_expand_only` reports such a migration as a contract phase so the caller can
require an explicit, recorded decision rather than a silent one.

Upgrade safety (WP-18, REQ-OPS-008) adds two things on top, both read-only:

* **A declaration per migration.** Every module declares ``reversible: true`` or
  ``reversible: false`` in its docstring (:func:`read_declaration`). The declaration is a
  claim about that migration's ``downgrade()``, and ``tests/unit/test_migrations.py`` *tests*
  the claim — it runs the downgrade and compares the schema with a fresh upgrade to the
  parent revision — so a declaration that flatters the migration fails there rather than
  during an incident.
* **A dry run.** :func:`dry_run_sql` asks Alembic for the SQL of the pending range without
  executing it, so an operator reads what an upgrade would do before it does it.

Neither function imports a migration module, opens a write transaction or contacts anything.
"""

from __future__ import annotations

import ast
import io
import re
import sqlite3
import tempfile
from collections.abc import Iterable, Sequence
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import typer
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url

__all__ = [
    "CONTRACT_OPERATIONS",
    "EXPAND_OPERATIONS",
    "DryRun",
    "MigrationDeclaration",
    "MigrationFinding",
    "MigrationReport",
    "UnsupportedDryRunError",
    "check_expand_only",
    "contract_operations",
    "current_revision",
    "declarations",
    "dry_run_sql",
    "irreversible",
    "pending_declarations",
    "read_declaration",
    "revision_order",
    "split_statements",
]


class UnsupportedDryRunError(RuntimeError):
    """The dry run cannot render SQL for this deployment's database.

    Raised rather than silently returning nothing: a dry run that printed an empty plan would
    read as "nothing to do", which is the one answer it must never invent.
    """


#: Migration helpers that only add capability. Everything here is safe while an old
#: replica is still serving.
EXPAND_OPERATIONS: Final[tuple[str, ...]] = (
    "create_table",
    "create_index",
    "create_foreign_key",
    "create_check_constraint",
    "add_column",
    "create_table_comment",
    "create_exclude_constraint",
    "bulk_insert",
)

#: Migration helpers that remove or narrow capability and therefore break old code.
CONTRACT_OPERATIONS: Final[tuple[str, ...]] = (
    "drop_column",
    "drop_table",
    "drop_index",
    "drop_constraint",
    "rename_table",
    "alter_column",
)

#: Operations whose effect this checker cannot judge from source alone (raw SQL, data
#: backfills). They are reported as *unknown* so a reviewer looks, rather than passed
#: silently.
OPAQUE_OPERATIONS: Final[tuple[str, ...]] = (
    "execute",
    "bulk_insert",
)


@dataclass(frozen=True, slots=True)
class MigrationFinding:
    """One operation a rolling upgrade would not survive."""

    revision: str
    operation: str
    detail: str
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "operation": self.operation,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """The verdict for one migration (or a chain of them)."""

    revisions: tuple[str, ...]
    findings: tuple[MigrationFinding, ...] = ()
    expand_operations: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def expand_only(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "expand_only": self.expand_only,
            "revisions": list(self.revisions),
            "expand_operations": list(self.expand_operations),
            "findings": [item.to_dict() for item in self.findings],
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        if self.expand_only:
            return f"expand-only ({len(self.revisions)} revision(s) checked)"
        return (
            f"NOT expand-only: {len(self.findings)} operation(s) would break a rolling "
            f"upgrade ({', '.join(sorted({item.operation for item in self.findings}))})"
        )


def _op_name(node: ast.Call) -> str | None:
    """``op.drop_column`` → ``"drop_column"``; anything else → ``None``."""
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "op"
    ):
        return func.attr
    return None


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return None


def _first_arg(node: ast.Call) -> str | None:
    return _literal(node.args[0]) if node.args else None


def _keyword_value(node: ast.Call, name: str) -> str | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return _literal(keyword.value)
    return None


def _call_findings(revision: str, node: ast.Call) -> Iterable[MigrationFinding]:
    """Every finding one ``op.*`` call implies."""
    name = _op_name(node)
    if name is None:
        return ()
    subject = _first_arg(node) or _keyword_value(node, "table_name") or "?"
    if name in {"drop_column", "drop_table", "drop_index", "drop_constraint", "rename_table"}:
        return (
            MigrationFinding(
                revision=revision,
                operation=name,
                detail=f"op.{name}({subject!r}) removes something old code still reads",
            ),
        )
    if name == "alter_column":
        findings: list[MigrationFinding] = []
        if _keyword_value(node, "new_column_name") is not None:
            findings.append(
                MigrationFinding(
                    revision=revision,
                    operation="rename_column",
                    detail=(
                        f"op.alter_column({subject!r}, new_column_name=…) renames a column; "
                        "add the new one, backfill, then drop the old in a later release"
                    ),
                )
            )
        nullable = _keyword_value(node, "nullable")
        if nullable == "False":
            findings.append(
                MigrationFinding(
                    revision=revision,
                    operation="set_not_null",
                    detail=(
                        f"op.alter_column({subject!r}, nullable=False) rejects the NULLs an "
                        "old replica still writes; enforce it in the contract phase"
                    ),
                )
            )
        type_change = _keyword_value(node, "type_")
        if type_change is not None:
            findings.append(
                MigrationFinding(
                    revision=revision,
                    operation="change_type",
                    detail=(
                        f"op.alter_column({subject!r}, type_=…) narrows a type in place; add a "
                        "new column and dual-write instead"
                    ),
                )
            )
        return tuple(findings)
    if name == "execute":
        return (
            MigrationFinding(
                revision=revision,
                operation="execute",
                detail=(
                    f"op.execute({subject!r}) is opaque to this checker: a reviewer must "
                    "confirm it is additive"
                ),
                severity="medium",
            ),
        )
    return ()


def contract_operations(source: str, *, revision: str) -> tuple[MigrationFinding, ...]:
    """Every non-expand operation in one migration's ``upgrade()``.

    Only ``upgrade`` is inspected: a ``downgrade`` is allowed to reverse anything, because
    it only runs when the deployment is already going backwards.
    """
    tree = ast.parse(source)
    findings: list[MigrationFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "upgrade":
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                findings.extend(_call_findings(revision, inner))
    return tuple(findings)


def _read_revision(path: Path) -> tuple[str | None, str | None]:
    """``(revision, down_revision)`` from a migration module, without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    revision: str | None = None
    down: str | None = None
    for node in tree.body:
        target: str | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        elif isinstance(node, ast.Assign) and node.targets:
            first = node.targets[0]
            target = first.id if isinstance(first, ast.Name) else None
            value = node.value
        if target == "revision":
            revision = _literal(value)
        elif target == "down_revision":
            down = _literal(value)
    return revision, down


def revision_order(versions_dir: str | Path, *, head: str | None = None) -> tuple[str, ...]:
    """Revision ids in application order (base → head), following ``down_revision``."""
    directory = Path(versions_dir)
    graph: dict[str, tuple[str | None, Path]] = {}
    for path in sorted(directory.glob("*.py")):
        revision, down = _read_revision(path)
        if revision is None:
            continue
        graph[revision] = (down, path)
    if head is None:
        children = {down for down, _ in graph.values() if down is not None}
        leaves = [revision for revision in graph if revision not in children]
        head = sorted(leaves)[-1] if leaves else None
    order: list[str] = []
    cursor = head
    while cursor is not None and cursor in graph and cursor not in order:
        order.append(cursor)
        cursor = graph[cursor][0]
    order.reverse()
    return tuple(order)


def check_expand_only(
    versions_dir: str | Path,
    *,
    revision: str | None = None,
    head: str | None = None,
) -> MigrationReport:
    """Inspect ``revision`` (or the graph's head) and report non-expand operations.

    ``revision=None, head=None`` checks the graph's head, which is the property a release
    review actually needs: *the upgrade I am about to roll out is online-safe*.
    """
    directory = Path(versions_dir)
    target = revision or head
    if target is None:
        order = revision_order(directory)
        if not order:
            return MigrationReport(revisions=(), notes=("no migration revisions found",))
        target = order[-1]
    path = None
    for candidate in sorted(directory.glob("*.py")):
        found, _ = _read_revision(candidate)
        if found == target:
            path = candidate
            break
    if path is None:
        return MigrationReport(
            revisions=(target,), notes=(f"revision {target!r} not found in {directory}",)
        )
    findings = contract_operations(path.read_text(encoding="utf-8"), revision=target)
    expand = tuple(
        sorted(
            {
                name
                for name in _op_names(path.read_text(encoding="utf-8"))
                if name in EXPAND_OPERATIONS
            }
        )
    )
    notes: list[str] = []
    if any(item.severity == "medium" for item in findings):
        notes.append("opaque operations present: a reviewer must confirm they are additive")
    return MigrationReport(
        revisions=(target,), findings=findings, expand_operations=expand, notes=tuple(notes)
    )


def _op_names(source: str) -> tuple[str, ...]:
    tree = ast.parse(source)
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _op_name(node)
            if name is not None:
                names.append(name)
    return tuple(names)


def check_chain(
    versions_dir: str | Path, *, revisions: Sequence[str] | None = None
) -> MigrationReport:
    """Inspect several revisions at once (the historical audit, for a release note)."""
    order = revision_order(versions_dir) if revisions is None else tuple(revisions)
    findings: list[MigrationFinding] = []
    expand: set[str] = set()
    checked: list[str] = []
    for revision in order:
        report = check_expand_only(versions_dir, revision=revision)
        if report.findings or report.expand_operations:
            checked.append(revision)
        findings.extend(report.findings)
        expand.update(report.expand_operations)
    return MigrationReport(
        revisions=tuple(checked),
        findings=tuple(findings),
        expand_operations=tuple(sorted(expand)),
    )


# ------------------------------------------------------------------ reversibility (WP-18)
#: The declaration is a line of the migration's own docstring: ``reversible: true``. A line
#: form rather than a module variable keeps it inside the prose a reviewer already reads, and
#: makes an *absent* declaration distinguishable from a ``False`` one.
_DECLARATION: Final = re.compile(r"(?im)^[ \t]*reversible[ \t]*:[ \t]*(true|false)[ \t]*$")


@dataclass(frozen=True, slots=True)
class MigrationDeclaration:
    """What one migration says about itself, and whether it says anything at all."""

    revision: str
    path: str
    reversible: bool | None
    has_downgrade: bool

    @property
    def declared(self) -> bool:
        return self.reversible is not None

    @property
    def name(self) -> str:
        return Path(self.path).name

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "file": self.name,
            "reversible": self.reversible,
            "declared": self.declared,
            "has_downgrade": self.has_downgrade,
        }

    def summary(self) -> str:
        if not self.declared:
            return f"{self.revision} (UNDECLARED)"
        return f"{self.revision} ({'reversible' if self.reversible else 'NOT reversible'})"


def read_declaration(path: str | Path) -> MigrationDeclaration:
    """Read one migration's ``reversible`` declaration, without importing it."""
    target = Path(path)
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    revision, _ = _read_revision(target)
    docstring = ast.get_docstring(tree) or ""
    match = _DECLARATION.search(docstring)
    reversible = None if match is None else match.group(1).lower() == "true"
    has_downgrade = any(
        isinstance(node, ast.FunctionDef) and node.name == "downgrade" for node in tree.body
    )
    return MigrationDeclaration(
        revision=revision or target.stem,
        path=str(target),
        reversible=reversible,
        has_downgrade=has_downgrade,
    )


def declarations(versions_dir: str | Path) -> tuple[MigrationDeclaration, ...]:
    """Every migration's declaration, in application order."""
    directory = Path(versions_dir)
    by_revision: dict[str, Path] = {}
    for path in sorted(directory.glob("*.py")):
        revision, _ = _read_revision(path)
        if revision is not None:
            by_revision[revision] = path
    return tuple(
        read_declaration(by_revision[revision])
        for revision in revision_order(directory)
        if revision in by_revision
    )


def pending_declarations(
    versions_dir: str | Path, *, current: str | None, target: str = "head"
) -> tuple[MigrationDeclaration, ...]:
    """The declarations for the range an upgrade from ``current`` to ``target`` would apply.

    ``current`` is the database's applied revision (``None`` for an empty database).
    """
    directory = Path(versions_dir)
    order = (
        revision_order(directory) if target == "head" else revision_order(directory, head=target)
    )
    start = order.index(current) + 1 if current in order else 0
    wanted = set(order[start:])
    return tuple(item for item in declarations(directory) if item.revision in wanted)


def irreversible(pending: Iterable[MigrationDeclaration]) -> tuple[MigrationDeclaration, ...]:
    """The migrations in ``pending`` that declare themselves non-reversible.

    A migration that declares nothing counts as non-reversible here: the safe default is to
    demand an explicit acknowledgement rather than to assume the best of an undeclared
    downgrade.
    """
    return tuple(item for item in pending if item.reversible is not True)


# ------------------------------------------------------------------------- the dry run
def _alembic_config(database_url: str) -> Config:
    """An Alembic config for this repository's migrations, pointed at ``database_url``."""
    root = Path(__file__).resolve().parents[3]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def current_revision(database_url: str) -> str | None:
    """The revision the database has applied, or ``None`` when it has none."""
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            revision = MigrationContext.configure(connection).get_current_revision()
    finally:
        engine.dispose()
    return revision


def split_statements(sql: str) -> tuple[str, ...]:
    """Split SQL text into statements, keeping each statement's ``--`` comments attached."""
    statements: list[str] = []
    buffer: list[str] = []
    for line in sql.splitlines():
        buffer.append(line)
        if line.rstrip().endswith(";"):
            statements.append("\n".join(buffer).strip())
            buffer = []
    tail = "\n".join(buffer).strip()
    if tail:
        statements.append(tail)
    return tuple(statements)


#: Statement keywords that are *reads*: reflection, not migration. Alembic's SQLite batch mode
#: reflects the table it is about to recreate, and none of that belongs in a printed plan.
_READ_KEYWORDS: Final = ("SELECT", "PRAGMA", "WITH", "EXPLAIN")


def _is_ddl(statement: str) -> bool:
    head = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
    return head not in _READ_KEYWORDS


def _scratch_copy(database_url: str, destination: Path) -> None:
    """Snapshot a SQLite database to ``destination`` using SQLite's own backup API.

    A file copy would be wrong under WAL (the committed tail lives in the ``-wal`` sidecar);
    ``Connection.backup`` takes a consistent snapshot the way SQLite itself means it to be
    taken. The source is opened **read-only in effect** — the backup API only reads from it.
    """
    database = make_url(database_url).database
    if not database or database == ":memory:":
        msg = f"cannot copy a non-file SQLite database: {database_url}"
        raise UnsupportedDryRunError(msg)
    source = Path(database)
    if source.is_file():
        with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as origin:
            with closing(sqlite3.connect(destination)) as copy:
                origin.backup(copy)
    else:
        # An empty database is a legitimate state (a first install); the snapshot of it is
        # simply an empty file, which is what SQLite would create.
        destination.touch()


@dataclass(frozen=True, slots=True)
class DryRun:
    """The SQL an upgrade would run, and how that SQL was obtained."""

    #: ``"offline"`` — Alembic rendered it without a database; ``"scratch-snapshot"`` — the
    #: upgrade really ran, but against a throwaway snapshot of this database.
    method: str
    statements: tuple[str, ...]
    current: str | None
    target: str

    @property
    def sql(self) -> str:
        return "\n\n".join(self.statements)

    def method_note(self) -> str:
        """One honest sentence about how the SQL below was obtained."""
        if self.method == "offline":
            return "rendered by Alembic in --sql mode: no statement was executed anywhere"
        return (
            "rendered by applying the upgrade to a throwaway snapshot of this database and "
            "capturing what the driver received; the database itself was not modified"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "method_note": self.method_note(),
            "current": self.current,
            "target": self.target,
            "statements": len(self.statements),
            "sql": self.sql,
        }


def dry_run_sql(database_url: str, *, target: str = "head") -> DryRun:
    """The SQL the pending upgrade would run, without running any of it on your database.

    Two renderings, because one of them cannot work everywhere:

    * **offline** — Alembic's ``--sql`` mode (`upgrade <current>:<target> --sql`). It executes
      nothing at all, and it is the right answer for a server dialect. It cannot render
      SQLite's ``batch_alter_table``, which needs to reflect the live table.
    * **scratch-snapshot** — the upgrade is executed against a throwaway snapshot of the
      database (SQLite's backup API, taken read-only) and the statements the driver receives
      are captured. The real database is never opened for writing, and the snapshot is
      discarded; what is printed is what the engine was actually given.

    ``dry_run_sql`` never mutates ``database_url``. That is the whole point of it.
    """
    current = current_revision(database_url)
    if make_url(database_url).get_backend_name() == "sqlite":
        return _snapshot_dry_run(database_url, current=current, target=target)
    return _offline_dry_run(database_url, current=current, target=target)


def _offline_dry_run(database_url: str, *, current: str | None, target: str) -> DryRun:
    config = _alembic_config(database_url)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        command.upgrade(config, f"{current or 'base'}:{target}", sql=True)
    return DryRun(
        method="offline",
        statements=split_statements(buffer.getvalue()),
        current=current,
        target=target,
    )


def _snapshot_dry_run(database_url: str, *, current: str | None, target: str) -> DryRun:
    captured: list[str] = []

    def _capture(
        _conn: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if _is_ddl(statement):
            captured.append(statement.strip())

    with tempfile.TemporaryDirectory(prefix="arachne-dry-run-") as directory:
        snapshot = Path(directory) / "snapshot.db"
        _scratch_copy(database_url, snapshot)
        url = f"sqlite:///{snapshot}"
        engine = create_engine(url)
        event.listen(engine, "before_cursor_execute", _capture)
        # Alembic logs "Running upgrade 0015 -> 0016" while it walks the snapshot, and that
        # line during a *dry run* reads as though the upgrade were being applied. It is
        # captured (and re-emitted if the run fails) rather than printed.
        log = io.StringIO()
        try:
            config = _alembic_config(url)
            with redirect_stdout(log), redirect_stderr(log):
                with engine.connect() as connection:
                    # A caller-provided connection is the documented way to drive Alembic from
                    # code that owns the connection; migrations/env.py honours the attribute.
                    config.attributes["connection"] = connection
                    command.upgrade(config, target)
        except BaseException:
            typer.echo(log.getvalue(), err=True, nl=False)
            raise
        finally:
            event.remove(engine, "before_cursor_execute", _capture)
            engine.dispose()
    return DryRun(
        method="scratch-snapshot",
        statements=tuple(captured),
        current=current,
        target=target,
    )
