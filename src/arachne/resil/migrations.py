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
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

__all__ = [
    "CONTRACT_OPERATIONS",
    "EXPAND_OPERATIONS",
    "MigrationFinding",
    "MigrationReport",
    "check_expand_only",
    "contract_operations",
    "revision_order",
]

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
