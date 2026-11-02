"""The pure patch engine: a fix plan plus a repo tree → a unified diff (S27, REQ-FIX-001).

Nothing here touches git, the network, the database or the audit trail: the engine reads
the files the finding's evidence names, applies the plan's edits **in memory**, and returns
the before/after pair for each file. That is what makes the artifact reviewable before any
effect — a proposal is a diff an operator reads, and the human approval gate sits between
this module and every write anywhere.

Path discipline is the whole of the safety here, so it is stated once and tested directly:

* a target path is resolved from the finding's evidence, never from a plan — a plan selects
  *which* of the evidence paths it accepts (its ``globs``), it never invents one;
* the resolved path must be inside the authorized repo root **after** ``resolve()`` (so a
  symlink cannot walk out of the tree) and must be a regular file;
* a file outside the root, a missing file, a file that does not match the plan, and a file
  the plan leaves unchanged are all *skipped with a reason*, never silently patched.
"""

from __future__ import annotations

import difflib
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from arachne.core.errors import ConfigurationError
from arachne.fix.plans import EditOp, FixPlan

__all__ = [
    "FileEdit",
    "PlanApplication",
    "apply_plan",
    "diff_stats",
    "render_diff",
    "repo_root_of",
    "resolve_targets",
    "strip_location",
]

#: How many files one proposal may touch, and how large a file it may edit. Bounded so a
#: mis-authored plan cannot turn a review into a whole-repo rewrite.
MAX_TARGET_FILES: Final = 12
MAX_TARGET_BYTES: Final = 262144

_LOCAL_PREFIXES: Final = ("repo:", "path:", "file:", "dir:", "local:")


def repo_root_of(asset_value: str) -> Path | None:
    """The local repository directory an asset value names, or ``None`` (a remote ref).

    Mirrors the M5 review's own resolution (``repo:/path``, ``file:///path``, a bare path);
    a remote ``git@host:org/repo`` or ``https://…`` reference has no local tree, so a fix
    can never be proposed against one.
    """
    value = asset_value.strip()
    lowered = value.lower()
    parts = value.partition(":")
    if parts[1] and f"{parts[0].lower()}:" in _LOCAL_PREFIXES:
        value = parts[2]
    elif parts[1] and "://" not in lowered and not value.startswith("/"):
        return None
    if value.lower().startswith("file://"):
        value = value[len("file://") :]
    if "://" in value or re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:", value):
        return None
    root = Path(value).expanduser()
    try:
        return root.resolve() if root.exists() else None
    except OSError:  # pragma: no cover - unreachable path shape
        return None


def strip_location(location: str) -> str:
    """``deploy.yaml#spec/template/spec`` → ``deploy.yaml`` (the file half of a location)."""
    return location.split("#", 1)[0].strip()


def resolve_targets(
    root: Path,
    locations: tuple[str, ...],
    *,
    globs: tuple[str, ...] = (),
    max_files: int = MAX_TARGET_FILES,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve evidence locations to repo-relative files.

    Returns ``(resolved, skipped)`` where a skipped entry reads ``path: reason`` so the
    refusal is visible in the proposal rather than invisible in a log. Deterministic order.
    """
    resolved: list[str] = []
    skipped: list[str] = []
    base = _real(root)
    for raw in locations:
        relative = strip_location(raw).replace("\\", "/").lstrip("/")
        if not relative:
            skipped.append(f"{raw}: empty location")
            continue
        in_globs = (
            not globs
            or any(fnmatch.fnmatch(relative, pattern) for pattern in globs)
            or any(fnmatch.fnmatch(Path(relative).name, pattern) for pattern in globs)
        )
        if not in_globs:
            skipped.append(f"{relative}: outside the plan's globs")
            continue
        candidate = base / relative
        try:
            real = candidate.resolve()
        except OSError:  # pragma: no cover - unreadable path
            skipped.append(f"{relative}: unresolvable")
            continue
        if real != base and base not in real.parents:
            skipped.append(f"{relative}: escapes the repository root")
            continue
        if not real.is_file():
            skipped.append(f"{relative}: not a regular file in the tree")
            continue
        as_relative = real.relative_to(base).as_posix()
        if real.stat().st_size > MAX_TARGET_BYTES:
            skipped.append(f"{as_relative}: larger than {MAX_TARGET_BYTES} bytes")
            continue
        if as_relative not in resolved:
            resolved.append(as_relative)
    ordered = tuple(sorted(resolved))
    if len(ordered) > max_files:
        skipped.extend(f"{item}: beyond the {max_files}-file limit" for item in ordered[max_files:])
        ordered = ordered[:max_files]
    return ordered, tuple(skipped)


def _real(root: Path) -> Path:
    try:
        return root.resolve()
    except OSError:  # pragma: no cover - defensive
        return root


@dataclass(frozen=True, slots=True)
class FileEdit:
    """One file's before/after text, with how many times the plan bit in it."""

    relative: str
    before: str
    after: str
    matched: int


@dataclass(frozen=True, slots=True)
class PlanApplication:
    """What applying a plan to one tree produced (or why it produced nothing)."""

    plan_id: str
    root: Path
    files: tuple[FileEdit, ...] = ()
    targets: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    already_fixed: bool = False
    #: ``""`` when the plan applied; otherwise the single reason it did not.
    reason: str = ""

    @property
    def applied(self) -> bool:
        return bool(self.files) and not self.already_fixed and not self.reason

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(edit.relative for edit in self.files)

    def diff(self) -> str:
        return render_diff(self.files)


def render_diff(files: tuple[FileEdit, ...], *, context: int = 3) -> str:
    """A deterministic unified diff (``a/``/``b/`` prefixes, stable file order)."""
    chunks: list[str] = []
    for edit in sorted(files, key=lambda item: item.relative):
        chunks.extend(
            difflib.unified_diff(
                edit.before.splitlines(keepends=True),
                edit.after.splitlines(keepends=True),
                fromfile=f"a/{edit.relative}",
                tofile=f"b/{edit.relative}",
                n=context,
            )
        )
    return "".join(chunks)


def diff_stats(diff: str) -> tuple[int, int, int]:
    """``(files, added_lines, removed_lines)`` for a unified diff."""
    files = 0
    added = 0
    removed = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            files += 1
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return files, added, removed


def _apply_edit(text: str, edit: EditOp) -> tuple[str, int]:
    pattern = edit.pattern
    if edit.op == "replace":
        limit = edit.count if edit.count else 0
        updated, matched = re.subn(pattern, edit.replacement, text, count=limit, flags=re.MULTILINE)
        return updated, matched
    # insert_after: add `text` after each matched *line*, preserving the original line.
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    matched = 0
    limit = edit.count if edit.count else 0
    compiled = re.compile(pattern, re.MULTILINE)
    for line in lines:
        out.append(line)
        if compiled.search(line) and (not limit or matched < limit):
            out.append(edit.text if edit.text.endswith("\n") else edit.text + "\n")
            matched += 1
    return "".join(out), matched


def apply_plan(
    plan: FixPlan,
    root: Path,
    targets: tuple[str, ...],
    *,
    max_files: int = MAX_TARGET_FILES,
) -> PlanApplication:
    """Apply ``plan`` to ``targets`` under ``root``; never writes anything to disk."""
    base = _real(root)
    if not targets:
        return PlanApplication(plan_id=plan.id, root=base, reason="no target file in the evidence")
    edits: list[FileEdit] = []
    skipped: list[str] = []
    already_fixed = 0
    for relative in targets[:max_files]:
        path = base / relative
        try:
            before = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            skipped.append(f"{relative}: unreadable ({exc})")
            continue
        if plan.fixed_already(before):
            already_fixed += 1
            skipped.append(f"{relative}: the fix is already present")
            continue
        text = before
        matched = 0
        failed: str | None = None
        for edit in plan.edits:
            updated, hits = _apply_edit(text, edit)
            if hits < edit.min_matches:
                failed = (
                    f"edit {edit.op} {edit.pattern!r} matched {hits} time(s) "
                    f"(needs {edit.min_matches})"
                )
                break
            if edit.max_matches is not None and hits > edit.max_matches:
                failed = (
                    f"edit {edit.op} {edit.pattern!r} matched {hits} time(s) "
                    f"(max {edit.max_matches})"
                )
                break
            text = updated
            matched += hits
        if failed is not None:
            skipped.append(f"{relative}: {failed}")
            continue
        if text == before:
            skipped.append(f"{relative}: the plan leaves this file unchanged")
            continue
        edits.append(FileEdit(relative=relative, before=before, after=text, matched=matched))
    if not edits:
        reason = "already-fixed" if already_fixed else "the plan does not apply to this tree"
        return PlanApplication(
            plan_id=plan.id,
            root=base,
            targets=targets,
            skipped=tuple(skipped),
            already_fixed=bool(already_fixed),
            reason=reason,
        )
    return PlanApplication(
        plan_id=plan.id,
        root=base,
        files=tuple(edits),
        targets=targets,
        skipped=tuple(skipped),
    )


def require_catalog_path(path: str | Path) -> Path:
    """A tiny helper the CLI uses to fail loudly on a missing plan catalog path."""
    resolved = Path(path).expanduser()
    if not resolved.exists():
        msg = f"fix-plan catalog {resolved} does not exist"
        raise ConfigurationError(msg)
    return resolved
