"""Provably-scoped diffs: the REQ-FIX-003 prohibitions, enforced on the artifact (S27).

A proposal is only useful if an operator can be *sure* what it contains. This module reads
the diff — the exact bytes the operator would apply — and refuses it, by name, if it would
do any of the things area FIX forbids forever:

===============================  ==================================================
``secret-in-added-line``         the diff *introduces* credential material
``secret-in-removed-line``       the diff reproduces credential material it removes
``file-deletion``                ``--- /dev/null`` / ``+++ /dev/null``
``mode-or-symlink-change``       ``old mode``/``new mode``/``deleted file mode``
``file-rename``                  ``rename from``/``rename to``
``binary-patch``                 ``GIT binary patch`` / ``Binary files … differ``
``absolute-path``                a hunk header naming an absolute path
``path-escape``                  a ``..`` segment in a hunk header
``file-outside-the-plan``        a changed path the plan did not select
``dependency-manifest-change``   any edit to a dependency manifest or lockfile
``destructive-operation``        an added line that deletes/overwrites/rewrites state
``diff-budget-exceeded``         more files or changed lines than the grant allows
===============================  ==================================================

Two of these are *recoverable* rather than fatal, and the distinction matters:

* a **removed** secret can be masked out of the emitted diff (``[REDACTED]``), which makes
  the artifact safe to store and review — but a masked diff is no longer byte-applicable, so
  the verdict carries ``verbatim=False`` and the proposal is marked manual-apply. This is
  why the shipped catalog ships no credential-removal plan: the honest artifact there is
  guidance plus a human's edit, and the fix-verification loop already closes it.
* everything else is fatal: the proposal is refused and *recorded*, never silently dropped.

The check is deliberately textual and deterministic. It is not a sandbox — the sandbox is
"ARACHNE writes nothing anywhere without a human approval, and never merges or applies
anything, ever".
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from arachne.core.redaction import contains_secret, redact_text

__all__ = [
    "DEPENDENCY_MANIFESTS",
    "DiffBudgets",
    "DiffVerdict",
    "analyze_diff",
]

#: Dependency manifests and lockfiles a fix may never edit (REQ-FIX-003: "no dependency
#: upgrades beyond the fix"). A dependency-class remediation is surfaced as guidance; a
#: version bump is not a scoped fix and would not survive the reviewer's own judgement.
DEPENDENCY_MANIFESTS: Final[frozenset[str]] = frozenset(
    {
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "gemfile",
        "gemfile.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "composer.lock",
        "mix.exs",
        "pubspec.yaml",
    }
)

#: Commands an artifact may not add. Deliberately blunt: a fix that has to delete, format,
#: rewrite or force-overwrite state is not a scoped fix, and the operator can always make
#: that change by hand.
_DESTRUCTIVE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s"),
    re.compile(r"\bmkfs(\.\w+)?\b"),
    re.compile(r"\bdd\s+(if|of)="),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+(-R\s+)?777\b"),
    re.compile(r"\bgit\s+(push\s+--force|reset\s+--hard|clean\s+-[a-zA-Z]*f)"),
    re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b"),
    re.compile(r">\s*/dev/(sd|nvme|hd)"),
)

_NO_NEWLINE = "\\ No newline at end of file"

#: The two credential prohibitions, named once so a test can assert on them directly.
_ADDED_LINE_RULE: Final = "secret-in-added-line"
_REMOVED_LINE_RULE: Final = "secret-in-removed-line"


@dataclass(frozen=True, slots=True)
class DiffBudgets:
    """The bounds a diff must fit inside (``None`` disables one bound)."""

    max_files: int | None = 12
    max_changed_lines: int | None = 400


@dataclass(frozen=True, slots=True)
class DiffVerdict:
    """The safety verdict on one diff.

    ``diff`` is the **emitted** diff: identical to the input except that a masked secret
    removal has already been rewritten in place (see ``masked_lines``/``verbatim``). When
    the verdict is not ``clean`` the diff must not be stored at all — the engine refuses.
    """

    diff: str
    violations: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    added_lines: int = 0
    removed_lines: int = 0
    masked_lines: int = 0
    #: False when the emitted diff no longer reproduces its input byte-for-byte (a masked
    #: removal), so it cannot be committed or applied as-is.
    verbatim: bool = True

    @property
    def codes(self) -> tuple[str, ...]:
        """The distinct prohibition codes violated, in first-seen order."""
        seen: list[str] = []
        for entry in self.violations:
            code = entry.split(":", 1)[0]
            if code not in seen:
                seen.append(code)
        return tuple(seen)

    @property
    def clean(self) -> bool:
        return not self.violations

    def summary(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "violations": list(self.violations),
            "files": list(self.files),
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "masked_lines": self.masked_lines,
            "verbatim": self.verbatim,
        }


def analyze_diff(
    diff: str,
    *,
    allowed_paths: Iterable[str] = (),
    budgets: DiffBudgets | None = None,
    mask_removals: bool = False,
) -> DiffVerdict:
    """Judge ``diff`` against the area-FIX prohibitions (see the module docstring).

    ``allowed_paths`` is the plan's own target list: a changed path outside it is refused,
    which is what makes "the diff is scoped" a property of the artifact rather than of the
    code path that produced it.
    """
    limits = budgets or DiffBudgets()
    allowed = {item.lstrip("/") for item in allowed_paths}
    violations: list[str] = []
    files: list[str] = []
    added = 0
    removed = 0
    masked = 0
    verbatim = True
    current: str | None = None
    out: list[str] = []

    for line in diff.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped.startswith(("--- ", "+++ ")):
            header = stripped[4:].strip()
            marker, _, path = header.partition("\t")
            path = path.strip() or marker
            if path == "/dev/null":
                violations.append(f"file-deletion: a hunk header names /dev/null ({header})")
            else:
                relative = path[2:] if path.startswith(("a/", "b/")) else path
                if relative.startswith("/"):
                    violations.append(f"absolute-path: {relative}")
                if any(part == ".." for part in relative.split("/")):
                    violations.append(f"path-escape: {relative}")
                if stripped.startswith("+++ "):
                    current = relative
                    if relative not in files:
                        files.append(relative)
                    if allowed and relative not in allowed:
                        violations.append(f"file-outside-the-plan: {relative}")
            out.append(line)
            continue
        if stripped.startswith(("old mode ", "new mode ", "deleted file mode ", "new file mode ")):
            violations.append(f"mode-or-symlink-change: {stripped}")
            out.append(line)
            continue
        if stripped.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            violations.append(f"file-rename: {stripped}")
            out.append(line)
            continue
        if stripped.startswith(("GIT binary patch", "Binary files ")):
            violations.append(f"binary-patch: {stripped}")
            out.append(line)
            continue
        if stripped.startswith(("diff --git ", "index ", "similarity index ", "@@", _NO_NEWLINE)):
            out.append(line)
            continue
        if stripped.startswith("+") and not stripped.startswith("+++"):
            added += 1
            if contains_secret(stripped):
                violations.append(f"{_ADDED_LINE_RULE}: {current or '<unknown file>'}")
            for pattern in _DESTRUCTIVE_PATTERNS:
                if pattern.search(stripped):
                    violations.append(
                        f"destructive-operation: {pattern.pattern} in {current or '<unknown>'}"
                    )
                    break
            out.append(line)
            continue
        if stripped.startswith("-") and not stripped.startswith("---"):
            removed += 1
            if contains_secret(stripped):
                if mask_removals:
                    out.append("-" + redact_text(stripped[1:]) + "\n")
                    masked += 1
                    verbatim = False
                else:
                    violations.append(f"{_REMOVED_LINE_RULE}: {current or '<unknown file>'}")
                    out.append(line)
                continue
            out.append(line)
            continue
        out.append(line)

    for relative in files:
        if relative.rsplit("/", 1)[-1].lower() in DEPENDENCY_MANIFESTS:
            violations.append(f"dependency-manifest-change: {relative}")
    if limits.max_files is not None and len(files) > limits.max_files:
        violations.append(f"diff-budget-exceeded: {len(files)} files (max {limits.max_files})")
    if limits.max_changed_lines is not None and (added + removed) > limits.max_changed_lines:
        violations.append(
            f"diff-budget-exceeded: {added + removed} changed lines "
            f"(max {limits.max_changed_lines})"
        )

    emitted = "".join(out) if not verbatim else diff
    return DiffVerdict(
        diff=emitted,
        violations=tuple(violations),
        files=tuple(files),
        added_lines=added,
        removed_lines=removed,
        masked_lines=masked,
        verbatim=verbatim,
    )
