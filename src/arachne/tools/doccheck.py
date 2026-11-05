"""The documentation integrity checker (REQ-DOC-001, REQ-DOC-003).

The repository's own documentation is part of the product, and the failure mode it has
already suffered once is *silent*: a path cited in a docstring or a link points at a file
that does not exist, and nothing notices until a reader follows it. This tool is the gate
that notices.

What it checks
--------------

* **Markdown links** — every ``[text](target)`` whose target is repository-relative resolves.
* **Backticked paths in Markdown prose** — every inline-code span that looks like a
  repository path resolves. Fenced code blocks are *not* scanned: they show commands and
  examples, not citations.
* **Path strings in Python docstrings and comments** — the same rule, applied only to the
  prose regions of a module (``ast`` for docstrings, ``tokenize`` for comments), never to its
  code, so a runtime path in a string literal is not mistaken for a citation.
* **Comment lines in configuration and script files** — ``#`` comments in ``.toml``,
  ``.ini``, ``.cfg``, ``.conf``, ``.sh``, ``.yaml``/``.yml`` and ``.env.example``.
* **Cited commits** — a hexadecimal token on a line that talks about a commit, a revision or
  a ``git`` command must name an object that exists in this repository
  (``git cat-file -t``). REQ-DOC-003: no document cites a commit that is not here.

What a "path candidate" is
--------------------------

Not every word with a slash in it is a path, and a checker that cries wolf is turned off.
A token is treated as a repository-path claim only when it:

1. contains ``/``, has no whitespace, and is not a URL (no scheme, no leading ``/``,
   no ``//``), and is not a glob (``tests/test_*.py``) or a dotted hostname
   (``github.com/...``); and
2. either opens with a top-level entry that exists (``docs/…``, ``src/…``, ``tests/…``) or
   ends with a known file extension.

A token that satisfies (2) must then resolve against one of the *resolution roots*: the
repository root, ``src/``, ``src/arachne/``, ``src/arachne/modules/`` (the tree's own
shorthand — ``core/http.py`` and ``m5/cloud.py`` are used in prose throughout) or the
directory of the file that cites it (which is what makes ``../README.md`` work).

Scope
-----

The checker covers what ships. ``.git``, virtualenvs, caches and the build-time artefacts
(the specification directory, the prompt library and the progress tracker) are excluded
because none of them is in a distribution. The exclusions are named in ``SKIP_DIRS`` and
``SKIP_NAMES`` below; there is no per-path ignore list, and the allowlist for *candidate*
paths is the short, individually justified ``ALLOWLIST`` table.

Usage::

    python -m arachne.tools.doccheck [PATH ...]     # default: the repository root
    python -m arachne.tools.doccheck --self-test    # prove it fails on a dangling link
    python -m arachne.tools.doccheck --list-allowlist

Exit code is 0 when the tree is clean, 1 when a reference is dangling, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "ALLOWLIST",
    "Violation",
    "check_tree",
    "main",
    "scan_file",
]

#: Directories that never ship and are never scanned, whatever the surface says.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "htmlcov",
        "build",
        "dist",
    }
)

#: **What the checker covers: the shipped surface, stated positively.** A directory walk
#: descends only into these, and only these root files are read. Everything else at the
#: repository root is build-time scaffolding or local tooling, which is not part of the
#: product and is removed before release (REQ-DOC-006) — so it is not a documentation
#: surface a reader can follow. Stating the surface rather than the exclusions costs one
#: line when the layout grows and cannot quietly hide a shipped document.
SHIPPED_DIRS: Final[frozenset[str]] = frozenset(
    {"benchmarks", "clients", "deploy", "docker", "docs", "examples", "migrations", "src", "tests"}
)

SHIPPED_ROOT_FILES: Final[frozenset[str]] = frozenset(
    {
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "alembic.ini",
        "coverage-ledger.json",
        "coverage-ledger.md",
        "coverage_matrix.md",
        "pyproject.toml",
        ".env.example",
    }
)

#: Extensions whose ``#`` comments are prose and therefore citable.
COMMENT_SUFFIXES: frozenset[str] = frozenset(
    {".toml", ".cfg", ".ini", ".conf", ".sh", ".yaml", ".yml", ".example", ".txt"}
)

#: A trailing ``:12-18`` on a path is a line range, not part of the name.
_LINE_RANGE = re.compile(r":\d+(?:-\d+)?$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_TOKEN = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./@~-]*")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_HOSTNAME = re.compile(r"^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+$")
_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@-]*$")
_HEX = re.compile(r"\b[0-9a-f]{7,40}\b")
_COMMIT_WORDS = re.compile(r"\b(?:commit|commits|commit-ish|sha|shas|revision|git|tag)\b", re.I)

KNOWN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".md",
        ".py",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".txt",
        ".sh",
        ".sql",
        ".ts",
        ".tsx",
        ".js",
        ".html",
        ".css",
        ".tf",
        ".go",
        ".svg",
        ".xml",
        ".csv",
        ".env",
        ".conf",
        ".example",
        ".jinja",
        ".j2",
        ".lock",
    }
)

#: Paths that are correct in prose but are not repository files. Every entry carries the
#: reason it is here; an entry without a reason is a bug in this table, not in the docs.
ALLOWLIST: tuple[tuple[str, str], ...] = (
    (
        ".arachne/",
        "Generated runtime state (gitignored): the scheduler and hypothesis-control files "
        "live beside the database at run time, not in the repository.",
    ),
)

#: REQ-DOC-003: "Decision records MAY retain them only when explicitly labelled as
#: historical." A line carrying this marker is a deliberate quotation of a pre-flatten path
#: and is not checked. The marker is a literal to grep for, so a labelled line is a
#: deliberate act, never an accident.
HISTORICAL_MARKER: Final = "`historical`"

#: How long a single ``git cat-file`` may take. It answers from the local object store, so
#: this is a guard against a wedged repository, not a wait for the network.
GIT_TIMEOUT_S: Final = 10


@dataclass(frozen=True, slots=True)
class Violation:
    """One documented reference that does not resolve."""

    path: str
    line: int
    kind: str
    token: str
    detail: str = ""

    def render(self) -> str:
        suffix = f" ({self.detail})" if self.detail else ""
        return f"{self.path}:{self.line}: {self.kind}: {self.token}{suffix}"


@dataclass(frozen=True, slots=True)
class Roots:
    """Where a cited path may be rooted."""

    repo: Path
    top: frozenset[str]

    @classmethod
    def for_repo(cls, repo: Path) -> Roots:
        return cls(repo=repo, top=frozenset(entry.name for entry in repo.iterdir()))

    @property
    def candidates(self) -> tuple[Path, ...]:
        return (
            self.repo,
            self.repo / "src",
            self.repo / "src" / "arachne",
            self.repo / "src" / "arachne" / "modules",
        )

    def resolve(self, token: str, *, base: Path) -> bool:
        for root in (*self.candidates, base):
            try:
                if (root / token).exists():
                    return True
            except OSError:  # pragma: no cover - an unreadable path is a broken tree
                return False
        return False


def _is_allowlisted(token: str) -> bool:
    return any(token.startswith(prefix) for prefix, _ in ALLOWLIST)


def _strip_token(raw: str) -> str:
    token = raw.split("#", 1)[0]
    token = _LINE_RANGE.sub("", token)
    return token.rstrip(".,;:)]}'\"")


def path_candidate(raw: str, roots: Roots) -> str | None:
    """Return the repository-relative path ``raw`` claims to be, or ``None``."""
    if "/" not in raw or _SCHEME.match(raw) or raw.startswith(("/", "~", "./", "//")):
        return None
    token = _strip_token(raw)
    if not token or "/" not in token or " " in token:
        return None
    segments = token.split("/")
    if segments[0] == ".." and len(segments) > 1:
        segments = segments[1:]
        relative = True
    else:
        relative = False
    if not segments or any(not _SEGMENT.match(segment) for segment in segments):
        return None
    if _HOSTNAME.match(segments[0]):
        return None
    if not relative and segments[0] not in roots.top:
        lowered = token.lower()
        if not any(lowered.endswith(extension) for extension in KNOWN_EXTENSIONS):
            return None
    return token


def _unexpected(roots: Roots, token: str, *, base: Path) -> bool:
    if _is_allowlisted(token):
        return False
    for root in (roots.repo, *roots.candidates, base):
        try:
            if (root / token).exists():
                return False
        except OSError:  # pragma: no cover
            return False
    return True


def _scan_text(
    path: Path,
    text: str,
    roots: Roots,
    *,
    check_commits: bool,
) -> list[Violation]:
    """Scan prose regions of ``text`` for dangling paths and unreachable commits."""
    rel = _relative(path, roots.repo)
    violations: list[Violation] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if HISTORICAL_MARKER in line:
            continue
        if check_commits:
            violations.extend(_commit_violations(rel, number, line, roots))
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for span in _spans(line):
            for match in _TOKEN.finditer(span):
                token = path_candidate(match.group(0), roots)
                if token is None or not _usable(span, match.start(), match.end()):
                    continue
                if _unexpected(roots, token, base=path.parent):
                    violations.append(
                        Violation(rel, number, "dangling-path", token, "no such file or directory")
                    )
    return violations


def _spans(line: str) -> list[str]:
    """The prose spans of a Markdown line: link targets and inline-code contents."""
    spans = [match.group(1) for match in _MD_LINK.finditer(line)]
    spans += [match.group(1) for match in _INLINE_CODE.finditer(line)]
    return spans


def _usable(span: str, start: int, end: int) -> bool:
    """False for a URL path (``/.well-known/…``) or a glob (``tests/test_*_safety.py``)."""
    before = span[start - 1] if start > 0 else ""
    after = span[end] if end < len(span) else ""
    return before != "/" and after not in ("*", "?")


def _commit_violations(rel: str, number: int, line: str, roots: Roots) -> list[Violation]:
    if not _COMMIT_WORDS.search(line):
        return []
    out: list[Violation] = []
    for match in _HEX.finditer(line):
        sha = match.group(0)
        if _object_exists(sha, roots.repo):
            continue
        out.append(Violation(rel, number, "unreachable-commit", sha, "git cat-file -t failed"))
    return out


def _object_exists(sha: str, repo: Path) -> bool:
    completed = subprocess.run(  # noqa: S603 - a fixed argv of literals, no shell
        ["git", "-C", str(repo), "cat-file", "-t", sha],
        capture_output=True,
        text=True,
        check=False,
        timeout=GIT_TIMEOUT_S,
    )
    return completed.returncode == 0


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:  # pragma: no cover - scanning outside the tree
        return path.as_posix()


def _python_prose(path: Path) -> dict[int, str]:
    """Line number -> prose on that line, for docstrings and comments only."""
    text = path.read_text(encoding="utf-8")
    prose: dict[int, str] = {}
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(
                node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
            ):
                continue
            if not node.body:
                continue
            first = node.body[0]
            if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)):
                continue
            if not isinstance(first.value.value, str):
                continue
            start = getattr(first, "lineno", 0)
            end = getattr(first, "end_lineno", start) or start
            for number in range(start, end + 1):
                if 1 <= number <= len(lines):
                    prose[number] = lines[number - 1]
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT and 1 <= token.start[0] <= len(lines):
            prose[token.start[0]] = lines[token.start[0] - 1]
    return prose


def scan_file(path: Path, roots: Roots) -> list[Violation]:
    """Every dangling reference this file carries."""
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _scan_python(path, roots)
    if suffix == ".md":
        return _scan_text(path, path.read_text(encoding="utf-8"), roots, check_commits=True)
    if suffix in COMMENT_SUFFIXES:
        return _scan_text(path, _comment_lines(path), roots, check_commits=False)
    return []


def _scan_python(path: Path, roots: Roots) -> list[Violation]:
    prose = _python_prose(path)
    rel = _relative(path, roots.repo)
    violations: list[Violation] = []
    for number in sorted(prose):
        line = prose[number]
        if HISTORICAL_MARKER in line:
            continue
        for match in _TOKEN.finditer(line):
            token = path_candidate(match.group(0), roots)
            if token is None or not _usable(line, match.start(), match.end()):
                continue
            if _unexpected(roots, token, base=path.parent):
                violations.append(
                    Violation(rel, number, "dangling-path", token, "no such file or directory")
                )
    return violations


def _comment_lines(path: Path) -> str:
    """The ``#`` comment lines of a configuration or script file, blanked elsewhere."""
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        out.append(line if stripped.startswith("#") else "")
    return "\n".join(out)


def _shipped(path: Path, repo: Path) -> bool:
    """True when ``path`` is part of the surface this checker covers."""
    try:
        relative = path.resolve().relative_to(repo.resolve())
    except ValueError:  # pragma: no cover - a path outside the tree
        return False
    parts = relative.parts
    if not parts:
        return False
    if len(parts) == 1:
        return parts[0] in SHIPPED_ROOT_FILES
    return parts[0] in SHIPPED_DIRS


def _inside(path: Path, repo: Path) -> bool:
    """True when ``path`` is the repository root or below it."""
    resolved = path.resolve()
    root = repo.resolve()
    return resolved == root or root in resolved.parents


def check_tree(paths: list[Path], *, roots: Roots | None = None) -> list[Violation]:
    """Scan ``paths`` (files or directories) and return every violation found.

    An explicitly named *file* is always scanned, and a directory outside the repository is
    walked in full: a caller asking about one document or one tree wants that checked. Only a
    walk of the repository itself is restricted to the shipped surface.
    """
    resolved = roots or Roots.for_repo(Path.cwd())
    violations: list[Violation] = []
    for path in paths:
        if path.is_file():
            violations.extend(scan_file(path, resolved))
            continue
        surface_only = _inside(path, resolved.repo)
        for child in sorted(path.rglob("*")):
            if not child.is_file():
                continue
            if surface_only and not _shipped(child, resolved.repo):
                continue
            if SKIP_DIRS & set(child.parts):
                continue
            if child.suffix.lower() not in {".py", ".md", *COMMENT_SUFFIXES}:
                continue
            try:
                violations.extend(scan_file(child, resolved))
            except (OSError, UnicodeDecodeError):  # pragma: no cover - unreadable file
                continue
    return violations


def _self_test() -> int:
    """Prove the checker fails on a deliberately dangling link and passes on a good one."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs").mkdir()
        (root / "docs" / "real.md").write_text("# real\n", encoding="utf-8")
        good = root / "good.md"
        good.write_text("See [real](docs/real.md) and `docs/real.md`.\n", encoding="utf-8")
        bad = root / "bad.md"
        bad.write_text("See [gone](docs/gone.md) and `docs/gone.md`.\n", encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        roots = Roots.for_repo(root)
        clean = check_tree([good], roots=roots)
        dirty = check_tree([bad], roots=roots)
    if clean:
        _out(f"self-test FAILED: a good link was reported: {[v.render() for v in clean]}")
        return 1
    if len(dirty) != 2:
        _out(f"self-test FAILED: expected 2 violations, got {[v.render() for v in dirty]}")
        return 1
    _out("self-test passed: a good link resolves, a dangling one is reported twice")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="doccheck", description="Documentation integrity gate")
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories (default: .)")
    parser.add_argument("--self-test", action="store_true", help="check the checker itself")
    parser.add_argument(
        "--list-allowlist", action="store_true", help="print the justified exceptions and exit"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.list_allowlist:
        for prefix, reason in ALLOWLIST:
            _out(f"{prefix}\n    {reason}")
        return 0
    paths = list(args.paths) or [Path()]
    missing = [path for path in paths if not path.exists()]
    if missing:
        _err(f"doccheck: no such path: {', '.join(str(path) for path in missing)}")
        return 2
    repo = Path.cwd()
    roots = Roots.for_repo(repo)
    violations = check_tree(paths, roots=roots)
    for violation in violations:
        _out(violation.render())
    if violations:
        _err(f"doccheck: {len(violations)} dangling reference(s)")
        return 1
    _out(f"doccheck: clean ({len(paths)} path(s) scanned, {len(ALLOWLIST)} allowlisted prefix)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
