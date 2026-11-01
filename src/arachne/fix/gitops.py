"""The only module in ARACHNE that starts a process, and the only one that touches git (S27).

Everything the fix engine needs from git is here, and the vocabulary is *closed*: the
subcommand lists below are the complete set this module can run, and
``tests/test_fix_safety.py`` asserts that structurally (every invocation's first element is
a member, and no forbidden verb — ``push``, ``merge``, ``reset``, ``fetch``, ``clone``,
``checkout``, ``switch``… — appears anywhere in the vocabulary). That is how "NEVER merges,
NEVER pushes to the default branch" stops being a promise in a docstring and becomes a
property of the code: there is no command here that *can* merge or push.

Two rules shape every process this module starts:

* **The argv is a list, never a string, and its program is a literal.** :func:`git_argv`
  refuses a subcommand outside the vocabulary and any argument carrying a control
  character; :func:`run_declared_test` starts only a runner from :data:`TEST_RUNNERS`, each
  of which is written out as a literal in the source, so "what can this repository's grant
  make ARACHNE execute" is a question the code answers at a glance. No shell is ever
  involved (``shell=False``, a timeout, ``GIT_TERMINAL_PROMPT=0``,
  ``GIT_CONFIG_NOSYSTEM=1``), and nothing is composed from scanned content.
* **The write path is a throwaway worktree.** ``git worktree add --detach <scratch> <base>``
  checks the authorized repo's base commit out into a temporary directory *outside* the
  repository; the patched files are written there, ``git add``ed and committed with a fixed
  bot identity (and ``core.hooksPath`` pointed at a non-existent path, so a repository's own
  commit hooks cannot run arbitrary code during a proposal); the branch is then created with
  ``git branch <arachne-fix-*> <commit>`` **in the authorized repository** — a ref and
  nothing else; finally the worktree is removed. The repository's ``HEAD`` and its default
  branch are captured before and re-read after: a difference is a hard error, so the
  invariant "the operator's checkout is untouched" is asserted rather than assumed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from arachne.core.errors import ArachneError
from arachne.fix.grants import TEST_OUTPUT_CHARS

__all__ = [
    "ALLOWED_SUBCOMMANDS",
    "FORBIDDEN_SUBCOMMANDS",
    "TEST_RUNNERS",
    "BranchResult",
    "GitOperationError",
    "TestRun",
    "branch_exists",
    "commit_exists",
    "create_patch_branch",
    "current_branch",
    "git_argv",
    "head_commit",
    "is_clean",
    "is_git_repo",
    "patch_branch_name",
    "ref_commit",
    "run_declared_test",
]

#: Control characters, NUL and the escape byte — never escaped, always refused. Tab and
#: newline are deliberately *not* in the set: a commit message legitimately spans lines, and
#: there is no shell for either to break out of (git itself refuses them in a ref or path).
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: A commit message is bounded like every other string this module handles.
MAX_MESSAGE_CHARS: Final = 4000

#: Read-only git subcommands this module may run.
READONLY_SUBCOMMANDS: Final = (
    "rev-parse",
    "symbolic-ref",
    "show-ref",
    "status",
    "log",
    "ls-files",
)

#: Mutating git subcommands this module may run — deliberately the whole set.
WRITE_SUBCOMMANDS: Final = ("worktree", "add", "commit", "branch", "init")

#: Every git subcommand the module can start.
ALLOWED_SUBCOMMANDS: Final = READONLY_SUBCOMMANDS + WRITE_SUBCOMMANDS

#: Verbs that must never appear: a merge, a push, a history rewrite, a fetch, a clone.
FORBIDDEN_SUBCOMMANDS: Final = (
    "push",
    "merge",
    "rebase",
    "reset",
    "clean",
    "checkout",
    "switch",
    "stash",
    "fetch",
    "pull",
    "clone",
    "remote",
    "submodule",
    "filter-branch",
    "gc",
    "prune",
    "am",
    "cherry-pick",
    "revert",
)

#: The test runners ARACHNE will start, in the order the source declares them. A grant's
#: ``test_command[0]`` must be one of these (``grants.FixRepoGrant``). The list is
#: deliberately short and enumerable — it is the answer to "which programs can a grant make
#: this deployment execute?", and adding one is a code change a reviewer sees.
TEST_RUNNERS: Final = (
    "pytest",
    "python",
    "python3",
    "tox",
    "nox",
    "npm",
    "pnpm",
    "yarn",
    "make",
    "go",
    "cargo",
    "mvn",
    "gradle",
)

#: The fixed bot identity commits carry. The grant's name is appended as a trailer, so a
#: proposal is attributable in the repository's log without being attributable to a human.
_BOT_NAME: Final = "ARACHNE"
_BOT_EMAIL: Final = "arachne@localhost"

#: Branch names this module creates, and the only shape it accepts.
BRANCH_RE: Final = re.compile(r"^arachne-fix-[A-Za-z0-9][A-Za-z0-9._-]{0,72}$")

#: Where git looks for hooks during our own commit: nowhere.
_NO_HOOKS: Final = ""

_DEFAULT_TIMEOUT: Final = 120


class GitOperationError(ArachneError):
    """A git operation the fix engine needed could not be completed safely."""


def patch_branch_name(finding_id: int, slug: str) -> str:
    """``arachne-fix-<finding>-<slug>`` — the dedicated branch REQ-FIX-002 asks for."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-")[:40].strip("-")
    return f"arachne-fix-{finding_id}-{cleaned or 'proposal'}"


@dataclass(frozen=True, slots=True)
class TestRun:
    """One execution of a command (a git verb, or a repository's own test suite)."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def output_tail(self) -> str:
        combined = (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()
        return combined[-TEST_OUTPUT_CHARS:]

    def summary(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass(frozen=True, slots=True)
class BranchResult:
    """The branch a submission created, and the invariants that held while creating it."""

    branch: str
    commit: str
    files: tuple[str, ...]
    default_branch: str | None
    default_branch_unchanged: bool
    head_unchanged: bool


def git_argv(args: Sequence[str]) -> list[str]:
    """Validate one git invocation against the closed vocabulary; return its argv list.

    A subcommand outside :data:`ALLOWED_SUBCOMMANDS` (plus git's own ``-c`` configuration
    flag) is refused, and so is any argument carrying a control character — so ``push``,
    ``merge`` and ``reset --hard`` are not merely unused, they are unrepresentable.
    """
    if not args:
        msg = "refusing to run git with no arguments"
        raise GitOperationError(msg)
    head = args[0]
    if head not in ALLOWED_SUBCOMMANDS and head != "-c":
        msg = f"refusing to run git {head!r}: not in the allowed subcommand vocabulary"
        raise GitOperationError(msg)
    for item in args:
        if len(item) > MAX_MESSAGE_CHARS:
            msg = f"refusing to pass a {len(item)}-character argument to git"
            raise GitOperationError(msg)
        if _CONTROL_CHARS.search(item):
            msg = "refusing to pass a control character to git"
            raise GitOperationError(msg)
    return ["git", *args]


def _env() -> dict[str, str]:
    """A process environment that cannot prompt, cannot read system config, cannot page."""
    env = dict(os.environ)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return env


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):  # pragma: no cover - text=True keeps this unreachable
        return value.decode("utf-8", "replace")
    return value


def _git(args: Sequence[str], *, cwd: Path, timeout: int = _DEFAULT_TIMEOUT) -> TestRun:
    """Run one validated git verb; report it the way a test run is reported."""
    parts = git_argv(args)
    location = str(cwd)
    environ = _env()
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["git", *parts[1:]],
            shell=False,
            cwd=location,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environ,
        )
    except subprocess.TimeoutExpired as exc:
        return TestRun(
            argv=tuple(parts),
            exit_code=-1,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except OSError as exc:
        return TestRun(
            argv=tuple(parts),
            exit_code=-1,
            stderr=f"cannot start git: {exc}",
            duration_seconds=time.monotonic() - started,
        )
    return TestRun(
        argv=tuple(parts),
        exit_code=int(completed.returncode),
        stdout=_decode(completed.stdout),
        stderr=_decode(completed.stderr),
        duration_seconds=time.monotonic() - started,
    )


def _must(args: Sequence[str], *, cwd: Path, timeout: int = _DEFAULT_TIMEOUT) -> TestRun:
    result = _git(args, cwd=cwd, timeout=timeout)
    if not result.passed:
        msg = (
            f"git {' '.join(args)} failed in {cwd} "
            f"(exit {result.exit_code}): {result.output_tail()[:400]}"
        )
        raise GitOperationError(msg)
    return result


# ------------------------------------------------------------------ read-only queries
def is_git_repo(path: Path) -> bool:
    """True when ``path`` is a work tree of a git repository."""
    if not path.is_dir():
        return False
    result = _git(["rev-parse", "--is-inside-work-tree"], cwd=path)
    return result.passed and result.stdout.strip() == "true"


def head_commit(path: Path) -> str | None:
    result = _git(["rev-parse", "--verify", "HEAD"], cwd=path)
    return result.stdout.strip() if result.passed else None


def current_branch(path: Path) -> str | None:
    """The checked-out branch name, or ``None`` on a detached HEAD."""
    name = _git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=path).stdout.strip()
    return name or None


def ref_commit(path: Path, ref: str) -> str | None:
    result = _git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=path)
    return result.stdout.strip() if result.passed else None


def commit_exists(path: Path, commit: str) -> bool:
    return ref_commit(path, commit) is not None


def branch_exists(path: Path, branch: str) -> bool:
    return _git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=path).passed


def is_clean(path: Path) -> bool:
    """True when the work tree has no staged or unstaged changes (untracked ignored)."""
    result = _git(["status", "--porcelain", "--untracked-files=no"], cwd=path)
    return result.passed and not result.stdout.strip()


# ------------------------------------------------------------------ the write path
def create_patch_branch(
    repo: Path,
    *,
    branch: str,
    base: str,
    changes: Mapping[str, str],
    message: str,
    default_branch: str | None = None,
    grant_name: str = "",
) -> BranchResult:
    """Commit ``changes`` on ``branch`` in ``repo``, via a throwaway worktree.

    ``changes`` maps repo-relative paths to their full new content. The repository's own
    working tree is never checked out, written to or switched; only a new branch ref appears.
    """
    if not BRANCH_RE.match(branch):
        msg = f"refusing to create branch {branch!r}: not an arachne-fix-* name"
        raise GitOperationError(msg)
    if branch == default_branch:
        msg = f"refusing to commit to the default branch {branch!r}"
        raise GitOperationError(msg)
    if branch_exists(repo, branch):
        msg = f"branch {branch!r} already exists in {repo}; refusing to overwrite it"
        raise GitOperationError(msg)
    if not changes:
        msg = "refusing to create a branch with no changes"
        raise GitOperationError(msg)

    head_before = head_commit(repo)
    default_before = ref_commit(repo, default_branch) if default_branch else None

    scratch = Path(tempfile.mkdtemp(prefix="arachne-fix-worktree-"))
    added_worktree = False
    try:
        _must(["worktree", "add", "--detach", str(scratch), base], cwd=repo)
        added_worktree = True
        paths: list[str] = []
        for relative, text in sorted(changes.items()):
            target = (scratch / relative).resolve()
            if scratch.resolve() not in target.parents:
                msg = f"refusing to write {relative!r}: it leaves the worktree"
                raise GitOperationError(msg)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            paths.append(relative)
        _must(["add", "--", *paths], cwd=scratch)
        trailer = f"{message}\n\nARACHNE-Proposal-Grant: {grant_name or 'unknown'}\n"
        _must(
            [
                "-c",
                f"user.name={_BOT_NAME}",
                "-c",
                f"user.email={_BOT_EMAIL}",
                "-c",
                "commit.gpgsign=false",
                "-c",
                f"core.hooksPath={_NO_HOOKS}",
                "commit",
                "--quiet",
                "-m",
                trailer,
            ],
            cwd=scratch,
        )
        commit = head_commit(scratch)
        if commit is None:  # pragma: no cover - the commit above would have failed
            msg = "the patch commit produced no revision"
            raise GitOperationError(msg)
        # The ref is created in the authorized repository: never checked out, never merged.
        _must(["branch", branch, commit], cwd=repo)
    finally:
        if added_worktree:
            _git(["worktree", "remove", "--force", str(scratch)], cwd=repo)
        shutil.rmtree(scratch, ignore_errors=True)

    head_after = head_commit(repo)
    default_after = ref_commit(repo, default_branch) if default_branch else None
    if head_before is not None and head_after != head_before:
        msg = f"git HEAD moved while creating {branch!r} in {repo}; refusing to continue"
        raise GitOperationError(msg)
    if default_before != default_after:
        msg = f"the default branch {default_branch!r} moved while creating {branch!r}"
        raise GitOperationError(msg)
    return BranchResult(
        branch=branch,
        commit=commit,
        files=tuple(sorted(changes)),
        default_branch=default_branch,
        default_branch_unchanged=default_before == default_after,
        head_unchanged=head_before == head_after,
    )


def run_declared_test(
    program: str, arguments: Sequence[str], *, cwd: Path, timeout: int = 900
) -> TestRun:
    """Run a repository's own test command in ``cwd``.

    ``program`` is a member of :data:`TEST_RUNNERS` and ``arguments`` is the operator's own
    grant argv (already refused at load time if any element carries a shell
    metacharacter). Each runner is started from a literal in this function, with
    ``shell=False`` and a timeout: no program name arrives from the scanned estate, and
    nothing is composed into a command line.
    """
    if program not in TEST_RUNNERS:
        msg = (
            f"refusing to run {program!r} as a test runner; ARACHNE starts only "
            f"{', '.join(TEST_RUNNERS)}"
        )
        raise GitOperationError(msg)
    for item in arguments:
        if _CONTROL_CHARS.search(item):
            msg = "refusing to pass a control character to the test command"
            raise GitOperationError(msg)
    location = str(cwd)
    environ = _env()
    started = time.monotonic()
    try:
        if program == "pytest":
            completed = subprocess.run(
                ["pytest", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "python":
            completed = subprocess.run(
                ["python", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "python3":
            completed = subprocess.run(
                ["python3", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "tox":
            completed = subprocess.run(
                ["tox", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "nox":
            completed = subprocess.run(
                ["nox", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "npm":
            completed = subprocess.run(
                ["npm", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "pnpm":
            completed = subprocess.run(
                ["pnpm", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "yarn":
            completed = subprocess.run(
                ["yarn", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "make":
            completed = subprocess.run(
                ["make", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "go":
            completed = subprocess.run(
                ["go", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "cargo":
            completed = subprocess.run(
                ["cargo", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "mvn":
            completed = subprocess.run(
                ["mvn", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        elif program == "gradle":
            completed = subprocess.run(
                ["gradle", *arguments],
                shell=False,
                cwd=location,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environ,
            )
        else:  # pragma: no cover - guarded by the allowlist check above
            msg = f"no spawn branch for the runner {program!r}; refusing to guess one"
            raise GitOperationError(msg)
    except subprocess.TimeoutExpired as exc:
        return TestRun(
            argv=(program, *arguments),
            exit_code=-1,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except OSError as exc:
        return TestRun(
            argv=(program, *arguments),
            exit_code=-1,
            stderr=f"cannot start {program!r}: {exc}",
            duration_seconds=time.monotonic() - started,
        )
    return TestRun(
        argv=(program, *arguments),
        exit_code=int(completed.returncode),
        stdout=_decode(completed.stdout),
        stderr=_decode(completed.stderr),
        duration_seconds=time.monotonic() - started,
    )


class WorktreeSession:
    """A scratch checkout of a repo revision, removed on exit (never the operator's tree)."""

    def __init__(self, *, repo: Path, base: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.repo = repo
        self.base = base
        self.timeout = timeout
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix="arachne-fix-verify-"))
        _must(["worktree", "add", "--detach", str(self.path), self.base], cwd=self.repo)
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        if self.path is not None:
            _git(["worktree", "remove", "--force", str(self.path)], cwd=self.repo)
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
