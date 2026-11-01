"""The operator's authorization to fix a repository, and the deny-by-default resolution (S27).

REQ-FIX-001 is blunt about scope: proposals exist "only for repos/configs the operator has
explicitly granted". So the grant is a *file the operator wrote*, there is **no shipped
default**, and an empty grant set authorizes nothing:

* a finding whose target resolves to no granted repository gets a recorded refusal and a
  guidance-only proposal (the remediation catalog's steps), never a diff;
* the grant declares the repository's own test command (``test_command``). ARACHNE never
  invents one, and never guesses one from the tree — guessing would mean executing a
  command the operator did not authorize;
* the grant carries the budget the diff must fit inside, so "a scoped patch" is the
  operator's number, not the engine's opinion;
* a grant whose ``test_command`` is empty marks its repo **untestable**: proposals against
  it are flagged as such. They only reach a branch/PR if the operator also set
  ``allow_untestable``, which is a deliberate, recorded risk acceptance (REQ-FIX-002).

The path in a grant is resolved once, at authorization time, and every later check compares
*resolved* paths — so a symlinked grant cannot be retargeted between the proposal and the
submission.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.core.errors import ConfigurationError
from arachne.fix.patch import repo_root_of
from arachne.fix.safety import DiffBudgets

__all__ = [
    "FixGrantSet",
    "FixRepoGrant",
    "RepoAuthorization",
    "load_fix_grants",
    "parse_fix_grants",
]

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: A program name that resolves through ``PATH``. The test command is executed with
#: ``shell=False`` and a sequence argv, so nothing here can start a shell — but a path is
#: still refused, because "the program this grant names" must be a literal, not a location
#: that something else could occupy between authorization and execution.
_PROGRAM_RE = re.compile(r"^[A-Za-z0-9._+-]+$")

#: The shape a git branch name must have (no ``..``, no leading dash, bounded length).
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,80}$")

#: Characters no argument may contain. They are the shell's vocabulary (and the glob
#: vocabulary); refusing them keeps a grant's argv readable as "exactly these words".
_FORBIDDEN_ARG_CHARS: Final = frozenset(";|&$`<>(){}!*?\n\r\\")

#: How many characters of a repo's test output are kept as evidence.
TEST_OUTPUT_CHARS: Final = 20000


class FixRepoGrant(BaseModel):
    """One repository the operator has authorized ARACHNE to propose fixes against."""

    model_config = _MODEL_CONFIG

    name: str = Field(min_length=1, max_length=128)
    #: The local repository (a path, or a ``repo:<path>`` spelling). Never a remote URL:
    #: ARACHNE does not clone, fetch or push, so there is nothing to authorize remotely.
    path: str = Field(min_length=1, max_length=1024)
    #: The branch a fix must never touch. ``None`` means "whatever the repo is on when the
    #: submission happens", recorded on the proposal so the invariant stays checkable.
    default_branch: str | None = Field(default=None, max_length=255)
    #: The repository's own test suite, as argv (``["python", "-m", "pytest", "-q"]``).
    #: Empty means the repo is untestable for ARACHNE.
    test_command: tuple[str, ...] = ()
    #: Accept an untestable proposal all the way to a branch/PR. Off by default: an
    #: unverified patch is exactly the risk R-18 case the requirement asks to flag.
    allow_untestable: bool = False
    #: Run the declared test command once on the base commit before the patch, so "the tests
    #: pass" can never be claimed for a tree whose suite was already failing. One extra run
    #: of the suite per submission is the price; turn it off only if the suite is far too
    #: slow to run twice, and accept that a pre-broken suite then reads as a fix.
    baseline_test_run: bool = True
    #: Asset values this grant covers (``repo:/srv/app``). Empty means "any target that
    #: resolves to this repository", which is the same thing for a single-repo grant.
    targets: tuple[str, ...] = ()
    max_files: int = Field(default=12, ge=1, le=100)
    max_changed_lines: int = Field(default=400, ge=1, le=20000)
    test_timeout_seconds: int = Field(default=900, ge=1, le=7200)
    enabled: bool = True

    @model_validator(mode="after")
    def _validate(self) -> FixRepoGrant:
        if repo_root_of(self.path) is None and not self.path.startswith(("/", "~", ".")):
            raise ValueError(
                f"grant {self.name}: path {self.path!r} is not a local directory "
                "(a remote git reference cannot be authorized)"
            )
        if self.test_command:
            program = self.test_command[0]
            if not _PROGRAM_RE.match(program):
                raise ValueError(
                    f"grant {self.name}: test command program {program!r} must be a bare "
                    "program name (no path separators), resolved through PATH"
                )
            for argument in self.test_command:
                if _FORBIDDEN_ARG_CHARS & set(argument):
                    raise ValueError(
                        f"grant {self.name}: test argument {argument!r} contains a shell "
                        "metacharacter; the command runs with shell=False, so state the "
                        "literal words only"
                    )
        if self.default_branch is not None and not _BRANCH_RE.match(self.default_branch):
            raise ValueError(
                f"grant {self.name}: default_branch {self.default_branch!r} is not a branch name"
            )
        return self

    @property
    def testable(self) -> bool:
        return bool(self.test_command)

    @property
    def root(self) -> Path | None:
        return repo_root_of(self.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "default_branch": self.default_branch,
            "testable": self.testable,
            "allow_untestable": self.allow_untestable,
            "targets": list(self.targets),
            "max_files": self.max_files,
            "max_changed_lines": self.max_changed_lines,
            "test_timeout_seconds": self.test_timeout_seconds,
            "enabled": self.enabled,
        }


class FixGrantSet(BaseModel):
    """Every grant an operator has declared. An empty set authorizes nothing."""

    model_config = _MODEL_CONFIG

    version: str = Field(default="1.0", min_length=1, max_length=32)
    repos: tuple[FixRepoGrant, ...] = ()

    @model_validator(mode="after")
    def _validate_unique(self) -> FixGrantSet:
        seen: set[str] = set()
        for grant in self.repos:
            if grant.name in seen:
                raise ValueError(f"duplicate fix-repo grant name {grant.name!r}")
            seen.add(grant.name)
        return self

    def covered(self) -> tuple[str, ...]:
        return tuple(grant.name for grant in self.repos if grant.enabled)

    def resolve(self, asset_value: str) -> RepoAuthorization | None:
        """The grant covering ``asset_value``, or ``None`` (the caller then refuses)."""
        root = repo_root_of(asset_value)
        if root is None:
            return None
        for grant in self.repos:
            if not grant.enabled:
                continue
            grant_root = grant.root
            if grant_root is None or grant_root != root:
                continue
            if grant.targets and asset_value.strip() not in grant.targets:
                continue
            return RepoAuthorization(grant=grant, root=root, target=asset_value.strip())
        return None


@dataclass(frozen=True, slots=True)
class RepoAuthorization:
    """A resolved grant: the declared repo, the tree it points at, the target it covers."""

    grant: FixRepoGrant
    root: Path
    target: str

    @property
    def name(self) -> str:
        return self.grant.name

    @property
    def testable(self) -> bool:
        return self.grant.testable

    @property
    def budgets(self) -> DiffBudgets:
        return DiffBudgets(
            max_files=self.grant.max_files, max_changed_lines=self.grant.max_changed_lines
        )


def parse_fix_grants(data: Any, *, source: str = "<memory>") -> FixGrantSet:
    if data is None:
        return FixGrantSet()
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return FixGrantSet.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(f"{source}: invalid fix-repo grants: {'; '.join(parts)}") from exc


def load_fix_grants(path: str | None = None) -> FixGrantSet:
    """Load the grant set from ``path``; no path means **nothing is authorized**.

    There is deliberately no bundled default: an authorization that ships with the tool
    would be an authorization the operator never gave.
    """
    if path is None:
        return FixGrantSet()
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"fix-repo grant file {resolved} does not exist"
        raise ConfigurationError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot read fix-repo grants {resolved}: {exc}") from exc
    return parse_fix_grants(data, source=str(resolved))
