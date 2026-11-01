"""The lab repository, materialized as a real git repository (S27 tests).

The fixture tree (``tests/fixtures/fix-lab/``) is plain files on purpose: a ``.git``
directory committed inside ARACHNE's own tree would be a gitlink, and every test that needs a
repository would then depend on a submodule nobody can see. So the tests build one: copy the
tree, ``git init``, commit, and hand the result to the engine as the operator's granted
repository.

Two knobs change the *repository's* behaviour rather than ARACHNE's, which is what makes the
risk-R-18 and REQ-FIX-002 cases testable honestly:

* ``strict`` adds a spec that requires privileged mode, so the hardening patch **fails the
  repository's own suite** — the case the requirement says must be flagged, not submitted;
* ``testable=False`` builds the grant without a test command, the case that must be flagged
  as untestable.

Nothing here is imported by the engine; it is a test fixture, and the git calls it makes are
its own (a test may start a process; ARACHNE's process boundary lives in
:mod:`arachne.fix.gitops`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

__all__ = [
    "FIX_LAB_FIXTURE",
    "PLANTS",
    "STRICT_SPEC",
    "LabRepo",
    "build_lab_repo",
    "grant_document",
    "runner_on_path",
    "write_grants",
]

#: The committed fixture tree.
FIX_LAB_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "fix-lab"

#: The misconfigurations a test can plant, as ``(file, anchor, replacement)``. The fixture
#: tree ships clean, so "which flaw does this test fix?" is answered by the test's own call
#: rather than by a fixture everybody shares and nobody re-reads.
PLANTS: dict[str, tuple[str, str, str]] = {
    "privileged": (
        "deploy/api.yaml",
        "            readOnlyRootFilesystem: true",
        "            privileged: true\n            readOnlyRootFilesystem: true",
    ),
    "host-network": (
        "deploy/api.yaml",
        "    spec:\n      automountServiceAccountToken: false",
        "    spec:\n      hostNetwork: true\n      automountServiceAccountToken: false",
    ),
    "run-as-root": (
        "deploy/api.yaml",
        "            runAsNonRoot: true",
        "            runAsNonRoot: false",
    ),
    "latest-image": (
        "deploy/api.yaml",
        "          image: registry.internal/payments-api:1.4.2",
        "          image: registry.internal/payments-api:latest",
    ),
    "database": (
        "infra/main.tf",
        "  storage_encrypted   = true",
        "  storage_encrypted   = true\n  publicly_accessible = true",
    ),
    "unencrypted-storage": (
        "infra/main.tf",
        "  storage_encrypted   = true",
        "  storage_encrypted   = false",
    ),
    "bucket": (
        "infra/main.tf",
        '  acl    = "private"',
        '  acl    = "public-read"',
    ),
}

#: A spec that insists the container stays privileged: the "this repository needs it" case,
#: which is exactly why ARACHNE never decides on its own that a hardening change is safe.
#: It passes on a repository that *does* run privileged, so the patch is what breaks it.
STRICT_SPEC = '''"""The platform team's rule: this deployment needs privileged mode."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_the_container_stays_privileged() -> None:
    document = yaml.safe_load((ROOT / "deploy" / "api.yaml").read_text(encoding="utf-8"))
    container = document["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is True, (
        "the payments API needs privileged mode to reach the HSM"
    )
'''

#: A spec that fails on the repository as it stands: the "the suite was already red" case,
#: where a passing patched run would prove nothing at all.
BROKEN_SPEC = '''"""The platform team's target: five replicas."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_the_target_replica_count() -> None:
    document = yaml.safe_load((ROOT / "deploy" / "api.yaml").read_text(encoding="utf-8"))
    assert document["spec"]["replicas"] == 5, "the outage review set the target at five"
'''


@dataclass(frozen=True, slots=True)
class LabRepo:
    """A materialized lab repository."""

    root: Path
    default_branch: str
    base_commit: str
    test_command: tuple[str, ...]

    @property
    def asset_value(self) -> str:
        return f"repo:{self.root}"

    def head(self) -> str:
        return subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()

    def branch_commit(self, branch: str) -> str | None:
        completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            ["git", "-C", str(self.root), "rev-parse", "--verify", f"refs/heads/{branch}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    def branches(self) -> tuple[str, ...]:
        completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            [
                "git",
                "-C",
                str(self.root),
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())

    def commit_files(self, commit: str) -> tuple[str, ...]:
        completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            ["git", "-C", str(self.root), "show", "--name-only", "--format=", commit],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())

    def commit_diff(self, commit: str) -> str:
        completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            ["git", "-C", str(self.root), "show", "--format=", commit],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return completed.stdout

    def read(self, relative: str) -> str:
        return (self.root / relative).read_text(encoding="utf-8")

    def working_tree_clean(self) -> bool:
        completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
            ["git", "-C", str(self.root), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return not completed.stdout.strip()


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed argv built here, never a shell
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


def build_lab_repo(
    tmp_path: Path,
    *,
    strict: bool = False,
    broken_baseline: bool = False,
    default_branch: str = "main",
    testable: bool = True,
    plant: tuple[str, ...] = ("privileged",),
) -> LabRepo:
    """Copy the fixture tree into ``tmp_path``, plant the named misconfigurations, commit."""
    root = tmp_path / "payments-api"
    shutil.copytree(FIX_LAB_FIXTURE, root)
    for name in plant:
        relative, anchor, replacement = PLANTS[name]
        path = root / relative
        text = path.read_text(encoding="utf-8")
        assert anchor in text, f"cannot plant {name!r}: {relative} lost its anchor"
        path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    if strict:
        anchored = (root / "deploy" / "api.yaml").read_text(encoding="utf-8")
        assert "privileged: true" in anchored, "the strict spec needs a privileged container"
        (root / "specs" / "test_privileged_required.py").write_text(STRICT_SPEC, encoding="utf-8")
    if broken_baseline:
        (root / "specs" / "test_replica_target.py").write_text(BROKEN_SPEC, encoding="utf-8")
    _git("init", "--quiet", f"--initial-branch={default_branch}", cwd=root)
    _git("add", "--all", cwd=root)
    _git(
        "-c",
        "user.name=Lab Author",
        "-c",
        "user.email=lab@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "the payments API's deploy configuration",
        cwd=root,
    )
    test_command: tuple[str, ...] = (
        ("python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "specs")
        if testable
        else ()
    )
    return LabRepo(
        root=root,
        default_branch=default_branch,
        base_commit=_rev_parse(root),
        test_command=test_command,
    )


def _rev_parse(root: Path) -> str:
    completed = subprocess.run(  # noqa: S603 - a fixed argv in a test helper
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return completed.stdout.strip()


def grant_document(
    repo: LabRepo,
    *,
    name: str = "payments-api",
    allow_untestable: bool = False,
    baseline_test_run: bool = True,
    max_changed_lines: int = 400,
    targets: tuple[str, ...] = (),
) -> dict[str, object]:
    """The operator's grant file, as YAML-shaped data."""
    return {
        "version": "1.0",
        "repos": [
            {
                "name": name,
                "path": str(repo.root),
                "default_branch": repo.default_branch,
                "test_command": list(repo.test_command),
                "allow_untestable": allow_untestable,
                "baseline_test_run": baseline_test_run,
                "max_changed_lines": max_changed_lines,
                "targets": list(targets),
            }
        ],
    }


def write_grants(path: Path, *documents: dict[str, object]) -> Path:
    """Write one grants file holding every repo of every given document."""
    repos: list[object] = []
    for document in documents:
        repos.extend(document.get("repos") or [])  # type: ignore[arg-type]
    path.write_text(yaml.safe_dump({"version": "1.0", "repos": repos}), encoding="utf-8")
    return path


def runner_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the running interpreter's directory on ``PATH``.

    The grant names a bare program (``python3``) because ARACHNE starts a runner from a
    literal, never from a path. The test therefore has to make the *deployment's* PATH
    resolve that name — which is also the honest statement of the operational requirement:
    the test runner must be on the path of whoever runs ``arachne fix submit``.
    """
    directory = str(Path(sys.executable).parent)
    current = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{current}")
