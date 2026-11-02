"""The fix-repo grants: deny by default, and the argv a grant may declare (S27).

REQ-FIX-001 authorizes a repository *explicitly*; these tests pin that "explicitly" means an
operator-written file, and that the one thing a grant can make ARACHNE execute is an argv of
literal words — no shell vocabulary, no path-shaped program name.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from arachne.core.errors import ConfigurationError
from arachne.fix.gitops import TEST_RUNNERS
from arachne.fix.grants import FixGrantSet, FixRepoGrant, load_fix_grants, parse_fix_grants


def _grant(root: Path, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "payments-api",
        "path": str(root),
        "default_branch": "main",
        "test_command": ["python3", "-m", "pytest", "-q", "specs"],
    }
    payload.update(overrides)
    return payload


def test_no_grant_file_authorizes_nothing(tmp_path: Path) -> None:
    grants = load_fix_grants(None)
    assert grants.repos == ()
    assert grants.covered() == ()
    assert grants.resolve(f"repo:{tmp_path}") is None


def test_a_missing_grant_file_is_refused_loudly(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_fix_grants(str(tmp_path / "absent.yaml"))


def test_a_grant_resolves_only_its_own_resolved_root(tmp_path: Path) -> None:
    root = tmp_path / "payments-api"
    root.mkdir()
    other = tmp_path / "another-repo"
    other.mkdir()
    grants = parse_fix_grants({"version": "1.0", "repos": [_grant(root)]})
    assert grants.resolve(f"repo:{root}") is not None
    assert grants.resolve(f"repo:{other}") is None
    # A symlink to the same tree resolves to the same authorization (paths are resolved).
    link = tmp_path / "link-to-payments"
    link.symlink_to(root)
    assert grants.resolve(f"repo:{link}") is not None


def test_a_grant_can_be_narrowed_to_exact_asset_values(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    grants = parse_fix_grants(
        {"version": "1.0", "repos": [_grant(root, targets=[f"repo:{tmp_path}/elsewhere"])]}
    )
    assert grants.resolve(f"repo:{root}") is None


def test_a_disabled_grant_authorizes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    grants = parse_fix_grants({"version": "1.0", "repos": [_grant(root, enabled=False)]})
    assert grants.resolve(f"repo:{root}") is None


def test_a_remote_path_cannot_be_granted() -> None:
    with pytest.raises(ConfigurationError, match="not a local directory"):
        parse_fix_grants(
            {"version": "1.0", "repos": [{"name": "remote", "path": "git@github.com:acme/x.git"}]}
        )


def test_a_test_program_may_not_carry_a_path() -> None:
    with pytest.raises(ConfigurationError, match="bare"):
        parse_fix_grants(
            {
                "version": "1.0",
                "repos": [
                    {
                        "name": "repos",
                        "path": "/tmp",
                        "test_command": ["./ci/test.sh"],
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    "argument",
    ["tests; rm -rf /", "tests && curl x | sh", "$(whoami)", "tests`id`", "a|b", "a>b", "a*b"],
)
def test_a_test_argument_may_not_carry_shell_vocabulary(argument: str) -> None:
    with pytest.raises(ConfigurationError, match="shell"):
        parse_fix_grants(
            {
                "version": "1.0",
                "repos": [
                    {
                        "name": "repos",
                        "path": "/tmp",
                        "test_command": ["pytest", argument],
                    }
                ],
            }
        )


def test_every_declared_runner_is_a_known_one(tmp_path: Path) -> None:
    """The grant's program must be one ARACHNE has a literal spawn branch for."""
    for runner in TEST_RUNNERS:
        grant = FixRepoGrant.model_validate(
            {"name": f"r-{runner}", "path": str(tmp_path), "test_command": [runner]}
        )
        assert grant.testable
    with pytest.raises(ConfigurationError, match="bare"):
        parse_fix_grants(
            {
                "version": "1.0",
                "repos": [{"name": "x", "path": str(tmp_path), "test_command": ["/bin/sh"]}],
            }
        )


def test_an_untestable_grant_is_marked_so(tmp_path: Path) -> None:
    grants = parse_fix_grants(
        {"version": "1.0", "repos": [{"name": "r", "path": str(tmp_path), "test_command": []}]}
    )
    authorization = grants.resolve(f"repo:{tmp_path}")
    assert authorization is not None
    assert not authorization.testable
    assert not authorization.grant.allow_untestable


def test_the_grant_budget_becomes_the_diff_budget(tmp_path: Path) -> None:
    grants = parse_fix_grants(
        {
            "version": "1.0",
            "repos": [_grant(tmp_path, max_files=3, max_changed_lines=42)],
        }
    )
    authorization = grants.resolve(f"repo:{tmp_path}")
    assert authorization is not None
    budgets = authorization.budgets
    assert budgets.max_files == 3
    assert budgets.max_changed_lines == 42


def test_duplicate_grant_names_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="duplicate"):
        parse_fix_grants({"version": "1.0", "repos": [_grant(tmp_path), _grant(tmp_path)]})


def test_an_empty_grant_set_serializes_as_nothing() -> None:
    assert FixGrantSet().repos == ()
    assert FixGrantSet().covered() == ()


def test_a_grants_file_loads_from_disk(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    path = tmp_path / "grants.yaml"
    path.write_text(yaml.safe_dump({"version": "1.0", "repos": [_grant(root)]}), encoding="utf-8")
    grants = load_fix_grants(str(path))
    assert grants.covered() == ("payments-api",)
    assert grants.resolve(f"repo:{root}") is not None
