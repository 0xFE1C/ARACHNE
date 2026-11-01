"""F-08-06: no ``eval``/``exec`` anywhere in the codebase.

Matchers and templates are restricted expression languages (regex, JSONPath); arbitrary
code execution from target-derived data is out of scope by design. Ruff's bandit rules
(S307) already flag these, but an explicit test keeps the guarantee visible and
independent of lint configuration.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "arachne"
BANNED_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
BANNED_ATTR_CALLS = frozenset(
    {
        "eval",
        "exec",
        "pickle.loads",
        "marshal.loads",
        "yaml.unsafe_load",
        "yaml.load_all",
        "subprocess.Popen",
    }
)


def python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


@pytest.mark.parametrize("path", python_files(), ids=lambda path: str(path.name))
def test_no_eval_exec_or_dynamic_import(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        assert name not in BANNED_CALLS, (
            f"{path.name}:{node.lineno} calls {name}(); dynamic evaluation is banned (F-08-06)"
        )
        assert name not in BANNED_ATTR_CALLS, (
            f"{path.name}:{node.lineno} calls {name}(); unsafe deserialization is banned"
        )


def test_no_dangerous_imports() -> None:
    banned_modules = {"pickle", "marshal", "shelve", "ctypes"}
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = {node.module.split(".")[0]}
            else:
                continue
            overlap = names & banned_modules
            assert not overlap, f"{path.name} imports {sorted(overlap)}; banned for safety"


def test_yaml_is_loaded_with_safe_load_only() -> None:
    for path in python_files():
        source = path.read_text(encoding="utf-8")
        if "yaml" not in source:
            continue
        assert "yaml.load(" not in source, f"{path.name} uses yaml.load(); use safe_load()"
