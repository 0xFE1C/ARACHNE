"""Generate the counts the documentation claims (REQ-DOC-002).

Every number a shipped document states about the system — how many checks, how many rules,
how many tests — has been wrong at least once in this repository's history, and the reason is
always the same: it was typed by hand next to the thing that changed. This tool is the
alternative. It derives each number from the artefact that owns it:

* check counts, and the module count, from the **registry** (``ModuleRegistry.discover()``);
* the heuristic-rule count from the bundled rule corpus;
* the AI adapter count from the provider registry;
* the collected test count, and the safety-suite counts, from **pytest's own collection**;
* the research-coverage figures from the coverage tool over the corpus;
* the module count ``src/`` holds, which is the tree ``mypy --strict`` checks.

``--check`` compares the result against the committed documents and exits non-zero on the
first number that disagrees, which is what makes the badge in ``README.md`` unable to drift:
a count that changes without updating the documentation fails the build.

The two pytest collections run the project's own ``pytest`` with a fixed list of literal
arguments. There is no shell, no string concatenation and no caller-supplied value: the only
way to see a different collection is to change this file. The console script is resolved from
*this* interpreter's environment (its ``bin`` directory placed first on ``PATH``), so the
scope is the project's test scope whether or not a virtualenv happens to be active.

Usage::

    python -m arachne.tools.counts             # human-readable report
    python -m arachne.tools.counts --json      # machine-readable
    python -m arachne.tools.counts --check     # exit 1 when a documented number is stale

Exit code is 0 on success, 1 when ``--check`` finds a stale number.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

__all__ = ["Claim", "claims", "collect", "main", "module_rows", "report", "stale"]

#: The pytest collection the test count comes from, printed in the report so a reader can
#: reproduce the number by hand. The safety-suite collection below is
#: ``pytest tests/test_safety.py --collect-only -q``.
COLLECT_COMMAND: Final = 'pytest tests -m "not perf" --collect-only -q'

#: How long a collection may take. Collection imports the test modules and runs no test; a
#: suite that cannot be collected in this long is a problem the gate should report, not wait
#: for.
COLLECT_TIMEOUT_S: Final = 300


@dataclass(frozen=True, slots=True)
class Claim:
    """One documented number: the file, the literal that states it, and the metric."""

    path: str
    literal: str
    metric: str


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return here.parent  # pragma: no cover - an unpacked tree without pyproject


def _env() -> dict[str, str]:
    """The environment with this interpreter's ``bin`` directory first on ``PATH``."""
    bindir = str(Path(sys.executable).parent)
    existing = os.environ.get("PATH", "")
    return {**os.environ, "PATH": f"{bindir}{os.pathsep}{existing}"}


def _run_collect() -> str:
    """Collect the default test scope; return pytest's stdout."""
    completed = subprocess.run(
        # S607: the project's own pytest console script, resolved from this interpreter's
        # environment by ``_env`` rather than pinned to an absolute path.
        ["pytest", "tests", "-m", "not perf", "--collect-only", "-q", "-p", "no:cacheprovider"],  # noqa: S607
        cwd=_repo_root(),
        env=_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=COLLECT_TIMEOUT_S,
    )
    return completed.stdout


def _run_safety_collect() -> str:
    """Collect the primary safety suite; return pytest's stdout."""
    completed = subprocess.run(
        ["pytest", "tests/test_safety.py", "--collect-only", "-q", "-p", "no:cacheprovider"],  # noqa: S607
        cwd=_repo_root(),
        env=_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=COLLECT_TIMEOUT_S,
    )
    return completed.stdout


def _count(stdout: str) -> int:
    summary = re.search(r"(\d+) tests collected", stdout)
    if summary:
        return int(summary.group(1))
    return sum(1 for line in stdout.splitlines() if "::" in line)


@lru_cache(maxsize=1)
def collected_tests() -> tuple[int, int]:
    """``(collected, safety)`` for the default scope, from one pytest collection run."""
    stdout = _run_collect()
    total = _count(stdout)
    safety = sum(
        1
        for line in stdout.splitlines()
        if "::" in line and line.split("::", 1)[0].endswith("_safety.py")
    )
    return total, safety


def registry_counts() -> dict[str, int]:
    """Per-module and total registered-check counts, from the registry itself."""
    from arachne.modules.registry import ModuleRegistry

    registry = ModuleRegistry.discover()
    counts: dict[str, int] = {}
    for group in registry.groups:
        counts[f"checks.{group.id}"] = len(group.checks)
    counts["checks.total"] = sum(counts.values())
    counts["modules"] = len(registry.groups)
    return counts


def rule_count() -> int:
    """The heuristic rules the shipped corpus defines."""
    from arachne.analyzer.rules import load_rule_set

    return len(load_rule_set().rules)


def provider_count() -> int:
    """The AI provider adapters that can actually be built."""
    from arachne.ai.providers.registry import PROVIDER_CLASSES

    return len(PROVIDER_CLASSES)


def source_file_count() -> int:
    """How many Python modules ``src/`` contains (the tree ``mypy --strict`` checks)."""
    root = _repo_root() / "src"
    return len([path for path in root.rglob("*.py") if "__pycache__" not in path.parts])


def coverage_counts() -> tuple[int, int, float]:
    """``(mapped, total, percent)`` for the research corpus."""
    from arachne.modules.coverage import build_coverage

    report = build_coverage()
    return report.mapped, report.total, report.percent


@lru_cache(maxsize=1)
def primary_safety_tests() -> int:
    """The primary safety suite's collected test count."""
    return _count(_run_safety_collect())


def collect() -> dict[str, float]:
    """Every documented count, as a flat mapping of metric name to value."""
    values: dict[str, float] = dict(registry_counts())
    values["rules.heuristic"] = rule_count()
    values["ai.providers"] = provider_count()
    total, safety = collected_tests()
    values["tests.collected"] = total
    values["tests.safety_all"] = safety
    values["tests.safety_primary"] = primary_safety_tests()
    mapped, universe, percent = coverage_counts()
    values["coverage.mapped"] = mapped
    values["coverage.total"] = universe
    values["coverage.percent"] = percent
    values["src.modules"] = source_file_count()
    return values


def _modules() -> tuple[str, ...]:
    return tuple(
        key.removeprefix("checks.") for key in registry_counts() if key.startswith("checks.M")
    )


def claims(values: dict[str, float] | None = None) -> tuple[Claim, ...]:
    """The exact literals the committed documents must carry for ``values``."""
    counts = values or collect()
    total = int(counts["checks.total"])
    modules = int(counts["modules"])
    tests = f"{int(counts['tests.collected']):,}"
    rules = int(counts["rules.heuristic"])
    providers = int(counts["ai.providers"])
    safety = int(counts["tests.safety_primary"])
    safety_all = int(counts["tests.safety_all"])
    mapped = int(counts["coverage.mapped"])
    universe = int(counts["coverage.total"])
    percent = counts["coverage.percent"]
    src = int(counts["src.modules"])

    out: list[Claim] = [
        Claim("README.md", f"checks-{total}-", "checks.total"),
        Claim("README.md", f"**{total} registered checks**", "checks.total"),
        # The banner is the first thing a reader sees on the README, so it carries the same
        # claim as the badge. It went stale once ("152 checks" while every other surface said
        # 448) because the gate only ever read Markdown; a rendered SVG is still a document a
        # user reads, so its number is pinned like any other.
        Claim("docs/assets/banner.svg", f"· {total} checks ·", "checks.total"),
        Claim("README.md", f"checks, {modules} modules", "modules"),
        Claim("README.md", f"tests-{tests}-", "tests.collected"),
        Claim("README.md", f"**{tests} tests**", "tests.collected"),
        Claim("README.md", f"{safety}-test safety suite", "tests.safety_primary"),
        Claim("README.md", f"heuristic ({rules} rules", "rules.heuristic"),
        Claim("README.md", f"{providers} provider adapters", "ai.providers"),
        Claim("docs/release-notes.md", f"**{tests}** tests collected", "tests.collected"),
        Claim("docs/release-notes.md", f"**{safety} tests**", "tests.safety_primary"),
        Claim("docs/release-notes.md", f"**{safety_all}** in the safety files", "tests.safety_all"),
        Claim("docs/release-notes.md", f"**{src}** Python modules", "src.modules"),
        Claim("docs/operator-guide.md", f"**{mapped}/{universe} ({percent}%)**", "coverage.mapped"),
    ]
    out += [Claim("README.md", f"| **{module}**", f"checks.{module}") for module in _modules()]
    return tuple(out)


def report(values: dict[str, float]) -> str:
    """The human-readable report, in a stable order."""
    lines = ["ARACHNE documented counts (REQ-DOC-002)", f"  (test scope: {COLLECT_COMMAND})"]
    for key in sorted(values):
        value = values[key]
        rendered = f"{value:,.0f}" if float(value).is_integer() else f"{value}"
        lines.append(f"  {key:24} {rendered}")
    return "\n".join(lines)


def stale(values: dict[str, float]) -> list[str]:
    """Every claim whose literal is missing from its committed document."""
    root = _repo_root()
    missing: list[str] = []
    for claim in claims(values):
        path = root / claim.path
        if not path.is_file():  # pragma: no cover - a missing document is a different failure
            missing.append(f"{claim.path}: missing document")
            continue
        if claim.literal not in path.read_text(encoding="utf-8"):
            missing.append(f"{claim.path}: {claim.literal!r} (metric {claim.metric})")
    return missing


def module_rows() -> dict[str, int]:
    """The README module table's numbers, parsed, keyed by module id.

    Parsed rather than asserted as whole row literals so that a renamed module title does not
    fail a count test; the *number* is what must be right.
    """
    text = (_repo_root() / "README.md").read_text(encoding="utf-8")
    rows: dict[str, int] = {}
    for match in re.finditer(r"\|\s*\*\*(M\d)\*\*[^|]*\|\s*(\d+)", text):
        rows[match.group(1)] = int(match.group(2))
    return rows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="counts", description="Documentation count generator")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--check", action="store_true", help="exit 1 when a number is stale")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    values = collect()
    if args.json:
        sys.stdout.write(json.dumps(values, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(report(values) + "\n")
    if args.check:
        missing = stale(values)
        for line in missing:
            sys.stderr.write(f"stale: {line}\n")
        if missing:
            sys.stderr.write(f"counts: {len(missing)} documented number(s) are stale\n")
            return 1
        sys.stdout.write(f"counts: {len(claims(values))} documented number(s) agree\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
