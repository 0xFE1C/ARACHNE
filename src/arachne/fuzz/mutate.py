"""Mutation testing over the safety core (REQ-QUAL-008).

Coverage says a line ran. Mutation says the assertion would have noticed if the line were
wrong. On the safety core — the scope gate, the proof ladder, the audit chain, the SQL proof
helper — "the test would not notice" is the one answer that is unacceptable, so this module is
the gate that asks the question and refuses to accept the answer silently.

**How a mutant is run.** The module's source is parsed, one node is altered, the result is
written to a temporary file, and the real test suite is run in a subprocess with
:mod:`arachne.fuzz.mutant_loader` resolving that one import name to the altered file. Nothing
is stubbed, nothing is monkeypatched, and the mutant never touches the working tree. The
subprocess command is a fixed list of literals written out at the call site — the interpreter
by name, mirroring the interpreter CI runs the suite with — and everything that varies (which
module is mutated, which tests cover it) travels in the environment, so nothing is ever
spliced into a command line.

**The interpreter matters.** The subprocess is the caller's ``python``, so the gate requires
the project's interpreter first on ``PATH`` (``.venv/bin/activate``): a ``python`` that cannot
import this package would otherwise report every mutant as killed, or as errored, for reasons
that have nothing to do with the mutant. :func:`preflight` checks that before a single mutant
runs and says so plainly.

**What counts as what — stated here because a mutation score is easy to inflate.**

* **killed** — the run ended with at least one *failed* test. The suite noticed.
* **survived** — the run passed. The suite did not notice; this is the finding.
* **timeout** — the mutant hung the suite. Counted as killed: the suite did notice, by never
  finishing, which the per-test timeout turns into a failure.
* **error** — the mutant could not even be collected or imported. It counts as *neither*:
  crediting a crash as detection would inflate the score, and the score is the number this
  gate exists to keep honest.
* **allowed** — an entry in the curated allowlist: a mutant that is genuinely equivalent to
  the original, so no test could ever kill it. Each entry carries a written reason, and the
  gate fails when an entry no longer matches any mutant.

**Why these operators.** Comparison, boolean and boundary mutations on a safety core are
where the risk lives: a ``>=`` that should be ``>`` is the classic off-by-one on a scope
boundary, and an ``and`` that should be ``or`` is the classic fail-open. Arithmetic and
blank-statement mutations are deliberately out of scope — they produce volume, not signal, on
this code.

**Bounded runtime.** ``--sample N`` selects a deterministic subset (every k-th mutant) for a
pull request; the nightly job runs the whole set. ``--budget-seconds`` stops the run and
reports what it managed rather than letting a slow mutant hold the job.

Usage::

    python -m arachne.fuzz.mutate --list                # every mutant, no tests run
    python -m arachne.fuzz.mutate --sample 12 --check   # the pull-request subset, gated
    python -m arachne.fuzz.mutate --check --json        # the nightly run, gated
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import typer

from arachne.fuzz.mutant_loader import MODULE_ENV, SOURCE_ENV, STATUS_ENV, TESTS_ENV

__all__ = [
    "ALLOWED",
    "DEFAULT_CONFIG_FILE",
    "ERROR",
    "KILLED",
    "OPERATORS",
    "SURVIVED",
    "TIMEOUT",
    "Mutant",
    "MutationConfig",
    "MutationReport",
    "Outcome",
    "all_mutants",
    "classify",
    "default_config_file",
    "module_name",
    "mutants_for_module",
    "mutation_sites",
    "preflight",
    "run_gate",
    "run_mutant",
    "select",
    "stale_allowlist",
]

DEFAULT_CONFIG_FILE: Final = Path("pyproject.toml")
CONFIG_TABLE: Final = "tool.arachne.mutation"

KILLED: Final = "killed"
SURVIVED: Final = "survived"
TIMEOUT: Final = "timeout"
ERROR: Final = "error"
ALLOWED: Final = "allowed"

#: The operators this gate applies. Comparison and boolean first, because that is where a
#: safety core breaks; the literal ones catch a fail-open default.
OPERATORS: Final[tuple[str, ...]] = (
    "compare-op",
    "bool-op",
    "bool-literal",
    "not-removal",
    "number",
)

_COMPARISON_SWAPS: Final[dict[type[ast.cmpop], type[ast.cmpop]]] = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}

#: A pytest summary line like ``1 failed, 2 passed`` — the evidence that a test failed.
_FAILED_LINE: Final = re.compile(r"\d+ (?:failed|error)")
#: A module that will not even import is an errored mutant, not a detected one.
_COLLECTION_ERROR: Final = re.compile(r"errors? during collection|ERROR collecting", re.IGNORECASE)


class GateError(RuntimeError):
    """The gate cannot run: the environment is wrong, not the code under test."""


@dataclass(frozen=True, slots=True)
class TargetScope:
    """One module under mutation and the tests that cover it.

    The scope is per module rather than one list for all four: a mutant in ``proof/sql.py``
    has no business running the scope-gate suite, and narrowing the scope is what keeps a
    full run inside a nightly job. The direction of the risk is understood — a narrower scope
    can only produce *more* survivors, never fewer, so it cannot flatter the score.
    """

    path: str
    tests: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "tests": list(self.tests)}


@dataclass(frozen=True, slots=True)
class Site:
    """One place a mutation could be applied."""

    lineno: int
    operator: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.lineno, "operator": self.operator, "description": self.description}


@dataclass(frozen=True, slots=True)
class Mutant:
    """One mutation of one module: the altered source, the scope it is judged by, and origin."""

    module: str
    path: str
    site: Site
    source: str
    tests: tuple[str, ...] = ()
    occurrence: int = 1

    @property
    def identifier(self) -> str:
        """The allowlist key: stable while the line does not move."""
        base = f"{self.path}:{self.site.lineno}:{self.site.operator}"
        return base if self.occurrence == 1 else f"{base}#{self.occurrence}"

    @property
    def location(self) -> str:
        return f"{self.path}:{self.site.lineno}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "module": self.module,
            "path": self.path,
            "line": self.site.lineno,
            "operator": self.site.operator,
            "description": self.site.description,
            "tests": list(self.tests),
        }


class _Mutation(ast.NodeTransformer):
    """Walk the tree in source order; optionally mutate the node at ``target``.

    Used twice with the same traversal, so a site's index is the index the mutation uses.
    With ``target=None`` it only records sites; with a target it applies that one mutation
    and leaves every other node alone.

    ``declared`` holds the constants this walk refuses to touch: those that *configure a
    declaration* rather than take part in a decision — a decorator's arguments
    (``@dataclass(frozen=True, slots=True)``) and a ``field(...)`` call's
    (``field(init=False, compare=False)``). They are metadata about a class's own shape; no
    branch of the safety logic reads them, and a test that noticed ``slots=False`` would be
    testing Python's dataclass machinery. The first full run measured them from the other side:
    all 24 of those mutants survived, across every module, which is what "this is not a
    decision" looks like as data.
    """

    def __init__(self, target: int | None = None, declared: set[int] | None = None) -> None:
        self.target = target
        self.declared = declared or set()
        self.sites: list[Site] = []

    def _offer(self, node: ast.AST, operator: str, description: str, apply: Any) -> None:
        if id(node) in self.declared:
            return
        index = len(self.sites)
        self.sites.append(Site(int(getattr(node, "lineno", 0)), operator, description))
        if self.target is not None and index == self.target:
            apply()

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        for position, operator in enumerate(node.ops):
            replacement = _COMPARISON_SWAPS.get(type(operator))
            if replacement is None:
                continue

            def swap(
                node: ast.Compare = node,
                position: int = position,
                replacement: type[ast.cmpop] = replacement,
            ) -> None:
                node.ops[position] = replacement()

            self._offer(
                node, "compare-op", f"{type(operator).__name__} -> {replacement.__name__}", swap
            )
        return self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        if isinstance(node.op, ast.And | ast.Or):
            replacement: type[ast.boolop] = ast.Or if isinstance(node.op, ast.And) else ast.And

            def swap_op(
                node: ast.BoolOp = node, replacement: type[ast.boolop] = replacement
            ) -> None:
                node.op = replacement()

            self._offer(
                node, "bool-op", f"{type(node.op).__name__} -> {replacement.__name__}", swap_op
            )
        return self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        if isinstance(node.op, ast.Not):
            # `not x` cannot be expressed by editing the UnaryOp in place; the mutation is
            # applied by the second pass in `_mutate_source`, which knows the parent.
            self._offer(node, "not-removal", "not x -> x", lambda: None)
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        value = node.value
        if isinstance(value, bool):
            replacement_bool = not value

            def flip(node: ast.Constant = node, replacement: bool = replacement_bool) -> None:
                node.value = replacement

            self._offer(node, "bool-literal", f"{value} -> {not value}", flip)
        elif isinstance(value, int) and value in (0, 1):
            replacement_int = 0 if value == 1 else 1

            def swap_number(node: ast.Constant = node, replacement: int = replacement_int) -> None:
                node.value = replacement

            self._offer(node, "number", f"{value} -> {replacement_int}", swap_number)
        return node


def declaration_constants(tree: ast.AST) -> set[int]:
    """The constants a decorator or a ``field(...)`` call carries — declaration metadata.

    Collected by identity (``id``) from one parse, and consulted by the walk over that same
    parse, so the two agree on which node is which.
    """
    declared: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            for decorator in node.decorator_list:
                declared.update(
                    id(inner) for inner in ast.walk(decorator) if isinstance(inner, ast.Constant)
                )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "field"
        ):
            declared.update(
                id(inner) for inner in ast.walk(node) if isinstance(inner, ast.Constant)
            )
    return declared


def mutation_sites(source: str) -> tuple[Site, ...]:
    """Every site the operators would mutate in ``source``."""
    tree = ast.parse(source)
    walker = _Mutation(None, declaration_constants(tree))
    walker.visit(tree)
    return tuple(walker.sites)


class _NotRemoval(ast.NodeTransformer):
    """Replace the ``not`` at a known line with its operand, whatever the operand is."""

    def __init__(self, target_line: int) -> None:
        self.target_line = target_line
        self.applied = False

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if (
            not self.applied
            and isinstance(node.op, ast.Not)
            and int(getattr(node, "lineno", -1)) == self.target_line
        ):
            self.applied = True
            return node.operand
        return node


def _mutate_source(source: str, index: int) -> str:
    """``source`` with the site at ``index`` mutated."""
    tree = ast.parse(source)
    walker = _Mutation(index, declaration_constants(tree))
    mutated = walker.visit(tree)
    if walker.sites[index].operator == "not-removal":
        remover = _NotRemoval(walker.sites[index].lineno)
        mutated = remover.visit(mutated)
        if not remover.applied:  # pragma: no cover - the site came from this same tree
            msg = "the not-removal site could not be located after mutation"
            raise RuntimeError(msg)
    ast.fix_missing_locations(mutated)
    return ast.unparse(mutated)


def mutants_for_module(path: str | Path, *, tests: Sequence[str] = ()) -> tuple[Mutant, ...]:
    """Every mutant for one module file, judged by ``tests``."""
    target = Path(path)
    source = target.read_text(encoding="utf-8")
    module = module_name(target)
    scope = tuple(str(item) for item in tests)
    tree = ast.parse(source)
    declared = declaration_constants(tree)
    walker = _Mutation(None, declared)
    walker.visit(tree)
    mutants: list[Mutant] = []
    seen: dict[str, int] = {}
    for index, site in enumerate(walker.sites):
        altered = _mutate_source(source, index)
        key = f"{site.lineno}:{site.operator}"
        seen[key] = seen.get(key, 0) + 1
        mutants.append(
            Mutant(
                module=module,
                path=str(target),
                site=site,
                source=altered,
                tests=scope,
                occurrence=seen[key],
            )
        )
    return tuple(mutants)


def repo_root() -> Path:
    """The checkout root, found from this module's location (``src/arachne/fuzz/mutate.py``)."""
    return Path(__file__).resolve().parents[3]


def module_name(path: str | Path, *, root: str | Path | None = None) -> str:
    """The import name a file is reachable by: ``src/arachne/core/safety.py`` → the module.

    The path is taken relative to the checkout root first, so an absolute path and a relative
    one name the same module — which is what the loader matches on. Without that, a target
    outside ``src/`` (a test fixture, say) would resolve to its filesystem path and the finder
    would never match it, and *every* mutant of that target would look like a survivor.
    """
    resolved = Path(path).resolve()
    base = Path(root).resolve() if root is not None else repo_root()
    try:
        relative = resolved.relative_to(base)
    except ValueError:
        relative = Path(resolved.name)
    parts = list(relative.with_suffix("").parts)
    if "src" in parts:
        parts = parts[parts.index("src") + 1 :]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


# ------------------------------------------------------------------------------- config
@dataclass(frozen=True, slots=True)
class MutationConfig:
    """The gate's policy, as committed in ``pyproject.toml``."""

    targets: tuple[TargetScope, ...]
    min_score: float
    sample: int
    timeout_seconds: int
    budget_seconds: int
    #: The floor a *bounded subset* is held to. Twelve mutants cannot resolve three points, so
    #: the subset is a smoke test for a broken gate, not a measurement; the number has a
    #: statistical reason and it is written down in ``pyproject.toml``.
    min_score_sample: float = 0.0
    allowlist: Mapping[str, str] = field(default_factory=dict)

    def floor_for(self, *, partial: bool) -> float:
        """The floor a report should be judged by."""
        return self.min_score_sample if partial else self.min_score

    @property
    def tests(self) -> tuple[str, ...]:
        """Every test path any target is judged by, without duplicates."""
        seen: dict[str, None] = {}
        for target in self.targets:
            for path in target.tests:
                seen.setdefault(path, None)
        return tuple(seen)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CONFIG_FILE) -> MutationConfig:
        document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        table: Any = document
        for key in CONFIG_TABLE.split("."):
            table = table.get(key, {}) if isinstance(table, dict) else {}
        if not isinstance(table, dict) or not table:
            msg = f"{path} has no [{CONFIG_TABLE}] table"
            raise ValueError(msg)
        targets = tuple(
            TargetScope(
                path=str(entry["path"]),
                tests=tuple(str(item) for item in entry.get("tests", ())),
            )
            for entry in table.get("target", [])
        )
        if not targets:
            msg = f"{path} declares no [[{CONFIG_TABLE}.target]] entries"
            raise ValueError(msg)
        allowlist = {
            str(entry["id"]): str(entry.get("reason", "")).strip()
            for entry in table.get("allowlist", [])
        }
        missing = [key for key, reason in allowlist.items() if not reason]
        if missing:
            msg = f"allowlist entries with no reason: {', '.join(sorted(missing))}"
            raise ValueError(msg)
        return cls(
            targets=targets,
            min_score=float(table.get("min_score", 0.0)),
            sample=int(table.get("sample", 0)),
            timeout_seconds=int(table.get("timeout_seconds", 180)),
            budget_seconds=int(table.get("budget_seconds", 0)),
            min_score_sample=float(table.get("min_score_sample") or table.get("min_score") or 0.0),
            allowlist=allowlist,
        )


@dataclass(frozen=True, slots=True)
class Outcome:
    """One mutant's verdict."""

    mutant: Mutant
    status: str
    seconds: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.mutant.to_dict(),
            "status": self.status,
            "seconds": round(self.seconds, 3),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class MutationReport:
    """The gate's result."""

    outcomes: tuple[Outcome, ...]
    min_score: float
    #: ``"full"`` when every mutant ran, ``"sample"`` when a bounded subset did. The floor a
    #: subset is held to is lower, and the report says which one was applied.
    floor_kind: str = "full"
    stopped_early: bool = False

    @property
    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
        return counts

    @property
    def killed(self) -> int:
        return self.by_status.get(KILLED, 0) + self.by_status.get(TIMEOUT, 0)

    @property
    def survived(self) -> int:
        return self.by_status.get(SURVIVED, 0)

    @property
    def scored(self) -> int:
        return self.killed + self.survived

    @property
    def score(self) -> float:
        return self.killed / self.scored if self.scored else 1.0

    @property
    def survivors(self) -> tuple[Outcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.status == SURVIVED)

    @property
    def ok(self) -> bool:
        return self.score >= self.min_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "min_score": self.min_score,
            "ok": self.ok,
            "counts": self.by_status,
            "scored": self.scored,
            "floor_kind": self.floor_kind,
            "stopped_early": self.stopped_early,
            "survivors": [outcome.to_dict() for outcome in self.survivors],
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }

    def summary(self) -> str:
        counts = ", ".join(f"{count} {status}" for status, count in sorted(self.by_status.items()))
        verdict = "PASS" if self.ok else "FAIL"
        return (
            f"mutation {verdict}: score {self.score:.1%} against the {self.floor_kind} floor of "
            f"{self.min_score:.0%} ({counts or 'nothing run'})"
        )


def select(mutants: Sequence[Mutant], sample: int) -> tuple[Mutant, ...]:
    """The deterministic subset a pull request runs: every k-th mutant, in order."""
    if sample <= 0 or sample >= len(mutants):
        return tuple(mutants)
    stride = len(mutants) / sample
    return tuple(mutants[int(index * stride)] for index in range(sample))


def all_mutants(config: MutationConfig) -> tuple[Mutant, ...]:
    """Every mutant the configuration selects, in a stable order."""
    mutants: list[Mutant] = []
    for target in config.targets:
        mutants.extend(mutants_for_module(target.path, tests=target.tests))
    return tuple(sorted(mutants, key=lambda mutant: mutant.identifier))


def classify(returncode: int, output: str, *, loaded: bool = True) -> tuple[str, str]:
    """Turn a pytest exit into a verdict, refusing to credit a crash as detection.

    ``loaded`` is the plugin's own report of whether the mutant was really swapped in. When it
    is False nothing about the run can be believed — the suite just ran against the original
    code — so the outcome is an error whatever the exit code says.
    """
    if not loaded:
        return ERROR, "the mutant was never loaded: this run measured the original module"
    if returncode == 0:
        return SURVIVED, ""
    if _COLLECTION_ERROR.search(output):
        return ERROR, "the mutant could not be collected (not counted as detection)"
    if returncode == 1 and _FAILED_LINE.search(output):
        return KILLED, ""
    return ERROR, f"pytest exited {returncode} without a failing test"


def preflight(config: MutationConfig) -> str:
    """Refuse to start unless the interpreter the subprocesses will use can import us.

    A ``python`` that resolves to something other than this project's interpreter — or to
    nothing at all — would make every mutant look errored: a whole gate's worth of noise about
    nothing. Checking once, up front, turns that into one clear sentence.
    """
    try:
        probe = subprocess.run(
            ["python", "-c", "import arachne, pytest; print(pytest.__version__)"],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except OSError as exc:
        msg = (
            f"no 'python' could be run from PATH ({exc}), so the mutation gate cannot run: "
            "activate the project's virtualenv first"
        )
        raise GateError(msg) from exc
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout or "").strip().splitlines()
        msg = (
            "'python' on PATH cannot import arachne and pytest, so the mutation gate cannot "
            "run: activate the project's virtualenv (or put its bin on PATH) first. "
            f"{detail[-1] if detail else ''}"
        )
        raise GateError(msg)
    environment = dict(os.environ)
    environment[TESTS_ENV] = json.dumps(list(config.tests))
    check = subprocess.run(
        [
            "python",
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
        ],
        cwd=Path.cwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if check.returncode != 0:
        msg = f"the test suite could not be collected: {(check.stdout or '')[-400:]}"
        raise GateError(msg)
    return probe.stdout.strip()


def run_mutant(mutant: Mutant, config: MutationConfig) -> Outcome:
    """Run the suite against one mutant: a subprocess, the real tests, one module swapped.

    ``--tb=no -q -x`` keeps the output to the verdict, ``-o addopts=`` clears the repository's
    own addopts so a mutant run is the tests and nothing else, and
    ``-p arachne.fuzz.mutant_loader`` loads the plugin that swaps the module and scopes the
    run. Everything that varies travels in the environment, never in the command line.

    The verdict comes from two things: the plugin's own written word on whether the module was
    really swapped (``ARACHNE_MUTANT_STATUS``), and pytest's exit code. A run that never loaded
    the mutant cannot be scored at all, so it is an error however it ended.
    """
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="arachne-mutant-") as directory:
        source_path = Path(directory) / f"{Path(mutant.path).name}"
        source_path.write_text(mutant.source, encoding="utf-8")
        status_path = Path(directory) / "status.json"
        environment = dict(os.environ)
        environment[MODULE_ENV] = mutant.module
        environment[SOURCE_ENV] = str(source_path)
        environment[TESTS_ENV] = json.dumps(list(mutant.tests))
        environment[STATUS_ENV] = str(status_path)
        try:
            completed = subprocess.run(
                [
                    "python",
                    "-m",
                    "pytest",
                    "-x",
                    "-q",
                    "--tb=no",
                    "-p",
                    "no:cacheprovider",
                    "-o",
                    "addopts=",
                    "-p",
                    "arachne.fuzz.mutant_loader",
                ],
                cwd=Path.cwd(),
                env=environment,
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return Outcome(
                mutant,
                TIMEOUT,
                time.monotonic() - started,
                f"the suite did not finish in {config.timeout_seconds}s",
            )
        loaded = _mutant_was_loaded(status_path)
    output = (completed.stdout or "") + (completed.stderr or "")
    status, detail = classify(completed.returncode, output, loaded=loaded)
    return Outcome(mutant, status, time.monotonic() - started, detail)


def _mutant_was_loaded(status_path: Path) -> bool:
    """Whether the plugin reported a real swap. A missing report is not a load."""
    try:
        report = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(report.get("loaded")) if isinstance(report, dict) else False


def run_gate(
    config: MutationConfig,
    *,
    sample: int | None = None,
    budget_seconds: int | None = None,
    progress: Any = None,
) -> MutationReport:
    """Run the gate over the selected mutants and return the report."""
    every = all_mutants(config)
    wanted = select(every, sample if sample is not None else config.sample)
    budget = budget_seconds if budget_seconds is not None else config.budget_seconds
    partial = len(wanted) < len(every)
    started = time.monotonic()
    outcomes: list[Outcome] = []
    stopped_early = False
    for mutant in wanted:
        if budget and time.monotonic() - started > budget:
            stopped_early = True
            break
        if mutant.identifier in config.allowlist:
            outcomes.append(Outcome(mutant, ALLOWED, 0.0, config.allowlist[mutant.identifier]))
        else:
            outcomes.append(run_mutant(mutant, config))
        if progress is not None:
            progress(outcomes[-1])
    return MutationReport(
        outcomes=tuple(outcomes),
        min_score=config.floor_for(partial=partial),
        floor_kind="sample" if partial else "full",
        stopped_early=stopped_early,
    )


def stale_allowlist(config: MutationConfig) -> tuple[str, ...]:
    """Allowlist entries that no longer match a mutant — an allowlist that has rotted."""
    known = {mutant.identifier for mutant in all_mutants(config)}
    return tuple(sorted(key for key in config.allowlist if key not in known))


def default_config_file() -> Path:
    return repo_root() / DEFAULT_CONFIG_FILE


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m arachne.fuzz.mutate",
        description="Mutation testing over the safety core (REQ-QUAL-008).",
    )
    parser.add_argument("--config", type=Path, default=None, help="The pyproject.toml to read.")
    parser.add_argument("--sample", type=int, default=None, help="Run a deterministic subset.")
    parser.add_argument("--budget-seconds", type=int, default=None, help="Stop after this long.")
    parser.add_argument("--list", action="store_true", help="List the mutants and stop.")
    parser.add_argument("--check", action="store_true", help="Fail below the minimum score.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    args = parser.parse_args(argv)

    try:
        config = MutationConfig.load(args.config or default_config_file())
    except (OSError, ValueError, KeyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        return 2

    every = all_mutants(config)
    stale = stale_allowlist(config)
    if args.list:
        for mutant in every:
            mark = " (allowlisted)" if mutant.identifier in config.allowlist else ""
            typer.echo(f"{mutant.identifier}\t{mutant.site.description}{mark}")
        typer.echo(f"{len(every)} mutant(s), {len(config.allowlist)} allowlisted")
        return 0

    def progress(outcome: Outcome) -> None:
        if not args.json:
            typer.echo(
                f"  {outcome.status.upper():<9} {outcome.mutant.location}  "
                f"{outcome.mutant.site.description}  ({outcome.seconds:.1f}s)",
                err=True,
            )

    try:
        version = preflight(config)
    except (GateError, subprocess.TimeoutExpired) as exc:
        typer.echo(f"error: {exc}", err=True)
        return 2
    if not args.json:
        planned = len(select(every, args.sample or config.sample))
        typer.echo(f"running {planned} mutant(s) on pytest {version}")

    report = run_gate(
        config, sample=args.sample, budget_seconds=args.budget_seconds, progress=progress
    )
    payload = report.to_dict()
    payload["stale_allowlist"] = list(stale)
    payload["allowlist_size"] = len(config.allowlist)
    if args.json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for outcome in report.survivors:
            typer.echo(
                f"SURVIVOR {outcome.mutant.location}  {outcome.mutant.site.description}", err=True
            )
        for key in stale:
            typer.echo(f"STALE ALLOWLIST ENTRY {key}", err=True)
        typer.echo(report.summary())
    stale_matters = bool(stale) and not args.sample
    if stale_matters:
        typer.echo("the allowlist lists mutants that no longer exist", err=True)
    if args.check and (not report.ok or stale_matters):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    raise SystemExit(main())
