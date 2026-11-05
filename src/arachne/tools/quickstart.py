"""Execute the getting-started guide verbatim, and measure it (REQ-DOC-005).

A quickstart nobody executes is a claim, not a document: "time to first finding under ten
minutes" cannot be measured against prose. This tool is the measurement. It reads
``docs/getting-started.md`` itself, extracts the commands the page marks as executable, runs
them in order in a shell, and fails the build the moment one of them exits non-zero. Editing the
guide changes what runs, so the page and its proof cannot drift apart.

The page's convention
---------------------

A fenced block is executed when its info string says so, and only then::

    ```bash quickstart          # run, in order, in a shell; a non-zero exit fails the job
    ```bash quickstart service  # run in the background; wait for the port it names; stop at the end
    ```bash                    # illustrative: shown to the reader, never executed

The distinction is visible to the reader — the guide explains it — and it is what lets a page
show an optional extra or a Docker command without the CI job acquiring a Docker daemon. Every
block the page marks is run; nothing else is.

How it runs
-----------

The blocks are grouped into **segments** — a ``service`` block and the blocks that probe it, or
a run of ordinary blocks — and each segment is a single ``bash -c`` invocation with a
``timeout``. A service is started in the background *inside that shell*, waited for over the
port the page names, and stopped by an ``EXIT`` trap that kills its process group, so it cannot
outlive the run however the run ends. That design is deliberate: it means this tool starts
exactly one kind of process, with a fixed argv and no shell interpolation of anything outside
the page, which the repository's own hygiene gates assert
(``tests/unit/test_http_hygiene.py::test_the_quickstart_runner_calls_a_shell_only_with_the_guide_as_its_script``).

What is measured
----------------

* the **wall clock** for the whole corridor, compared with ``--target-seconds`` (600 s by
  default, the ten-minute target the requirement names);
* the **time to first finding** — the cumulative time through the live scan, which is the
  number the ten-minute claim is actually about;
* the **version** the corridor proves, checked against the version the page declares, so "the
  doc states the version it was verified against" is a machine-checked statement and not a
  sentence someone forgot to update.

`--check` is the static half: it verifies the page declares a version that matches
``pyproject.toml`` and still contains every step of the corridor. It runs in the documentation
job on every commit; the execution itself runs in a clean container.

Usage::

    python -m arachne.tools.quickstart                 # run the corridor and measure it
    python -m arachne.tools.quickstart --check          # static: version + corridor present
    python -m arachne.tools.quickstart --self-test      # prove a failing command fails the job

Exit code is 0 when the corridor passed inside the target, 1 when a command failed, a step
timed out, the version disagreed or the budget was exceeded, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "DEFAULT_DOC",
    "DEFAULT_STEP_TIMEOUT_S",
    "DEFAULT_TARGET_SECONDS",
    "REQUIRED",
    "Block",
    "RunReport",
    "StepResult",
    "check_page",
    "declared_version",
    "main",
    "parse_blocks",
    "run",
]

DEFAULT_DOC: Final = "docs/getting-started.md"
DEFAULT_TARGET_SECONDS: Final = 600

#: How long one documented step may take before the job fails. A command that hangs must fail
#: the run rather than hold the CI job open until its own timeout: the shell is killed, and the
#: shell's EXIT trap kills any service it started.
DEFAULT_STEP_TIMEOUT_S: Final = 300.0

#: `arachne --version` after a successful corridor: it has already started once, so this is a
#: guard against a wedged interpreter rather than a wait for anything.
VERSION_TIMEOUT_S: Final = 60.0

#: The fence info string tokens this tool understands. Nothing else is executable.
RUN: Final = "quickstart"
SERVICE: Final = "service"
SHELLS: Final = frozenset({"bash", "sh"})

#: The steps the corridor must still contain, as (label, compiled pattern). `--check` fails when
#: one is missing, so removing a step from the page is a red build rather than a shorter
#: quickstart nobody notices.
REQUIRED: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("install", re.compile(r"pip install -e \"\.\[dev\]\"")),
    ("migrate", re.compile(r"arachne db upgrade")),
    ("plan", re.compile(r"arachne scan .*--dry-run")),
    ("scan", re.compile(r"^arachne scan ", re.M)),
    ("report (markdown)", re.compile(r"arachne report .*--format md")),
    ("report (html)", re.compile(r"arachne report .*--format html")),
    ("serve", re.compile(r"arachne serve --host")),
    ("health", re.compile(r"curl .*/health")),
)

_DECLARED = re.compile(
    r"Verified against ARACHNE\s+\*{0,2}(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"
)
_FENCE = re.compile(r"^\s*(?P<fence>```|~~~)\s*(?P<info>.*?)\s*$")
_PORT = re.compile(r"--port\s+(?P<port>\d+)")
_LIVE_SCAN = re.compile(r"(?m)^\s*arachne scan (?!.*--dry-run).*$")
_VERSION_OUT = re.compile(r"(?P<version>\d+\.\d+\.\d+[^\s]*)")


@dataclass(frozen=True, slots=True)
class Block:
    """One executable fenced block."""

    index: int
    kind: str
    body: str

    @property
    def summary(self) -> str:
        for line in self.body.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                return stripped
        return "(empty)"

    @property
    def port(self) -> int | None:
        match = _PORT.search(self.body)
        return int(match.group("port")) if match else None


@dataclass(frozen=True, slots=True)
class StepResult:
    index: int
    kind: str
    command: str
    seconds: float
    returncode: int
    output: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True, slots=True)
class RunReport:
    steps: tuple[StepResult, ...]
    total_seconds: float
    first_finding_seconds: float | None
    target_seconds: int
    declared_version: str | None
    observed_version: str | None
    failures: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failures


def parse_blocks(text: str) -> tuple[list[Block], list[str]]:
    """Every executable block on the page, in order, plus any problems with the convention."""
    blocks: list[Block] = []
    problems: list[str] = []
    fence: str | None = None
    info = ""
    body: list[str] = []
    started = 0
    for number, line in enumerate(text.splitlines(), start=1):
        opener = _FENCE.match(line)
        if fence is None:
            if opener:
                fence = opener.group("fence")
                info = opener.group("info")
                body = []
                started = number
            continue
        if opener and opener.group("fence") == fence:
            tokens = info.split()
            if RUN in tokens:
                bad = False
                unknown = [token for token in tokens if token not in SHELLS | {RUN, SERVICE}]
                if unknown:
                    bad = True
                    problems.append(
                        f"line {started}: quickstart block has an unknown info token "
                        f"{', '.join(unknown)} (expected: one shell, `{RUN}`, optional `{SERVICE}`)"
                    )
                shell = [token for token in tokens if token in SHELLS]
                if not shell:
                    bad = True
                    problems.append(
                        f"line {started}: quickstart block names no shell "
                        f"(expected one of {', '.join(sorted(SHELLS))})"
                    )
                kind = SERVICE if SERVICE in tokens else RUN
                block = Block(index=len(blocks) + 1, kind=kind, body="\n".join(body))
                if kind == SERVICE and block.port is None:
                    # A service block is started in the background and waited for; without the
                    # port it names, the runner could not tell "serving" from "died".
                    bad = True
                    problems.append(
                        f"line {started}: a `{SERVICE}` block must name the port it listens on "
                        f"(a `--port N` in the command)"
                    )
                # A block whose annotation the runner does not fully understand is *not* run: a
                # command nobody can describe is a command nobody should execute unattended.
                if not bad:
                    blocks.append(block)
            fence = None
            info = ""
            body = []
            continue
        body.append(line)
    if fence is not None:
        problems.append(f"line {started}: unterminated code fence")
    return blocks, problems


def declared_version(text: str) -> str | None:
    match = _DECLARED.search(text)
    return match.group("version") if match else None


def _project_version(repo: Path) -> str | None:
    import tomllib

    path = repo / "pyproject.toml"
    if not path.is_file():
        return None
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    version = document.get("project", {}).get("version")
    return str(version) if version else None


def check_page(repo: Path, doc: Path = Path(DEFAULT_DOC)) -> tuple[list[str], list[Block]]:
    """The static half: the declared version agrees, and the corridor is still whole."""
    failures: list[str] = []
    journey = repo / doc
    if not journey.is_file():
        return ([f"{doc} does not exist"], [])
    text = journey.read_text(encoding="utf-8")
    blocks, problems = parse_blocks(text)
    failures.extend(f"{doc}:{problem}" for problem in problems)
    declared = declared_version(text)
    expected = _project_version(repo)
    if declared is None:
        failures.append(
            f"{doc}: no `Verified against ARACHNE **<version>**` statement; the page must say "
            "which version it was verified against"
        )
    elif expected is not None and declared != expected:
        failures.append(f"{doc}: declares version {declared} but pyproject.toml says {expected}")
    if not blocks:
        failures.append(f"{doc}: no executable `{RUN}` block; the corridor would run nothing")
        return failures, blocks
    joined = "\n".join(block.body for block in blocks)
    for label, pattern in REQUIRED:
        if not pattern.search(joined):
            failures.append(f"{doc}: the executable corridor has no {label} step")
    return failures, blocks


#: The prologue every segment script starts with: strict mode, job control (so a backgrounded
#: service is its own process *group* and can be killed with its children), and a trap that stops
#: it however the shell ends — a passing run, a failing step, or a timeout. The group kill is
#: what stops the service itself rather than only the subshell that started it: killing the
#: subshell alone leaves the service holding the pipe open and the runner waiting for it.
_SEGMENT_HEADER: Final = """set -euo pipefail
set -m
__qs_svc=''
__qs_cleanup() {
  if [ -n "$__qs_svc" ]; then
    kill -- -"$__qs_svc" 2>/dev/null || kill "$__qs_svc" 2>/dev/null || true
    wait "$__qs_svc" 2>/dev/null || true
  fi
}
trap __qs_cleanup EXIT
"""


def _service_lines(block: Block, *, wait_ticks: int) -> list[str]:
    """The lines that start ``block`` in the background and wait for the port it names."""
    port = block.port
    indented = "\n".join(f"  {line}" for line in block.body.splitlines())
    probe = f"  if (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null; then __qs_opened=1; break; fi"
    return [
        "{",
        indented,
        "} &",
        "__qs_svc=$!",
        "__qs_opened=0",
        f"for __qs_i in $(seq 1 {wait_ticks}); do",
        probe,
        '  if ! kill -0 "$__qs_svc" 2>/dev/null; then',
        "    echo '__qs_service_died__' >&2",
        "    exit 1",
        "  fi",
        "  sleep 0.2",
        "done",
        'if [ "$__qs_opened" -ne 1 ]; then',
        "  echo '__qs_service_silent__' >&2",
        "  exit 1",
        "fi",
    ]


def _segment_script(segment: list[Block], *, wait_ticks: int) -> str:
    """The shell script for a run of blocks, with per-step markers and a service trap.

    A ``service`` block starts its command in the background, waits until the port it names
    accepts a connection, and is killed by the ``EXIT`` trap when the shell ends — so the service
    cannot outlive the run even when the run fails, and the whole segment is a *single* fixed
    ``bash -c`` invocation: no process handle is held in Python, and no step of the page is
    interpreted by anything other than the shell the reader would use.

    Each block is bracketed by ``QS_STEP_START``/``QS_STEP_END`` markers carrying a fractional
    timestamp, which is how per-step timing survives the segment being one process.
    """
    lines: list[str] = []
    for block in segment:
        # The markers carry a leading newline: a documented command may print without a trailing
        # one (curl's JSON body does), and a marker glued to that output would not be read.
        lines.append(f"printf '\\nQS_STEP_START {block.index} %s\\n' \"$(date +%s.%N)\"")
        if block.kind == SERVICE:
            lines.extend(_service_lines(block, wait_ticks=wait_ticks))
        else:
            lines.append(block.body)
        lines.append(f"printf '\\nQS_STEP_END {block.index} %s\\n' \"$(date +%s.%N)\"")
    return _SEGMENT_HEADER + "\n".join(lines) + "\n"


def _segments(blocks: list[Block]) -> list[list[Block]]:
    """Group blocks so that a ``service`` block and what follows it share one shell.

    The service must stay alive for the blocks that probe it, and only the shell that started it
    can reliably stop it, so the shell is the unit of execution — not the block.
    """
    segments: list[list[Block]] = []
    for block in blocks:
        if block.kind == SERVICE or not segments:
            segments.append([block])
        else:
            segments[-1].append(block)
    return segments


_STEP_START = re.compile(r"^QS_STEP_START (\d+) ([0-9.]+)$")
_STEP_END = re.compile(r"^QS_STEP_END (\d+) ([0-9.]+)$")


def _tail(text: str, *, lines: int = 12) -> str:
    stripped = [line for line in text.splitlines() if line.strip()]
    return "\n".join(stripped[-lines:])


def _text(value: str | bytes | None) -> str:
    """What a timed-out child wrote, as text.

    ``TimeoutExpired`` carries ``bytes`` when the caller did not ask for text, so the decoding
    is here rather than assumed: this runner always asks for text, and a future caller that does
    not should still get a readable failure rather than a traceback.
    """
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _step_timings(output: str) -> tuple[list[int], dict[int, float]]:
    """Which steps started (in order), and the wall clock of those that finished.

    A step that started but never printed its end marker is the one the shell died in — which is
    how a failure is attributed to a *block* and not only to the segment that carried it.
    """
    started: list[int] = []
    starts: dict[int, float] = {}
    durations: dict[int, float] = {}
    for line in output.splitlines():
        start = _STEP_START.match(line)
        if start:
            index = int(start.group(1))
            starts[index] = float(start.group(2))
            started.append(index)
            continue
        end = _STEP_END.match(line)
        if end:
            index = int(end.group(1))
            if index in starts:
                durations[index] = max(0.0, float(end.group(2)) - starts[index])
    return started, durations


def run(
    repo: Path,
    doc: Path = Path(DEFAULT_DOC),
    *,
    target_seconds: int = DEFAULT_TARGET_SECONDS,
    verify_version: bool = True,
    service_wait_s: float = 60.0,
    step_timeout_s: float = DEFAULT_STEP_TIMEOUT_S,
) -> RunReport:
    """Run the corridor and measure it. Never raises for a failing step."""
    journey = repo / doc
    text = journey.read_text(encoding="utf-8")
    blocks, problems = parse_blocks(text)
    failures = list(problems)
    declared = declared_version(text)
    env = dict(os.environ)
    venv_bin = repo / ".venv" / "bin"
    env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    wait_ticks = max(1, int(service_wait_s / 0.2))

    steps: list[StepResult] = []
    first_finding: float | None = None
    cumulative = 0.0
    started = time.monotonic()
    for segment in _segments(blocks):
        script = _segment_script(segment, wait_ticks=wait_ticks)
        returncode = 0
        output = ""
        timed_out = False
        try:
            completed = subprocess.run(  # the page's own commands, run by the operator's shell
                ["bash", "-c", script],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=step_timeout_s,
            )
            returncode = completed.returncode
            output = completed.stdout + completed.stderr
        except subprocess.TimeoutExpired as exc:
            # A documented command that hangs must fail the job, not hang the runner: the timeout
            # kills the shell (and the shell's trap kills any service it started).
            timed_out = True
            returncode = 1
            output = _text(exc.stdout) + _text(exc.stderr)
        started_blocks, durations = _step_timings(output)
        tail = _tail(output)
        order = {block.index: block for block in segment}
        failing: Block | None = None
        for index in started_blocks:
            block = order.get(index)
            if block is None:  # pragma: no cover - a marker for a block outside this segment
                continue
            finished = index in durations
            seconds = durations.get(index, 0.0)
            cumulative += seconds
            # A block that printed its end marker succeeded; the one that started and never
            # finished is where the shell stopped, so it carries the segment's status.
            steps.append(
                StepResult(
                    block.index,
                    block.kind,
                    block.summary,
                    seconds,
                    0 if finished else returncode,
                    tail,
                )
            )
            if not finished and failing is None:
                failing = block
            if first_finding is None and _LIVE_SCAN.search(block.body):
                first_finding = cumulative
        if timed_out:
            line = (failing or segment[-1]).summary
            failures.append(
                f"step {(failing or segment[-1]).index} ({line}) did not finish within "
                f"{step_timeout_s:.0f}s"
            )
            break
        if returncode != 0:
            target = failing or segment[-1]
            if "__qs_service_died__" in output:
                failures.append(
                    f"step {target.index} ({target.summary}) exited before it served anything:"
                    f"\n{tail}"
                )
            elif "__qs_service_silent__" in output:
                failures.append(
                    f"step {target.index} ({target.summary}) did not start listening on port "
                    f"{target.port} within {service_wait_s:.0f}s"
                )
            else:
                failures.append(f"step {target.index} ({target.summary}) exited {returncode}")
            break
    total = time.monotonic() - started

    observed: str | None = None
    if verify_version and not failures:
        check = subprocess.run(
            ["bash", "-c", "arachne --version"],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=VERSION_TIMEOUT_S,
        )
        match = _VERSION_OUT.search(check.stdout + check.stderr)
        observed = match.group("version") if match else None
        if observed is None:
            failures.append("`arachne --version` produced no version after the corridor ran")
        elif declared is not None and observed != declared:
            failures.append(
                f"the corridor proves version {observed} but the page declares {declared}"
            )
    if total > target_seconds:
        failures.append(f"the corridor took {total:.1f}s, over the {target_seconds}s target")
    return RunReport(
        steps=tuple(steps),
        total_seconds=total,
        first_finding_seconds=first_finding,
        target_seconds=target_seconds,
        declared_version=declared,
        observed_version=observed,
        failures=tuple(failures),
    )


def render(report: RunReport, doc: Path = Path(DEFAULT_DOC)) -> None:
    _out(f"quickstart: {doc} ({len(report.steps)} step(s) executed)")
    for step in report.steps:
        mark = "ok" if step.ok else "FAIL"
        _out(f"  {step.index:>2}. {step.kind:<7} {step.seconds:7.2f}s  [{mark}]  {step.command}")
        if not step.ok:
            for line in step.output.splitlines():
                _out(f"        | {line}")
    verdict = "PASS" if report.ok else "FAIL"
    margin = report.target_seconds - report.total_seconds
    _out(
        f"quickstart: total {report.total_seconds:.1f}s "
        f"(target {report.target_seconds}s, margin {margin:.1f}s) — {verdict}"
    )
    if report.first_finding_seconds is not None:
        _out(
            f"quickstart: time to first finding {report.first_finding_seconds:.1f}s "
            f"(install → migrate → plan → scan; the {report.target_seconds}s target)"
        )
    else:
        _out("quickstart: time to first finding not reached (the corridor did not get to a scan)")
    if report.declared_version:
        _out(
            f"quickstart: page declares ARACHNE {report.declared_version}; "
            f"corridor proves {report.observed_version or 'nothing'}"
        )
    for failure in report.failures:
        _err(f"quickstart: {failure}")


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _self_test() -> int:
    """Prove a failing documented command fails the job, and a good page passes."""
    good = (
        "# Quickstart\n\n"
        "Verified against ARACHNE **9.9.9**.\n\n"
        "```bash quickstart\n"
        "echo installing\n"
        "```\n\n"
        "```bash quickstart\n"
        "echo migrated\n"
        "```\n"
    )
    bad = good.replace("echo migrated", "echo about to fail\nexit 3")
    missing = (
        "# Quickstart\n\nVerified against ARACHNE **9.9.9**.\n\n```bash quickstart\necho hi\n```\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs").mkdir()
        doc = repo / DEFAULT_DOC
        doc.write_text(good, encoding="utf-8")
        passing = run(repo, verify_version=False)
        doc.write_text(bad, encoding="utf-8")
        failing = run(repo, verify_version=False)
        doc.write_text(missing, encoding="utf-8")
        static_failures, _ = check_page(repo)
        doc.write_text(good.replace("9.9.9", "0.0.1"), encoding="utf-8")
        (repo / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
        version_failures, _ = check_page(repo)
    if not passing.ok:
        _out(f"self-test FAILED: a good corridor was reported: {list(passing.failures)}")
        return 1
    if failing.ok or "exited 3" not in " ".join(failing.failures):
        _out(f"self-test FAILED: a failing command did not fail the job: {list(failing.failures)}")
        return 1
    if not static_failures:
        _out("self-test FAILED: a page missing the corridor passed --check")
        return 1
    if not version_failures:
        _out("self-test FAILED: a version disagreement passed --check")
        return 1
    _out(
        "self-test passed: a failing command fails the job, a missing step and a version "
        "disagreement fail --check, a good corridor passes"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quickstart", description="Execute and measure the getting-started guide (REQ-DOC-005)"
    )
    parser.add_argument("--check", action="store_true", help="static check: version + corridor")
    parser.add_argument("--repo", type=Path, help="repository root (default: cwd)")
    parser.add_argument("--doc", type=Path, default=Path(DEFAULT_DOC), help="the guide to execute")
    parser.add_argument(
        "--target-seconds",
        type=int,
        default=DEFAULT_TARGET_SECONDS,
        help=f"the budget the corridor is held to (default: {DEFAULT_TARGET_SECONDS})",
    )
    parser.add_argument(
        "--service-wait", type=float, default=60.0, help="seconds to wait for a port"
    )
    parser.add_argument(
        "--step-timeout",
        type=float,
        default=DEFAULT_STEP_TIMEOUT_S,
        help=f"seconds one documented step may take (default: {DEFAULT_STEP_TIMEOUT_S:.0f})",
    )
    parser.add_argument("--self-test", action="store_true", help="check the tool itself")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    repo = args.repo or Path.cwd()
    if args.check:
        failures, blocks = check_page(repo, args.doc)
        for failure in failures:
            _err(f"quickstart: {failure}")
        if failures:
            return 1
        _out(
            f"quickstart: {args.doc} declares the pyproject version and still carries "
            f"{len(blocks)} executable block(s) and every required step"
        )
        return 0
    try:
        report = run(
            repo,
            args.doc,
            target_seconds=args.target_seconds,
            service_wait_s=args.service_wait,
            step_timeout_s=args.step_timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - the guide is in the tree
        _err(f"quickstart: {exc}")
        return 2
    render(report, args.doc)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
