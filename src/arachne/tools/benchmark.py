"""``python -m arachne.tools.benchmark`` — run the benchmark harness and gate on it (REQ-QUAL-005).

This is the CI entry point (the ``benchmark`` job in ``.github/workflows/ci.yml`` runs it) and
the operator's command. Three modes:

``--lab``
    Run the in-repo ground-truth lab (``tests/lab/web_lab.py``, the same vulnerable-by-design
    application the acceptance tests scan) and score the result. Fully offline apart from
    loopback, deterministic, and the suite's cases come from the lab's *own* declared ground
    truth — which is what makes the score mean something.
``--suite NAME --target URL``
    Run a suite against a hosted target (OWASP Benchmark, Juice Shop, DVWA). Needs the target
    and, for most of them, a credential and an attestation; the suite file documents the exact
    command.
``--gate``
    Compare every measured result against its committed baseline under ``benchmarks/`` and exit
    non-zero on a regression. Without ``--gate`` the run just prints and (with
    ``--write-baseline``) records.

Exit codes: ``0`` ok, ``1`` a regression or an inconsistency, ``2`` a usage/target error.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne import __version__
from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError
from arachne.quality.benchmark import (
    BenchmarkResult,
    BenchmarkSuite,
    GateReport,
    gate,
    load_suites,
    measure,
    result_from_score,
    verify_recorded,
    write_result,
)

__all__ = ["main"]

app = typer.Typer(
    name="benchmark",
    help="Score ARACHNE against ground-truth benchmark suites (S21, REQ-QUAL-005).",
    add_completion=False,
)


def _baseline_dir() -> Path:
    """``<repo>/code/benchmarks``: the committed results live beside the code that produced them.

    ``parents[3]`` is ``code/`` (``tools`` → ``arachne`` → ``src`` → ``code``), so the results
    sit next to the source tree that generated them and travel with it.
    """
    return Path(__file__).resolve().parents[3] / "benchmarks"


@app.command()
def run(
    suite: Annotated[
        str | None, typer.Option("--suite", help="Suite name (default: every shipped suite).")
    ] = None,
    lab: Annotated[
        bool, typer.Option("--lab", help="Run the in-repo ground-truth lab suite.")
    ] = False,
    target: Annotated[
        str | None, typer.Option("--target", help="Scan this URL and score the suite against it.")
    ] = None,
    gate_results: Annotated[
        bool, typer.Option("--gate", help="Fail on a regression against the committed baseline.")
    ] = False,
    write_baseline: Annotated[
        bool, typer.Option("--write-baseline", help="Commit this run as the new baseline.")
    ] = False,
    max_detection_drop: Annotated[
        float, typer.Option("--max-detection-drop", help="Tolerated detection drop.")
    ] = 0.02,
    max_fp_rise: Annotated[
        float, typer.Option("--max-fp-rise", help="Tolerated false-positive-rate rise.")
    ] = 0.02,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the report as JSON.")] = False,
) -> None:
    """Measure the suites and (with ``--gate``) block on a regression."""
    suites = load_suites()
    selected: list[BenchmarkSuite] = []
    if suite:
        if suite not in suites:
            typer.echo(f"unknown suite {suite!r}; known: {', '.join(sorted(suites))}", err=True)
            raise typer.Exit(code=2)
        selected = [suites[suite]]
    elif lab:
        selected = [suites["arachne-lab"]]
    elif target:
        if not suite:
            typer.echo("--target needs --suite", err=True)
            raise typer.Exit(code=2)
    else:
        selected = list(suites.values())

    reports: list[GateReport] = []
    measured_results: dict[str, BenchmarkResult] = {}
    for item in selected:
        if item.source == "lab" and (lab or (suite == item.name and target is None)):
            result = _run_lab(item)
            measured_results[item.name] = result
            reports.append(
                gate(
                    result,
                    directory=_baseline_dir(),
                    max_detection_drop=max_detection_drop,
                    max_fp_rise=max_fp_rise,
                )
                if gate_results
                else GateReport(suite=item.name, measured=True, score=result.numbers)
            )
            if write_baseline:
                write_result(_baseline_dir() / item.name / "baseline.json", result)
                typer.echo(f"wrote baseline for {item.name} ({result.numbers.record()})")
        elif target and suite:
            result = _run_target(item, target)
            measured_results[item.name] = result
            reports.append(
                gate(
                    result,
                    directory=_baseline_dir(),
                    max_detection_drop=max_detection_drop,
                    max_fp_rise=max_fp_rise,
                )
                if gate_results
                else GateReport(suite=item.name, measured=True, score=result.numbers)
            )
            if write_baseline:
                write_result(_baseline_dir() / item.name / "baseline.json", result)
                typer.echo(f"wrote baseline for {item.name} ({result.numbers.record()})")
        else:
            # A suite whose target is hosted elsewhere: the gate verifies what it can (the
            # committed baseline's presence and arithmetic) and says so.
            report = (
                verify_recorded(item, directory=_baseline_dir())
                if gate_results
                else (GateReport(suite=item.name, measured=False))
            )
            reports.append(report)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "arachne_version": __version__,
                    "ok": all(report.ok for report in reports),
                    "suites": [report.to_dict() for report in reports],
                },
                indent=2,
            )
        )
    else:
        _print(reports)
    if gate_results and not all(report.ok for report in reports):
        raise typer.Exit(code=1)


def _print(reports: Sequence[GateReport]) -> None:
    for report in reports:
        if report.score is not None:
            state = "measured" if report.measured else "recorded"
            typer.echo(f"{report.suite} ({state}): {report.score.record()}")
        else:
            typer.echo(f"{report.suite}: not measured")
        for problem in report.problems:
            typer.echo(f"  PROBLEM: {problem}", err=True)
        for regression in report.regressions:
            typer.echo(f"  REGRESSION [{regression.kind}]: {regression.detail}", err=True)
        for note in report.notes:
            typer.echo(f"  note: {note}")


# --------------------------------------------------------------------------- runners


def _run_lab(suite: BenchmarkSuite) -> BenchmarkResult:
    """Run the in-repo ground-truth lab and score it (the suite CI can gate on).

    The lab and the agentic harness are loaded **dynamically**, not imported: a shipped tool
    must not depend statically on the test suite, and the operator gets one clear message when
    it is missing instead of an import error at module load.
    """
    try:
        lab_module = importlib.import_module("tests.lab.web_lab")
        harness_module = importlib.import_module("tests.integration.test_agentic")
    except ImportError as exc:  # pragma: no cover - the lab is part of this repository
        raise ConfigurationError(
            "the in-repo lab suite needs this repository's test lab "
            "(tests/lab/web_lab.py): run it from a checkout"
        ) from exc

    async def measure_lab() -> Any:
        with lab_module.start_web_lab() as lab:
            harness = harness_module.make_harness(lab)
            request = harness.request
            if request is None:  # pragma: no cover - the harness always builds one
                raise ConfigurationError("the benchmark harness built no scan request")
            session = await harness.orchestrator.scan(request)
            if session.scan_id is None:  # pragma: no cover - a scan always has an id
                raise ConfigurationError("the benchmark scan produced no scan id")
            records = harness.findings.list_candidates(int(session.scan_id))
            return measure(records, suite)

    score = asyncio.run(measure_lab())
    return result_from_score(suite, score, arachne_version=__version__)


def _run_target(suite: BenchmarkSuite, target: str) -> BenchmarkResult:
    """Scan a hosted target and score the suite against it."""
    from arachne.core.target import (
        ModuleSelection,
        ScanOptions,
        ScanRequest,
        TargetDefinition,
        TargetKind,
        TargetSelector,
    )
    from arachne.data.services import build_orchestrator, build_services

    settings = get_settings()
    services = build_services(settings)
    try:
        definition = TargetDefinition(
            name=f"benchmark:{suite.name}",
            targets=(TargetSelector(kind=TargetKind.URL, value=target),),
        )
        request = ScanRequest(
            target=definition,
            # A benchmark scan is read-only detection: no active opt-in, no attestation, so it
            # cannot do anything the suite did not intend.
            options=ScanOptions(modules=ModuleSelection(enabled=("M3", "M4"))),
        )
        orchestrator = build_orchestrator(services)
        session = asyncio.run(orchestrator.scan(request))
        if session.scan_id is None:  # pragma: no cover
            raise ConfigurationError("the benchmark scan produced no scan id")
        records = services.findings.list_candidates(int(session.scan_id))
        score = measure(records, suite)
        return result_from_score(suite, score, arachne_version=__version__, target=target)
    finally:
        services.close()


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(app())
