"""``arachne fuzz`` — bounded safe fuzzing (S30, area FUZZ).

Four verbs, in the order an operator uses them:

- ``limits`` — the deployment's ceilings and the prohibition table: the case, request and
  wall-clock bounds an operator may ask for, the read-only operation allowlist per protocol, and
  the payload classes fuzzing will not generate. Read-only, sends nothing, and the answer to
  "what is this deployment willing to fuzz?" before a plan is written.
- ``engines`` — the registered engines and the message grammars this build ships. Also read-only:
  the list is the honest answer to "what can it actually mutate?".
- ``check <plan>`` — parse, authorize and *report*: the plan as it would run, with the resolved
  bounds and the case count per target. Nothing dials, so it is the verb to run in a change
  review before anyone approves the real one.
- ``run <plan>`` — the bounded run. It refuses without a fuzzing attestation, clamps the bounds to
  the deployment's ceiling, stops at the first degradation signal, and writes candidates — never
  findings.

Every verb exits non-zero when it refuses something, and a refusal is always printed with its
reason: an operator who has just been told "no" needs to know which grant or which bound said so.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from arachne.core.audit import build_auditor
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.fuzz.attestation import authorize_fuzz
from arachne.fuzz.bounds import STOP_ABORTED, STOP_BUDGET, FuzzBudget
from arachne.fuzz.engines import engine_names, get_engine
from arachne.fuzz.http_params import DEFAULT_FAMILIES, http_cases, load_fuzz_payloads
from arachne.fuzz.plan import load_fuzz_plan, render_fuzz_plan
from arachne.fuzz.prohibitions import (
    READ_ONLY_OPERATIONS,
    READ_ONLY_VERBS,
    ProhibitionSummary,
)
from arachne.fuzz.runner import FuzzRunner
from arachne.fuzz.wire import GRAMMAR_NAMES, get_grammar

__all__ = ["app"]

app = typer.Typer(help="Bounded safe fuzzing: bounded, attested, candidate-producing.")


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.secho(f"fuzz: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


def _read_plan(path: Path) -> str:
    if not path.is_file():
        _fail(f"plan {path} does not exist")
    return path.read_text(encoding="utf-8")


@app.command("limits", help="Print the deployment's fuzzing ceilings and prohibition table.")
def limits_command() -> None:
    """Read-only: what this deployment will let a fuzzing run do."""
    settings = get_settings()
    budget = FuzzBudget.from_settings(settings.fuzz)
    typer.echo("deployment ceilings")
    typer.echo(f"  cases per target    {budget.max_cases}")
    typer.echo(f"  requests per target {budget.max_requests}")
    typer.echo(f"  seconds per target  {budget.max_seconds:g}")
    typer.echo(f"  batch size          {budget.batch_size}")
    typer.echo(f"  default engine      {settings.fuzz.engine}")
    typer.echo(
        "  production fuzzing  "
        + ("permitted by this deployment" if settings.fuzz.allow_production else "refused")
    )
    typer.echo("")
    typer.echo("abort guard")
    typer.echo(f"  min samples                {settings.fuzz.health_min_samples}")
    typer.echo(f"  max probe error rate       {settings.fuzz.max_error_rate:.0%}")
    typer.echo(f"  max probe timeout rate     {settings.fuzz.max_timeout_rate:.0%}")
    typer.echo(f"  max probe latency ratio    {settings.fuzz.max_latency_ratio:g}x")
    typer.echo(f"  max consecutive failures   {settings.fuzz.max_consecutive_failures}")
    typer.echo("")
    typer.echo("read-only operations a grammar may declare")
    for protocol in sorted(READ_ONLY_OPERATIONS):
        codes = ", ".join(f"{code:#04x}" for code in sorted(READ_ONLY_OPERATIONS[protocol]))
        typer.echo(f"  {protocol:10s} {codes}")
    for protocol in sorted(READ_ONLY_VERBS):
        typer.echo(f"  {protocol:10s} {', '.join(sorted(READ_ONLY_VERBS[protocol]))}")
    typer.echo("")
    typer.echo("payload classes fuzzing will not generate")
    summary = ProhibitionSummary()
    typer.echo(f"  {', '.join(summary.classes)}")
    heads = summary.to_dict()["destructive_sql_heads"]
    typer.echo(f"  destructive SQL heads: {', '.join(sorted(heads))}")


@app.command("engines", help="List the registered engines and the shipped message grammars.")
def engines_command(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show each grammar's fields and case count.")
    ] = False,
) -> None:
    """Read-only: what this build can mutate, and how."""
    typer.echo("engines")
    for name in engine_names():
        engine = get_engine(name)
        marker = " (default)" if name == engine_names()[0] else ""
        typer.echo(f"  {name}{marker}")
        description = getattr(engine, "description", "")
        if description:
            typer.echo(f"      {description}")
    typer.echo("")
    typer.echo(f"grammars ({len(GRAMMAR_NAMES)})")
    for name in GRAMMAR_NAMES:
        grammar = get_grammar(name)
        verifier = grammar.verifier or "-"
        typer.echo(
            f"  {name:24s} {grammar.protocol:9s} {len(grammar.case_plan()):3d} cases  "
            f"verifier={verifier}"
        )
        if verbose:
            typer.echo(f"      {grammar.description}")
            for field in grammar.fields:
                typer.echo(
                    f"      {field.offset:4d}:{field.width:<3d} {field.name:22s} {field.kind.value}"
                )
            operators = grammar.operators(grammar.fields[0])
            typer.echo(
                f"      first field's operators: "
                f"{', '.join(operator.value for operator in operators)}"
            )
    typer.echo("")
    typer.echo(f"http payload families: {', '.join(DEFAULT_FAMILIES)} (default)")


@app.command("check", help="Parse and authorize a plan and report it; sends nothing.")
def check_command(
    plan_file: Annotated[Path, typer.Argument(help="The fuzzing plan (YAML or JSON).")],
) -> None:
    """The verb to run in a change review: everything a ``run`` would decide, minus the run."""
    settings = get_settings()
    try:
        plan = load_fuzz_plan(_read_plan(plan_file), source=str(plan_file))
    except ArachneError as exc:
        _fail(str(exc))

    ceiling = FuzzBudget.from_settings(settings.fuzz)
    requested = plan.budget or ceiling
    resolved = ceiling.narrowed(
        max_cases=requested.max_cases,
        max_requests=requested.max_requests,
        max_seconds=requested.max_seconds,
        batch_size=requested.batch_size,
    )
    clamped = ceiling.clamped_fields(requested)

    typer.echo(render_fuzz_plan(plan, budget=resolved))
    if clamped:
        typer.secho(
            f"bounds clamped to the deployment ceiling: {', '.join(clamped)}",
            fg=typer.colors.YELLOW,
        )
    typer.echo("")
    typer.echo("case plan (nothing is sent by this command)")
    payloads = load_fuzz_payloads(settings.web_payloads)
    total = 0
    for target in plan.wire_targets:
        grammar = get_grammar(target.grammar)
        cases = min(len(grammar.case_plan()), resolved.max_cases)
        total += cases
        typer.echo(f"  {target.label:20s} {cases} wire cases ({target.grammar})")
    for http_plan in plan.http_plans:
        cases = len(http_cases(http_plan, payloads, limit=resolved.max_cases))
        total += cases
        typer.echo(f"  {http_plan.label:20s} {cases} http cases ({','.join(http_plan.families)})")
    typer.echo(f"  {'total':20s} {total} cases across {plan.target_count} target(s)")

    auditor = build_auditor(settings, actor="cli")
    try:
        authorization = authorize_fuzz(
            plan.definition,
            plan.attestation,
            settings=settings.fuzz,
            auditor=auditor,
            run_id=plan.run_id,
        )
    except ArachneError as exc:
        _fail(f"the plan would be refused: {exc}")
    typer.secho("", nl=False)
    typer.secho(
        f"authorized: environment={authorization.environment_class} "
        f"by {authorization.attestation.attested_by}",
        fg=typer.colors.GREEN,
    )


@app.command(
    "run",
    help="Run a bounded, attested fuzzing plan; produces candidates, never findings.",
)
def run_command(
    plan_file: Annotated[Path, typer.Argument(help="The fuzzing plan (YAML or JSON).")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the JSON report here as well as to stdout."),
    ] = None,
) -> None:
    """Run the plan. Refuses without a grant; stops at the first degradation signal."""
    settings = get_settings()
    try:
        plan = load_fuzz_plan(_read_plan(plan_file), source=str(plan_file))
    except ArachneError as exc:
        _fail(str(exc))

    scope = plan.definition.compile_scope()
    auditor = build_auditor(settings, actor="cli")
    runner = FuzzRunner(settings=settings, scope=scope, auditor=auditor)
    try:
        report = asyncio.run(runner.run(plan))
    except ArachneError as exc:
        _fail(str(exc))

    document = report.to_dict()
    if output is not None:
        output.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    typer.echo(f"run {report.run_id}: {report.status}")
    typer.echo(f"  engine        {report.engine} ({report.engine_description})")
    typer.echo(f"  cases run     {report.cases_run}")
    typer.echo(f"  candidates    {len(report.candidates)}  (candidates are not findings)")
    typer.echo(f"  healthy after {'yes' if report.healthy_after else 'NO — the run was stopped'}")
    for target in report.targets:
        typer.echo(
            f"  {target.label:20s} {target.kind:5s} {target.cases_run:4d} cases, "
            f"{len(target.candidates):3d} candidates, {target.stop_reason}"
        )
        for reason in target.abort_reasons:
            typer.secho(f"      stopped: {reason}", fg=typer.colors.YELLOW)
        for refusal in target.refusals:
            typer.secho(f"      refused: {refusal}", fg=typer.colors.RED)
    for candidate in report.candidates:
        verifier = candidate.verifier or "manual triage"
        typer.echo(
            f"  candidate {candidate.id}  {candidate.signal.value:12s} "
            f"{candidate.target} {candidate.field}/{candidate.operator} -> {verifier}"
        )
    if output is not None:
        typer.echo(f"report written to {output}")
    if report.aborted:
        raise typer.Exit(code=1)
    if report.status == STOP_BUDGET:
        typer.secho(
            "the run stopped at a bound, not at the end of its case plan",
            fg=typer.colors.YELLOW,
        )
    if report.status not in (STOP_ABORTED, STOP_BUDGET):
        typer.secho("completed within its bounds", fg=typer.colors.GREEN)
