"""``arachne fix`` — remediation as code (S27, area FIX).

The operator verbs of the proposal lifecycle, in the order the workflow uses them:

- ``plans`` — the fix-plan catalog (which classes ARACHNE can turn into an artifact), and
  ``repos`` — the operator's grants (which repositories it may touch at all). Both are
  read-only, and both exist so "why did ARACHNE refuse?" is answerable before anything runs.
- ``propose <finding-id>`` — build the artifact: resolve the plan, apply it to the finding's
  own evidence files, judge the diff, self-scan it with ARACHNE's IaC scanner, and record it.
  Nothing outside ARACHNE changes. Exit ``0`` when a proposal awaiting approval was written,
  ``1`` when the outcome was flagged (unsupported class, no grant, unsafe diff, already
  fixed), ``2`` on a refusal the operator must act on (unknown finding, no store).
- ``show <id>`` / ``list`` — read the artifact and its whole trail back.
- ``approve <id> --by <human>`` / ``reject <id> --by <human>`` — the human gate. There is no
  flag that skips it.
- ``submit <id>`` — repository mode: the repository's own test suite first, then the
  dedicated ``arachne-fix-*`` branch and the reviewable PR artifact. A failing suite is
  flagged and nothing is created.
- ``applied <id> --by <human>`` then ``verify <id>`` — the REQ-FIX-005 loop: a human says the
  fix landed, the targeted re-scan runs, and the finding auto-closes on verified absence.

No verb here merges, applies or pushes anything, and none can: see
:mod:`arachne.fix.gitops`'s closed subcommand vocabulary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.fix.grants import load_fix_grants
from arachne.fix.plans import load_fix_plan_catalog
from arachne.fix.proposal import (
    FixProposalEngine,
    proposal_json,
    propose_sync,
    verify_sync,
)

__all__ = ["app"]

app = typer.Typer(help="Remediation as code: propose, approve, submit, verify (S27).")


def _engine() -> Any:
    """The stack every verb works against; a deployment that cannot answer is a refusal."""
    from arachne.data.services import build_services

    try:
        services = build_services(get_settings())
    except ArachneError as exc:
        _fail(str(exc))
    return services, FixProposalEngine(services)


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.secho(f"fix: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


# ------------------------------------------------------------------ catalog & grants
@app.command(name="plans")
def plans_command(
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List the fix-plan catalog: the classes ARACHNE can turn into an artifact."""
    settings = get_settings()
    try:
        catalog = load_fix_plan_catalog(settings.fix.plans)
    except ArachneError as exc:
        _fail(str(exc))
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "version": catalog.version,
                    "plans": [plan.to_dict() for plan in catalog.plans],
                },
                indent=2,
            )
        )
        return
    typer.echo(f"fix-plan catalog {catalog.version}: {len(catalog.plans)} plan(s)")
    for plan in catalog.plans:
        state = "" if plan.enabled else " (disabled)"
        typer.echo(f"  {plan.id} [{plan.kind}]{state} — {plan.summary}")
        if plan.applies_to.checks or plan.applies_to.rules:
            typer.echo(
                "      checks: "
                + (", ".join(plan.applies_to.checks) or "any")
                + " · rules: "
                + (", ".join(plan.applies_to.rules) or "any")
            )


@app.command(name="repos")
def repos_command(
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List the granted repositories — the only ones a proposal may target."""
    settings = get_settings()
    try:
        grants = load_fix_grants(settings.fix.grants)
    except ArachneError as exc:
        _fail(str(exc))
    if json_output:
        typer.echo(
            json.dumps(
                {"version": grants.version, "repos": [g.to_dict() for g in grants.repos]},
                indent=2,
            )
        )
        return
    if not grants.repos:
        typer.echo(
            "no repository is granted; ARACHNE proposes guidance only. Point "
            "ARACHNE_FIX_GRANTS at a grants file to authorize one."
        )
        return
    typer.echo(f"{len(grants.repos)} grant(s) declared")
    for grant in grants.repos:
        root = grant.root
        typer.echo(f"  {grant.name}: {grant.path} ({'present' if root else 'missing'})")
        typer.echo(
            f"      tests: {' '.join(grant.test_command) or '<none: untestable>'}"
            f" · default branch: {grant.default_branch or '<current>'}"
            f" · budget: {grant.max_files} file(s)/{grant.max_changed_lines} line(s)"
        )


# ------------------------------------------------------------------ the lifecycle
@app.command(name="propose")
def propose_command(
    finding_id: Annotated[int, typer.Argument(help="The finding to propose a fix for.")],
    by: Annotated[str, typer.Option("--by", help="Who is asking for the proposal.")] = "operator",
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Build and record a fix proposal (no effect outside ARACHNE)."""
    services, _ = _engine()
    try:
        record = propose_sync(services, finding_id, actor=by)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    if json_output:
        typer.echo(proposal_json(record))
    else:
        _print_proposal(record, include_diff=True)
    raise typer.Exit(code=0 if record.status == "proposed" else 1)


@app.command(name="list")
def list_command(
    status: Annotated[str | None, typer.Option("--status", help="Filter by status.")] = None,
    finding: Annotated[int | None, typer.Option("--finding", help="Filter by finding id.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="How many to show.")] = 25,
) -> None:
    """List proposals (newest first)."""
    services, engine = _engine()
    try:
        records = engine.proposals(finding_id=finding, status=status, limit=limit)
        summary = engine.summary()
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    typer.echo(
        f"{summary.total} proposal(s): "
        + (", ".join(f"{key}={value}" for key, value in sorted(summary.counts.items())) or "none")
    )
    for record in records:
        typer.echo(
            f"  #{record.id} [{record.status}] {record.check_key or '?'} "
            f"({record.plan_id or 'no plan'}) finding={record.finding_id} "
            f"files={len(record.targets)}"
        )


@app.command(name="show")
def show_command(
    proposal_id: Annotated[int, typer.Argument(help="The proposal to show.")],
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show one proposal: its artifact, its verdicts and its whole trail."""
    services, engine = _engine()
    try:
        record = engine.proposal(proposal_id)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    if json_output:
        typer.echo(proposal_json(record))
        return
    _print_proposal(record, include_diff=True)


@app.command(name="approve")
def approve_command(
    proposal_id: Annotated[int, typer.Argument(help="The proposal to approve.")],
    by: Annotated[str, typer.Option("--by", help="The human approving it (required).")],
) -> None:
    """Approve a proposal — the human gate; nothing is submitted without it."""
    services, engine = _engine()
    try:
        record = engine.approve(proposal_id, actor=by)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    typer.echo(f"proposal #{record.id} approved by {record.approved_by}")


@app.command(name="reject")
def reject_command(
    proposal_id: Annotated[int, typer.Argument(help="The proposal to reject.")],
    by: Annotated[str, typer.Option("--by", help="Who rejected it.")] = "operator",
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
) -> None:
    """Reject a proposal, with the reason recorded."""
    services, engine = _engine()
    try:
        record = engine.reject(proposal_id, actor=by, reason=reason)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    typer.echo(f"proposal #{record.id} rejected ({record.flagged_reason})")


@app.command(name="submit")
def submit_command(
    proposal_id: Annotated[int, typer.Argument(help="The approved proposal to submit.")],
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Repository mode: the repo's own tests, then the arachne-fix-* branch and PR artifact."""
    services, engine = _engine()
    try:
        record = engine.submit(proposal_id)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    if json_output:
        typer.echo(proposal_json(record))
    else:
        typer.echo(
            f"proposal #{record.id}: {record.status}"
            f" · branch {record.branch or '-'} @ {(record.commit or '-')[:12]}"
            f" · tests {record.test_outcome or 'not run'}"
        )
        if record.pr_artifact:
            typer.echo(f"  reviewable artifact: {record.pr_artifact}")
    raise typer.Exit(code=0 if record.status == "submitted" else 1)


@app.command(name="applied")
def applied_command(
    proposal_id: Annotated[int, typer.Argument(help="The proposal whose fix landed.")],
    by: Annotated[str, typer.Option("--by", help="The human who applied it (required).")],
) -> None:
    """Record that a human applied the fix — the precondition of the re-scan."""
    services, engine = _engine()
    try:
        record = engine.mark_applied(proposal_id, actor=by)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    typer.echo(f"proposal #{record.id}: the fix is recorded as applied by {record.applied_by}")


@app.command(name="verify")
def verify_command(
    proposal_id: Annotated[int, typer.Argument(help="The proposal to verify.")],
    by: Annotated[str, typer.Option("--by", help="Who is verifying.")] = "operator",
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Targeted re-scan of the affected checks; the finding auto-closes on absence."""
    services, _ = _engine()
    try:
        record = verify_sync(services, proposal_id, actor=by)
    except ArachneError as exc:
        _fail(str(exc))
    finally:
        services.close()
    if json_output:
        typer.echo(proposal_json(record))
    else:
        typer.echo(
            f"proposal #{record.id}: {record.status} "
            f"(verification scan {record.verification_scan_id or '-'}, "
            f"outcome {record.verification_outcome or '-'})"
        )
    raise typer.Exit(code=0 if record.status == "verified" else 1)


def _print_proposal(record: Any, *, include_diff: bool) -> None:
    typer.echo(f"proposal #{record.id} [{record.status}]")
    typer.echo(f"  finding: #{record.finding_id} ({record.check_key or 'unknown check'})")
    typer.echo(f"  asset:   {record.asset_value or 'unknown'}")
    typer.echo(f"  plan:    {record.plan_id or 'none'} ({record.kind}) · author {record.author}")
    if record.repo_name:
        typer.echo(f"  repo:    {record.repo_name} ({record.repo_path})")
    typer.echo(f"  parity:  {record.parity}")
    typer.echo(f"  summary: {record.summary}")
    if record.flagged_reason:
        typer.echo(f"  flagged: {record.flagged_reason}")
    if record.targets:
        typer.echo("  files:   " + ", ".join(record.targets))
    if record.skipped:
        typer.echo("  skipped: " + "; ".join(record.skipped))
    safety = record.safety_json
    if safety:
        typer.echo(
            f"  scope:   clean={safety.get('clean')} "
            f"+{safety.get('added_lines')}/-{safety.get('removed_lines')} line(s) "
            f"verbatim={safety.get('verbatim')}"
        )
    self_scan = record.self_scan_json
    if self_scan.get("required"):
        typer.echo(f"  self-scan: clean={self_scan.get('clean')} — {self_scan.get('detail')}")
    if record.test_command_json:
        typer.echo(
            "  tests:   "
            + " ".join(str(item) for item in record.test_command_json.get("argv") or [])
            + f" → {record.test_outcome}"
        )
    if record.branch:
        typer.echo(f"  branch:  {record.branch} @ {(record.commit or '')[:12]}")
    if record.approved_by:
        typer.echo(f"  approved by {record.approved_by}")
    if record.applied_by:
        typer.echo(f"  applied by {record.applied_by}")
    if record.verification_outcome:
        typer.echo(
            f"  verification: {record.verification_outcome} (scan {record.verification_scan_id})"
        )
    if include_diff and record.diff_text:
        typer.echo("")
        typer.echo(record.diff_text.rstrip())


def grants_path() -> Path | None:
    """Where the deployment's grants live (the CLI's ``--help`` footnote imports this)."""
    raw = get_settings().fix.grants
    return Path(raw).expanduser() if raw else None
