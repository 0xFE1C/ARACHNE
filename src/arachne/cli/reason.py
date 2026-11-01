"""``arachne reason`` — the agentic loop's operator surface (S21, area AGENT).

Four verbs, and each one answers a question an operator actually asks:

``status``  what did the agent decide, and did anything get refused? Reads the persisted journal
            (``scans.stats["hypotheses"]``) and prints the proposals, the decisions with their
            reason codes, and the budget.
``replay``  re-derive a run from its journal alone, offline: the input hash is recomputed, the
            decisions are checked against the proposals, and the heuristic engine is re-run
            (REQ-AGENT-002). It proves the record, and it never touches a target.
``pause``/``abort``  the kill switch (REQ-AGENT-007). The directive is a file a *running* scan
            reads between two hypotheses, so this works against a scan that is mid-flight,
            possibly on another node. ``resume`` clears a directive for one scan;
            ``--all`` sets a deployment-wide stop that a scan's own resume does not clear.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from arachne.core.catalog import load_catalog
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import build_services
from arachne.reasoning.control import HypothesisControl, build_hypothesis_control
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.model import HypothesisJournal
from arachne.reasoning.replay import replay_journal

__all__ = ["reason_app"]

reason_app = typer.Typer(
    name="reason",
    help="Agentic reasoning: the journal, offline replay and the operator kill switch (S21).",
    no_args_is_help=True,
)


def _control() -> HypothesisControl:
    settings = get_settings()
    return build_hypothesis_control(settings.hypotheses.control_path)


def _journal_of(scan_id: int) -> HypothesisJournal:
    services = build_services(get_settings())
    try:
        record = services.store.get_scan(scan_id)
        if record is None:
            raise ArachneError(f"scan {scan_id} does not exist")
        document = (record.stats or {}).get("hypotheses")
        journal = HypothesisJournal.from_document(document)
        if journal is None:
            raise ArachneError(f"scan {scan_id} recorded no agentic reasoning")
        return journal
    finally:
        services.close()


@reason_app.command("status")
def reason_status(
    scan: Annotated[int, typer.Argument(help="Scan id to read the journal of.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the journal document.")] = False,
) -> None:
    """Show what the agent proposed, what it decided, and what it refused (REQ-AGENT-002)."""
    journal = _journal_of(scan)
    if as_json:
        typer.echo(json.dumps(journal.to_dict(), indent=2))
        return
    typer.echo(
        f"scan {journal.scan_id}: mode={journal.mode.value} engine={journal.engine} "
        f"state={journal.state.value}"
    )
    typer.echo(
        f"proposed {journal.proposed}, decided {journal.cursor}, executed "
        f"{len(journal.executed)}, refused {len(journal.refused)}; budget "
        f"{journal.budget.hypotheses_spent}/{journal.budget.max_hypotheses} hypotheses, "
        f"{journal.budget.probes_spent}/{journal.budget.max_probes} probes, "
        f"{journal.budget.deferred} deferred"
    )
    typer.echo(f"inputs {journal.inputs_hash[:16]}… rules {journal.rules_version or 'unknown'}")
    if journal.fallback:
        typer.echo(f"degraded: {journal.fallback}")
    if journal.note:
        typer.echo(f"note: {journal.note}")
    typer.echo("")
    typer.echo(f"{'check':<30} {'asset':<32} {'outcome':<9} reason")
    typer.echo("-" * 100)
    for decision in journal.decisions:
        typer.echo(
            f"{decision.check_id[:30]:<30} {decision.asset[:32]:<32} "
            f"{decision.outcome.value:<9} {decision.reason[:48]}"
        )


@reason_app.command("replay")
def reason_replay(
    scan: Annotated[int | None, typer.Argument(help="Scan id whose journal to replay.")] = None,
    path: Annotated[
        Path | None, typer.Option("--file", help="A journal document saved with --json.")
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the replay report as JSON.")
    ] = False,
) -> None:
    """Re-derive a run from its journal, offline (REQ-AGENT-002). Exits non-zero if it fails."""
    if path is None and scan is None:
        raise ArachneError("give a scan id or --file")
    if path is not None:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArachneError(f"{path}: not a readable journal document: {exc}") from exc
        journal = HypothesisJournal.from_document(document)
        if journal is None:
            raise ArachneError(f"{path}: not a journal document")
    else:
        assert scan is not None
        journal = _journal_of(scan)
    index = CheckIndex.from_catalog(load_catalog())
    report = replay_journal(journal, index=index)
    if as_json:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        verdict = "consistent" if report.ok else "INCONSISTENT"
        typer.echo(
            f"scan {report.scan_id}: {verdict} — inputs {report.recomputed_hash[:16]}… "
            f"({report.decisions} decision(s), {report.executed} executed)"
        )
        if report.proposals_reproduced:
            typer.echo("the heuristic engine reproduces the recorded proposals exactly")
        elif report.engine == "ai":
            typer.echo(
                "the recorded proposals differ from a fresh heuristic reading (expected for an "
                "AI run; the record is authoritative)"
            )
        for problem in report.problems:
            typer.echo(f"  problem: {problem}")
        for note in report.notes:
            typer.echo(f"  note: {note}")
    if not report.ok:
        raise typer.Exit(code=1)


def _directive(
    scan: Annotated[int | None, typer.Argument(help="Scan id (omit with --all).")] = None,
    every: Annotated[
        bool, typer.Option("--all", help="Apply to every scan of this deployment.")
    ] = False,
    explain: str = "",
) -> None:
    if scan is None and not every:
        raise ArachneError("give a scan id, or --all for the whole deployment")
    control = _control()
    control.set(None if every else scan, explain)  # type: ignore[arg-type]
    where = "every scan" if every else f"scan {scan}"
    typer.echo(f"{where}: {explain} recorded (read by the scan between two hypotheses)")


@reason_app.command("pause")
def reason_pause(
    scan: Annotated[int | None, typer.Argument(help="Scan id (omit with --all).")] = None,
    every: Annotated[
        bool, typer.Option("--all", help="Apply to every scan of this deployment.")
    ] = False,
) -> None:
    """Pause agentic expansion between two hypotheses, leaving a resumable scan (REQ-AGENT-007)."""
    _directive(scan, every, "pause")


@reason_app.command("abort")
def reason_abort(
    scan: Annotated[int | None, typer.Argument(help="Scan id (omit with --all).")] = None,
    every: Annotated[
        bool, typer.Option("--all", help="Apply to every scan of this deployment.")
    ] = False,
) -> None:
    """Abort agentic expansion between two hypotheses, leaving a resumable scan (REQ-AGENT-007)."""
    _directive(scan, every, "abort")


@reason_app.command("resume")
def reason_resume(
    scan: Annotated[int | None, typer.Argument(help="Scan id to clear (omit with --all).")] = None,
    every: Annotated[bool, typer.Option("--all", help="Clear the deployment-wide stop.")] = False,
) -> None:
    """Clear a pause/abort directive so the next ``arachne scan --resume`` continues."""
    control = _control()
    control.clear(None if every else scan)
    where = "every scan" if every else f"scan {scan}"
    typer.echo(f"{where}: directive cleared")
