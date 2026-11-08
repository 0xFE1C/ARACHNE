"""``arachne fp`` — false-positive feedback and tuning (F-05-07).

Four verbs, one learner:

``arachne fp mark FINDING``
    record that a finding was a false positive (the default), or ``--not-fp`` that it was
    real. This writes the same ``fp_feedback`` row the REST API's ``PATCH /findings`` writes,
    with the same key, so the two interfaces cannot disagree about what an operator said.
``arachne fp stats``
    the current learner table: per (check, asset kind, signature) how many marks exist, the
    false-positive rate, the threshold in force and the threshold the feedback implies.
``arachne fp tune``
    the same table reduced to suggestions, and with ``--write`` a threshold file a deployment
    points ``ARACHNE_FP_THRESHOLDS`` at.
``arachne fp check CHECK``
    one check's row, for a pipeline that wants a specific answer.

Nothing here ever deletes a finding; ``mark`` sets the status the operator asked for
(``fp`` or ``open``) and appends feedback. The tuner reads the feedback, never the status.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml

from arachne.analyzer.fp import (
    FeedbackRecord,
    FpTuner,
    TunerRow,
    feedback_key_for,
    load_fp_thresholds,
    split_feedback_key,
)
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.api_store import ApiQueryStore
from arachne.data.services import ScanServices, build_services

__all__ = ["fp_app"]

fp_app = typer.Typer(
    name="fp",
    help="False-positive feedback and per-check threshold tuning.",
    no_args_is_help=True,
)

#: Statuses an operator may set through ``fp mark``.
_STATUSES = ("fp", "open", "accepted", "fixed", "wontfix", "false-positive")


def _store() -> ScanServices:
    return build_services(get_settings())


def _key_for_row(row: Any) -> str:
    return feedback_key_for(row.check_id, row.asset_kind)


def _render_rows(rows: tuple[TunerRow, ...], *, as_json: bool) -> str:
    if as_json:
        return json.dumps([row.to_dict() for row in rows], indent=2)
    if not rows:
        return "no operator feedback recorded yet"
    lines = [
        f"{'check':<34} {'asset':<8} {'marks':>5} {'fp':>4} {'rate':>6} {'now':>4} {'tuned':>6}",
        "-" * 74,
    ]
    for row in rows:
        lines.append(
            f"{row.check_id[:34]:<34} {row.asset_kind[:8]:<8} {row.total:>5} "
            f"{row.false_positives:>4} {row.fp_rate:>5.0%} {row.threshold:>4} {row.suggested:>6}"
        )
    return "\n".join(lines)


@fp_app.command("mark")
def fp_mark(
    finding: Annotated[int, typer.Argument(help="Finding id to record feedback for.")],
    note: Annotated[
        str | None, typer.Option("--note", "-n", help="Why the operator decided this.")
    ] = None,
    not_fp: Annotated[
        bool,
        typer.Option("--not-fp", help="Record the finding as a true positive (unmark an FP)."),
    ] = False,
    status: Annotated[
        str | None,
        typer.Option("--status", help="Status to set on the finding (default: fp / open)."),
    ] = None,
    actor: Annotated[
        str | None, typer.Option("--actor", help="Who is recording this (audit + feedback row).")
    ] = None,
) -> None:
    """Record operator false-positive feedback for a finding."""
    is_fp = not not_fp
    target_status = status or ("fp" if is_fp else "open")
    if target_status not in _STATUSES:
        raise ArachneError(f"status {target_status!r} is not one of {', '.join(_STATUSES)}")
    services = _store()
    try:
        queries = ApiQueryStore(services.session_factory)
        row = queries.finding_row(finding)
        if row is None:
            raise ArachneError(f"finding {finding} does not exist")
        key = _key_for_row(row)
        updated = queries.set_finding_status(finding, target_status)
        assert updated is not None  # checked above
        services.analyses.record_feedback(
            FeedbackRecord(key=key, is_fp=is_fp, finding_id=finding, note=note),
            actor=actor or services.settings.actor,
        )
        typer.echo(
            f"finding {finding}: status={target_status} key={key} "
            f"recorded={'false positive' if is_fp else 'true positive'}"
        )
    finally:
        services.close()


@fp_app.command("stats")
def fp_stats(
    check: Annotated[
        str | None, typer.Option("--check", help="Only this check id (dot form).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the learner table: marks, FP rate and thresholds per check."""
    services = _store()
    try:
        thresholds = load_fp_thresholds(services.settings.analysis.fp_thresholds)
        tuner = FpTuner(dict(services.analyses.feedback_stats(None)), thresholds=thresholds)
        rows = tuner.rows()
        if check:
            rows = tuple(row for row in rows if row.check_id == check)
        typer.echo(_render_rows(rows, as_json=as_json))
    finally:
        services.close()


@fp_app.command("check")
def fp_check(
    check: Annotated[str, typer.Argument(help="Check id in dot form, e.g. m4.env-file-probe.")],
    asset_kind: Annotated[
        str, typer.Option("--asset-kind", help="Asset kind the finding is attached to.")
    ] = "unknown",
    signature: Annotated[
        str, typer.Option("--signature", help="Signature id, when one fired.")
    ] = "",
) -> None:
    """Print the threshold one (check, asset kind, signature) key has earned."""
    services = _store()
    try:
        thresholds = load_fp_thresholds(services.settings.analysis.fp_thresholds)
        key = "|".join([check, asset_kind, signature or "none"])
        tuner = FpTuner(dict(services.analyses.feedback_stats([key])), thresholds=thresholds)
        typer.echo(f"{key}\n  required confidence: {tuner.required_confidence(key)}")
        typer.echo(f"  {tuner.describe(key)}")
        typer.echo(f"  {_confidence_note(tuner, key)}")
    finally:
        services.close()


def _confidence_note(tuner: FpTuner, key: str) -> str:
    if tuner.penalty(key) == 0:
        return "no adjustment from operator feedback"
    return f"feedback lowers the learned threshold from {tuner.threshold} to {tuner.learned(key)}"


@fp_app.command("tune")
def fp_tune(
    write: Annotated[
        Path | None,
        typer.Option("--write", "-w", help="Write the suggested thresholds to this file."),
    ] = None,
    minimum_marks: Annotated[
        int,
        typer.Option("--minimum-marks", help="Ignore keys with fewer marks than this."),
    ] = 3,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Suggest per-check thresholds from the feedback, and optionally write them.

    Only keys with at least ``--minimum-marks`` marks are suggested, because a 1/1 rate is
    noise. The suggestion is what the tuner already applies to a *new* finding from the key;
    writing it down makes the decision reviewable and lets an operator raise it further.
    """
    services = _store()
    try:
        thresholds = load_fp_thresholds(services.settings.analysis.fp_thresholds)
        tuner = FpTuner(dict(services.analyses.feedback_stats(None)), thresholds=thresholds)
        rows = tuple(row for row in tuner.rows() if row.total >= max(1, minimum_marks))
        if as_json:
            typer.echo(json.dumps([row.to_dict() for row in rows], indent=2))
        else:
            typer.echo(_render_rows(rows, as_json=False))
        if write is not None:
            payload: dict[str, Any] = {
                "version": "1.0",
                "default": thresholds.default,
                "checks": {
                    row.check_id: row.suggested
                    for row in rows
                    if row.suggested != thresholds.default
                },
            }
            write.parent.mkdir(parents=True, exist_ok=True)
            write.write_text(
                "# Generated by `arachne fp tune --write` (F-05-07).\n"
                + yaml.safe_dump(payload, sort_keys=True),
                encoding="utf-8",
            )
            typer.echo(f"wrote {len(payload['checks'])} suggestion(s) to {write}")
    finally:
        services.close()


def check_key_parts(key: str) -> tuple[str, str, str]:
    """``check|asset|signature`` split, exposed for tests and callers."""
    return split_feedback_key(key)
