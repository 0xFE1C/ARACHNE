"""``arachne verify-finding`` — re-run one finding's proof (WP-13, REQ-PROOF-016).

The command is the operator's "is this still true?" question, and its whole value is that the
answer is produced the same way a scan produces one: the same scope gate, the same
attestation gate, the same check, run against the same asset through the same scoped client.
It never escalates the proof level (a check that now declares a higher rung is refused), and
it never touches the network before both gates have passed.

The exit code is the contract:

* ``0`` — the verdict is ``still-verified``, ``no-longer-verified`` or ``inconclusive``. Those
  are three *answers* to the question, and an answer with a non-zero exit would make ``||``
  and CI treat a truthful "it is gone" as a tool failure.
* ``1`` — ``refused``: nothing was re-checked (expired or non-covering attestation, an
  out-of-scope asset, no verification record, or a check that would escalate the level).
  A refusal means the question was not answered, so a script must be able to see it.

``--json`` prints the same verdict as a document, for a caller that would rather parse it.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import build_services
from arachne.proof.reverify import ReverificationResult, reverify_finding_sync

__all__ = ["render_reverification", "verify_finding_command"]

_EXIT_VERDICT = 0
_EXIT_REFUSED = 1


def verify_finding_command(
    finding_id: Annotated[int, typer.Argument(help="The finding to re-verify (its numeric id).")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the verdict as JSON instead of prose.")
    ] = False,
    actor: Annotated[
        str | None,
        typer.Option("--actor", help="Who is asking; recorded in the audit trail."),
    ] = None,
) -> None:
    """Re-run the proof behind one finding against the same asset (REQ-PROOF-016)."""
    services = build_services(get_settings())
    try:
        try:
            result = reverify_finding_sync(services, finding_id, actor=actor or "operator")
        except ArachneError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        typer.echo(render_reverification(result))
    if result.refused:
        # Non-zero *after* the verdict is printed, so a caller always sees why.
        raise typer.Exit(code=_EXIT_REFUSED)


def render_reverification(result: ReverificationResult) -> str:
    """The operator-readable verdict, one block."""
    lines = [f"finding {result.finding_id}: {result.outcome.upper()}"]
    if result.check_id:
        what = f"  check:     {result.check_id}"
        if result.level:
            what += f" (level {result.level})"
        lines.append(what)
    if result.asset:
        lines.append(f"  asset:     {result.asset}")
    if result.original_scan_id is not None:
        lines.append(f"  scan:      {result.original_scan_id} (original)")
    if result.verification_scan_id is not None:
        lines.append(f"  re-scan:   {result.verification_scan_id}")
    if result.parent_record_id is not None:
        parent = f"  parent:    verification record {result.parent_record_id}"
        if result.record_id is not None:
            parent += f" → new record {result.record_id}"
        lines.append(parent)
    lines.append(f"  detail:    {result.detail}")
    return "\n".join(lines)
