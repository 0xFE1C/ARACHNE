"""``arachne quality`` — the FP workflow: suppressions, risk acceptances, FP-rate trends (S21).

The verbs an operator needs, in the order the workflow runs:

``trends``      per-check false-positive rates over time, with the rising ones called out —
                the process question the requirement adds to the tuner's totals (REQ-QUAL-004);
``suppress``    add, list or revoke a suppression rule. A reason is required and the actor is
                attributed, because a suppression is a decision someone owns (REQ-QUAL-002);
``accept``      accept a risk with an owner, a justification and an expiry, list or withdraw
                one, and ``expire`` re-open whatever has lapsed (REQ-QUAL-003).

Nothing here deletes a finding. A suppression silences a finding in the *diff* and is countable;
an acceptance changes nothing except the clock it runs against, and the re-open is audited.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer

from arachne.analyzer.fp import compute_trends, rising_alerts
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import ScanServices, build_services
from arachne.quality.acceptance import RiskAcceptance
from arachne.quality.suppressions import Suppression

__all__ = ["quality_app"]

quality_app = typer.Typer(
    name="quality",
    help="The FP workflow: suppression rules, risk acceptances and FP-rate trends.",
    no_args_is_help=True,
)


def _services() -> ScanServices:
    return build_services(get_settings())


def _quality(services: ScanServices) -> Any:
    store = getattr(services, "quality", None)
    if store is None:
        raise ArachneError("this deployment has no quality store configured")
    return store


# --------------------------------------------------------------------------- trends


@quality_app.command("trends")
def quality_trends(
    days: Annotated[int, typer.Option("--days", help="Window in days.")] = 30,
    alert: Annotated[
        float, typer.Option("--alert", help="Rise in FP rate that raises an alert.")
    ] = 0.1,
    window: Annotated[int, typer.Option("--window", help="Buckets in the recent window.")] = 2,
    minimum_marks: Annotated[
        int, typer.Option("--minimum-marks", help="Marks a window needs to mean something.")
    ] = 3,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Per-check false-positive rates over time, and which are rising."""
    services = _services()
    try:
        store = _quality(services)
        since = datetime.now(UTC) - timedelta(days=max(1, days))
        trends = compute_trends(store.feedback_history(since=since), days=days)
        alerts = rising_alerts(trends, threshold=alert, window=window, min_marks=minimum_marks)
        if as_json:
            typer.echo(
                json.dumps(
                    {
                        "trends": [item.to_dict(window=window) for item in trends],
                        "alerts": [item.to_dict() for item in alerts],
                    },
                    indent=2,
                )
            )
            return
        if not trends:
            typer.echo("no operator feedback recorded in this window")
            return
        typer.echo(f"{'key':<44} {'marks':>5} {'fp':>4} {'rate':>6} {'recent':>7}")
        typer.echo("-" * 70)
        for trend in trends:
            typer.echo(
                f"{trend.key[:44]:<44} {trend.marks:>5} {trend.false_positives:>4} "
                f"{trend.fp_rate:>5.0%} {trend.recent_rate(window=window):>6.0%}"
            )
        if alerts:
            typer.echo("")
            typer.echo("rising false-positive rate:")
            for item in alerts:
                typer.echo(
                    f"  {item.key}: {item.baseline_rate:.0%} → {item.recent_rate:.0%} "
                    f"(+{item.delta:.0%} over {item.recent_marks} recent mark(s))"
                )
        else:
            typer.echo("")
            typer.echo("no rising false-positive rate above the alert threshold")
    finally:
        services.close()


# --------------------------------------------------------------------------- suppressions


@quality_app.command("suppress")
def quality_suppress(
    check: Annotated[str, typer.Option("--check", help="Check id (dot form).")],
    reason: Annotated[str, typer.Option("--reason", "-r", help="Why (>= 8 characters).")],
    asset: Annotated[
        str | None, typer.Option("--asset", help="Asset pattern (fnmatch) for a pattern rule.")
    ] = None,
    finding: Annotated[
        int | None, typer.Option("--finding", help="Finding id for a finding rule.")
    ] = None,
    days: Annotated[
        int | None, typer.Option("--days", help="Expire the rule after this many days.")
    ] = None,
    actor: Annotated[str | None, typer.Option("--actor", help="Who is deciding.")] = None,
) -> None:
    """Record a suppression rule."""
    services = _services()
    try:
        kind = "finding" if finding is not None else "pattern" if asset else "rule"
        rule = Suppression(
            kind=kind,  # type: ignore[arg-type]
            check_id=check if kind != "finding" else check or None,
            asset_pattern=asset,
            finding_id=finding,
            reason=reason,
            actor=actor or services.settings.actor,
            expires_at=(datetime.now(UTC) + timedelta(days=days)) if days else None,
        )
        stored = _quality(services).add_suppression(rule)
        typer.echo(
            f"suppression #{stored.id} (v{stored.version}, {stored.kind}) recorded by "
            f"{stored.actor}: {stored.check_id or stored.finding_id}"
        )
    finally:
        services.close()


@quality_app.command("suppressions")
def quality_suppressions(
    all_rules: Annotated[bool, typer.Option("--all", help="Include revoked rules.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the suppression rules (newest first)."""
    services = _services()
    try:
        rows = _quality(services).list_suppressions(active_only=not all_rules)
        if as_json:
            typer.echo(json.dumps([row.to_dict() for row in rows], indent=2))
            return
        if not rows:
            typer.echo("no suppression rules recorded")
            return
        for row in rows:
            state = "active" if row.active else "revoked"
            typer.echo(
                f"#{row.id} v{row.version} {row.kind:<8} {state:<8} "
                f"{row.check_id or row.finding_id} {row.asset_pattern or ''} "
                f"— {row.reason} ({row.actor})"
            )
    finally:
        services.close()


@quality_app.command("unsuppress")
def quality_unsuppress(
    suppression_id: Annotated[int, typer.Argument(help="Suppression id to revoke.")],
    actor: Annotated[str | None, typer.Option("--actor", help="Who is deciding.")] = None,
) -> None:
    """Revoke a suppression rule (the row stays for the record)."""
    services = _services()
    try:
        revoked = _quality(services).revoke_suppression(
            suppression_id, actor=actor or services.settings.actor
        )
        if revoked is None:
            raise ArachneError(f"suppression {suppression_id} does not exist")
        typer.echo(f"suppression #{revoked.id} revoked")
    finally:
        services.close()


# --------------------------------------------------------------------------- acceptances


@quality_app.command("accept")
def quality_accept(
    finding: Annotated[int | None, typer.Option("--finding", help="Finding id.")] = None,
    check: Annotated[str | None, typer.Option("--check", help="Check id (rule-wide).")] = None,
    owner: Annotated[str, typer.Option("--owner", help="Who owns the risk.")] = "",
    justification: Annotated[
        str, typer.Option("--justification", "-j", help="Why it is acceptable (>= 12 chars).")
    ] = "",
    days: Annotated[int, typer.Option("--days", help="Days until the acceptance expires.")] = 30,
    actor: Annotated[str | None, typer.Option("--actor", help="Who is recording it.")] = None,
) -> None:
    """Accept a risk: owner, justification and an expiry are all required."""
    services = _services()
    try:
        acceptance = RiskAcceptance(
            finding_id=finding,
            check_id=check,
            owner=owner,
            justification=justification,
            expires_at=datetime.now(UTC) + timedelta(days=max(1, days)),
            actor=actor or services.settings.actor,
        )
        stored = _quality(services).add_acceptance(acceptance)
        typer.echo(
            f"acceptance #{stored.id} recorded by {stored.actor}: "
            f"{stored.finding_id or stored.check_id} owned by {stored.owner}, "
            f"expires {stored.expires_at.isoformat()}"
        )
    finally:
        services.close()


@quality_app.command("acceptances")
def quality_acceptances(
    finding: Annotated[int | None, typer.Option("--finding", help="Only this finding.")] = None,
    active_only: Annotated[
        bool, typer.Option("--active/--all", help="Only acceptances in force.")
    ] = True,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List risk acceptances."""
    services = _services()
    try:
        rows = _quality(services).list_acceptances(finding_id=finding, active_only=active_only)
        if as_json:
            typer.echo(json.dumps([row.to_dict() for row in rows], indent=2))
            return
        if not rows:
            typer.echo("no risk acceptances recorded")
            return
        for row in rows:
            state = "withdrawn" if row.revoked_at else "active"
            typer.echo(
                f"#{row.id} {state:<9} {row.finding_id or row.check_id} owner={row.owner} "
                f"expires={row.expires_at.isoformat()} — {row.justification}"
            )
    finally:
        services.close()


@quality_app.command("withdraw")
def quality_withdraw(
    acceptance_id: Annotated[int, typer.Argument(help="Acceptance id to withdraw.")],
    actor: Annotated[str | None, typer.Option("--actor", help="Who is withdrawing.")] = None,
) -> None:
    """Withdraw an acceptance before it expires."""
    services = _services()
    try:
        revoked = _quality(services).revoke_acceptance(
            acceptance_id, actor=actor or services.settings.actor
        )
        if revoked is None:
            raise ArachneError(f"acceptance {acceptance_id} does not exist")
        typer.echo(f"acceptance #{revoked.id} withdrawn")
    finally:
        services.close()


@quality_app.command("expire")
def quality_expire(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Re-open every finding whose acceptance has expired."""
    services = _services()
    try:
        decisions = _quality(services).reopen_expired()
        payload = [item.to_dict() for item in decisions]
        if as_json:
            typer.echo(json.dumps({"reopened": payload}, indent=2))
            return
        if not decisions:
            typer.echo("nothing expired")
            return
        for item in decisions:
            typer.echo(
                f"finding {item.finding_id} re-opened (acceptance #{item.acceptance_id}, "
                f"owner {item.owner}, expired {item.expired_at.isoformat()})"
            )
    finally:
        services.close()
