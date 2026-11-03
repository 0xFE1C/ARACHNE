"""``arachne scan`` — plan and run a scan (F-07-01, F-01-03/04/10).

Two modes, one command:

``--dry-run``
    prints the complete plan (steps, checks, estimated request counts, scope, attestation
    status) and makes **zero** requests. It needs no database and no attestation, which is
    what makes it usable as a pre-flight check: "what would this scan do, and am I allowed
    to run it?"
``--resume <scan-id>``
    continues an interrupted or failed scan from its last completed step (F-01-04). The
    target fixture is supplied again and must describe the same target as the stored scan.

Without either flag the scan runs for real: state is persisted per step, every request
flows through the shared scoped client, and one audit event accompanies every request and
every refusal.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.cli.ci import (
    EXIT_AT_OR_ABOVE,
    EXIT_CLEAN,
    SEVERITY_LEVELS,
    gate_exit_code,
    gate_summary,
    parse_threshold,
)
from arachne.core.audit import Auditor, build_auditor
from arachne.core.config import get_settings
from arachne.core.orchestrator import Orchestrator, ScanSession
from arachne.core.planner import ScanPlan
from arachne.core.target import (
    EngineName,
    ModuleSelection,
    ScanRequest,
    load_scan_request,
)
from arachne.data.services import build_orchestrator, build_services

__all__ = ["render_plan", "render_run", "scan_command"]


def _load_request(
    target: Path,
    *,
    engine: EngineName | None,
    active_checks: bool | None,
    enable: str | None,
    disable: str | None,
    check: str | None = None,
) -> ScanRequest:
    """Load the fixture and apply command-line overrides to its options."""
    request = load_scan_request(target)
    options = request.options
    overrides: dict[str, object] = {}
    if engine is not None:
        overrides["engine"] = engine
    if active_checks is not None:
        overrides["active_checks"] = active_checks
    if enable is not None or disable is not None or check is not None:
        overrides["modules"] = ModuleSelection(
            enabled=_modules(enable) or options.modules.enabled,
            disabled=_modules(disable) or options.modules.disabled,
            checks=_checks(check) or options.modules.checks,
        )
    if not overrides:
        return request
    return request.model_copy(update={"options": options.model_copy(update=overrides)})


def _modules(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip().upper() for item in value.split(",") if item.strip())


def _checks(value: str | None) -> tuple[str, ...]:
    """Opt-in check ids (``--check m4.default-credentials``), comma-separated."""
    if not value:
        return ()
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


def scan_command(
    target: Annotated[
        Path,
        typer.Option(
            "--target",
            "-t",
            help="Target definition fixture (YAML or JSON), F-01-01.",
            exists=False,
        ),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print the plan and make zero requests (F-01-10)."),
    ] = False,
    resume: Annotated[
        int | None,
        typer.Option("--resume", help="Resume this scan id from its last completed step."),
    ] = None,
    engine: Annotated[
        EngineName | None, typer.Option("--engine", help="Analysis engine for this scan.")
    ] = None,
    active_checks: Annotated[
        bool | None,
        typer.Option(
            "--active-checks/--no-active-checks",
            help="Opt in to active checks; the attestation must authorize them (F-01-09).",
        ),
    ] = None,
    enable: Annotated[
        str | None, typer.Option("--enable", help="Comma-separated module ids to enable (M1..M6).")
    ] = None,
    disable: Annotated[
        str | None,
        typer.Option("--disable", help="Comma-separated module ids to disable (M1..M6)."),
    ] = None,
    check: Annotated[
        str | None,
        typer.Option(
            "--check",
            help=(
                "Comma-separated opt-in check ids to run (e.g. "
                "m4.default-credentials). A check that is off by default runs only when "
                "named here, and an active check also needs --active-checks."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the plan (dry run) as JSON.")
    ] = False,
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            help=(
                "Tenant/workspace slug the scan belongs to (F-07-06). The target must fall "
                "inside that project's scope; omit for the default workspace."
            ),
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help=(
                "CI gate (F-07-05): exit 2 when a finding is at or above this severity "
                "(info|low|medium|high|critical), 1 when findings exist below it, 0 when "
                "clean. 'none' (or ARACHNE_CI_FAIL_ON unset) disables the gate."
            ),
        ),
    ] = None,
) -> None:
    """Plan a scan (--dry-run), run one, or resume an interrupted one (--resume)."""
    if dry_run and resume is not None:
        msg = "--dry-run and --resume are mutually exclusive"
        raise typer.BadParameter(msg)

    threshold = _resolve_threshold(fail_on)

    request = _load_request(
        target,
        engine=engine,
        active_checks=active_checks,
        enable=enable,
        disable=disable,
        check=check,
    )

    if resume is not None:
        services = build_services(get_settings())
        try:
            project_id, project_scope = _resolve_project(services, project)
            orchestrator = build_orchestrator(
                services, project_id=project_id, project_scope=project_scope
            )
            session = asyncio.run(orchestrator.resume(resume, request))
            counts = _counts_for(services, session.scan_id)
        finally:
            services.close()
        _emit(session, json_output=json_output, counts=counts)
        _enforce_gate(counts, threshold)
        return

    if dry_run:
        # No database, no HTTP client, no scorer: the dry run is pure computation — unless a
        # project was named, in which case its scope has to be read to plan honestly.
        dry_project_id: int | None = None
        dry_project_scope = None
        if project:
            services = build_services(get_settings())
            try:
                dry_project_id, dry_project_scope = _resolve_project(services, project)
            finally:
                services.close()
        orchestrator = Orchestrator(
            settings=get_settings(),
            auditor=_memory_auditor(),
            project_id=dry_project_id,
            project_scope=dry_project_scope,
        )
        plan = orchestrator.plan(request, dry_run=True)
        if json_output:
            typer.echo(json.dumps(plan.to_dict(), indent=2, default=str))
        else:
            typer.echo(render_plan(plan))
        return

    services = build_services(get_settings())
    try:
        project_id, project_scope = _resolve_project(services, project)
        orchestrator = build_orchestrator(
            services, project_id=project_id, project_scope=project_scope
        )
        session = asyncio.run(orchestrator.scan(request))
        counts = _counts_for(services, session.scan_id)
    finally:
        services.close()
    _emit(session, json_output=json_output, counts=counts)
    _enforce_gate(counts, threshold)


def _resolve_project(services: Any, project: str | None) -> tuple[int | None, Any]:
    """Resolve ``--project`` to ``(id, scope)``; no project means no restriction."""
    if not project:
        return None, None
    record = services.projects.resolve(project)
    return record.id, record.to_scope()


def _resolve_threshold(fail_on: str | None) -> str:
    """The CI-gate threshold: the flag, else ``ARACHNE_CI_FAIL_ON``, else ``none``."""
    raw = fail_on if fail_on is not None else (os.environ.get("ARACHNE_CI_FAIL_ON") or "none")
    try:
        return parse_threshold(raw)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _counts_for(services: Any, scan_id: int | None) -> dict[str, int]:
    """Severity counts for the gate, read from the store (the analyzer's verdicts)."""
    if scan_id is None:
        return {}
    from arachne.data.api_store import ApiQueryStore

    counts = dict(ApiQueryStore(services.session_factory).severity_counts(scan_id))
    for severity in SEVERITY_LEVELS:
        counts.setdefault(severity, 0)
    return counts


def _enforce_gate(counts: dict[str, int], threshold: str) -> None:
    """Apply the F-07-05 exit-code policy (0 clean / 1 below / 2 at-or-above)."""
    if threshold == "none":
        return
    code = gate_exit_code(counts, threshold)
    if code == EXIT_CLEAN:
        typer.echo(f"ci gate: clean (threshold {threshold})")
        return
    label = "at or above" if code == EXIT_AT_OR_ABOVE else "below"
    typer.echo(
        f"ci gate: findings {label} threshold {threshold} "
        f"({gate_summary(counts, threshold)['at_or_above']} at/above); exit {code}",
        err=True,
    )
    raise SystemExit(code)


def _memory_auditor() -> Auditor:
    """Auditor that writes to structured logs only (the dry run touches no store)."""
    settings = get_settings()
    return build_auditor(settings, logging_enabled=True)


def _emit(session: ScanSession, *, json_output: bool, counts: dict[str, int] | None = None) -> None:
    if json_output:
        payload = {
            "plan": session.plan.to_dict(),
            "scan_id": session.scan_id,
            "status": session.status.value,
            "steps": {
                "executed": [
                    step.value for step in (session.outcome.executed if session.outcome else ())
                ],
                "skipped": [
                    step.value for step in (session.outcome.skipped if session.outcome else ())
                ],
                "already_completed": [
                    step.value
                    for step in (session.outcome.already_completed if session.outcome else ())
                ],
            },
            "assets": session.outcome.assets if session.outcome else 0,
        }
        if counts is not None:
            payload["severities"] = {name: int(counts.get(name, 0)) for name in SEVERITY_LEVELS}
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(render_run(session))


def render_plan(plan: ScanPlan) -> str:
    """Human-readable plan (the default ``--dry-run`` output)."""
    lines: list[str] = []
    mode = "dry run" if plan.dry_run else "plan"
    lines.append(f"ARACHNE {mode} — target {plan.target_name!r} (engine: {plan.engine})")
    lines.append(f"  plan version {plan.plan_version}, created {plan.created_at.isoformat()}")

    lines.append("  scope (compiled from the target definition, deny by default):")
    labels = (
        ("allowed_hosts", "hosts"),
        ("allowed_domains", "domains"),
        ("allowed_networks", "networks"),
        ("url_prefixes", "url prefixes"),
        ("allowed_refs", "references"),
        ("excluded_hosts", "excluded hosts"),
        ("excluded_domains", "excluded domains"),
        ("excluded_networks", "excluded networks"),
        ("excluded_url_prefixes", "excluded url prefixes"),
        ("excluded_refs", "excluded references"),
    )
    for key, label in labels:
        values = plan.scope.get(key) or []
        if values:
            lines.append(f"    {label + ':':22}{', '.join(values)}")
    if plan.deployment_scope is not None:
        declared = plan.deployment_scope.get("allowed_hosts") or []
        lines.append(
            f"    {'deployment scope:':22}hosts={declared or '(none)'} "
            "— every target must fit inside it"
        )

    if plan.attestation is None:
        lines.append("  authorization: none — a live scan would be refused")
    else:
        attestation = plan.attestation
        reference = attestation.get("authorization_ref") or "(no reference)"
        lines.append(
            f"  authorization: {attestation.get('attested_by')} @ "
            f"{attestation.get('attested_at')} [{reference}]"
        )
    lines.append(f"  live-ready: {'yes' if plan.live_ready else 'NO'}")

    lines.append(f"  assets ({plan.totals.targets} target(s), {plan.totals.hosts} host(s)):")
    for asset in plan.assets:
        flag = " (capped)" if asset.capped else ""
        lines.append(
            f"    {asset.kind.value:15}{asset.value:44}{asset.request_units} unit(s){flag}"
        )

    lines.append("  pipeline:")
    for step in plan.steps:
        detail = (
            f"{len(step.checks)} check(s)"
            if step.checks
            else (step.skip_reason or step.description.lower())
        )
        marker = "" if step.executable else "  [not executable in this build]"
        lines.append(
            f"    {step.order}. {step.step.value:12}{step.estimated_requests:6d} request(s)  "
            f"{detail}{marker}"
        )
        # REQ-DET-015: the browser crawl's page and time budget is part of the plan, so an
        # operator sees the bound before the browser ever opens. Absent when the crawl is
        # off or the optional extra is not installed (never a claim that it will happen).
        if step.budget_pages is not None and step.budget_seconds is not None:
            lines.append(
                f"       browser crawl budget: {step.budget_pages} navigation(s) / "
                f"{step.budget_seconds:g}s (enforced; every navigation passes the scope "
                "gate before the request)"
            )

    lines.append(
        f"  checks ({plan.totals.included_checks} included, "
        f"{plan.totals.withheld_checks} withheld):"
    )
    for check in plan.included_checks:
        active = " [active]" if check.requires_active_checks else ""
        proof = f" [{check.proof_effective.value}"
        if check.proof_effective.rank < check.proof.rank:
            proof += f"↓{check.proof.value}]"
        else:
            proof += "]"
        lines.append(
            f"    [{check.module}] {check.name:30}{check.research_ref:10}"
            f"{check.estimated_requests:5d} request(s){active}{proof}"
        )
        if check.proof_note:
            lines.append(f"        proof: {check.proof_note}")
    # REQ-PROOF-004: an L3/L4 check in the plan prints the attestation it demands of a
    # live scan (and the live scan is refused without it — the proof gate).
    state_checks = [check for check in plan.included_checks if check.proof.needs_state_attestation]
    if state_checks:
        names = ", ".join(f"{check.module}.{check.name}" for check in state_checks)
        if plan.attestation is not None and plan.attestation.get("state_changes_authorized"):
            lines.append(
                f"  proof (L3/L4): {names} — state-change attestation present "
                f"[{plan.attestation.get('attested_by')}]"
            )
        else:
            lines.append(
                f"  proof (L3/L4): {names} — REQUIRED: an attestation with "
                "state_changes_authorized=true; a live scan including them is REFUSED"
            )
    withheld = plan.withheld_checks
    if withheld:
        lines.append("  withheld:")
        for check in withheld:
            lines.append(f"    [{check.module}] {check.name:30}{check.skip_reason}")

    lines.append(
        "  totals: "
        f"{plan.totals.included_checks} checks, "
        f"{plan.totals.active_checks} active, "
        f"{plan.totals.estimated_requests} estimated request(s), "
        f"proof L2+ {plan.totals.proof_l2plus}, "
        f"downgraded {plan.totals.proof_downgrades}, "
        f"modules {', '.join(plan.totals.modules) or '(none)'}"
    )
    if plan.warnings:
        lines.append("  warnings:")
        lines.extend(f"    - {warning}" for warning in plan.warnings)
    lines.append("  (dry run: no request was made and no database was opened)")
    return "\n".join(lines)


def render_run(session: ScanSession) -> str:
    """Human-readable summary of a live scan or a resume."""
    outcome = session.outcome
    lines = [
        f"scan {session.scan_id}: {session.status.value}"
        + (" (resumed)" if outcome is not None and outcome.resumed else ""),
        f"  target:  {session.plan.target_name}",
        f"  engine:  {session.plan.engine}",
        f"  assets:  {outcome.assets if outcome else 0} recorded",
    ]
    if outcome is not None:
        executed = ", ".join(step.value for step in outcome.executed) or "(none)"
        skipped = ", ".join(step.value for step in outcome.skipped) or "(none)"
        already = ", ".join(step.value for step in outcome.already_completed) or "(none)"
        lines.append(f"  steps executed:  {executed}")
        lines.append(f"  steps skipped:   {skipped}")
        lines.append(f"  already complete: {already}")

    checks = _check_statistics(session)
    if checks:
        lines.append("  checks:")
        for step, stats in checks:
            lines.append(
                f"    {step:12}{stats['checks_run']} run, "
                f"{stats['checks_skipped']} skipped, {stats['checks_failed']} failed, "
                f"{stats['candidates']} candidate(s), {stats['assets_recorded']} new asset(s)"
                + (
                    f", {stats['osint_requests']} third-party request(s)"
                    if stats.get("osint_requests")
                    else ""
                )
            )

    analysis = _analysis_statistics(session)
    if analysis is not None:
        step, stats = analysis
        severities: dict[str, int] = _as_int_map(stats.get("severities"))
        rendered = ", ".join(f"{count} {name}" for name, count in severities.items()) or "none"
        lines.append(f"  analysis ({step}):")
        lines.append(
            f"    {stats.get('candidates_analyzed', 0)} candidate(s) → "
            f"{stats.get('findings', 0)} finding(s) [{rendered}]"
            + (f", {stats['dropped']} dropped" if stats.get("dropped") else "")
            + (f", {stats['low_confidence']} low-confidence" if stats.get("low_confidence") else "")
        )
        rules_fired = _as_str_list(stats.get("rules_fired"))
        if rules_fired:
            lines.append(f"    rules fired: {', '.join(rules_fired)}")
        signatures = _as_str_list(stats.get("signatures_matched"))
        if signatures:
            lines.append(f"    signatures:  {', '.join(signatures)}")
        ai = _ai_statistics(stats)
        if ai is not None:
            budget = ai.get("budget")
            budget = budget if isinstance(budget, dict) else {}
            tokens = budget.get("tokens")
            tokens = tokens if isinstance(tokens, dict) else {}
            lines.append(
                f"    ai: {ai.get('provider') or '(none)'} / {ai.get('model') or '(none)'}"
                f" — {budget.get('requests', 0)} call(s), "
                f"{tokens.get('total_tokens', 0)} token(s), "
                f"${float(tokens.get('cost_usd') or 0):.4f}"
                + (f", {ai['degraded']} degraded to heuristic" if ai.get("degraded") else "")
            )
    correlation = _correlation_statistics(session)
    if correlation is not None:
        stats = correlation
        lines.append(
            f"  correlation: {stats.get('compounds', 0)} compound finding(s), "
            f"{stats.get('merged', 0)} merged duplicate(s)"
        )
    return "\n".join(lines)


#: Step-statistics keys the checks engine writes (``modules.handlers``).
_CHECK_STAT_KEYS = (
    "checks_run",
    "checks_skipped",
    "checks_failed",
    "candidates",
    "assets_recorded",
)


def _check_statistics(session: ScanSession) -> list[tuple[str, dict[str, int]]]:
    """Per-step check counters, for the steps that ran checks."""
    record = session.record
    if record is None:
        return []
    out: list[tuple[str, dict[str, int]]] = []
    for state in record.steps:
        if "checks_run" not in state.stats:
            continue
        out.append(
            (
                state.step.value,
                {key: int(state.stats.get(key, 0)) for key in _CHECK_STAT_KEYS}
                | {"osint_requests": int(state.stats.get("osint_requests", 0))},
            )
        )
    return out


def _ai_statistics(stats: dict[str, Any]) -> dict[str, Any] | None:
    """The analysis step's ``ai`` block, when the scan ran an AI engine (S9)."""
    ai = stats.get("ai")
    return dict(ai) if isinstance(ai, dict) else None


def _as_int_map(value: Any) -> dict[str, int]:
    """A ``{name: count}`` step stat, coerced (the stats column is free-form JSON)."""
    if not isinstance(value, dict):
        return {}
    return {str(key): int(count) for key, count in value.items() if isinstance(count, int)}


def _as_str_list(value: Any) -> list[str]:
    """A step-stat list (``rules_fired``, ``signatures_matched``) as strings."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _analysis_statistics(session: ScanSession) -> tuple[str, dict[str, Any]] | None:
    """The analysis step's statistics, when that step ran."""
    record = session.record
    if record is None:
        return None
    for state in record.steps:
        if "candidates_analyzed" in state.stats:
            return state.step.value, dict(state.stats)
    return None


def _correlation_statistics(session: ScanSession) -> dict[str, Any] | None:
    """The correlation step's statistics, when it produced or merged anything."""
    record = session.record
    if record is None:
        return None
    for state in record.steps:
        if "compounds" in state.stats:
            return dict(state.stats)
    return None
