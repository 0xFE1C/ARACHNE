"""``arachne iac-gate`` — the pre-deploy IaC/CI gate (S23, REQ-POSTURE-002).

One command a pipeline can call before deploy: point it at a directory (or a single
file) of Terraform, Kubernetes manifests and CI pipeline configs, and it runs ARACHNE's
M5 artifact reviews — the IaC misconfiguration review, the structured Kubernetes policy
rules (the same ones the admission webhook enforces), the CI/CD workflow audit — through
a **real scan**, so the findings carry the same schema, the same evidence and the same
check provenance as any other ARACHNE scan. The exit-code policy is the F-07-05 CI gate:
``0`` clean, ``1`` findings all below the threshold, ``2`` at least one at or above.

The scan is offline by construction: the target is a local ``repo:`` reference (no
clone, no fetch), the checks it runs read local artifacts only, and the self-attestation
the command records says exactly that ("local pre-deploy review of <path>; no network
requests") so the audit trail never mistakes it for a network scan. Everything still
passes the real gates — scope, attestation, proof — because it is a real scan.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.cli.ci import (
    gate_exit_code,
    gate_summary,
    parse_threshold,
)
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.core.target import (
    AuthorizationAttestation,
    EngineName,
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetKind,
    TargetSelector,
)
from arachne.data.api_store import ApiQueryStore
from arachne.data.services import build_orchestrator, build_services

__all__ = ["iac_gate_command"]

app = typer.Typer(help="Pre-deploy IaC/CI scanning (S23, REQ-POSTURE-002).")


def _self_attestation(path: Path) -> AuthorizationAttestation:
    """The local-review attestation the operator's own invocation stands for.

    A CI job running ``arachne iac-gate .`` is the operator authorizing a *local artifact
    review of their own tree* — no network, no target contact. Recording it as a real
    attestation (instead of bypassing the gate) is what keeps "every live scan carries an
    attestation" true without a ceremony for the offline case.
    """
    return AuthorizationAttestation(
        attested_by="arachne iac-gate (local pre-deploy review)",
        attested_at=datetime.now(UTC),
        scope_statement=(
            f"Local pre-deploy IaC/CI review of {path}; the scan reads local artifacts only "
            "and makes no network requests."
        ),
        allowed_targets=(f"repo:{path}",),
        authorization_ref=f"iac-gate:{path.name}",
    )


def _scan_request(path: Path, checks: tuple[str, ...]) -> ScanRequest:
    selector = TargetSelector(kind=TargetKind.CLOUD, value="repo:" + str(path))
    definition = TargetDefinition(
        name=f"iac:{path.name}",
        targets=(selector,),
        attestation=_self_attestation(path),
    )
    options = ScanOptions(
        engine=EngineName.HEURISTIC,
        active_checks=False,
        modules=ModuleSelection(enabled=("M5",), checks=checks),
        notes="arachne iac-gate: local pre-deploy review (offline by construction)",
    )
    return ScanRequest(target=definition, options=options)


def _counts_for(scan_id: int, session_factory: Any) -> dict[str, int]:
    """Severity counts for the gate (F-07-05's input), read before the store closes."""
    return dict(ApiQueryStore(session_factory).severity_counts(scan_id))


@app.command(name="gate")
def iac_gate_command(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=True, help="IaC/CI tree to review."),
    ],
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help=(
                "CI gate (F-07-05): exit 2 when a finding is at or above this severity "
                "(info|low|medium|high|critical). Default: ARACHNE_CI_FAIL_ON, else 'high'."
            ),
        ),
    ] = None,
    check: Annotated[
        str | None,
        typer.Option("--check", help="Additional opt-in M5 checks to include (comma-separated)."),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Machine-readable gate block.")
    ] = False,
) -> None:
    """Scan a local IaC/CI tree and exit per the CI-gate policy (0/1/2)."""
    threshold = parse_threshold(fail_on or "high")
    root = path.expanduser().resolve()
    extra_checks: tuple[str, ...] = ()
    if check:
        extra_checks = tuple(item.strip() for item in check.split(",") if item.strip())
    try:
        request = _scan_request(root, extra_checks)
        settings = get_settings()
        services = build_services(settings)
        try:
            orchestrator = build_orchestrator(services)
            session = asyncio.run(orchestrator.scan(request))
            assert session.scan_id is not None
            counts = _counts_for(session.scan_id, services.session_factory)
        finally:
            services.close()
    except ArachneError as exc:
        typer.secho(f"iac-gate: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"scan {session.scan_id}: reviewed {root} — "
        f"{sum(counts.values())} finding(s); threshold {threshold}"
    )
    if json_output:
        typer.echo(json.dumps(gate_summary(counts, threshold), indent=2))
    code = gate_exit_code(counts, threshold)
    raise typer.Exit(code=code)
