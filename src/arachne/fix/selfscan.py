"""The IaC self-scan: a fix may not introduce a finding of its own (S27, REQ-FIX-004).

REQ-FIX-004 asks that IaC/cloud proposals be "validated against ARACHNE's own IaC scanner
(REQ-POSTURE-002) so a fix never introduces a finding of its own". This module is that
validation, and it is a **real scan**: the patched files are materialized in a temporary tree
and reviewed by the same M5 artifact reviews the pre-deploy gate runs
(:mod:`arachne.cli.iac`), through :meth:`Orchestrator.scan` — so the verdict carries the same
scope gate, the same attestation, the same analysis and the same evidence schema as any other
ARACHNE scan, and both runs leave scans of their own in the trail.

The verdict is a **delta**, and that word is the whole design:

* the *before* tree holds the files exactly as the finding found them;
* the *after* tree holds them as the fix would leave them;
* both are reviewed, and the proposal is clean when nothing appears in the after set that was
  not already in the before set.

An absolute reading — "no finding may name a changed file" — would refuse a legitimate fix
whenever the file had a *second*, pre-existing problem (a manifest with a privileged container
*and* host networking, say): the fix would be blamed for a misconfiguration it did not touch,
and the operator's real choice would be to widen the diff. The delta reading is also what a
reviewer actually asks: *does this change make things worse?*

Both runs are offline by construction — the target is a local ``repo:`` reference, so nothing
is cloned and no request leaves the process — and the self-attestation each scan records says
so, which is what keeps "every scan carries an attestation" true without a ceremony.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

__all__ = [
    "SELF_SCAN_CHECKS",
    "SelfScanFinding",
    "SelfScanResult",
    "artifact_locations",
    "review_tree",
    "self_scan_request",
    "self_scan_sync",
    "self_scan_tree",
]

#: The M5 reviews a fix's artifact must survive: the IaC misconfiguration review (which also
#: evaluates the structured Kubernetes policy rules) and the CI/CD workflow audit — named
#: exactly as the pre-deploy gate (REQ-POSTURE-002) names them, on top of the module's own
#: default set, which ``enabled=("M5",)`` keeps in place.
SELF_SCAN_CHECKS = ("m5.tfstate-exposure", "m5.cicd-audit")


def _attestation(root: Path, *, phase: str) -> AuthorizationAttestation:
    return AuthorizationAttestation(
        attested_by=f"arachne fix ({phase} IaC self-scan)",
        attested_at=datetime.now(UTC),
        scope_statement=(
            f"Local {phase} self-scan of {root}; the scan reads local artifacts only and "
            "makes no network requests."
        ),
        allowed_targets=(f"repo:{root}",),
        authorization_ref=f"fix-self-scan:{phase}:{root.name}",
    )


def self_scan_request(root: Path, *, phase: str = "post-fix") -> ScanRequest:
    """The offline review request for one tree (a real scan's front door)."""
    selector = TargetSelector(kind=TargetKind.CLOUD, value="repo:" + str(root))
    definition = TargetDefinition(
        name=f"fix-self-scan:{phase}:{root.name}",
        targets=(selector,),
        attestation=_attestation(root, phase=phase),
    )
    options = ScanOptions(
        engine=EngineName.HEURISTIC,
        active_checks=False,
        modules=ModuleSelection(enabled=("M5",), checks=SELF_SCAN_CHECKS),
        notes=f"arachne fix: {phase} IaC self-scan (offline by construction)",
    )
    return ScanRequest(target=definition, options=options)


@dataclass(frozen=True, slots=True)
class SelfScanFinding:
    """One re-scan finding that names a file the fix changed."""

    check_key: str | None
    severity: str | None
    title: str
    locations: tuple[str, ...]
    rule: str | None = None

    @property
    def identity(self) -> tuple[str | None, str | None, tuple[str, ...]]:
        """What "a finding of its own" means: same check, same rule, same files."""
        return (self.check_key, self.rule, self.locations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_key": self.check_key,
            "severity": self.severity,
            "title": self.title,
            "locations": list(self.locations),
            "rule": self.rule,
        }


@dataclass(frozen=True, slots=True)
class SelfScanResult:
    """The self-scan verdict: what the patched files report, and what is *new*."""

    required: bool
    clean: bool
    scan_id: int | None = None
    baseline_scan_id: int | None = None
    findings: tuple[SelfScanFinding, ...] = ()
    introduced: tuple[SelfScanFinding, ...] = ()
    detail: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "clean": self.clean,
            "scan_id": self.scan_id,
            "baseline_scan_id": self.baseline_scan_id,
            "findings": [item.to_dict() for item in self.findings],
            "introduced": [item.to_dict() for item in self.introduced],
            "detail": self.detail,
        }


def artifact_locations(evidence: Any) -> tuple[tuple[str, ...], dict[str, Any]]:
    """The file locations and the artifact of one finding's evidence rows.

    An evidence row of kind ``artifact`` carries the check's verdict as facts
    (``locations`` for the IaC review, ``location`` for the single-file reviews); the paths
    are what makes "did this finding come from the fix's files?" answerable.
    """
    locations: list[str] = []
    artifact: dict[str, Any] = {}
    for item in getattr(evidence, "__iter__", lambda: ())():
        if getattr(item, "kind", None) != "artifact":
            continue
        payload = getattr(item, "payload", None)
        if not isinstance(payload, dict):
            continue
        artifact = dict(payload)
        raw = payload.get("locations")
        if isinstance(raw, (list, tuple)):
            locations.extend(str(entry).split("#", 1)[0] for entry in raw)
        single = payload.get("location")
        if isinstance(single, str):
            locations.append(single.split("#", 1)[0])
    return tuple(sorted({item.strip().lstrip("/") for item in locations if item.strip()})), artifact


async def review_tree(
    services: Any, root: Path, *, changed_files: tuple[str, ...], phase: str
) -> tuple[int | None, tuple[SelfScanFinding, ...]]:
    """Review one tree and return the findings that name a ``changed_files`` path."""
    from arachne.data.services import build_orchestrator

    orchestrator = build_orchestrator(services)
    session = await orchestrator.scan(self_scan_request(root, phase=phase))
    scan_id = session.scan_id
    if scan_id is None:  # pragma: no cover - scan() always persists one
        return None, ()
    changed = {item.lstrip("/") for item in changed_files}
    out: list[SelfScanFinding] = []
    for candidate in services.findings.list_candidates(int(scan_id)):
        if candidate.status in {"fp", "merged"} or candidate.severity is None:
            continue
        locations, artifact = artifact_locations(candidate.evidence)
        touched = tuple(item for item in locations if item in changed)
        if not touched:
            continue
        rule = artifact.get("rule")
        out.append(
            SelfScanFinding(
                check_key=candidate.check_key,
                severity=candidate.severity,
                title=candidate.title,
                locations=touched,
                rule=str(rule) if isinstance(rule, str) else None,
            )
        )
    return int(scan_id), tuple(out)


async def self_scan_tree(
    services: Any,
    root: Path,
    *,
    changed_files: tuple[str, ...],
    baseline_root: Path | None = None,
    required: bool = True,
) -> SelfScanResult:
    """Compare the patched files' findings against the pre-fix files' findings."""
    after_scan, after = await review_tree(
        services, root, changed_files=changed_files, phase="post-fix"
    )
    if not required:
        return SelfScanResult(required=False, clean=True, scan_id=after_scan, findings=after)
    before_scan, before = (
        await review_tree(services, baseline_root, changed_files=changed_files, phase="pre-fix")
        if baseline_root is not None
        else (None, ())
    )
    known = {item.identity for item in before}
    introduced = tuple(item for item in after if item.identity not in known)
    if introduced:
        detail = (
            f"self-scan {after_scan} reports "
            + "; ".join(
                f"{item.check_key} ({item.rule or 'rule'}) on {', '.join(item.locations)}"
                for item in introduced[:4]
            )
            + " on the changed files, and the pre-fix review did not"
        )
    else:
        detail = (
            f"self-scan {after_scan} reviewed the patched files and introduced no finding "
            f"({len(after)} finding(s) on them, all present before the fix)"
        )
    return SelfScanResult(
        required=required,
        clean=not introduced,
        scan_id=after_scan,
        baseline_scan_id=before_scan,
        findings=after,
        introduced=introduced,
        detail=detail,
    )


def self_scan_sync(
    services: Any,
    root: Path,
    *,
    changed_files: tuple[str, ...],
    baseline_root: Path | None = None,
    required: bool = True,
) -> SelfScanResult:
    """The synchronous entry point the CLI uses (a scan is async, like any other)."""
    return asyncio.run(
        self_scan_tree(
            services,
            root,
            changed_files=changed_files,
            baseline_root=baseline_root,
            required=required,
        )
    )
