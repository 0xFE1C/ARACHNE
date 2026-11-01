"""A small estate lab for the S28 tests: three hosts, real stores' shapes, known paths.

Area SIM's accept criteria are all "on the lab model", so the lab has to be a *model* with a
predictable answer, not a convenient set of objects. This helper builds one: a public web
application with an exposed configuration file, vendor-default credentials and an injection
flaw (the three-hop chain), a database host reachable from the application, and a legacy host
exposing a deprecated service. Reachability comes from the same evidence payload the M2 port
scan writes, so the model is built the way a real deployment's would be.

The helpers return the four inputs ``build_estate_graph`` takes, so a test can assert on the
model and on the composition without a database — and the integration suite runs the same
shapes through the real stores.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.analyzer.model import Analysis, Remediation
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.lifecycle import AssetRecord
from arachne.sim.model import EstateGraph, IdentityBinding, build_estate_graph
from arachne.sim.reachability import ServiceObservation

__all__ = [
    "APP_HOST",
    "DB_HOST",
    "ESTATE_KEY",
    "LEGACY_HOST",
    "StoredShapes",
    "lab_candidate",
    "lab_estate",
    "lab_graph",
    "lab_inputs",
    "lab_service_note",
]

APP_HOST = "app.example"
DB_HOST = "db.internal"
LEGACY_HOST = "legacy.example"
ESTATE_KEY = "lab-estate"


@dataclass(frozen=True, slots=True)
class StoredShapes:
    """The three store shapes ``build_estate_graph`` reads, plus the bindings."""

    assets: tuple[AssetRecord, ...]
    candidates: tuple[Any, ...]
    analyses: tuple[Analysis, ...]
    identity_bindings: tuple[IdentityBinding, ...]
    reachability: tuple[ServiceObservation, ...]


class FakeEvidence:
    """The evidence shape ``finding_store.EvidenceRecord`` has, without a store."""

    __slots__ = ("created_at", "id", "kind", "payload", "sha256")

    def __init__(self, evidence_id: int, kind: str, payload: dict[str, Any]) -> None:
        self.id = evidence_id
        self.kind = kind
        self.payload = payload
        self.sha256: str | None = None
        self.created_at = None


class FakeCandidate:
    """The candidate shape ``finding_store.CandidateRecord`` has, without a store."""

    __slots__ = (
        "asset_id",
        "asset_kind",
        "asset_value",
        "check_id",
        "check_key",
        "confidence",
        "created_at",
        "evidence",
        "id",
        "module",
        "research_ref",
        "scan_id",
        "severity",
        "status",
        "title",
    )

    def __init__(
        self,
        *,
        finding_id: int,
        title: str,
        asset_value: str,
        check_key: str,
        severity: str,
        asset_kind: str = "host",
        scan_id: int = 1,
        confidence: float = 90.0,
        status: str = "open",
        evidence: tuple[Any, ...] = (),
    ) -> None:
        self.id = finding_id
        self.scan_id = scan_id
        self.title = title
        self.status = status
        self.confidence = confidence
        self.severity = severity
        self.check_id = finding_id
        self.asset_id = finding_id
        self.asset_kind = asset_kind
        self.asset_value = asset_value
        self.check_key = check_key
        self.module = check_key.split(".", 1)[0].upper() if "." in check_key else "M4"
        self.research_ref = None
        self.created_at = None
        self.evidence = evidence


def lab_service_note(hosts: dict[str, list[int]]) -> dict[str, Any]:
    """The M2 port scan's evidence payload shape: ``{"hosts": {host: [ports]}}``."""
    return {"backend": "connect", "port_policy": "top 100 TCP", "hosts": hosts, "banners": {}}


def lab_candidate(
    *,
    finding_id: int,
    check_key: str,
    title: str,
    asset: str,
    severity: str,
    cwe: str,
    scan_id: int = 1,
    asset_kind: str = "host",
) -> Analysis:
    """A verified analysis on the lab estate, shaped as the composer reads it."""
    return Analysis(
        title=title,
        severity=severity,
        confidence=90,
        narrative=f"{title} was confirmed on {asset}.",
        remediation=Remediation(
            id=f"fix-{check_key.replace('.', '-')}",
            summary=f"remediate {title}",
            steps=("apply the vendor fix",),
        ),
        finding_id=finding_id,
        check_id=check_key,
        asset=asset,
        cwe=cwe,
        verdict="analyzed",
        verified=True,
    )


def lab_inputs() -> StoredShapes:
    """The lab estate as the four shapes a model is built from."""
    assets = (
        AssetRecord(id=1, scan_id=1, kind="url", value=f"https://{APP_HOST}/"),
        AssetRecord(id=2, scan_id=1, kind="host", value=DB_HOST),
        AssetRecord(id=3, scan_id=1, kind="host", value=LEGACY_HOST),
    )

    # The port scan's own evidence: which ports answered, and therefore what is reachable.
    port_scan = FakeCandidate(
        finding_id=900,
        title="TCP port scan",
        asset_value=APP_HOST,
        check_key="M2/port-scan@1.0",
        severity="info",
        evidence=(
            FakeEvidence(
                901,
                "note",
                lab_service_note(
                    {
                        APP_HOST: [22, 443],
                        DB_HOST: [3306],
                        LEGACY_HOST: [23],
                    }
                ),
            ),
        ),
    )

    candidates: tuple[Any, ...] = (
        FakeCandidate(
            finding_id=1,
            title="Exposed environment file",
            asset_value=f"https://{APP_HOST}/.env",
            check_key="M4/env-file-probe@1.0",
            severity="high",
            asset_kind="url",
        ),
        FakeCandidate(
            finding_id=2,
            title="Vendor-default credentials",
            asset_value=APP_HOST,
            check_key="M4/default-credentials@1.0",
            severity="high",
        ),
        FakeCandidate(
            finding_id=3,
            title="SQL injection in the login form",
            asset_value=f"https://{APP_HOST}/login",
            check_key="M3/sqli-oracle@1.0",
            severity="critical",
            asset_kind="url",
        ),
        FakeCandidate(
            finding_id=4,
            title="Database service exposed to the application network",
            asset_value=DB_HOST,
            check_key="M5/exposed-database@1.0",
            severity="high",
        ),
        FakeCandidate(
            finding_id=5,
            title="Deprecated telnet service is reachable",
            asset_value=LEGACY_HOST,
            check_key="M2/telnet-service@1.0",
            severity="medium",
        ),
        port_scan,
    )

    analyses = (
        lab_candidate(
            finding_id=1,
            check_key="M4/env-file-probe@1.0",
            title="Exposed environment file",
            asset=f"https://{APP_HOST}/.env",
            severity="high",
            cwe="CWE-200",
        ),
        lab_candidate(
            finding_id=2,
            check_key="M4/default-credentials@1.0",
            title="Vendor-default credentials",
            asset=APP_HOST,
            severity="high",
            cwe="CWE-1392",
        ),
        lab_candidate(
            finding_id=3,
            check_key="M3/sqli-oracle@1.0",
            title="SQL injection in the login form",
            asset=f"https://{APP_HOST}/login",
            severity="critical",
            cwe="CWE-89",
        ),
        lab_candidate(
            finding_id=4,
            check_key="M5/exposed-database@1.0",
            title="Database service exposed to the application network",
            asset=DB_HOST,
            severity="high",
            cwe="CWE-306",
        ),
    )

    identity_bindings = (
        IdentityBinding(
            identity="portal",
            host=APP_HOST,
            kind="credential",
            source="scan 1",
        ),
        IdentityBinding(
            identity="portal",
            host=DB_HOST,
            kind="credential",
            source="scan 1",
        ),
    )

    return StoredShapes(
        assets=assets,
        candidates=candidates,
        analyses=analyses,
        identity_bindings=identity_bindings,
        reachability=(),
    )


def lab_estate(
    *, auditor: Auditor | None = None, estate_key: str = ESTATE_KEY, **overrides: Any
) -> EstateGraph:
    """The lab estate model, built the way the composition root builds one."""
    shapes = lab_inputs()
    sink = MemoryAuditSink()
    effective = auditor or Auditor(sink, actor="pytest")
    _ = effective
    return build_estate_graph(
        estate_key=estate_key,
        assets=overrides.get("assets", shapes.assets),
        candidates=overrides.get("candidates", shapes.candidates),
        analyses=overrides.get("analyses", shapes.analyses),
        identity_bindings=overrides.get("identity_bindings", shapes.identity_bindings),
        reachability=overrides.get("reachability"),
        built_from_scans=overrides.get("built_from_scans", (1,)),
    )


def lab_graph(**overrides: Any) -> EstateGraph:
    """Alias kept for readability in tests that think in terms of "the lab graph"."""
    return lab_estate(**overrides)
