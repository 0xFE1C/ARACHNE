"""Schema versioning (F-09-02).

Alembic owns the migration graph (``migrations/``) and its ``alembic_version`` table is
the authoritative schema version. :data:`LATEST_SCHEMA_REVISION` is the revision this
code expects; tests assert the two agree, so forgetting to run/commit a migration fails
CI instead of failing in production. Every scan report carries this value so a report can
be read against the schema that produced it ("version everything").
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "ALEMBIC_VERSION_TABLE",
    "EXTENSION_TABLE_NAMES",
    "LATEST_SCHEMA_REVISION",
    "SPEC_TABLE_NAMES",
    "TABLE_NAMES",
]

#: Revision this code expects ``alembic upgrade head`` to reach.
LATEST_SCHEMA_REVISION: Final = "0014"

#: Table Alembic uses to record the applied revision.
ALEMBIC_VERSION_TABLE: Final = "alembic_version"

#: The evidence-store tables defined in in dependency order.
SPEC_TABLE_NAMES: Final[tuple[str, ...]] = (
    "targets",
    "scans",
    "assets",
    "checks",
    "findings",
    "evidences",
    "analysis_log",
    "audit_log",
    "scans_diff",
)

#: Tables this project adds to the spec's core set, with the stage that added them.
EXTENSION_TABLE_NAMES: Final[tuple[str, ...]] = (
    # S2 / F-01-04: per-step progress, so a crashed scan resumes from its last step.
    "scan_steps",
    # S5 / F-05-07: operator false-positive feedback for the confidence tuner.
    "fp_feedback",
    # S14 / F-07-06: tenant/workspace rows (scope + report branding per project).
    "projects",
    # S14 / F-09-03: ingested CVE/EPSS feed artefacts and their normalised rows.
    "feeds",
    "feed_entries",
    # S16 / area SCALE: the Postgres work queue and the registered agent fleet.
    "scan_queue",
    "scan_agents",
    # S17 / area IDAM: service accounts, pending OIDC flows, and minted sessions.
    "service_accounts",
    "sso_flows",
    "auth_sessions",
    # S21 / area QUAL: the FP workflow's suppression rules and risk acceptances.
    "suppressions",
    "risk_acceptances",
    # S23 / area POSTURE: continuous exposure management — drift baselines, the
    # fix-verification history and CMDB asset criticality.
    "posture_baselines",
    "posture_verifications",
    "asset_criticality",
    # S24 / area VALID: detection validation (purple team) — campaigns, the runs whose
    # trend they build, and the defender alerts ingested to score them.
    "purple_campaigns",
    "purple_runs",
    "purple_alerts",
    # S25 / areas RESIL + TRUST: the tamper-evidence trail (signed chain checkpoints and
    # the per-scan row seals), the HA leader leases and the offline content-pack provenance.
    "integrity_anchors",
    "integrity_seals",
    "leader_leases",
    "content_packs",
    # S26 / area ECOS: the marketplace review pipeline's provenance — one row per pack
    # review (the signature/safety/parity gates and the decision), so "why is this pack
    # listed?" is answerable from the database.
    "pack_reviews",
    # S27 / area FIX: remediation as code — one row per proposed artifact, carrying the
    # human approval, the repository's own test verdict, the IaC self-scan delta and the
    # fix-verification act that closed the finding.
    "fix_proposals",
    # S28 / area SIM: the event-driven re-simulation trend — one row per re-run of the
    # estate model, carrying the simulated path counts and exposure score the posture view
    # plots. Its own table on purpose: a simulation point is an observation of a
    # computation, never a finding, so nothing that reads findings can reach it.
    "simulation_points",
)

#: Every table the schema owns.
TABLE_NAMES: Final[tuple[str, ...]] = SPEC_TABLE_NAMES + EXTENSION_TABLE_NAMES
