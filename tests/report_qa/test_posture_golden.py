"""The S23 golden files: the estate posture report and the criticality-scaled paths.

Two executive-facing renderings, pinned so they cannot drift silently:

* REQ-POSTURE-004 — the estate posture & trend report (trend table, drift per period,
  the fix-verification loop, the watched inventory) rendered from stored data only;
* REQ-POSTURE-006 — attack paths ranked and labelled by CMDB business impact: a tier-1
  asset's *terminal-medium* path ranks as **high**, above a tier-less medium, and the
  report states where the tier came from. Without an import the paths carry no
  criticality and the report is byte-identical to its pre-S23 form.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import jsonschema

from arachne.posture.cmdb import CriticalityIndex
from arachne.posture.trend import (
    ScanPoint,
    build_estate_posture,
    estate_payload,
    render_estate_markdown,
)
from arachne.report import REPORT_SCHEMA_VERSION, load_report_schema
from arachne.report.builder import build_report_data
from tests.helpers.report import make_analysis, make_candidate, make_inputs

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)


# ------------------------------------------------------------------ REQ-POSTURE-004
def _estate_inputs() -> tuple[list[ScanPoint], list[dict[str, object]]]:
    points = [
        ScanPoint(
            scan_id=1,
            target_name="lab-estate",
            created_at=datetime(2026, 10, 30, 9, 0, tzinfo=UTC),
            counts={"high": 2, "medium": 1, "info": 3},
        ),
        ScanPoint(
            scan_id=2,
            target_name="lab-estate",
            created_at=datetime(2026, 10, 31, 9, 0, tzinfo=UTC),
            counts={"high": 1, "medium": 2, "info": 3},
        ),
    ]
    return points, []


def test_the_estate_report_renders_the_trend_and_the_fix_loop() -> None:
    """REQ-POSTURE-004 (golden): the executive rendering, deterministic across renders."""
    points, _ = _estate_inputs()
    finding_sets = [
        {
            "m1.x|a": _FindingView(1, "m1.x", "a", "medium"),
            "m1.y|b": _FindingView(2, "m1.y", "b", "high"),
        },
        {
            "m1.x|a": _FindingView(3, "m1.x", "a", "medium"),
            "m1.y|b": _FindingView(4, "m1.y", "b", "high"),
            "m1.z|c": _FindingView(5, "m1.z", "c", "high"),
        },
    ]
    posture = build_estate_posture(
        project="Lab Estate",
        points=points,
        finding_sets=finding_sets,
        open_counts={"high": 1, "medium": 2, "info": 3},
        closed_by_verification=4,
        reopened_regressions=1,
        still_open_verifications=2,
        inventory={"storage": 3, "database": 1},
        watched_scopes=[("endpoint:http://lab/posture", 4)],
        now=NOW,
    )
    markdown = render_estate_markdown(posture)
    assert markdown == render_estate_markdown(posture)  # deterministic

    assert "# Estate posture — Lab Estate" in markdown
    assert "| Scan | Target | Critical | High | Medium | Low | Info | Total |" in markdown
    assert "| 1 | lab-estate | 0 | 2 | 1 | 0 | 3 | 6 |" in markdown
    assert "| 2 | lab-estate | 0 | 1 | 2 | 0 | 3 | 6 |" in markdown
    # The drift sentence with the new finding named.
    assert "1 new, 0 fixed, 0 regressed, 2 recurring" in markdown
    assert "new: **high** m1.z on c" in markdown
    # The fix loop, in the executive's vocabulary.
    assert "4 finding(s) closed by verified fix" in markdown
    assert "1 regression(s) re-opened" in markdown
    assert "Currently open: **6** (0 critical, 1 high)" in markdown
    assert "`endpoint:http://lab/posture` — 4 resource(s) under continuous watch" in markdown
    assert "database (1), storage (3)" in markdown

    payload = estate_payload(posture)
    assert payload["fix_loop"] == {
        "closed_by_verification": 4,
        "reopened_regressions": 1,
        "still_open_verifications": 2,
    }
    assert payload["scans"][1]["total"] == 6
    assert json.dumps(payload, sort_keys=True) == json.dumps(  # stable JSON
        estate_payload(posture), sort_keys=True
    )


def test_a_quiet_period_reads_as_the_estate_holding_steady() -> None:
    points = [ScanPoint(1, "lab", NOW, {"low": 1}), ScanPoint(2, "lab", NOW, {"low": 1})]
    finding_sets = [{"m1.x|a": _FindingView(1, "m1.x", "a", "low")}] * 2
    posture = build_estate_posture(
        project="Lab", points=points, finding_sets=finding_sets, open_counts={"low": 1}, now=NOW
    )
    markdown = render_estate_markdown(posture)
    assert "no change — the estate held steady" in markdown


class _FindingView:
    """The minimal finding view the drift computation reads (candidate-shaped)."""

    def __init__(self, scan_id: int, check_id: str, asset: str, severity: str) -> None:
        self.scan_id = scan_id
        self.check_id = check_id
        self.asset = _AssetView(asset)
        self.severity = severity


class _AssetView:
    def __init__(self, value: str) -> None:
        self.value = value


# ------------------------------------------------------------------ REQ-POSTURE-006
def _two_candidates(host: str, *, terminal: str = "critical"):
    exposure = make_candidate(
        number=1,
        title="Sensitive environment file exposed",
        asset_value=f"https://{host}/.env",
        check="env-file-probe",
        severity="medium",
        confidence=88,
        evidence_start=1,
    )
    terminal_finding = make_candidate(
        number=2,
        title="Unauthenticated admin dashboard",
        asset_value=f"https://{host}/admin",
        check="dashboard-exposure",
        severity=terminal,
        confidence=95,
        evidence_start=20,
    )
    analyses = [
        make_analysis(exposure, severity="medium", confidence=88, cwe="CWE-200"),
        make_analysis(
            terminal_finding,
            severity=terminal,
            confidence=95,
            cwe="CWE-306",
            remediation_id="dashboard-auth",
        ),
    ]
    return [exposure, terminal_finding], analyses


def _report_with(
    candidates: list[object],
    analyses: list[object],
    criticality: CriticalityIndex | None,
):
    inputs = make_inputs(candidates=candidates, analyses=analyses)  # type: ignore[arg-type]
    return build_report_data(
        type(inputs)(
            **{
                **{f: getattr(inputs, f) for f in inputs.__dataclass_fields__},
                "criticality": criticality,
            }
        )
    )


def test_a_tier_one_asset_scales_the_path_rank_and_is_labelled() -> None:
    """REQ-POSTURE-006 (golden): criticality scales the path's rank, never its finding."""
    # Two hosts, each a two-hop chain with the same terminal impact (medium):
    # payments is tier 1 in the CMDB, build is not in the import at all.
    payments_exposure = make_candidate(
        number=1,
        title="Sensitive environment file exposed",
        asset_value="https://payments.example/.env",
        check="env-file-probe",
        severity="low",
        confidence=88,
        evidence_start=1,
    )
    payments_admin = make_candidate(
        number=2,
        title="Unauthenticated admin dashboard",
        asset_value="https://payments.example/admin",
        check="dashboard-exposure",
        severity="medium",
        confidence=95,
        evidence_start=20,
    )
    build_exposure = make_candidate(
        number=3,
        title="Sensitive environment file exposed",
        asset_value="https://build.example/.env",
        check="env-file-probe",
        severity="low",
        confidence=88,
        evidence_start=40,
    )
    build_admin = make_candidate(
        number=4,
        title="Unauthenticated admin dashboard",
        asset_value="https://build.example/admin",
        check="dashboard-exposure",
        severity="medium",
        confidence=95,
        evidence_start=60,
    )
    analyses = [
        make_analysis(payments_exposure, severity="low", confidence=88, cwe="CWE-200"),
        make_analysis(
            payments_admin, severity="medium", confidence=95, cwe="CWE-306", remediation_id="r1"
        ),
        make_analysis(build_exposure, severity="low", confidence=88, cwe="CWE-200"),
        make_analysis(
            build_admin, severity="medium", confidence=95, cwe="CWE-306", remediation_id="r2"
        ),
    ]
    criticality = CriticalityIndex({"payments.example": 1})
    report = _report_with(
        [payments_exposure, payments_admin, build_exposure, build_admin], analyses, criticality
    )
    paths = report.attack_paths
    assert [entry.asset for entry in paths] == ["payments.example", "build.example"]
    # The tier-1 path ranks first (business high > the tier-less medium), and both carry
    # their labels — the tier-1 path's *terminal* severity is still medium.
    assert paths[0].criticality == 1
    assert paths[0].business_severity == "high"
    assert paths[0].severity == "medium"
    assert paths[1].criticality is None
    assert paths[1].business_severity is None
    assert paths[1].severity == "medium"


def test_the_report_renders_the_business_impact_and_validates_the_current_schema() -> None:
    candidates, analyses = _two_candidates("payments.example", terminal="medium")
    report = _report_with(candidates, analyses, CriticalityIndex({"payments.example": 1}))
    assert len(report.attack_paths) == 1
    entry = report.attack_paths[0]
    assert entry.criticality == 1
    assert entry.business_severity == "high"
    assert entry.severity == "medium"

    from arachne.report import render_markdown

    markdown = render_markdown(report)
    assert "- Business impact: tier 1 (ranks as **high**; from the CMDB import)" in markdown

    document = json.loads(report.model_dump_json())
    jsonschema.validate(document, load_report_schema())
    assert document["schema_version"] == REPORT_SCHEMA_VERSION

    # Determinism: the same inputs render the same bytes.
    again = _report_with(candidates, analyses, CriticalityIndex({"payments.example": 1}))
    assert render_markdown(again) == markdown


def test_without_an_import_the_paths_carry_no_criticality() -> None:
    """No CMDB import ⇒ byte-identical pre-S23 report (no label, unchanged order)."""
    candidates, analyses = _two_candidates("payments.example")
    report = _report_with(candidates, analyses, None)
    entry = report.attack_paths[0]
    assert entry.criticality is None
    assert entry.business_severity is None
    from arachne.report import render_markdown

    assert "Business impact" not in render_markdown(report)
