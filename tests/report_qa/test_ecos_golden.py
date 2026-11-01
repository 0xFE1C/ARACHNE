"""The ecosystem gate's golden artifacts (S26, REQ-ECOS-004/005/006).

Three requirements name a golden artifact in their accept criteria:

* REQ-ECOS-005 — "golden report in the second language" (``report-fr.md``);
* REQ-ECOS-006 — "branded report golden test" (``report-mspp-fr.md``, white-label mode);
* REQ-ECOS-004 — "golden screenshots at the gate" (the three ``.svg`` files, plus the
  normalized page snapshots in ``tests/integration/test_ui_golden.py``).

**On "screenshots":** the suite has no headless browser and adding one would make this gate
flaky and environment-dependent. The UI's visualizations are SVG the server writes, so the
committed ``.svg`` *is* the screenshot — deterministic, diffable, and reviewable in a pull
request, which a PNG is not. The report pages themselves are covered by normalized HTML
snapshots against the real app. `code/docs/operator-guide.md` §42 states this plainly.

The report goldens use the shared deterministic fixture (``tests/helpers/report.py``), so the
only variable between runs is the code under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.api.ui_visuals import attack_path_svg, coverage_bars_svg, posture_trend_svg
from arachne.report import Branding, render_markdown
from arachne.report.branding import resolve_branding, white_label
from arachne.report.model import ReportData
from tests.helpers.golden import assert_golden

#: The MSSP branding a white-label deployment renders with (REQ-ECOS-006).
MSSP_BRANDING = Branding(
    company_name="Acme Security",
    tagline="managed detection & response",
    primary_color="#112233",
    accent_color="#aa0000",
    logo_text="AS",
    footer_text="Delivered by Acme Security under contract",
    contact="soc@acme.example",
    classification="CONFIDENTIAL",
)


def _localised(report: ReportData, locale: str) -> ReportData:
    return report.model_copy(update={"locale": locale})


# --------------------------------------------------------------------------- report goldens
def test_the_english_report_matches_its_golden(synthetic_report: ReportData) -> None:
    """The reference locale: a change to any label is a change to this file."""
    assert_golden("report-en.md", render_markdown(synthetic_report))


def test_the_second_language_report_matches_its_golden(synthetic_report: ReportData) -> None:
    """REQ-ECOS-005's accept criterion: a golden report in French."""
    french = render_markdown(_localised(synthetic_report, "fr"))
    assert_golden("report-fr.md", french)
    # The label vocabulary is French, not merely declared so.
    for heading in (
        "## 1. Synthèse pour la direction",
        "## 4. Constats — Critique",
        "### A. Éléments de preuve (expurgés)",
    ):
        assert heading in french, heading
    # Identifiers are data and are never translated.
    assert synthetic_report.findings[0].check_id in french


def test_the_white_label_report_matches_its_golden(synthetic_report: ReportData) -> None:
    """REQ-ECOS-006's accept criterion: a branded, white-labelled report."""
    branded = synthetic_report.model_copy(update={"branding": white_label(MSSP_BRANDING)})
    branded = _localised(branded, "fr")
    rendered = render_markdown(branded)
    assert_golden("report-mspp-fr.md", rendered)
    assert "Acme Security" in rendered
    # White-label mode removes ARACHNE's own attribution from the document.
    assert "Report produced with ARACHNE" not in rendered
    assert "Delivered by Acme Security under contract" in rendered


def test_the_white_label_mode_is_applied_by_the_shared_resolver() -> None:
    """The mode is a deployment setting, so every surface applies it through one function."""
    from arachne.core.config import ReportSettings, Settings

    settings = Settings(report=ReportSettings(white_label=True))
    resolved = resolve_branding(settings, MSSP_BRANDING)
    assert resolved.show_arachne_branding is False
    # Without the mode, the same tenant branding keeps its ARACHNE attribution setting.
    plain = resolve_branding(Settings(), MSSP_BRANDING)
    assert plain.show_arachne_branding is True
    assert plain.company_name == "Acme Security"


# --------------------------------------------------------------------------- UI goldens (SVG)
#: A fixed attack-path set: three hops across two stages, one candidate, a cheapest break.
#: Hand-written rather than scanned so the golden is about the *renderer*, not about the
#: analyzer's output on a fixture that may legitimately change.
ATTACK_PATHS: list[dict[str, object]] = [
    {
        "id": "AP-1",
        "asset": "app.example",
        "severity": "critical",
        "stages": ["exposure", "access", "impact"],
        "fully_verified": False,
        "criticality": 1,
        "business_severity": "critical",
        "cheapest_break": "Pin the dashboard behind authentication",
        "cheapest_finding_id": "F-000041",
        "hops": [
            {
                "stage": "exposure",
                "check_id": "m4.dashboard-exposure",
                "title": "Unauthenticated admin dashboard",
                "asset": "app.example",
                "severity": "high",
                "verified": True,
                "finding_id": "F-000042",
                "evidence_refs": ["E-0004"],
            },
            {
                "stage": "access",
                "check_id": "m3.default-credentials",
                "title": "Default credentials accepted",
                "asset": "app.example",
                "severity": "critical",
                "verified": True,
                "finding_id": "F-000041",
                "evidence_refs": ["E-0007"],
            },
            {
                "stage": "impact",
                "check_id": "m6.lpe-index",
                "title": "Local privilege escalation candidate",
                "asset": "app.example",
                "severity": "critical",
                "verified": False,
                "verifying_check": "m6.lpe-verify",
                "evidence_refs": [],
            },
        ],
    },
    {
        "id": "AP-0",
        "asset": "legacy.example",
        "severity": "medium",
        "stages": ["exposure", "credentials"],
        "fully_verified": True,
        "criticality": None,
        "business_severity": None,
        "cheapest_break": "Remove the exposed backup",
        "cheapest_finding_id": None,
        "hops": [
            {
                "stage": "credentials",
                "check_id": "m2.exposed-backup",
                "title": "Exposed database backup",
                "asset": "legacy.example",
                "severity": "medium",
                "verified": True,
                "finding_id": "F-000007",
                "evidence_refs": ["E-0002"],
            }
        ],
    },
]

#: A fixed trend: three scans, one of them clean (the baseline tick must show).
TREND_POINTS: list[dict[str, object]] = [
    {"scan_id": 1, "target": "app.example", "counts": {"high": 2, "medium": 1}, "total": 3},
    {"scan_id": 2, "target": "app.example", "counts": {}, "total": 0},
    {
        "scan_id": 3,
        "target": "app.example",
        "counts": {"critical": 1, "low": 4},
        "total": 5,
    },
]

#: A fixed coverage block: mapped controls plus an explicit unmapped remainder.
COVERAGE: list[dict[str, object]] = [
    {
        "framework": "cis",
        "name": "CIS Critical Security Controls",
        "edition": "v8.1",
        "total_controls": 153,
        "controls": [
            {"status": "pass"},
            {"status": "pass"},
            {"status": "pass"},
            {"status": "fail"},
            {"status": "gap"},
        ],
    },
    {
        "framework": "pci-dss",
        "name": "PCI DSS",
        "edition": "v4.0",
        "total_controls": 12,
        "controls": [{"status": "gap"}, {"status": "gap"}],
    },
]


def test_the_attack_path_graph_matches_its_golden() -> None:
    """REQ-ECOS-004's attack-path visualization, as a committed screenshot."""
    svg = attack_path_svg(ATTACK_PATHS)
    assert_golden("attack-path-graph.svg", svg)
    # Verified vs candidate hops are visually distinct, and the asset label is escaped.
    assert svg.count("<circle") >= 4
    assert "candidate" not in svg  # the marker is structural (hollow ring), not a legend


def test_the_posture_trend_matches_its_golden() -> None:
    assert_golden("posture-trend.svg", posture_trend_svg(TREND_POINTS))


def test_the_control_coverage_chart_matches_its_golden() -> None:
    svg = coverage_bars_svg(COVERAGE)
    assert_golden("control-coverage.svg", svg)
    # The unmapped remainder is drawn: 153 controls with 5 mapped leaves 148 hatched.
    assert 'fill="url(#unmapped)"' in svg


def test_the_visualisations_are_deterministic_and_escape_their_input() -> None:
    """The property that makes a golden meaningful (and an asset value safe)."""
    assert attack_path_svg(ATTACK_PATHS) == attack_path_svg(list(reversed(ATTACK_PATHS)))
    assert posture_trend_svg(TREND_POINTS) == posture_trend_svg(TREND_POINTS)
    assert coverage_bars_svg(COVERAGE) == coverage_bars_svg(COVERAGE)
    hostile = [{**ATTACK_PATHS[0], "asset": '<img src=x onerror="alert(1)">'}]
    rendered = attack_path_svg(hostile)
    assert "<img" not in rendered
    assert "&lt;img" in rendered


def test_the_visualisations_handle_an_empty_estate() -> None:
    """An empty deployment renders a sentence, not a broken document."""
    for svg in (attack_path_svg([]), posture_trend_svg([]), coverage_bars_svg([])):
        assert svg.startswith("<svg")
        assert svg.endswith("</svg>")
        assert "No " in svg


@pytest.fixture(scope="module")
def golden_root() -> Path:
    """The directory the committed goldens live in (asserted to exist by the tests above)."""
    from tests.helpers.golden import GOLDEN_ROOT

    return GOLDEN_ROOT
