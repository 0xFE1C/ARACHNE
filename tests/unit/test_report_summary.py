"""Executive-summary synthesis in heuristic mode."""

from __future__ import annotations

from arachne.report.model import SeverityCounts
from arachne.report.summary import build_executive_summary, load_summary_templates


def _summary(**overrides: object) -> object:
    defaults: dict[str, object] = {
        "findings": (),
        "low_confidence": (),
        "counts": SeverityCounts(),
        "threshold": 55,
        "asset_count": 3,
        "host_count": 2,
        "url_count": 1,
        "modules": ("M3", "M4"),
        "duration_seconds": 2460.0,
        "engine": "heuristic",
        "templates": load_summary_templates(),
    }
    defaults.update(overrides)
    return build_executive_summary(**defaults)  # type: ignore[arg-type]


def test_the_counts_table_is_always_present() -> None:
    summary = _summary()
    assert summary.counts.total == 0
    assert summary.counts.as_rows()[0] == ("Critical", 0)


def test_no_findings_renders_the_clean_paragraph() -> None:
    summary = _summary()
    assert summary.posture == "clean (no confirmed findings)"
    joined = " ".join(summary.paragraphs)
    assert "No confirmed findings were recorded" in joined
    assert "critical" not in joined.lower() or "no confirmed" in joined.lower()


def test_posture_follows_the_worst_confirmed_severity() -> None:
    assert _summary(counts=SeverityCounts(critical=1)).posture == "critical"
    assert _summary(counts=SeverityCounts(high=1)).posture == "elevated"
    assert _summary(counts=SeverityCounts(medium=1)).posture == "moderate"
    assert _summary(counts=SeverityCounts(info=1)).posture == "low"


def test_headline_and_priority_order_are_deterministic(synthetic_report: object) -> None:
    report = synthetic_report
    summary = report.executive_summary
    # critical (F-000002) sorts ahead of high (F-000001)
    assert summary.headline_finding_ids[0] == "F-000002"
    assert summary.priority_order
    # The remediation summary is de-duplicated across findings sharing a catalog entry.
    assert len(summary.priority_order) == len(set(summary.priority_order))


def test_every_paragraph_has_its_references_resolved(synthetic_report: object) -> None:
    for paragraph in synthetic_report.executive_summary.paragraphs:
        assert "{" not in paragraph
        assert "}" not in paragraph
        assert paragraph.strip()


def test_low_confidence_is_reported_separately(synthetic_report: object) -> None:
    summary = synthetic_report.executive_summary
    assert summary.low_confidence_count == 1
    joined = " ".join(summary.paragraphs)
    assert "below the 55 confidence threshold" in joined
    assert "section 9" in joined


def test_a_trend_paragraph_appears_with_a_comparison() -> None:
    summary = _summary(
        findings=(),
        diff_counts={"new": 2, "fixed": 1, "regressed": 0, "recurring": 3},
        compared_scan="scan_1",
    )
    joined = " ".join(summary.paragraphs)
    assert "Compared with scan scan_1" in joined
    assert "2 new, 1 fixed, 0 regressed and 3 recurring" in joined


def test_provenance_names_the_engine_and_template_corpus() -> None:
    summary = _summary()
    assert summary.provenance.engine == "heuristic"
    assert summary.provenance.template_version
    assert summary.synthesized is True


def test_the_summary_is_stable_across_runs(synthetic_report: object) -> None:
    report = synthetic_report
    kwargs = {
        "findings": report.findings,
        "low_confidence": report.low_confidence,
        "counts": report.counts,
        "threshold": 55,
        "asset_count": 0,
        "host_count": 0,
        "url_count": 0,
        "modules": report.scope.modules,
        "duration_seconds": report.scope.duration_seconds,
        "engine": "heuristic",
    }
    first = build_executive_summary(**kwargs)  # type: ignore[arg-type]
    second = build_executive_summary(**kwargs)  # type: ignore[arg-type]
    assert first.paragraphs == second.paragraphs
