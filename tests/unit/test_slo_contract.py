"""The SLO contract (REQ-OPS-007).

REQ-OPS-007's acceptance criteria are about *agreement* between artefacts that live in
different places: the objectives in ``deploy/observability/slos/``, the alert rules and the
dashboard in ``deploy/observability/``, and the metric families ``GET /metrics`` exposes.
Nothing in a running system notices when those stop agreeing — the dashboard simply goes
green over a metric that no longer exists — so this file is the thing that notices.

Every rule below is paired with a case that makes it fail, because a contract test nobody
has seen fail is not evidence of anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arachne.core.metrics import METRIC_FAMILIES, MetricsRegistry
from arachne.ops import slo as slo_module
from arachne.ops.slo import (
    FAST_BURN,
    SCAN_OUTCOMES,
    SLO,
    SLOW_BURN,
    check,
    dashboard_queries,
    load_slos,
    metric_references,
    recorded_series,
    render_alert_rules,
    render_dashboard,
    validate_slos,
)

CODE_ROOT = Path(__file__).resolve().parents[2]
SLO_DIR = CODE_ROOT / "deploy" / "observability" / "slos"
ALERT_RULES = CODE_ROOT / "deploy" / "observability" / "alerts" / "arachne-slo-burn.yaml"
DASHBOARD = CODE_ROOT / "deploy" / "observability" / "dashboards" / "arachne-slo.json"

#: The three objectives REQ-OPS-007 names, by id.
REQUIRED_OBJECTIVES = {"api-availability", "api-latency", "scan-completion"}


@pytest.fixture(scope="module")
def slos() -> tuple[SLO, ...]:
    return load_slos(SLO_DIR)


# ------------------------------------------------------------------ the shipped artefacts
def test_the_definitions_live_in_the_repository(slos: tuple[SLO, ...]) -> None:
    assert {slo.id for slo in slos} == REQUIRED_OBJECTIVES


def test_every_definition_has_a_target_a_window_and_a_measurement_query(
    slos: tuple[SLO, ...],
) -> None:
    for slo in slos:
        assert 0.0 < slo.target < 1.0, slo.id
        assert slo.window, slo.id
        # The measurement query is the windowed one, not the template.
        assert "{{window}}" not in slo.query(), slo.id
        assert slo.window in slo.query(), slo.id
        assert slo.runbook_section, slo.id


def test_every_definition_is_free_of_duplicate_ids() -> None:
    """Two files declaring the same objective are a silent overwrite in a dashboard."""
    import tempfile

    body = (
        "id: same\ntitle: t\nservice: s\nowner: o\n"
        "objective: {target: 0.99, window: 5m}\n"
        "indicator: {type: ratio, sli_query: 'sum(rate(arachne_scans_total[{{window}}]))'}\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        for index in (1, 2):
            (Path(directory) / f"{index}.yaml").write_text(body, encoding="utf-8")
        with pytest.raises(ValueError, match="duplicate SLO ids"):
            load_slos(directory)


# ------------------------------------------------------------------- the metric contract
def test_every_definition_names_metrics_the_endpoint_exposes(slos: tuple[SLO, ...]) -> None:
    """REQ-OPS-007's contract test: no definition may measure a metric nobody publishes."""
    findings = validate_slos(slos, internal=recorded_series(slos))
    assert findings == (), "\n".join(str(finding) for finding in findings)


def test_the_referenced_families_render_on_the_endpoint(slos: tuple[SLO, ...]) -> None:
    """The families are not merely declared — the registry prints them when they have series."""
    registry = MetricsRegistry()
    for slo in slos:
        for reference in metric_references(slo.query()):
            family = next(item for item in METRIC_FAMILIES if item.name == reference.family_name)
            labels = dict.fromkeys(family.label_names, "x")
            if family.kind == "counter":
                registry.increment(family.name, labels)
            elif family.kind == "gauge":
                registry.set(family.name, 1.0, labels)
            else:
                registry.observe(family.name, 0.1, labels)
    rendered = registry.render()
    referenced = {
        reference.family_name for slo in slos for reference in metric_references(slo.query())
    }
    for name in sorted(referenced):
        assert f"# TYPE {name} " in rendered, name


def test_the_gate_fails_on_a_metric_the_endpoint_does_not_expose() -> None:
    """The negative case: an invented metric is reported, not accepted."""
    invented = SLO(
        id="invented",
        title="Invented",
        service="test",
        owner="test",
        description="",
        target=0.99,
        window="5m",
        sli_query="sum(rate(arachne_made_up_total[{{window}}]))",
        runbook_doc="docs/operator-guide.md",
        runbook_section="x",
    )
    findings = validate_slos([invented])
    assert [finding.code for finding in findings] == ["unknown-metric"]
    assert "arachne_made_up_total" in findings[0].detail


def test_the_gate_fails_on_a_label_the_family_does_not_carry() -> None:
    invented = SLO(
        id="invented",
        title="Invented",
        service="test",
        owner="test",
        description="",
        target=0.99,
        window="5m",
        sli_query='sum(rate(arachne_scans_total{outcome="completed"}[{{window}}]))',
        runbook_doc="docs/operator-guide.md",
        runbook_section="x",
    )
    findings = validate_slos([invented])
    assert [finding.code for finding in findings] == ["unknown-label"]


def test_the_gate_fails_on_a_label_value_the_deployment_never_emits() -> None:
    """`status="finished"` is a typo a dashboard would render as an empty panel for ever."""
    invented = SLO(
        id="invented",
        title="Invented",
        service="test",
        owner="test",
        description="",
        target=0.99,
        window="5m",
        sli_query='sum(rate(arachne_scans_total{status="finished"}[{{window}}]))',
        runbook_doc="docs/operator-guide.md",
        runbook_section="x",
    )
    findings = validate_slos([invented])
    assert [finding.code for finding in findings] == ["unknown-label-value"]
    assert "finished" in findings[0].detail


def test_the_gate_fails_on_a_threshold_bucket_the_histogram_does_not_have() -> None:
    invented = SLO(
        id="invented",
        title="Invented",
        service="test",
        owner="test",
        description="",
        target=0.99,
        window="5m",
        sli_query=(
            'sum(rate(arachne_api_request_duration_seconds_bucket{le="0.75"}[{{window}}])) '
            "/ sum(rate(arachne_api_request_duration_seconds_count[{{window}}]))"
        ),
        runbook_doc="docs/operator-guide.md",
        runbook_section="x",
    )
    findings = validate_slos([invented])
    assert [finding.code for finding in findings] == ["unknown-label-value"]
    assert "0.75" in findings[0].detail


def test_the_scan_outcome_vocabulary_matches_the_lifecycle_module() -> None:
    """`SCAN_OUTCOMES` is a claim about another module; read that module, do not trust it.

    ``core/lifecycle.py`` increments ``arachne_scans_total`` by calling ``_count_completion``
    with a literal status, so those literals *are* the vocabulary this SLO may select on. If a
    status is renamed there, the definition here must stop claiming to measure it.
    """
    import ast

    source = (CODE_ROOT / "src" / "arachne" / "core" / "lifecycle.py").read_text(encoding="utf-8")
    counted: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "_count_completion" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant):
                counted.add(str(first.value))
    assert counted == set(SCAN_OUTCOMES), (
        f"core/lifecycle.py counts {sorted(counted)} but the SLO selects {sorted(SCAN_OUTCOMES)}"
    )


# ---------------------------------------------------------------------- the burn alerts
def test_burn_alerts_exist_for_a_fast_and_a_slow_burn(slos: tuple[SLO, ...]) -> None:
    import yaml

    document = yaml.safe_load(ALERT_RULES.read_text(encoding="utf-8"))
    alerts = [rule for rule in document["groups"][0]["rules"] if "alert" in rule]
    by_slo: dict[str, set[str]] = {}
    for alert in alerts:
        by_slo.setdefault(alert["labels"]["slo"], set()).add(alert["labels"]["severity"])
    assert set(by_slo) == {slo.id for slo in slos}
    for identifier, severities in by_slo.items():
        assert severities == {FAST_BURN[3], SLOW_BURN[3]}, identifier
    thresholds = {alert["expr"].split(" > ")[1] for alert in alerts}
    assert thresholds == {"14.4", "6"}, thresholds


def test_every_alert_carries_a_runbook_link(slos: tuple[SLO, ...]) -> None:
    import yaml

    document = yaml.safe_load(ALERT_RULES.read_text(encoding="utf-8"))
    for rule in document["groups"][0]["rules"]:
        if "alert" not in rule:
            continue
        url = rule["annotations"]["runbook_url"]
        assert url.startswith("docs/operator-guide.md#"), rule["alert"]
        assert (CODE_ROOT / "docs" / "operator-guide.md").is_file()


def test_every_runbook_anchor_points_at_a_heading_that_exists(slos: tuple[SLO, ...]) -> None:
    """An alert whose runbook link is a 404 is worse than an alert with no link at all."""
    import re

    guide = (CODE_ROOT / "docs" / "operator-guide.md").read_text(encoding="utf-8")
    headings = {
        re.sub(r"[^a-z0-9 -]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        for line in guide.splitlines()
        if line.startswith("#")
    }
    for slo in slos:
        anchor = slo.runbook_anchor.split("#", 1)[1]
        assert anchor in headings, (
            f"{slo.id} points at {slo.runbook_anchor}, but no heading in the guide slugs to "
            f"{anchor!r}"
        )


def test_the_committed_alert_rules_are_what_the_definitions_generate(
    slos: tuple[SLO, ...],
) -> None:
    """The generated artefact is checked in, and this is the check that keeps it honest."""
    assert ALERT_RULES.read_text(encoding="utf-8") == render_alert_rules(slos), (
        "run `python -m arachne.ops.slo --render`"
    )


def test_the_gate_fails_when_the_rules_are_stale(slos: tuple[SLO, ...], tmp_path: Path) -> None:
    stale = tmp_path / "rules.yaml"
    stale.write_text("groups: []\n", encoding="utf-8")
    findings = check(slo_dir=SLO_DIR, rules_path=stale)
    assert [finding.code for finding in findings] == ["stale-rules"]


def test_the_gate_passes_on_the_shipped_tree() -> None:
    assert check(slo_dir=SLO_DIR, rules_path=ALERT_RULES) == ()


# ------------------------------------------------------- the dashboard (dashboards as code)
def test_the_committed_dashboard_is_what_the_definitions_generate(
    slos: tuple[SLO, ...],
) -> None:
    assert DASHBOARD.is_file(), "the dashboard artefact is missing"
    assert DASHBOARD.read_text(encoding="utf-8") == render_dashboard(slos), (
        "run `python -m arachne.ops.slo --render`"
    )


def test_every_objective_gets_a_panel_for_its_indicator_and_its_burn_rate(
    slos: tuple[SLO, ...],
) -> None:
    document = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    titles = [panel["title"] for panel in document["panels"]]
    for slo in slos:
        assert f"{slo.title} \u2014 current" in titles, slo.id
        assert f"{slo.title} \u2014 budget burn rate" in titles, slo.id


def test_every_panel_query_measures_something_the_endpoint_exposes(
    slos: tuple[SLO, ...],
) -> None:
    """A dashboard is a shipped artefact, so its queries get the same contract as the SLOs."""
    names = {family.name for family in METRIC_FAMILIES} | set(recorded_series(slos))
    for expression in dashboard_queries(DASHBOARD.read_text(encoding="utf-8")):
        for reference in metric_references(expression):
            assert reference.family_name in names, (
                f"a panel measures {reference.name!r}, which /metrics does not expose"
            )


def test_a_stale_dashboard_is_reported(tmp_path: Path) -> None:
    stale = tmp_path / "dashboard.json"
    stale.write_text('{"panels": []}\n', encoding="utf-8")
    findings = check(slo_dir=SLO_DIR, rules_path=ALERT_RULES, dashboard_path=stale)
    assert [finding.code for finding in findings] == ["stale-dashboard"]


def test_the_burn_rate_is_expressed_against_the_error_budget(slos: tuple[SLO, ...]) -> None:
    """A 99.9 % objective has a 0.001 budget, so the divisor is 0.001 — not 1 minus something."""
    availability = next(slo for slo in slos if slo.id == "api-availability")
    assert availability.error_budget_ratio == pytest.approx(0.001)
    expression = availability.burn_expression(availability.burn_policies[0])
    assert expression.endswith("/ 0.001")


def test_window_replacement_only_touches_the_placeholder(slos: tuple[SLO, ...]) -> None:
    slo = next(item for item in slos if item.id == "api-availability")
    assert slo_module._WINDOW_PLACEHOLDER in slo.sli_query
    assert "{{window}}" not in slo.query("1h")
    assert "[1h]" in slo.query("1h")
