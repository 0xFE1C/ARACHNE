"""The S28 golden report: a simulated section that cannot be mistaken for a finding.

REQ-SIM-004's accept criterion is "golden report; gate-verdict exclusion test", and the golden
here is the whole document rather than the section alone, because the property that matters is
a property of the *whole*: a reader (or a script) must be able to see, from the rendered text,
which parts were observed and which were computed under hypotheticals. So this file pins

* the complete Markdown of a report that carries both verified findings and a simulated
  what-if run over the lab estate, and
* the structural separations a golden alone would not catch — that the verified sections
  contain no simulated entity, that the block is the only place a simulated path exists, and
  that a simulated severity never reaches a count.

The report is deliberately one that *does* have findings: separating simulated from verified
is only meaningful when both are present.
"""

from __future__ import annotations

import json

from arachne.cli.ci import EXIT_CLEAN, gate_exit_code
from arachne.ecos.ci_gate import findings_from_report
from arachne.report.builder import simulation_block
from arachne.report.html_render import html_to_text, render_html
from arachne.report.markdown import render_markdown
from arachne.report.model import REPORT_SCHEMA_VERSION, ReportData
from arachne.sim.change import simulate_change
from arachne.sim.hypotheses import ChangeSet, Hypothesis
from arachne.sim.whatif import simulate
from tests.helpers.estate import APP_HOST, LEGACY_HOST, lab_estate
from tests.helpers.golden import assert_golden
from tests.helpers.report import synthetic_report

PUBLISH = ChangeSet(
    name="publish-legacy-console",
    description=(
        "Publish the legacy admin console on 8443 and assume the newly published advisory "
        "is exploitable, while the default-credential finding is closed."
    ),
    hypotheses=(
        Hypothesis.new_exposure(
            "hyp-1",
            LEGACY_HOST,
            port=8443,
            service="https",
            note="the legacy console is published by mistake",
        ),
        Hypothesis.new_vulnerability(
            "hyp-2",
            LEGACY_HOST,
            title="Newly published RCE in the legacy console",
            severity="critical",
            cwe="CWE-89",
            note="assume the advisory published yesterday is exploitable",
        ),
        Hypothesis.applied_fix(
            "hyp-3", APP_HOST, "m4.default-credentials", note="rotate the vendor defaults"
        ),
    ),
)


def _report_with_simulation() -> ReportData:
    delta = simulate_change(lab_estate(), PUBLISH)
    block = simulation_block(change=delta)
    report = synthetic_report()
    return report.model_copy(update={"simulation": block})


def test_the_simulated_report_matches_its_golden() -> None:
    """The whole document: findings first, the what-if annex last and clearly labelled."""
    assert_golden("report-simulated.md", render_markdown(_report_with_simulation()))


def test_the_golden_report_keeps_every_simulated_entity_out_of_the_verified_sections() -> None:
    report = _report_with_simulation()
    markdown = render_markdown(report)
    verified = markdown[: markdown.index("## 13.")]
    simulated = markdown[markdown.index("## 13.") :]

    for hypothesis in PUBLISH.hypotheses:
        assert hypothesis.id in simulated
        assert hypothesis.id not in verified
    assert "Simulated — nothing here was observed on a target" in simulated
    assert "sim.new-exposure.hyp-1" in simulated
    assert "sim.new-exposure.hyp-1" not in verified
    assert "hypothetical" in simulated
    assert "hypothetical" not in verified


def test_the_verified_body_is_byte_identical_to_a_report_without_a_simulation() -> None:
    """Attaching a simulation changes nothing above §13 — the separation is additive."""
    with_simulation = render_markdown(_report_with_simulation())
    without = render_markdown(synthetic_report())

    assert with_simulation.startswith(without.rstrip("\n"))
    assert "## 13." not in without


def test_the_json_document_carries_the_simulation_in_its_own_block_only() -> None:
    report = _report_with_simulation()
    document = json.loads(report.model_dump_json())

    # 1.12 is WP-13's: the per-finding ``verification`` record became required
    # (REQ-PROOF-015). Pinned so a further bump is a conscious act, not silent drift.
    assert document["schema_version"] == REPORT_SCHEMA_VERSION == "1.12"
    block = document["simulation"]
    assert block["provenance"] == "simulated"
    assert block["change"]["name"] == "publish-legacy-console"
    assert block["change"]["exposure_delta"] == 10

    # Nothing simulated appears under any finding-shaped key.
    verified_blob = json.dumps(
        {
            "findings": document["findings"],
            "low_confidence": document["low_confidence"],
            "attack_paths": document["attack_paths"],
        },
        sort_keys=True,
    )
    assert "sim." not in verified_blob
    assert "hyp-" not in verified_blob


def test_a_simulated_severity_never_reaches_a_count_or_a_gate_verdict() -> None:
    report = _report_with_simulation()
    assert report.simulation is not None
    # The simulated block really does carry a critical hop — otherwise this proves nothing.
    assert any(hop.severity == "critical" for path in report.simulation.paths for hop in path.hops)

    counts = {
        severity: len(report.findings_by_severity(severity))
        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )
    }
    # The verified counts are the fixture's, untouched by the critical simulated hop.
    assert counts["critical"] == 1  # synthetic_report's own critical finding
    assert gate_exit_code(counts, "high") == 2  # the *verified* critical finding trips it
    assert findings_from_report(report)  # and the gate's own adapter sees only findings


def test_the_html_report_shows_the_same_separate_section() -> None:
    text = html_to_text(render_html(_report_with_simulation()))

    assert "Simulated scenarios (what-if)" in text
    assert "Nothing in this section was observed on a target" in text
    assert "hypothetical" in text


def test_a_report_without_a_simulation_renders_no_section_at_all() -> None:
    markdown = render_markdown(synthetic_report())

    assert "## 13." not in markdown
    assert "Simulated" not in markdown


def test_the_delta_is_reported_with_both_directions() -> None:
    """REQ-SIM-005's demo: one change that adds, one that closes, on the same model."""
    graph = lab_estate()

    worse = simulate_change(graph, PUBLISH)
    better = simulate_change(
        graph,
        ChangeSet(
            name="harden-app",
            hypotheses=(
                Hypothesis.applied_fix("f1", APP_HOST, "m4.default-credentials"),
                Hypothesis.applied_fix("f2", APP_HOST, "m3.sqli-oracle"),
            ),
        ),
    )

    assert worse.exposure_delta == 10
    assert LEGACY_HOST in {item.path.asset for item in worse.introduced}
    # Closing the app's credentials link leaves the exposure with nothing to reach: the path
    # that remains is a *different* path (its hop set changed), so one is introduced and one
    # removed — the delta says exactly that rather than "the path survived".
    assert {item.asset for item in worse.removed} == {APP_HOST}
    assert better.exposure_delta == -10
    assert len(better.removed) == 1

    # And the two blocks render their own numbers, not a shared summary.
    worse_block = simulation_block(change=worse)
    better_block = simulation_block(change=better)
    assert worse_block.change is not None and worse_block.change.exposure_delta == 10
    assert better_block.change is not None and better_block.change.exposure_delta == -10


def test_a_what_if_run_block_renders_its_hypotheses_and_paths() -> None:
    run = simulate(
        lab_estate(),
        (
            Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
            Hypothesis.compromised_credential("hyp-2", "db.internal", identity="portal"),
        ),
    )
    block = simulation_block(run=run)

    assert {item.id for item in block.hypotheses} == {"hyp-1", "hyp-2"}
    assert block.refusals == ()
    # Every path the model holds is reported: the estate as scanned, plus what the
    # hypotheticals add. The observed one is not marked hypothetical, the new ones are.
    assert {path.asset for path in block.paths} == {APP_HOST, LEGACY_HOST, "db.internal"}
    hypothetical = {path.asset for path in block.paths if path.hypothetical}
    assert hypothetical == {LEGACY_HOST, "db.internal"}
    assert block.model["hosts"] == 3
    assert gate_exit_code({}, "high") == EXIT_CLEAN
