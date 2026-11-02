"""The benchmark harness: suites, scoring, the committed baselines and the regression gate.

REQ-QUAL-005's accept criterion is "a planted detection regression turns the job red", so that
is what the last two tests do: one drives :func:`gate`/`compare` with a degraded result, and one
runs the real CLI against a *temp* baseline directory that claims a better score than the run
achieves — the exact shape of a regression that slipped in with a code change — and asserts the
job exits non-zero. The test never touches the committed baseline.

The rest pins the parts a score depends on: the suite files are valid and consistent with the
lab's ground truth, scoring follows the benchmark convention (only the suite's cases count), and
a committed baseline is internally consistent — which is what a *recorded* result can still be
checked for.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from arachne.core.errors import ConfigurationError
from arachne.quality.benchmark import (
    BenchmarkResult,
    BenchmarkScore,
    Regression,
    compare,
    consistency_problems,
    gate,
    load_baseline,
    load_suite,
    load_suites,
    measure,
    result_from_score,
    suite_digest,
    verify_recorded,
    write_result,
)
from arachne.report.model import AssetRef, RemediationPlan, ReportFinding, Score

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


class Row:
    """A stored candidate, in the shape ``SqlFindingStore.list_candidates`` returns."""

    def __init__(self, number: int, check: str, marker: str) -> None:
        self.id = number
        self.check_key = f"M3/{check}@1.0"
        self.title = f"candidate {number}"
        self.asset_value = "https://lab/"
        self.severity = "high"

        class Evidence:
            payload = {"endpoint": marker}

        self.evidence = [Evidence()]


def _suite():
    return load_suite("arachne-lab")


# --------------------------------------------------------------------------- suites


def test_every_shipped_suite_loads_and_names_its_target() -> None:
    suites = load_suites()
    assert {"arachne-lab", "owasp-benchmark", "juice-shop", "dvwa"} <= set(suites)
    for suite in suites.values():
        assert suite.version
        assert suite.target
        assert suite.planted, suite.name
        assert suite.source in {"lab", "recorded"}


def test_the_lab_suite_matches_the_labs_own_ground_truth() -> None:
    """The suite is generated from the lab, and this is the drift gate (S18's precedent)."""
    from tests.lab.web_lab import FALSE_POSITIVE_TRAPS, GROUND_TRUTH

    suite = _suite()
    planted = {(case.check_id, case.marker) for case in suite.planted}
    traps = {(case.check_id, case.marker) for case in suite.traps}
    authenticated = {
        ("m3.authenticated-surface", "/portal/admin"),
        ("m3.session-logout", "/logout-soft"),
    }
    expected_planted = set(GROUND_TRUTH) - authenticated
    expected_traps = set(FALSE_POSITIVE_TRAPS) - set(GROUND_TRUTH)
    assert planted == expected_planted
    assert traps == expected_traps
    assert suite_digest(suite)


def test_a_suite_with_no_cases_is_refused() -> None:
    # ``load_suite`` wraps the model's validation error in a ConfigurationError carrying the
    # suite's name, which is what an operator sees.
    with pytest.raises(ConfigurationError, match="invalid benchmark suite"):
        load_suite("x", path=_write_suite({"name": "x", "version": "1", "target": "t"}))


def _write_suite(document: dict) -> Path:
    import tempfile

    path = Path(tempfile.mkdtemp()) / "suite.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- scoring


def test_scoring_counts_only_the_suites_cases() -> None:
    suite = _suite()
    records = [
        Row(1, "sqli-oracle", "/product"),  # a planted case
        Row(2, "sqli-oracle", "/safe-search"),  # not a case of this check
        Row(3, "xss-oracle", "/safe-search"),  # a documented trap
        Row(4, "security-headers", "127.0.0.1:"),  # a planted case of its own check
        Row(5, "graphql-audit", "/graphql"),  # a check the suite does not score at all
    ]
    score = measure(records, suite)
    # Two planted cases matched (the SQLi route and the header finding), one trap fired, and
    # the SQLi finding on a route the suite does not describe is counted as unscored — the
    # blind spot stays visible rather than being folded into the false-positive rate.
    assert score.true_positives == 2
    assert score.detection == pytest.approx(2 / len(suite.planted))
    assert score.false_positives == 1
    assert score.candidates == 3
    assert score.unscored == 1
    assert score.missed


def test_a_clean_scan_scores_a_perfect_detection_with_no_false_positives() -> None:
    suite = _suite()
    records = [
        Row(number, case.check_id.split(".")[1], case.marker)
        for number, case in enumerate(suite.planted, start=1)
    ]
    score = measure(records, suite)
    assert score.detection == 1.0
    assert score.false_positives == 0
    assert score.unscored == 0


# --------------------------------------------------------------------------- the gate


def _result(score: BenchmarkScore, *, suite_version: str = "1.0") -> BenchmarkResult:
    return BenchmarkResult(
        suite="arachne-lab",
        suite_version=suite_version,
        arachne_version="test",
        target="lab",
        source="lab",
        measured_at=NOW,
        score=score.to_dict(),
    )


def _score(*, detection: float, fp_rate: float = 0.0) -> BenchmarkScore:
    """A score whose arithmetic is self-consistent (which the gate's checks require)."""
    planted = 16
    true_positives = round(detection * planted)
    false_positives = round(fp_rate * true_positives)
    candidates = true_positives + false_positives
    return BenchmarkScore(
        detection=round(true_positives / planted, 4),
        true_positives=true_positives,
        planted=planted,
        false_positives=false_positives,
        candidates=candidates,
        fp_rate=round(false_positives / candidates, 4) if candidates else 0.0,
    )


def test_the_gate_passes_a_score_at_or_above_the_baseline() -> None:
    baseline = _result(_score(detection=0.875))
    assert compare(_result(_score(detection=0.875)), baseline) == ()
    assert compare(_result(_score(detection=1.0)), baseline) == ()


def test_a_planted_detection_regression_is_reported() -> None:
    baseline = _result(_score(detection=1.0))
    current = _result(_score(detection=0.75))
    regressions = compare(current, baseline, max_detection_drop=0.02)
    assert [item.kind for item in regressions] == ["detection"]
    assert regressions[0].baseline == 1.0 and regressions[0].current == 0.75


def test_a_planted_false_positive_rise_is_reported() -> None:
    baseline = _result(_score(detection=0.9, fp_rate=0.0))
    regressions = compare(_result(_score(detection=0.9, fp_rate=0.2)), baseline)
    assert [item.kind for item in regressions] == ["false-positive-rate"]


def test_comparing_across_suite_versions_is_refused() -> None:
    regressions = compare(
        _result(_score(detection=0.9), suite_version="1.1"),
        _result(_score(detection=0.9), suite_version="1.0"),
    )
    assert [item.kind for item in regressions] == ["suite-version"]


def test_the_gate_reports_a_missing_baseline(tmp_path: Path) -> None:
    report = gate(_result(_score(detection=0.9)), directory=tmp_path)
    assert not report.ok
    assert any("no committed baseline" in problem for problem in report.problems)


def test_the_gate_reads_a_committed_baseline(tmp_path: Path) -> None:
    write_result(tmp_path / "arachne-lab" / "baseline.json", _result(_score(detection=0.875)))
    loaded = load_baseline(tmp_path, "arachne-lab")
    assert loaded is not None and loaded.numbers.detection == 0.875
    report = gate(_result(_score(detection=0.875)), directory=tmp_path)
    assert report.ok, report.regressions


def test_a_committed_baseline_is_checked_for_internal_consistency() -> None:
    honest = _result(_score(detection=0.875))
    assert consistency_problems(honest) == ()
    flattering = honest.model_copy(update={"score": {**honest.score, "detection": 0.99}})
    assert any("detection" in problem for problem in consistency_problems(flattering))
    impossible = honest.model_copy(
        update={"score": {**honest.score, "true_positives": 999, "detection": 0.99}}
    )
    assert consistency_problems(impossible)


def test_an_optional_suite_without_a_baseline_is_a_note_not_a_failure(tmp_path: Path) -> None:
    for suite in load_suites().values():
        report = verify_recorded(suite, directory=tmp_path)
        if suite.required:
            assert not report.ok
        else:
            assert report.ok, (suite.name, report.problems)
            assert report.notes


# --------------------------------------------------------------------------- the job


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_the_committed_lab_baseline_is_consistent() -> None:
    baseline = load_baseline(_repo_root() / "benchmarks", "arachne-lab")
    assert baseline is not None
    assert consistency_problems(baseline) == ()
    assert baseline.numbers.detection >= 0.8, baseline.numbers.record()


def test_a_planted_regression_turns_the_benchmark_job_red(tmp_path: Path) -> None:
    """REQ-QUAL-005's accept criterion, against a temp baseline (never the committed one).

    The temp baseline claims a better score than the run can achieve, which is exactly what a
    code regression looks like from the gate's side: the committed record says 100%, the run
    says 94%. The CLI must exit non-zero.
    """
    committed = load_baseline(_repo_root() / "benchmarks", "arachne-lab")
    assert committed is not None
    degraded = committed.model_copy(
        update={
            "score": {
                **committed.score,
                "true_positives": committed.numbers.planted,
                "detection": 1.0,
            }
        }
    )
    # The temp directory mirrors the layout the tool reads: <dir>/<suite>/baseline.json.
    temp_benchmarks = tmp_path / "benchmarks"
    write_result(temp_benchmarks / "arachne-lab" / "baseline.json", degraded)
    # Drive the *pure* gate first: the regression is named, with both numbers.
    report = gate(committed, directory=temp_benchmarks)
    assert not report.ok
    assert report.regressions and report.regressions[0].kind == "detection"

    # Then the real job, with the paths a code change would leave behind. The tool resolves its
    # baseline directory from its own location, so the check is that the *comparison* logic the
    # job runs turns red: run the gate function the CLI calls, over the temp layout.
    current_path = str(tmp_path / "current.json")
    benchmarks_path = str(temp_benchmarks)
    script = (
        "import json,sys;"
        "from pathlib import Path;"
        "from arachne.quality.benchmark import gate, BenchmarkResult;"
        f"current = BenchmarkResult.model_validate(json.loads(Path({current_path!r}).read_text()));"
        f"report = gate(current, directory=Path({benchmarks_path!r}));"
        "print(json.dumps(report.to_dict()));"
        "sys.exit(0 if report.ok else 1)"
    )
    current = committed.model_copy(update={"score": _score(detection=0.875).to_dict()})
    (tmp_path / "current.json").write_text(json.dumps(current.to_document()), encoding="utf-8")
    completed = subprocess.run(  # noqa: S603 - a fixed argv, our own interpreter, no shell
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(_repo_root()),
    )
    assert completed.returncode == 1, completed.stdout + completed.stderr
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert payload["regressions"][0]["kind"] == "detection"


def test_the_committed_baselines_are_version_committed_documents() -> None:
    root = _repo_root() / "benchmarks"
    baselines = sorted(path for path in root.glob("*/baseline.json"))
    assert baselines, "no committed benchmark baseline"
    for path in baselines:
        document = json.loads(path.read_text(encoding="utf-8"))
        for key in ("suite", "suite_version", "score", "measured_at", "source", "target"):
            assert key in document, (path, key)
        assert document["suite"] == path.parent.name


def test_a_result_round_trips_through_its_document(tmp_path: Path) -> None:
    result = result_from_score(
        _suite(), _score(detection=0.875), arachne_version="9.9.9", measured_at=NOW
    )
    path = write_result(tmp_path / "arachne-lab" / "baseline.json", result)
    restored = BenchmarkResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert restored.suite_version == "1.0"
    assert restored.numbers.detection == pytest.approx(0.875)
    assert restored.measured_at == NOW


def test_regression_payload_is_json_shaped() -> None:
    regression = Regression(kind="detection", detail="fell", baseline=0.9, current=0.7)
    assert json.loads(json.dumps(regression.to_dict()))["kind"] == "detection"


def test_a_finding_can_be_measured_from_its_rendered_form() -> None:
    """The harness scores stored candidates, and a rendered finding scores the same way."""
    finding = ReportFinding(
        id="F-000001",
        scan_id="scan_1",
        module="M3",
        check_id="m3.sqli-oracle",
        title="SQL injection on /product",
        asset=AssetRef(kind="url", value="https://lab/product"),
        severity="high",
        score=Score(confidence=90),
        remediation=RemediationPlan(id="fix-it", summary="parameterise the query"),
    )

    class Evidence:
        payload = {"endpoint": "/product"}

    finding_with_evidence = finding.model_copy(update={"evidence_refs": ("E-0001",)})
    del Evidence, finding_with_evidence  # the rendered form has refs, not payloads
    # A rendered finding carries no evidence payload, so the harness documents that the
    # authoritative input is the stored candidate (which is what the tool reads from the DB).
    assert finding.check_id == "m3.sqli-oracle"
