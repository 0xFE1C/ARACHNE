"""The mutation gate's own tests (REQ-QUAL-008).

A gate that measures whether tests notice a wrong line has to be shown noticing things
itself, so most of this file is the gate run end to end on a fixture module whose answer is
known: ``tests/fixtures/mutation/subject.py`` is mutated, and
``tests/fixtures/mutation/test_subject.py`` — which asserts that module's real behaviour — is
run against the mutant in a subprocess, exactly as the safety core is.

The rest pins the policy: the four modules REQ-QUAL-008 names, a floor above zero, an
allowlist entry that must carry a reason, and a stale entry that must be reported rather than
ignored.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from arachne.fuzz.mutate import (
    ALLOWED,
    DEFAULT_CONFIG_FILE,
    ERROR,
    KILLED,
    OPERATORS,
    SURVIVED,
    GateError,
    Mutant,
    MutationConfig,
    MutationReport,
    Outcome,
    Site,
    TargetScope,
    classify,
    default_config_file,
    mutants_for_module,
    mutation_sites,
    preflight,
    run_mutant,
    select,
    stale_allowlist,
)

CODE_ROOT = Path(__file__).resolve().parents[2]
SUBJECT = CODE_ROOT / "tests" / "fixtures" / "mutation" / "subject.py"
SUBJECT_TESTS = "tests/fixtures/mutation/test_subject.py"

#: The four modules REQ-QUAL-008 names, by repository path.
REQUIRED_TARGETS = {
    "src/arachne/core/safety.py",
    "src/arachne/core/proof.py",
    "src/arachne/core/integrity.py",
    "src/arachne/proof/sql.py",
}


@pytest.fixture
def interpreter_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate runs `python` from PATH, so point PATH at the interpreter running the suite."""
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")


def _subject_config(**overrides: object) -> MutationConfig:
    fields: dict[str, object] = {
        "targets": (TargetScope(path=str(SUBJECT), tests=(SUBJECT_TESTS,)),),
        "min_score": 0.5,
        "sample": 0,
        "timeout_seconds": 300,
        "budget_seconds": 0,
    }
    fields.update(overrides)
    return MutationConfig(**fields)  # type: ignore[arg-type]


# ------------------------------------------------------------------ the policy as committed
def test_the_committed_policy_targets_the_four_modules_req_qual_008_names() -> None:
    config = MutationConfig.load(default_config_file())
    assert {target.path for target in config.targets} == REQUIRED_TARGETS
    for target in config.targets:
        assert target.tests, f"{target.path} has no covering tests"
        for path in (target.path, *target.tests):
            assert (CODE_ROOT / path).is_file(), path


def test_the_floor_is_a_real_floor() -> None:
    config = MutationConfig.load(default_config_file())
    assert 0.0 < config.min_score <= 1.0
    assert config.timeout_seconds > 0
    assert config.sample > 0, "a pull-request subset must be configured"
    assert 0.0 < config.min_score_sample <= config.min_score, (
        "the sample floor must be set and must not be stricter than the full-run floor: a "
        "bounded subset cannot resolve the same difference"
    )


def test_a_partial_run_is_judged_by_the_sample_floor() -> None:
    config = _subject_config(min_score=0.9, min_score_sample=0.2)
    assert config.floor_for(partial=True) == 0.2
    assert config.floor_for(partial=False) == 0.9
    report = MutationReport(
        outcomes=(Outcome(mutants_for_module(SUBJECT)[0], SURVIVED, 1.0),),
        min_score=config.floor_for(partial=True),
        floor_kind="sample",
    )
    assert not report.ok
    assert "sample floor" in report.summary()
    assert report.to_dict()["floor_kind"] == "sample"


def test_the_committed_allowlist_is_small_and_every_entry_has_a_reason() -> None:
    """The exit criterion, as a test: a visibly small allowlist, each entry justified."""
    config = MutationConfig.load(default_config_file())
    assert len(config.allowlist) <= 12, (
        f"{len(config.allowlist)} allowlisted mutants is not a curated list; either the tests "
        "should kill them or the entry needs a much better reason"
    )
    for identifier, reason in config.allowlist.items():
        assert len(reason) > 20, f"{identifier} needs a reason a reviewer can weigh"


def test_an_allowlist_entry_without_a_reason_is_refused(tmp_path: Path) -> None:
    """The mechanism, exercised on its own document: a reasonless entry cannot be loaded."""
    document = (
        "[tool.arachne.mutation]\n"
        "min_score = 0.5\nsample = 1\ntimeout_seconds = 10\nbudget_seconds = 0\n"
        "[[tool.arachne.mutation.target]]\n"
        'path = "src/arachne/core/safety.py"\n'
        'tests = ["tests/test_safety.py"]\n'
        "[[tool.arachne.mutation.allowlist]]\n"
        'id = "src/arachne/core/safety.py:1:number"\n'
        'reason = ""\n'
    )
    path = tmp_path / "pyproject.toml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError, match="no reason"):
        MutationConfig.load(path)


def test_an_allowlist_entry_that_is_still_valid_loads(tmp_path: Path) -> None:
    document = (
        "[tool.arachne.mutation]\n"
        "min_score = 0.5\nsample = 1\ntimeout_seconds = 10\nbudget_seconds = 0\n"
        "[[tool.arachne.mutation.target]]\n"
        'path = "src/arachne/core/safety.py"\n'
        'tests = ["tests/test_safety.py"]\n'
        "[[tool.arachne.mutation.allowlist]]\n"
        'id = "src/arachne/core/safety.py:1:number"\n'
        'reason = "an equivalent mutant, for the purpose of this test"\n'
    )
    path = tmp_path / "pyproject.toml"
    path.write_text(document, encoding="utf-8")
    config = MutationConfig.load(path)
    assert config.allowlist == {
        "src/arachne/core/safety.py:1:number": "an equivalent mutant, for the purpose of this test"
    }


def test_a_stale_allowlist_entry_is_reported(tmp_path: Path) -> None:
    """An allowlist that swallows mutants which no longer exist is how a gate rots."""
    real = MutationConfig.load(default_config_file())
    first = next(iter(real.allowlist)) if real.allowlist else "src/arachne/core/safety.py:1:number"
    config = _subject_config(allowlist={f"{first}-does-not-exist": "a reason long enough to pass"})
    assert stale_allowlist(config) == (f"{first}-does-not-exist",)


# ------------------------------------------------------------------------- the operators
def test_the_operators_cover_comparisons_booleans_and_boundaries() -> None:
    assert set(OPERATORS) >= {"compare-op", "bool-op", "bool-literal", "not-removal"}
    sites = mutation_sites(SUBJECT.read_text(encoding="utf-8"))
    operators = {site.operator for site in sites}
    assert "compare-op" in operators
    assert "bool-literal" in operators
    assert {"LtE -> Lt", "Lt -> LtE", "Gt -> GtE"} <= {site.description for site in sites}


def test_a_comparison_is_swapped_in_the_mutated_source() -> None:
    mutants = mutants_for_module(SUBJECT)
    boundary = next(mutant for mutant in mutants if mutant.site.description == "LtE -> Lt")
    assert "value < limit" in boundary.source
    assert "value <= limit" in SUBJECT.read_text(encoding="utf-8")


def test_a_mutation_refuses_to_touch_the_original_file() -> None:
    """The gate never edits the working tree: the altered source lives in the mutant object."""
    before = SUBJECT.read_text(encoding="utf-8")
    mutants_for_module(SUBJECT)
    assert SUBJECT.read_text(encoding="utf-8") == before


def test_two_mutations_on_one_line_get_distinct_identifiers() -> None:
    mutants = mutants_for_module(SUBJECT)
    identifiers = [mutant.identifier for mutant in mutants]
    assert len(identifiers) == len(set(identifiers)), "two mutants share an allowlist key"


# ------------------------------------------------------------------------- the verdicts
def test_classify_refuses_to_credit_a_crash_as_detection() -> None:
    assert classify(0, "5 passed") == (SURVIVED, "")
    assert classify(1, "1 failed, 4 passed")[0] == KILLED
    status, detail = classify(2, "ERROR collecting tests/x.py")
    assert status == ERROR and "collected" in detail
    assert classify(3, "INTERNALERROR")[0] == ERROR


def test_the_score_is_killed_over_decided() -> None:
    mutant = mutants_for_module(SUBJECT)[0]
    report = MutationReport(
        outcomes=(
            Outcome(mutant, KILLED, 1.0),
            Outcome(mutant, KILLED, 1.0),
            Outcome(mutant, SURVIVED, 1.0),
            Outcome(mutant, ERROR, 1.0),
            Outcome(mutant, ALLOWED, 0.0, "equivalent"),
        ),
        min_score=0.5,
    )
    assert report.killed == 2
    assert report.survived == 1
    assert report.scored == 3, "an errored or allowlisted mutant must not enter the denominator"
    assert report.score == pytest.approx(2 / 3)
    assert report.ok
    assert report.by_status[ALLOWED] == 1


def test_a_report_below_the_floor_is_not_ok() -> None:
    mutant = mutants_for_module(SUBJECT)[0]
    report = MutationReport(
        outcomes=(Outcome(mutant, KILLED, 1.0), Outcome(mutant, SURVIVED, 1.0)),
        min_score=0.9,
    )
    assert not report.ok
    assert "FAIL" in report.summary()


def test_the_sample_is_deterministic_and_every_kth() -> None:
    mutants = mutants_for_module(SUBJECT)
    first = select(mutants, 3)
    assert first == select(mutants, 3)
    assert len(first) == 3
    assert select(mutants, 0) == tuple(mutants)
    assert select(mutants, 10_000) == tuple(mutants)


# ------------------------------------------------------------- the gate, run end to end
def test_the_mutant_is_loaded_and_the_covering_test_kills_it(interpreter_on_path: None) -> None:
    """The whole point: the altered module is what the tests import, and they notice."""
    config = _subject_config()
    mutants = mutants_for_module(SUBJECT, tests=(SUBJECT_TESTS,))
    boundary = next(mutant for mutant in mutants if mutant.site.operator == "compare-op")
    outcome = run_mutant(boundary, config)
    assert outcome.status == KILLED, f"{outcome.status}: {outcome.detail}"
    assert outcome.seconds > 0


def test_the_gate_reports_a_survivor_rather_than_assuming_coverage(
    interpreter_on_path: None,
) -> None:
    """The control case: an unreached boundary must come back as a survivor."""
    mutants = mutants_for_module(SUBJECT, tests=(SUBJECT_TESTS,))
    unreached = next(
        mutant
        for mutant in mutants
        if mutant.site.operator == "compare-op" and mutant.site.lineno >= 28
    )
    outcome = run_mutant(unreached, _subject_config())
    assert outcome.status == SURVIVED, f"{outcome.status}: {outcome.detail}"


def test_preflight_refuses_an_interpreter_that_cannot_import_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong PATH must be one clear sentence, not a gate's worth of errored mutants."""
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(GateError, match="virtualenv"):
        preflight(_subject_config())


def test_a_mutant_that_cannot_be_imported_is_an_error_not_a_verdict(
    interpreter_on_path: None,
) -> None:
    """The failure mode this gate must never have: measuring the original code in silence.

    A mutant that breaks its own module cannot be judged — the suite never ran against it —
    so it is reported as an error. Counting it as "killed" would inflate the score; counting it
    as "survived" would invent a test gap. Neither is allowed.
    """
    mutant = mutants_for_module(SUBJECT, tests=(SUBJECT_TESTS,))[0]
    broken = Mutant(
        module=mutant.module,
        path=mutant.path,
        site=mutant.site,
        source=mutant.source + '\nraise RuntimeError("this mutant cannot be imported")\n',
        tests=mutant.tests,
        occurrence=mutant.occurrence,
    )
    outcome = run_mutant(broken, _subject_config())
    assert outcome.status == ERROR, f"{outcome.status}: {outcome.detail}"


def test_the_loader_refuses_to_report_a_verdict_it_could_not_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plugin raises the session's exit status when the mutant was never imported."""
    from arachne.fuzz import mutant_loader

    monkeypatch.setenv(mutant_loader.MODULE_ENV, "arachne.core.safety")
    monkeypatch.setenv(mutant_loader.SOURCE_ENV, str(SUBJECT))
    monkeypatch.setattr(mutant_loader, "_SERVED", {})

    class _Session:
        exitstatus = 0

    session = _Session()
    mutant_loader.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 3, "an unapplied mutation must not look like a verdict"


def test_the_default_config_file_is_the_repository_pyproject() -> None:
    assert default_config_file() == Path(DEFAULT_CONFIG_FILE).resolve() or (
        default_config_file().name == "pyproject.toml"
    )


def test_an_object_without_a_mutant_source_is_left_alone() -> None:
    """The loader is inert without the environment variables, so `-p` is always safe."""
    from arachne.fuzz import mutant_loader

    mutant_loader.install()
    sites = mutant_loader.scoped_paths()
    assert sites == ()

    class _Config:
        class hook:  # noqa: N801 - mirrors pytest's interface
            @staticmethod
            def pytest_deselected(items: list[object]) -> None:  # pragma: no cover
                return None

    item = type("Item", (), {"path": Path("tests/unit/test_scope.py")})()
    items = [item]
    mutant_loader.pytest_collection_modifyitems(_Config(), items)
    assert items == [item], "an unscoped run must not drop any test"


def test_a_mutant_and_a_site_render_their_own_dicts() -> None:
    mutant = Mutant(
        module="arachne.example",
        path="src/arachne/example.py",
        site=Site(lineno=7, operator="compare-op", description="Lt -> LtE"),
        source="x = 1\n",
    )
    payload = mutant.to_dict()
    assert payload["id"] == "src/arachne/example.py:7:compare-op"
    assert payload["location" if "location" in payload else "line"] == 7
