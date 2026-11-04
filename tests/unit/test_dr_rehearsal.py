"""The disaster-recovery rehearsal (REQ-OPS-010).

A restore that has never been rehearsed is a hope. These tests drive the whole procedure —
back up, restore into a scratch database, compare row counts, verify the restored audit
chain, hold the result against the objectives — and then break it, one stage at a time, to
show that a broken stage is named and fails loudly rather than reporting a green run.

The tamper cases edit rows through the ORM and commit, which is what a database-level
attacker with write access does; every value here is bound by SQLAlchemy, never formatted
into a statement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.audit import AuditAction
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.signing import build_signer
from arachne.data.models import AuditLog, Base, Finding, Scan, Target
from arachne.data.services import build_services
from arachne.resil.backup import read_bundle, restore_bundle
from arachne.resil.rehearsal import (
    STAGES,
    RehearsalError,
    record_rehearsal,
    recorded_runs,
    rehearse,
)

CODE_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A migrated, populated deployment: a target, a scan, a finding and a real audit chain."""
    database_url = f"sqlite:///{tmp_path / 'live.db'}"
    monkeypatch.setenv("ARACHNE_DATABASE_URL", database_url)
    monkeypatch.setenv("ARACHNE_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[2] / "migrations")
    )
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    services = build_services(get_settings())
    try:
        with services.session_factory.begin() as session:
            target = Target(name="rehearsal-estate", scope_json={"hosts": ["lab.example.net"]})
            session.add(target)
            session.flush()
            scan = Scan(target_id=target.id, status="completed")
            session.add(scan)
            session.flush()
            session.add(Finding(scan_id=scan.id, title="planted finding", status="open"))
        # The auditor builds the hash chain; without chained rows the integrity stage would
        # have nothing to check and would pass vacuously.
        for index in range(3):
            services.auditor.record(
                AuditAction.SCAN_CREATED,
                target="lab.example.net",
                meta={"index": index},
            )
    finally:
        services.close()
    return database_url


def test_the_rehearsal_runs_every_stage_and_reports_rto_and_rpo(
    deployment: str, tmp_path: Path
) -> None:
    report = rehearse(scratch_dir=tmp_path / "scratch")
    assert [stage.name for stage in report.stages] == list(STAGES)
    assert report.ok, report.summary()
    assert report.verdict == "passed"
    assert report.failed_stage is None
    assert report.measured_rto_seconds > 0
    assert report.measured_rpo_seconds >= 0
    assert report.measured_rto_seconds <= report.declared_rto_seconds
    assert report.measured_rpo_seconds <= report.declared_rpo_seconds
    assert report.rows["targets"] == 1
    assert report.rows["scans"] == 1
    assert report.rows["audit_log"] == 3
    # The audit-chain stage really had something to verify.
    chain = next(stage for stage in report.stages if stage.name == "audit-chain")
    assert chain.ok and "intact" in chain.detail
    assert all("nothing to verify" not in note for note in report.notes)


def test_the_rehearsal_does_not_write_to_the_source_database(
    deployment: str, tmp_path: Path
) -> None:
    """The source is only ever read: its rows and its revision are untouched."""
    engine = create_engine(deployment)
    try:
        with sessionmaker(bind=engine)() as session:
            before = {
                model.__tablename__: session.scalar(select(func.count()).select_from(model))
                for model in (Target, Scan, Finding, AuditLog)
            }
    finally:
        engine.dispose()

    report = rehearse(scratch_dir=tmp_path / "scratch", keep_scratch=True)
    assert report.ok

    engine = create_engine(deployment)
    try:
        with sessionmaker(bind=engine)() as session:
            after = {
                model.__tablename__: session.scalar(select(func.count()).select_from(model))
                for model in (Target, Scan, Finding, AuditLog)
            }
    finally:
        engine.dispose()
    assert after == before


def test_each_run_is_recorded_once_and_pass_or_fail_is_in_the_record(
    deployment: str, tmp_path: Path
) -> None:
    record = tmp_path / "rehearsals.jsonl"
    first = rehearse(scratch_dir=tmp_path / "one")
    second = rehearse(scratch_dir=tmp_path / "two")
    record_rehearsal(first, record)
    record_rehearsal(second, record)
    lines = [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2, "a rehearsal must append, not overwrite, its predecessor"
    for line in lines:
        assert line["verdict"] == "passed"
        assert "measured_rto_seconds" in line and "measured_rpo_seconds" in line
        assert line["declared_rto_seconds"] and line["declared_rpo_seconds"]
    assert len(recorded_runs(record)) == 2


def test_a_broken_restore_stage_fails_loudly_and_names_itself(
    deployment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exit criterion: a failure pages with the failing stage named."""

    def explode(*args: object, **kwargs: object) -> None:
        msg = "the scratch database could not be created"
        raise RuntimeError(msg)

    monkeypatch.setattr("arachne.resil.rehearsal.restore_bundle", explode)
    with pytest.raises(RehearsalError) as caught:
        rehearse(scratch_dir=tmp_path / "scratch")
    assert caught.value.stage == "restore"
    assert "restore" in str(caught.value)


def test_a_row_count_mismatch_fails_the_rehearsal(
    deployment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("arachne.resil.rehearsal._restored_row_counts", lambda url: {"targets": 0})
    with pytest.raises(RehearsalError) as caught:
        rehearse(scratch_dir=tmp_path / "scratch")
    assert caught.value.stage == "row-counts"
    assert "targets" in caught.value.detail


def test_a_tampered_trail_is_caught_by_the_audit_chain_stage(
    deployment: str, tmp_path: Path
) -> None:
    """Rows can arrive intact in number and still be wrong; that is this stage's job."""
    engine = create_engine(deployment)
    try:
        with sessionmaker(bind=engine).begin() as session:
            row = session.scalars(select(AuditLog).order_by(AuditLog.id)).first()
            assert row is not None
            payload = dict(row.meta_json or {})
            payload["meta"] = {"index": "tampered"}
            row.meta_json = payload
    finally:
        engine.dispose()

    with pytest.raises(RehearsalError) as caught:
        rehearse(scratch_dir=tmp_path / "scratch")
    assert caught.value.stage == "audit-chain"


def test_a_breached_objective_fails_the_rehearsal(deployment: str, tmp_path: Path) -> None:
    """A run that recovers, but too slowly, is a failed rehearsal — not a pass with a note."""
    with pytest.raises(RehearsalError) as caught:
        rehearse(scratch_dir=tmp_path / "scratch", rto_seconds=0)
    assert caught.value.stage == "objectives"
    assert "measured RTO" in caught.value.detail


def test_the_cli_rehearses_records_and_fails_with_a_non_zero_exit(
    deployment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    record = tmp_path / "rehearsals.jsonl"
    result = runner.invoke(
        app,
        ["dr", "rehearse", "--record", str(record), "--json", "--keep-scratch"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "passed"
    assert [stage["name"] for stage in payload["stages"]] == list(STAGES)
    assert record.is_file()

    # A broken stage exits non-zero and names itself.
    def explode(*args: object, **kwargs: object) -> None:
        msg = "the archive was unreadable"
        raise RuntimeError(msg)

    monkeypatch.setattr("arachne.resil.rehearsal.restore_bundle", explode)
    failed = runner.invoke(app, ["dr", "rehearse", "--record", str(record)])
    assert failed.exit_code == 1
    assert "restore" in failed.output

    history = runner.invoke(app, ["dr", "rehearse", "--record", str(record), "--history"])
    assert history.exit_code == 0
    assert "passed" in history.output


def test_the_history_view_is_empty_before_the_first_run(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app, ["dr", "rehearse", "--history", "--record", str(tmp_path / "none.jsonl")]
    )
    assert result.exit_code == 0
    assert "no recorded rehearsals" in result.output


def test_the_rehearsal_reports_a_bundle_it_can_verify(deployment: str, tmp_path: Path) -> None:
    """The bundle the rehearsal writes is a real, signed, restorable bundle."""
    scratch = tmp_path / "scratch"
    report = rehearse(scratch_dir=scratch, keep_scratch=True)
    assert report.ok
    bundle = read_bundle(report.bundle, signer=build_signer(get_settings()))
    engine = create_engine(f"sqlite:///{tmp_path / 'replay.db'}")
    try:
        Base.metadata.create_all(engine)
        restored = restore_bundle(bundle, session_factory=sessionmaker(bind=engine), engine=engine)
    finally:
        engine.dispose()
    assert restored.rows > 0, "the rehearsal's bundle restored nothing"


# ----------------------------------------------------------- the schedule (REQ-OPS-010)
def test_the_rehearsal_runs_on_a_schedule_in_a_non_production_environment() -> None:
    """REQ-OPS-010: "runs automatically on a schedule". A command nobody calls is not a run.

    Read as text rather than parsed: YAML's ``on`` key is the boolean True under the loader
    this repository uses, which makes a parsed read of the trigger block more confusing than
    the four strings that matter here.
    """
    text = (CODE_ROOT / ".github" / "workflows" / "rehearsal.yml").read_text(encoding="utf-8")
    assert "schedule:" in text, "the rehearsal workflow has no schedule"
    assert "cron:" in text, "the schedule declares no cron expression"
    assert "workflow_dispatch:" in text, "an operator must be able to run it on demand"
    assert "arachne dr rehearse" in text, "the scheduled job does not run the rehearsal"
    assert "--record" in text, "the scheduled job does not keep the per-run record"
    # The same nightly job carries the full mutation run: both are measurements rather than
    # diff gates, and both are too slow for a pull request.
    assert "python -m arachne.fuzz.mutate --sample 0 --check" in text


def test_ci_runs_the_bounded_mutation_subset_on_every_pull_request() -> None:
    text = (CODE_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python -m arachne.fuzz.mutate --sample 12 --check" in text, (
        "the pull-request subset of the mutation gate is not part of CI"
    )
    assert "python -m arachne.ops.slo --check" in text, "the SLO contract is not part of CI"
    assert "arachne db migrations --check" in text, "the reversibility gate is not part of CI"
    assert "autoscaling.enabled=true" in text, "CI never renders the autoscaling manifests"
