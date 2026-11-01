"""Acceptance: two scheduled scans produce a new/fixed/regressed diff (F-01-05, F-06-05).

This is the stage's second definition of done. A schedule points at a local web root; the first
run scans it, the fixture is then changed (a shell escalated, a CI log removed, a secret added),
and the second run scans it again. The scheduler must run the real pipeline both times, compare
the two finding sets, and persist the ``new``/``fixed``/``regressed`` sets in ``scans_diff``.

The fixture is built from scratch rather than copied so the two runs differ in exactly three
ways — which is what makes the assertion on each change kind meaningful.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.config import SchedulerSettings, Settings
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import ScanDiff
from arachne.data.report_store import SqlScanDiffStore
from arachne.data.services import build_services
from arachne.scheduler import Scheduler, ScheduleSpec, ScheduleState, ScheduleStore

#: The signature shell the escalated file becomes (an eval over a decoded blob).
_SIGNATURE_SHELL = (
    "<?php\n"
    "$k = 'H4sIAAAAAAAAA0tMSgYAAAD//wMAAAAAAAAAAAA=';\n"
    "@eval(gzinflate(base64_decode($k)));\n"
)


def _heuristics_only_shell() -> str:
    """A PHP file that trips the behaviour heuristics but matches no signature."""
    blob = base64.b64encode(os.urandom(700)).decode("ascii")
    return (
        "<?php\n"
        "$p = '" + blob + "';\n"
        "$f = chr(101).chr(118).chr(97).chr(108).chr(40).chr(36).chr(112).chr(41);\n"
    )


def _write_fixture(root: Path, version: int) -> None:
    """(Re)write the web root for one version, starting from a clean directory each time."""
    import shutil

    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.php").write_text("<?php echo 'hello'; ?>\n", encoding="utf-8")
    if version == 1:
        (root / "shell.php").write_text(_heuristics_only_shell(), encoding="utf-8")
        logs = root / ".ci-logs"
        logs.mkdir()
        (logs / "build.txt").write_text(
            "2026-10-20 deploy\nprintenv | sort\nset -x\n::add-mask::***\n", encoding="utf-8"
        )
    else:
        (root / "shell.php").write_text(_SIGNATURE_SHELL, encoding="utf-8")
        # The CI log is gone (the leak was fixed) and a new secret appeared.
        (root / "secrets.php").write_text(
            "<?php\n$key = 'AKIAIOSFODNN7EXAMPLE';\n", encoding="utf-8"
        )


def _target_fixture(path: Path, webroot: Path) -> Path:
    document = {
        "target": {
            "name": "scheduled-webroot",
            "targets": [{"kind": "cloud", "value": f"repo:{webroot}"}],
            "attestation": {
                "attested_by": "Jane Operator <jane.operator@example.com>",
                "attested_at": "2026-10-01T00:00:00Z",
                "expires_at": "2027-10-01T00:00:00Z",
                "authorization_ref": "S11-SCHED",
                "scope_statement": "Unit authorization covering the local web-root fixture",
                "allowed_targets": [f"repo:{webroot}"],
                "active_checks_authorized": False,
            },
        },
        "options": {
            "engine": "heuristic",
            "active_checks": False,
            "modules": {"enabled": ["M6"], "disabled": [], "checks": []},
        },
    }
    fixture = path / "sched-target.yaml"
    fixture.write_text(yaml.safe_dump(document), encoding="utf-8")
    return fixture


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[tuple[Scheduler, sessionmaker[Session], Path]]:
    database = tmp_path / "sched.db"
    engine = create_sqlite_engine(f"sqlite:///{database}")
    create_all(engine)
    factory = create_session_factory(engine)
    settings = Settings(
        database_url=f"sqlite:///{database}",
        log_level="CRITICAL",
        log_json=False,
        scheduler=SchedulerSettings(state_path=str(tmp_path / "state.json")),
    )
    services = build_services(settings)
    scheduler = Scheduler(
        settings, store=ScheduleStore(settings.scheduler.state_path), services=services
    )
    try:
        yield scheduler, factory, tmp_path
    finally:
        scheduler.close()
        engine.dispose()


async def test_two_scheduled_runs_produce_a_new_fixed_regressed_diff(
    stack: tuple[Scheduler, sessionmaker[Session], Path],
) -> None:
    scheduler, factory, tmp_path = stack
    webroot = tmp_path / "webroot"
    _write_fixture(webroot, 1)
    target = _target_fixture(tmp_path, webroot)

    spec = ScheduleSpec(id="nightly", target=str(target), cron="0 3 * * *")
    scheduler.store.upsert(spec, state=ScheduleState())

    # ---- first run: nothing to compare against --------------------------------
    first = await scheduler.run_one(spec, now=datetime(2026, 6, 1, 3, 0, tzinfo=UTC))
    assert first.status == "completed"
    assert first.scan_id is not None
    assert first.previous_scan_id is None
    assert first.diff is None

    # ---- change the fixture, then run again -----------------------------------
    _write_fixture(webroot, 2)
    second = await scheduler.run_one(spec, now=datetime(2026, 6, 2, 3, 0, tzinfo=UTC))
    assert second.status == "completed"
    assert second.previous_scan_id == first.scan_id
    assert second.scan_id is not None and second.scan_id != first.scan_id

    # ---- DONE criterion 2: every change kind is present -----------------------
    counts = second.counts
    assert counts.get("new", 0) >= 1, f"no new finding: {second.diff}"
    assert counts.get("fixed", 0) >= 1, f"no fixed finding: {second.diff}"
    assert counts.get("regressed", 0) >= 1, f"no regressed finding: {second.diff}"

    diff = second.diff or {}
    assert any("secret-scan" in key for key in diff.get("new", []))
    assert any("ci-secret-leak" in key for key in diff.get("fixed", []))
    assert any("webshell-yara" in key for key in diff.get("regressed", []))

    # ---- the diff is persisted for the report / trend section -----------------
    stored = SqlScanDiffStore(factory).get(first.scan_id, second.scan_id)
    assert stored is not None
    assert stored.changes["counts"] == counts
    with factory() as db:
        rows = db.scalars(select(ScanDiff)).all()
    assert len(rows) == 1

    # ---- state advanced to the next cron occurrence ---------------------------
    state = scheduler.store.get("nightly").state
    assert state.last_scan_id == second.scan_id
    assert state.next_run_at is not None and state.next_run_at.day == 3
