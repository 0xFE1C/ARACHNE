"""The workspace driven by the shipped ``workspace.js`` — including the timer (§4.3, REQ-UIX-006).

``src/arachne/templates/web/static/workspace.js`` is the keyboard model the browser runs. This
module executes *that file* (not a copy of it) in ``node``, through the driver in
``tests/fixtures/workspace/driver.cjs``, so the three claims §4.3 makes are checked against the
artefact that ships:

* **Every documented shortcut works.** ``SHORTCUTS`` in ``arachne/api/workspace.py`` is the
  oracle: for each documented key the script is handed a synthetic key event and must produce the
  documented action — and the script must bind nothing that is not documented. A key that exists
  but is undocumented, or the reverse, fails here.
* **Focus survives a re-render.** The pitfall is a roving tabindex that resets: the core's
  ``afterRerender`` must keep the focused row when it is still on the page, and fall back to the
  row that took its place when a bulk action removed it.
* **Twenty findings can be triaged in under three minutes, keyboard only.** The driver is pointed
  at a real server on a real port: it presses the documented keys, performs the requests those
  keys produce, and is timed end to end. The timer therefore measures the interface's own cost —
  keystrokes and round trips — with no mouse event anywhere in the run.

``node`` is a clean skip when it is absent, with the same contract ``test_sdk_contract.py`` uses:
the skip is asserted, and the module is listed in ``tests/skip_allowlist.json`` with its reason.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.helpers.api import SCANNER_KEY, ApiHarness, make_api_harness

from arachne.api import workspace as ws
from arachne.api.auth import API_KEY_COOKIE
from arachne.core.audit import AuditAction

#: The repository root, so the driver can be named by a literal relative path (below).
REPO_ROOT = Path(__file__).resolve().parents[2]

#: The shipped keyboard model, and the driver that loads it. The driver reaches the script by a
#: fixed relative path; ``test_the_driver_loads_the_shipped_script`` keeps the two in step.
WORKSPACE_JS = Path("src/arachne/templates/web/static/workspace.js")
DRIVER = Path("tests/fixtures/workspace/driver.cjs")

#: The independent expectation of what each documented action must *produce* (written here, not
#: read from the script): the effect type the adapter dispatches on.
EXPECTED_EFFECT: dict[str, set[str]] = {
    "next": {"focus"},
    "previous": {"focus"},
    "select": {"selection"},
    "select-range": {"selection"},
    "triage": {"submit"},
    "suppress": {"drawer"},
    "accept": {"drawer"},
    "open": {"open"},
    "undo": {"undo"},
    "search": {"search"},
    "shortcut-sheet": {"sheet"},
    "escape": {"clear", "sheet", "drawer"},
}


@dataclass(frozen=True, slots=True)
class LiveWorkspace:
    base_url: str
    harness: ApiHarness


def _require_node() -> None:
    """A clean, allowlisted skip when ``node`` is absent: a bare environment stays green."""
    if shutil.which("node") is None:
        pytest.skip("node is not on PATH; the workspace script test needs it")


def test_the_script_test_skips_cleanly_when_node_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The skip is asserted, not assumed (pytest's ``Skipped`` is a ``BaseException``)."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(BaseException, match="node is not on PATH"):
        _require_node()


def test_the_driver_loads_the_shipped_script() -> None:
    """The driver's fixed relative path must be the script this module names."""
    reached = (DRIVER.parent / "../../../src/arachne/templates/web/static/workspace.js").resolve()
    assert reached == (REPO_ROOT / WORKSPACE_JS).resolve()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_serving(base_url: str, *, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/health", timeout=2.0)
        except httpx.HTTPError as exc:
            last = exc
        else:
            if response.status_code == 200:
                return
            last = f"health answered {response.status_code}"
        time.sleep(0.05)
    raise AssertionError(f"the app did not start: {last}")


@pytest.fixture
def live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LiveWorkspace]:
    """The fixture app on a real port, so ``node`` can drive it over HTTP."""
    uvicorn = pytest.importorskip("uvicorn")
    monkeypatch.chdir(REPO_ROOT)  # the driver is named by a literal relative path
    built = make_api_harness(tmp_path)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(built.app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_serving(base_url)
        yield LiveWorkspace(base_url=base_url, harness=built)
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        built.close()


def _drive(mode: str, live: LiveWorkspace, **args: Any) -> dict[str, Any]:
    """Run the driver once, handing it the scenario as a JSON document on **stdin**.

    The command line is two literals — the program name and the driver's repository path — and the
    scenario travels on the standard input channel, so no value from this test can reach a command
    line and there is no shell to reach anyway. The driver reports its observations on stdout as
    one JSON line; every assertion about them lives in this module.
    """
    _require_node()
    payload = json.dumps({"mode": mode, "base_url": live.base_url, "api_key": SCANNER_KEY, **args})
    completed = subprocess.run(
        ["node", "tests/fixtures/workspace/driver.cjs"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])  # type: ignore[no-any-return]


# ---------------------------------------------------------------- the keyboard contract
def test_every_documented_shortcut_is_bound_and_does_what_the_sheet_says(
    live: LiveWorkspace,
) -> None:
    table = ws.shortcut_table_json()
    observed = _drive("shortcuts", live, table=table)
    assert observed["mismatches"] == []
    assert observed["undocumented"] == [], "the script binds a key the sheet does not document"
    documented_keys = {key for row in table for key in row["keys"]}
    assert set(observed["bound"]) == documented_keys
    for press in observed["presses"]:
        assert press["effect"] in EXPECTED_EFFECT[press["action"]], press
    assert len(observed["presses"]) == len(documented_keys)


def test_the_documented_shortcut_sheet_renders_every_shortcut(live: LiveWorkspace) -> None:
    """The other half of "discoverable": the sheet on the page *is* the table."""
    live.harness.seed_finding(title="a finding to look at")
    with live.harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        page = client.get("/ui/findings")
    assert "data-shortcut-sheet" in page.text
    for shortcut in ws.SHORTCUTS:
        assert f"<kbd>{shortcut.chord}</kbd>" in page.text, shortcut.chord
        assert shortcut.label in page.text, shortcut.label
    assert "data-open-sheet" in page.text, "the sheet needs a way to open it without knowing '?'"


def test_focus_is_carried_across_a_re_render(live: LiveWorkspace) -> None:
    observed = _drive("rerender", live)
    assert observed["kept_focus"] == 3, "the focused row must survive a re-render"
    assert observed["kept_selection"] == [1, 3]
    assert observed["replaced_focus"] == 4, "focus falls back to the row that took its place"
    assert observed["replaced_selection"] == [1], "a stale id is dropped, never acted on"
    assert observed["empty_focus"] is None
    assert observed["shift_range"] == [1, 2, 3], "Shift+X takes the range from the anchor"
    assert observed["params"] == {"sel": "1,3", "focus": "3", "scroll": "0"}


# ---------------------------------------------------------------- the scripted usability run
def test_twenty_findings_are_triaged_in_under_three_minutes(live: LiveWorkspace) -> None:
    """The measured run: twenty findings, keyboard only, through the real server."""
    count = 20
    scan_id = live.harness.seed_scan()
    identifiers = [
        live.harness.seed_finding(scan_id=scan_id, title=f"usability finding {index}")
        for index in range(count)
    ]
    observed = _drive("run", live, count=count)
    elapsed_ms = int(observed["elapsed_ms"])

    # The number the handoff records, printed as the command's own output.
    print(
        f"\n[usability] {count} findings triaged in {elapsed_ms / 1000:.2f} s "
        f"({len(observed['pressed'])} keystrokes, {count} round trips)"
    )
    assert elapsed_ms < 180_000, f"the 20-finding triage took {elapsed_ms} ms"
    assert observed["ids"] == sorted(identifiers, reverse=True), "the workspace is a total order"
    assert observed["keyboard_only"] is True
    documented = {key for shortcut in ws.SHORTCUTS for key in shortcut.keys}
    assert set(observed["pressed"]) <= documented

    # What the run did, from the server's own records.
    statuses = [live.harness.context.queries.finding_row(item).status for item in identifiers]
    assert statuses.count(ws.TRIAGE_STATUS) == count - 1, "nineteen triaged, one undone"
    assert statuses.count("open") == 1
    assert observed["undo_restored"] is True
    reviewed = live.harness.events_of(AuditAction.FINDING_REVIEWED)
    assert len([event for event in reviewed if event.meta.get("triaged")]) == count
    assert len([event for event in reviewed if event.meta.get("undo")]) == 1

    # The bulk half: every row selected from the keyboard, one suppression each with a reason,
    # and one undo that revokes them all.
    assert observed["selected_count"] == count
    assert observed["suppressed"] is True
    assert observed["suppressed_then_undone"] is True
    quality = live.harness.services.quality
    assert list(quality.list_suppressions(active_only=True)) == []
    stored = quality.list_suppressions(active_only=False)
    assert len(stored) == count
    assert all(rule.reason.startswith("trimmed in the scripted usability run") for rule in stored)
    assert all(not rule.active for rule in stored)

    # §4.4's round trip, performed by the run itself.
    assert observed["round_trip"] is True
