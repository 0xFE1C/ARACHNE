"""Area SIM's safety invariants, proven structurally (S28, REQ-SIM-003 and REQ-SIM-004).

Three properties that must not be able to regress quietly, each tested the way the program
tests safety everywhere — by trying to break it:

**Zero network (REQ-SIM-003).** A *static* half (:mod:`arachne.sim.hygiene` scanning the
package's own sources for the network and egress imports it forbids) and a *dynamic* half (a
guard that denies every socket entry point for the duration of a simulation, fails closed, and
audits the attempt). The dynamic half is exercised against misconfiguration too: a collaborator
replaced by one that dials, a hypothesis that names a URL, and every documented entry point
individually.

**Nothing simulated is a finding (REQ-SIM-004).** A what-if run writes no finding row: the
package's sources name no finding-store writer, and on the report side a simulated block leaves
every finding-shaped field alone, so a gate fed from the report cannot see it — even when the
simulated paths are critical.

**The guard is reentrant and restores.** A simulation inside a simulation keeps the boundary
up, and the process can open a socket again once it exits: a boundary that leaked would break
every scan that followed it.
"""

from __future__ import annotations

import ast
import contextlib
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from arachne.cli.ci import EXIT_CLEAN, gate_exit_code
from arachne.core.audit import AuditAction, Auditor, AuditOutcome, MemoryAuditSink
from arachne.core.errors import SimulationNetworkError
from arachne.ecos.ci_gate import findings_from_report
from arachne.report.builder import build_report_data, simulation_block
from arachne.report.markdown import render_markdown
from arachne.report.model import ReportData
from arachne.sim.boundary import NETWORK_ENTRY_POINTS, guard_auditor, is_armed, no_network
from arachne.sim.hygiene import (
    FORBIDDEN_ARACHNE_MODULES,
    FORBIDDEN_CALLS,
    FORBIDDEN_MODULES,
    GUARD_MODULE,
    forbidden_imports,
    scan_tree,
    violations_for_package,
)
from arachne.sim.hypotheses import Hypothesis
from arachne.sim.model import build_estate_graph
from arachne.sim.whatif import simulate
from tests.helpers.estate import APP_HOST, LEGACY_HOST, lab_estate, lab_inputs
from tests.helpers.report import make_inputs

SIM_ROOT = Path(__file__).resolve().parents[1] / "src" / "arachne" / "sim"

#: The finding-store names a simulated result must never name. Checked as source text, because
#: the point is that area SIM does not *call* them — an import scan would miss a call through a
#: collaborator, and a collaborator is exactly the misconfiguration to guard against.
FINDING_WRITE_NAMES = (
    "record_candidate",
    "create_compound",
    "set_finding_status",
    "SqlFindingStore",
    "SqlAnalysisStore",
    "FindingStore",
    "AnalysisStore",
)


@pytest.fixture(autouse=True)
def _restored_boundary() -> Iterator[None]:
    """No test may leave the guard installed: the rest of the suite needs its sockets."""
    yield
    assert not is_armed(), "the zero-network guard leaked out of a test"


# ------------------------------------------------------------------ static half


def test_the_simulation_package_imports_nothing_that_can_reach_a_target() -> None:
    """The shipped package violates none of its own import rules (REQ-SIM-003)."""
    violations = violations_for_package("arachne.sim")
    assert violations == (), [repr(item) for item in violations]


def test_the_only_exempt_file_is_the_guard_and_only_for_the_socket_module() -> None:
    """The exemption is pinned, not implied: one file, one import, and nothing else.

    A rule with an unstated hole is not a rule. The guard module must hold ``socket`` in order
    to deny it; every other file in the package, and every other forbidden import here, must
    still fail the scan.
    """
    offenders = scan_tree(SIM_ROOT)
    assert set(offenders) == {GUARD_MODULE}, offenders
    assert {item.name for item in offenders[GUARD_MODULE]} == {"socket"}

    # A second file acquiring the socket import is still a violation.
    planted = forbidden_imports("import socket\n", path="sim/whatif.py")
    assert len(planted) == 1 and planted[0].name == "socket"


def test_the_rule_is_a_scan_of_the_real_tree_and_not_of_nothing() -> None:
    """A scan that found no files would pass vacuously; this pins what it looked at."""
    files = sorted(path.name for path in SIM_ROOT.rglob("*.py") if "__pycache__" not in path.parts)
    assert len(files) >= 8, files
    assert "boundary.py" in files and "hygiene.py" in files


@pytest.mark.parametrize(
    "source",
    [
        "import httpx\n",
        "import socket\n",
        "from socket import create_connection\n",
        "import ssl\n",
        "import subprocess\n",
        "import asyncio\n",
        "import arachne.core.http\n",
        "from arachne.core.net import ScopedNetClient\n",
        "from arachne.modules.m3.scanner import WebScanner\n",
        "from arachne.data.finding_store import SqlFindingStore\n",
        "import arachne.creds.broker\n",
        "import arachne.report.markdown\n",
        "import os\nos.system('curl http://evil.invalid')\n",
        "import importlib\nimportlib.import_module('socket')\n",
        "import os as _os\n_os.execv('/bin/sh', [])\n",
    ],
)
def test_a_planted_escape_is_caught_by_the_scanner(source: str) -> None:
    """Positive control: every class of escape the rules name is actually detected."""
    assert forbidden_imports(source), f"the scanner missed: {source!r}"


@pytest.mark.parametrize(
    "source",
    [
        "import json\nfrom dataclasses import dataclass\n",
        "from arachne.analyzer.paths import build_attack_paths\n",
        "from arachne.core.audit import Auditor\n",
        "from arachne.sim.model import EstateGraph\n",
        "from .boundary import no_network\n",
    ],
)
def test_a_legitimate_import_is_not_flagged(source: str) -> None:
    """The rule is a boundary, not a blanket ban: the pure collaborators stay available."""
    assert forbidden_imports(source) == ()


def test_the_simulation_sources_name_no_finding_store_writer() -> None:
    """REQ-SIM-004 structurally: no file in the package can write a finding."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(SIM_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        found = [name for name in FINDING_WRITE_NAMES if name in source]
        if found:
            offenders[path.name] = found
    assert offenders == {}, offenders


def test_the_forbidden_sets_name_the_real_escape_routes() -> None:
    """The rules are only as good as their contents; pin the classes they cover."""
    assert {"socket", "httpx", "ssl", "asyncio", "subprocess"} <= FORBIDDEN_MODULES
    assert {
        "arachne.core.http",
        "arachne.core.net",
        "arachne.modules",
        "arachne.data",
    } <= FORBIDDEN_ARACHNE_MODULES
    assert "os.system" in FORBIDDEN_CALLS
    assert "builtins.__import__" in FORBIDDEN_CALLS


def test_the_scanner_reads_the_ast_not_the_words_in_a_docstring() -> None:
    """``socket`` as a *word* in prose is not an import; only the AST is."""
    source = '"""A simulation that never opens a socket or an httpx client."""\nVALUE = 1\n'
    assert forbidden_imports(source) == ()
    assert {node.__class__.__name__ for node in ast.walk(ast.parse(source))} >= {
        "Module",
        "Constant",
    }


# ------------------------------------------------------------------ dynamic half


@pytest.fixture
def armed_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Record any socket call and fail the test loudly if one happens."""
    attempts: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        attempts.append(str(args[:1]))
        msg = "an armed socket was reached"
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "gethostbyname_ex", forbidden)
    yield attempts
    assert attempts == [], f"the simulation touched the network: {attempts}"


def test_a_whole_simulation_runs_with_every_socket_entry_point_armed(
    armed_sockets: list[str],
) -> None:
    """The end-to-end proof: model + what-if, sockets armed, zero attempts (REQ-SIM-003)."""
    run = simulate(
        lab_estate(),
        (
            Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
            Hypothesis.compromised_credential("hyp-2", APP_HOST),
        ),
    )

    assert run.result
    assert armed_sockets == []


@pytest.mark.parametrize("entry_point", NETWORK_ENTRY_POINTS)
def test_every_documented_entry_point_is_denied(entry_point: str) -> None:
    """The boundary is only as strong as its least-patched name."""
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    with pytest.raises(SimulationNetworkError):
        with no_network(auditor):
            _attempt(entry_point)

    blocked = sink.of_action(AuditAction.SIMULATION_BOUNDARY_VIOLATION)
    assert blocked, f"{entry_point} was not denied"
    assert all(event.outcome == AuditOutcome.BLOCKED for event in blocked)
    assert all(event.meta["entry_point"] == entry_point for event in blocked)


def _attempt(entry_point: str) -> None:
    """Try one entry point the guard is supposed to deny."""
    if entry_point == "socket.socket":
        socket.socket()
    elif entry_point.startswith("socket.socket."):
        # A socket that existed before the guard: the *method* must be denied too, which is
        # why the boundary patches the real class before swapping the constructor.
        preexisting = _bare_socket()
        try:
            if entry_point.endswith("connect"):
                preexisting.connect(("192.0.2.1", 80))
            elif entry_point.endswith("connect_ex"):
                preexisting.connect_ex(("192.0.2.1", 80))
            else:
                preexisting.sendto(b"x", ("192.0.2.1", 80))
        finally:
            _close_quietly(preexisting)
    elif entry_point == "socket.create_connection":
        socket.create_connection(("192.0.2.1", 80))
    elif entry_point == "socket.getaddrinfo":
        socket.getaddrinfo("example.invalid", 80)
    elif entry_point == "socket.gethostbyname":
        socket.gethostbyname("example.invalid")
    elif entry_point == "socket.gethostbyname_ex":
        socket.gethostbyname_ex("example.invalid")
    else:  # pragma: no cover - the parametrisation covers every branch
        msg = f"unhandled entry point {entry_point}"
        raise AssertionError(msg)


def _bare_socket() -> Any:
    """A socket object built through the *real* class, bypassing the constructor swap.

    The guard denies construction through the module attribute (``socket.socket``) **and** the
    instance methods, so a test of the method-level denial has to obtain an instance the way a
    long-lived process would: from the real class it opened its connection with earlier.
    """
    from arachne.sim import boundary

    real = boundary._REAL_SOCKET
    return real()


def _close_quietly(sock: Any) -> None:
    with contextlib.suppress(Exception):  # a test socket may already be unusable
        sock.close()


def test_a_collaborator_that_dials_is_refused_and_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The "even if misconfigured" case: the composer is replaced by one that reaches out.

    ARACHNE did not write every collaborator and cannot audit every upgrade, so the guarantee
    cannot rest on the sources being clean. It rests on the runtime boundary: the dial fails,
    the failure is a :class:`SimulationNetworkError`, and the attempt is blocked and audited.
    """
    import arachne.sim.model as model_module

    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    original = model_module.build_attack_paths

    def misconfigured(*args: Any, **kwargs: Any) -> Any:
        # What a hostile — or merely wrong — collaborator does inside the same call.
        socket.getaddrinfo("evil.example", 443)
        return original(*args, **kwargs)

    monkeypatch.setattr(model_module, "build_attack_paths", misconfigured)

    with pytest.raises(SimulationNetworkError):
        simulate(lab_estate(), (), auditor=auditor)

    events = sink.of_action(AuditAction.SIMULATION_BOUNDARY_VIOLATION)
    assert events and events[0].outcome == AuditOutcome.BLOCKED
    assert events[0].meta["entry_point"] == "socket.getaddrinfo"


def test_a_hypothesis_naming_a_url_sends_nothing(armed_sockets: list[str]) -> None:
    """A hypothetical target is data, never a destination: the URL is parsed, not fetched."""
    before = lab_estate().summary()["hosts"]

    run = simulate(
        lab_estate(),
        (
            Hypothesis.new_exposure("hyp-1", "https://new.example:8443/admin", port=8443),
            Hypothesis.new_vulnerability(
                "hyp-2",
                f"https://{APP_HOST}/login",
                title="new",
                severity="high",
                cwe="CWE-89",
            ),
        ),
    )

    assert armed_sockets == []
    assert run.refusals == ()
    assert run.model_after["hosts"] == before + 1


def test_the_guard_is_reentrant() -> None:
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    with no_network(auditor):
        assert is_armed()
        with no_network(auditor):
            assert is_armed()
            with pytest.raises(SimulationNetworkError):
                socket.getaddrinfo("example.invalid", 80)
        assert is_armed(), "the inner guard must not disarm the outer one"
    assert not is_armed()


def test_the_process_can_open_a_socket_again_after_a_simulation() -> None:
    """A boundary that leaked would break every scan that followed it."""
    simulate(lab_estate(), (Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),))
    assert not is_armed()
    assert guard_auditor() is None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        observed: list[bool] = []

        def accept_once() -> None:
            try:
                connection, _ = listener.accept()
                observed.append(True)
                connection.close()
            except OSError:  # pragma: no cover - the listener was closed first
                observed.append(False)

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(b"ping")
        thread.join(timeout=5)
    assert observed == [True], "the process could not open a socket after a simulation"


# ------------------------------------------------------------------ simulated is not a finding


def _report_with_simulated_critical_paths() -> ReportData:
    """A report with **no findings** whose simulated block claims a critical path."""
    run = simulate(
        lab_estate(),
        (
            Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
            Hypothesis.new_vulnerability(
                "hyp-2",
                LEGACY_HOST,
                title="Simulated RCE",
                severity="critical",
                cwe="CWE-89",
            ),
        ),
    )
    block = simulation_block(run=run)
    assert any(path.severity == "critical" for path in block.paths)

    report = build_report_data(make_inputs())
    assert report.findings == () and report.attack_paths == ()
    return report.model_copy(update={"simulation": block})


def test_a_simulated_path_never_enters_a_gate_verdict() -> None:
    """REQ-SIM-004: a critical *simulated* path leaves the gate clean."""
    report = _report_with_simulated_critical_paths()

    assert report.simulation is not None
    assert findings_from_report(report) == ()

    severities = ("critical", "high", "medium", "low", "info")
    counts = {severity: len(report.findings_by_severity(severity)) for severity in severities}
    assert counts["critical"] == 0
    assert gate_exit_code(counts, "high") == EXIT_CLEAN


def test_a_simulated_path_never_reaches_the_verified_attack_path_section() -> None:
    """The separation is structural: the simulated paths live only in their own field."""
    report = _report_with_simulated_critical_paths()

    assert report.attack_paths == ()
    assert report.simulation is not None
    assert report.simulation.provenance == "simulated"
    for path in report.simulation.paths:
        for hop in path.hops:
            assert hop.origin in ("observed", "hypothetical")
            if hop.origin == "hypothetical":
                assert hop.finding_id is None, "a hypothetical hop is nobody's finding"


def test_the_report_renderers_keep_the_simulated_section_separate() -> None:
    """The golden-report property, in its cheapest form: own section, own vocabulary."""
    markdown = render_markdown(_report_with_simulated_critical_paths())

    assert "## 13. Simulated scenarios (what-if)" in markdown
    simulated = markdown[markdown.index("## 13.") :]
    assert "simulated" in simulated
    assert "hypothetical" in simulated
    verified = markdown[markdown.index("## 4.") : markdown.index("## 13.")]
    assert "Simulated RCE" not in verified
    assert "hyp-2" not in verified
    assert "hypothetical" not in verified


def test_a_model_with_no_scan_data_is_not_a_model() -> None:
    """An empty estate produces an empty model, never a clean-looking one."""
    empty = build_estate_graph(estate_key="empty", reachability=())
    run = simulate(empty, ())

    assert run.baseline == ()
    assert run.result == ()
    assert run.exposure_before == 0
    assert run.model_after["hosts"] == 0


def test_the_analysis_a_hypothesis_injects_says_it_is_simulated() -> None:
    """The synthetic analysis is a claim about a hypothetical, and says so in its own fields."""
    analysis = Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443).as_analysis()

    assert analysis.check_id == "sim.new-exposure.hyp-1"
    assert analysis.remediation.source == "simulated"
    assert analysis.finding_id is None
    assert analysis.confidence == 100, "a stipulation holds inside its own world"


def test_the_lab_shape_is_the_shape_this_file_expects() -> None:
    """A guard against the helper drifting out from under these assertions."""
    shapes = lab_inputs()
    assert shapes.assets and shapes.candidates and shapes.analyses
    assert all(item.scan_id == 1 for item in shapes.assets)
