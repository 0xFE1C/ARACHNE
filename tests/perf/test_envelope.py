"""The published performance envelope and its gate (REQ-SCALE-009).

The envelope is a committed artefact: ``benchmarks/envelope/envelope.json`` holds the
measured p95 latency per list endpoint, the reference lab's checks per minute, the memory
figures, and the hardware, dataset and configuration they were measured on. These tests pin
three things a reader of that file depends on:

* the committed document is complete (no section may silently disappear) and its numbers are
  inside the documented budget;
* the command reproduces the same *shape* from scratch, so the file is regenerable rather
  than hand-edited; and
* the gate actually fails when a p95 breaches the budget or the committed baseline, because
  a gate that cannot fail is not a gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arachne.tools.envelope import (
    LIST_ENDPOINTS,
    P95_BUDGET_MS,
    build_envelope,
    gate_problems,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ENVELOPE_PATH = REPO_ROOT / "benchmarks" / "envelope" / "envelope.json"


def _committed() -> dict[str, Any]:
    return json.loads(ENVELOPE_PATH.read_text(encoding="utf-8"))


def test_the_committed_envelope_is_complete_and_within_budget() -> None:
    envelope = _committed()
    for section in ("hardware", "dataset", "configuration", "api", "memory", "scan"):
        assert section in envelope, f"the committed envelope has no {section!r} section"

    # The envelope must state what it was measured on (REQ-SCALE-009).
    hardware = envelope["hardware"]
    assert hardware["cpu"] and hardware["logical_cpus"]
    assert envelope["dataset"]["findings"] > 0
    assert envelope["configuration"]["target_rate_per_endpoint_per_second"] == 50.0

    endpoints = envelope["api"]["endpoints"]
    assert set(endpoints) == set(LIST_ENDPOINTS), "the measured endpoint set changed"
    for endpoint, numbers in endpoints.items():
        assert 0 < numbers["p95_ms"] <= envelope["api"]["p95_budget_ms"], endpoint
        assert numbers["p50_ms"] <= numbers["p95_ms"] <= numbers["p99_ms"] <= numbers["max_ms"]
        assert numbers["samples"] >= 100, f"{endpoint}: too few samples for a p95"
        # The achieved rate must track the stated target, or the p95 is not at 50 req/s.
        assert numbers["achieved_rate_per_second"] == pytest.approx(50.0, rel=0.05), endpoint

    assert envelope["scan"]["checks_per_minute_per_agent"] > 0
    assert (
        envelope["memory"]["benchmark_process_peak_rss_mib"]
        <= envelope["memory"]["scan_ceiling_mib"]
    )


def test_the_committed_envelope_satisfies_its_own_gate() -> None:
    envelope = _committed()
    assert gate_problems(envelope, envelope) == (), "the committed envelope breaches its own gate"


def test_the_gate_fails_when_a_p95_breaches_the_budget() -> None:
    envelope = _committed()
    current = json.loads(json.dumps(envelope))
    current["api"]["endpoints"][LIST_ENDPOINTS[0]]["p95_ms"] = P95_BUDGET_MS + 1.0
    problems = gate_problems(current, envelope)
    assert any("budget" in problem for problem in problems)


def test_the_gate_fails_when_a_p95_regresses_past_the_margin() -> None:
    envelope = _committed()
    current = json.loads(json.dumps(envelope))
    committed = envelope["api"]["endpoints"][LIST_ENDPOINTS[0]]["p95_ms"]
    current["api"]["endpoints"][LIST_ENDPOINTS[0]]["p95_ms"] = committed * 10
    problems = gate_problems(current, envelope)
    assert any("over" in problem for problem in problems)


@pytest.mark.perf
@pytest.mark.timeout(180)
def test_the_command_reproduces_the_envelope_shape() -> None:
    """A short, scan-free run produces the same document shape as the committed one."""
    fresh = build_envelope(duration=0.2, rate=50.0, include_scan=False, label="test")
    assert set(fresh) >= {"hardware", "dataset", "configuration", "api", "memory"}
    assert set(fresh["api"]["endpoints"]) == set(LIST_ENDPOINTS)
    assert fresh["scan"] is None  # this run asked for the API envelope only
    assert gate_problems(fresh, _committed()) == (), "a fresh measurement should be in budget"
