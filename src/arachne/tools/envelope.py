"""``python -m arachne.tools.envelope`` — measure and publish the performance envelope.

REQ-SCALE-009 asks for a *measured* performance envelope, not an adjective: p95 latency per
list endpoint at a stated request rate, scan throughput in checks per minute per agent, and
the memory ceiling of a scan — each stated with the hardware, the dataset and the
configuration it was measured on, and reproducible with one shipped command.

**What this measures.**

``api``
    Four list endpoints (``/api/v1/scans``, ``/api/v1/findings``, ``/api/v1/targets``,
    ``/api/v1/modules``) driven by an in-process ASGI client, sequentially, paced at
    :data:`TARGET_RATE` requests per second each. Latency is wall-clock from just before the
    request to just after the response, so it includes the application's own work and the
    SQLite round trips — but not a network, because there is not one: this measures the
    control plane, not a load balancer. The achieved rate is reported beside the target so a
    machine that could not keep up is visible rather than silently averaged away.
``scan``
    One heuristic scan of the in-repo ground-truth lab (``tests/lab/web_lab.py``) — the same
    fixture the acceptance and report QA suites scan — timed end to end, with the checks step's
    own ``checks_run`` counter. ``checks_per_minute_per_agent`` is that count over the elapsed
    minutes; one process is one agent.
``memory``
    The benchmark process's peak RSS across the whole run, and the resident-set growth the
    scan alone added (an upper bound, since ``VmHWM`` is a high-water mark).

**What it deliberately excludes.** AI inference (the scan is heuristic mode), the M1/M2
network modules (their cost on a synthetic estate is the scripted network, not the scanner),
multi-process load, and TLS. Each exclusion is recorded in the committed envelope rather than
implied.

**Modes.**

``--write PATH``
    Commit the measured envelope as JSON. The shipped envelope lives at
    ``benchmarks/envelope/envelope.json`` and travels with the release.
``--gate``
    Compare freshly measured latency against the committed envelope and exit non-zero when a
    p95 exceeds its budget (or the committed p95 by the stated margin). This is the CI perf
    gate; :data:`P95_BUDGET_MS` is the documented budget.

Exit codes: ``0`` ok, ``1`` a gate breach, ``2`` a usage error.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
import tempfile
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Annotated, Any, Final

import typer

from arachne import __version__
from arachne.core.config import ApiSettings, EvidenceSettings, Settings
from arachne.core.errors import ConfigurationError
from arachne.data.db import create_all, create_db_engine

__all__ = ["main"]

app = typer.Typer(
    name="envelope",
    help="Measure and publish the performance envelope (REQ-SCALE-009).",
    add_completion=False,
)

#: The request rate each list endpoint is paced at, requests per second.
TARGET_RATE: Final = 50.0
#: How long each endpoint is driven, in seconds. At :data:`TARGET_RATE` this is 150 samples
#: per endpoint; enough for a p95 that is a measurement rather than an anecdote.
DEFAULT_DURATION_S: Final = 3.0
#: The documented latency budget: a p95 above this fails the perf gate.
P95_BUDGET_MS: Final = 500.0
#: The margin by which a fresh measurement may exceed the committed p95 before the gate
#: fails. A benchmark that reddens at ±1 ms is a benchmark people switch off.
P95_REGRESSION_MARGIN: Final = 1.5
P95_REGRESSION_FLOOR_MS: Final = 10.0
#: The documented memory ceiling for a scan, in MiB.
PEAK_RSS_BUDGET_MIB: Final = 1024.0
#: The list endpoints the envelope covers, in the order they are measured.
LIST_ENDPOINTS: Final = (
    "/api/v1/scans",
    "/api/v1/findings",
    "/api/v1/targets",
    "/api/v1/modules",
)
#: The dataset the latency figures are measured against: a small estate with a report's worth
#: of findings. Stated in the committed envelope so a reader knows what "p95" was over.
DATASET: Final = {"scans": 10, "findings": 100, "assets": 10, "checks": 12}


def _percentile(values: Sequence[float], fraction: float) -> float:
    """The ``fraction`` percentile of ``values`` (nearest-rank, no interpolation)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round(fraction * (len(ordered) - 1))))
    return ordered[rank]


def _rss_mib() -> float:
    return _status_kib("VmRSS:") / 1024.0


def _hwm_mib() -> float:
    return _status_kib("VmHWM:") / 1024.0


def _status_kib(field: str) -> float:
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:  # pragma: no cover - non-Linux
        return 0.0
    for line in status.splitlines():
        if line.startswith(field):
            return float(line.split()[1])
    return 0.0  # pragma: no cover


def hardware_facts() -> dict[str, Any]:
    """The machine the numbers were measured on (REQ-SCALE-009's "hardware")."""
    model = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                model = line.partition(":")[2].strip()
                break
    except OSError:  # pragma: no cover - non-Linux
        model = platform.processor() or "unknown"
    return {
        "cpu": model,
        "logical_cpus": os.cpu_count(),
        "memory_mib": round(_meminfo_mib(), 1),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def _meminfo_mib() -> float:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return float(line.split()[1]) / 1024.0
    except OSError:  # pragma: no cover - non-Linux
        pass
    return 0.0


def _configuration(settings: Settings, *, rate: float, duration: float) -> dict[str, Any]:
    return {
        "target_rate_per_endpoint_per_second": rate,
        "duration_s_per_endpoint": duration,
        "achieve_mode": "sequential client, one request in flight",
        # The scheme only: the benchmark builds its own throwaway database, so a path here
        # would change every run and mean nothing in a committed file.
        "database_scheme": settings.database_url.split(":", 1)[0],
        "database_note": "throwaway database created for the benchmark run",
        "analysis_engine": "heuristic (no AI provider configured)",
        "modules_scanned": ["M3", "M4"],
        "http_max_body_bytes": settings.http.max_body_bytes,
        "http_retries": settings.http.retries,
        "per_host_rate_per_second": settings.rate_limit.per_host_rate,
        "evidence_backend": settings.evidence.backend,
        "workers": 1,
        "network": "none (loopback only): no TLS termination, no load balancer",
        "excluded": [
            "AI inference",
            "M1 OSINT and M2 network modules",
            "multiple API workers/processes",
            "TLS and proxy hops",
        ],
    }


def _benchmark_settings(workdir: Path) -> Settings:
    """A settings bundle for the benchmark: a throwaway database, no AI, generous limits.

    The API key is generated per run: a committed key would be a default credential, and this
    tool never talks to anything but itself.
    """
    import secrets

    return Settings(
        database_url=f"sqlite:///{workdir / 'envelope.db'}",
        log_level="CRITICAL",
        log_json=False,
        actor="envelope",
        api=ApiSettings(
            keys=(f"envelope:admin:{secrets.token_urlsafe(24)}",),
            require_tls=False,
            rate_limit_per_minute=1_000_000,
            rate_limit_burst=1_000_000,
        ),
        evidence=EvidenceSettings(backend="local", dir=str(workdir / "evidence")),
    )


def _seed(settings: Settings) -> tuple[Any, str]:
    """Build the stack and fill it with the documented dataset."""
    from arachne.data.models import Asset, Check, Finding, Scan, Target
    from arachne.data.services import build_services

    engine = create_db_engine(settings=settings)
    create_all(engine)
    engine.dispose()
    services = build_services(settings, check_schema=False)
    with services.session_factory() as session:
        target = Target(name="envelope", scope_json={})
        session.add(target)
        session.flush()
        check = Check(module="M3", name="xss-oracle", version="1.0")
        session.add(check)
        session.flush()
        for scan_number in range(DATASET["scans"]):
            scan = Scan(
                target_id=target.id,
                status="completed",
                plan_json={"target_name": "envelope", "engine": "heuristic"},
                engine="heuristic",
            )
            session.add(scan)
            session.flush()
            asset = Asset(
                scan_id=scan.id,
                kind="url",
                value=f"https://envelope.example/{scan_number}",
                meta_json={},
            )
            session.add(asset)
            session.flush()
            for finding_number in range(DATASET["findings"] // DATASET["scans"]):
                session.add(
                    Finding(
                        scan_id=scan.id,
                        check_id=check.id,
                        asset_id=asset.id,
                        title=f"envelope finding {scan_number}-{finding_number}",
                        severity="high",
                        confidence=90.0,
                        status="open",
                        evidence_refs_json=[],
                    )
                )
        session.commit()
    return services, settings.api.keys[0].rsplit(":", 1)[1]


async def _asgi_get(app: Any, path: str, *, key: str) -> tuple[int, bytes]:
    """One GET through the ASGI interface, with no HTTP client in the path.

    Driving the app's ASGI callable directly is the honest way to measure the control
    plane's own work — and it is also the only way allowed: ADR-05 keeps every HTTP library
    inside ``core/http.py``, so the benchmark may not import one to talk to its own process.
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1"),
            (b"x-api-key", key.encode()),
            (b"user-agent", b"ARACHNE-envelope"),
        ],
        "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 80),
        "app": app,
        "state": {},
    }
    inbox: list[dict[str, Any]] = [{"type": "http.request", "body": b"", "more_body": False}]
    status_code = 0
    body = bytearray()

    async def receive() -> dict[str, Any]:
        if inbox:
            return inbox.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = int(message["status"])
        elif message["type"] == "http.response.body":
            body.extend(message.get("body", b""))

    await app(scope, receive, send)
    return status_code, bytes(body)


async def _measure_latency(
    app: Any, *, key: str, endpoints: Iterable[str], rate: float, duration: float
) -> dict[str, Any]:
    """Drive each endpoint sequentially at ``rate`` and report its latency distribution."""
    out: dict[str, Any] = {}
    for endpoint in endpoints:
        # One untimed request first: the very first call to an endpoint pays lazy imports,
        # route compilation and the first SQLite execution. Leaving it in the sample would
        # put a cold-start outlier in the p95 and make the number about the process's
        # warm-up rather than the endpoint.
        await _asgi_get(app, endpoint, key=key)
        latencies: list[float] = []
        interval = 1.0 / rate
        started = time.perf_counter()
        next_at = started
        statuses: set[int] = set()
        while time.perf_counter() - started < duration:
            next_at += interval
            stamp = time.perf_counter()
            status, _body = await _asgi_get(app, endpoint, key=key)
            latencies.append((time.perf_counter() - stamp) * 1000.0)
            statuses.add(status)
            delay = next_at - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
        elapsed = time.perf_counter() - started
        if statuses != {200}:  # pragma: no cover - a broken app is an operator error
            raise ConfigurationError(f"{endpoint} answered {sorted(statuses)}, not 200")
        out[endpoint] = {
            "samples": len(latencies),
            "achieved_rate_per_second": round(len(latencies) / elapsed, 2),
            "p50_ms": round(_percentile(latencies, 0.50), 2),
            "p95_ms": round(_percentile(latencies, 0.95), 2),
            "p99_ms": round(_percentile(latencies, 0.99), 2),
            "max_ms": round(max(latencies), 2),
        }
    return out


def _measure_scan() -> dict[str, Any]:
    """One heuristic scan of the in-repo lab, timed, with the checks step's own counter.

    The lab and harness are loaded dynamically, exactly as the benchmark tool does it: a
    shipped tool must not depend statically on the test suite, and the operator gets one
    clear message when the repository is not a checkout.
    """
    import importlib

    try:
        lab_module = importlib.import_module("tests.lab.web_lab")
        harness_module = importlib.import_module("tests.integration.test_agentic")
    except ImportError as exc:  # pragma: no cover - the lab ships with this repository
        raise ConfigurationError(
            "the envelope's scan measurement needs this repository's reference lab "
            "(tests/lab/web_lab.py): run it from a checkout"
        ) from exc

    from arachne.core.lifecycle import ScanStatus
    from arachne.core.planner import ScanStep

    before = _rss_mib()

    async def run() -> tuple[float, dict[str, Any]]:
        with lab_module.start_web_lab() as lab:
            harness = harness_module.make_harness(lab)
            request = harness.request
            if request is None:  # pragma: no cover - the harness always builds one
                raise ConfigurationError("the envelope harness built no scan request")
            started = time.perf_counter()
            session = await harness.orchestrator.scan(request)
            elapsed = time.perf_counter() - started
            if session.status is not ScanStatus.COMPLETED:  # pragma: no cover
                raise ConfigurationError(f"the reference scan ended {session.status}")
            state = session.record.step_state(ScanStep.CHECKS) if session.record else None
            stats = dict(state.stats) if state else {}
            return elapsed, stats

    elapsed, stats = asyncio.run(run())
    checks_run = int(stats.get("checks_run", 0))
    minutes = elapsed / 60.0
    return {
        "target": "in-repo web lab (tests/lab/web_lab.py)",
        "elapsed_s": round(elapsed, 2),
        "checks_run": checks_run,
        "checks_per_minute_per_agent": round(checks_run / minutes, 1) if minutes else 0.0,
        "findings": int(stats.get("candidates", 0)),
        "peak_rss_growth_mib": round(max(0.0, _hwm_mib() - before), 1),
    }


def build_envelope(
    *,
    workdir: Path | None = None,
    duration: float = DEFAULT_DURATION_S,
    rate: float = TARGET_RATE,
    include_scan: bool = True,
    label: str = "",
) -> dict[str, Any]:
    """Measure the whole envelope and return it as a JSON-shaped document."""
    from arachne.api.app import create_app

    owned = workdir is None
    directory = workdir or Path(tempfile.mkdtemp(prefix="arachne-envelope-"))
    settings = _benchmark_settings(directory)
    services = None
    try:
        services, key = _seed(settings)
        api_app = create_app(services, settings=settings)
        latency = asyncio.run(
            _measure_latency(
                api_app, key=key, endpoints=LIST_ENDPOINTS, rate=rate, duration=duration
            )
        )
        scan = _measure_scan() if include_scan else None
        envelope: dict[str, Any] = {
            "arachne_version": __version__,
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "label": label,
            "hardware": hardware_facts(),
            "dataset": dict(DATASET),
            "configuration": _configuration(settings, rate=rate, duration=duration),
            "api": {
                "endpoints": latency,
                "p95_budget_ms": P95_BUDGET_MS,
            },
            "scan": scan,
            "memory": {
                "benchmark_process_peak_rss_mib": round(_hwm_mib(), 1),
                "scan_ceiling_mib": PEAK_RSS_BUDGET_MIB,
            },
        }
        return envelope
    finally:
        if services is not None:
            services.close()
        if owned:
            import shutil

            shutil.rmtree(directory, ignore_errors=True)


def write_envelope(path: Path, envelope: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_envelope(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"{path}: not a readable envelope: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"{path}: the envelope is not a JSON object")
    return document


def gate_problems(current: dict[str, Any], baseline: dict[str, Any]) -> tuple[str, ...]:
    """Every way the fresh measurement breaches the budget or the committed envelope."""
    problems: list[str] = []
    for endpoint, numbers in sorted(current.get("api", {}).get("endpoints", {}).items()):
        budget = float(current["api"].get("p95_budget_ms", P95_BUDGET_MS))
        p95 = float(numbers["p95_ms"])
        if p95 > budget:
            problems.append(f"{endpoint}: p95 {p95:.1f} ms exceeds the {budget:.0f} ms budget")
        committed = baseline.get("api", {}).get("endpoints", {}).get(endpoint, {}).get("p95_ms")
        if committed is None:
            problems.append(f"{endpoint}: not present in the committed envelope")
            continue
        allowed = float(committed) * P95_REGRESSION_MARGIN + P95_REGRESSION_FLOOR_MS
        if p95 > allowed:
            problems.append(
                f"{endpoint}: p95 {p95:.1f} ms is over {allowed:.1f} ms "
                f"(committed {float(committed):.1f} ms, margin {P95_REGRESSION_MARGIN}x "
                f"+{P95_REGRESSION_FLOOR_MS:.0f} ms)"
            )
    peak = float(current.get("memory", {}).get("benchmark_process_peak_rss_mib", 0.0))
    ceiling = float(current.get("memory", {}).get("scan_ceiling_mib", PEAK_RSS_BUDGET_MIB))
    if peak > ceiling:
        problems.append(f"peak RSS {peak:.1f} MiB is over the {ceiling:.0f} MiB ceiling")
    return tuple(problems)


def _default_envelope_path() -> Path:
    return Path(__file__).resolve().parents[3] / "benchmarks" / "envelope" / "envelope.json"


@app.command()
def run(
    write: Annotated[
        Path | None, typer.Option("--write", help="Commit the measured envelope to this path.")
    ] = None,
    gate: Annotated[
        bool, typer.Option("--gate", help="Fail when a p95 breaches the budget or the baseline.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the envelope as JSON.")] = False,
    duration: Annotated[
        float, typer.Option("--duration", help="Seconds to drive each endpoint.")
    ] = DEFAULT_DURATION_S,
    rate: Annotated[
        float, typer.Option("--rate", help="Requests per second per endpoint.")
    ] = TARGET_RATE,
    skip_scan: Annotated[
        bool, typer.Option("--skip-scan", help="Measure the API envelope only.")
    ] = False,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Committed envelope to gate against.")
    ] = None,
    label: Annotated[str, typer.Option("--label", help="A note recorded with the numbers.")] = "",
) -> None:
    """Measure the envelope; optionally commit it and gate on it."""
    if duration <= 0 or rate <= 0:
        typer.echo("--duration and --rate must be positive", err=True)
        raise typer.Exit(code=2)
    envelope = build_envelope(duration=duration, rate=rate, include_scan=not skip_scan, label=label)
    if write is not None:
        write_envelope(write, envelope)
        typer.echo(f"wrote envelope to {write}")
    if as_json:
        typer.echo(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        _print_envelope(envelope)
    if gate:
        baseline_path = baseline or _default_envelope_path()
        committed = load_envelope(baseline_path)
        problems = gate_problems(envelope, committed)
        for problem in problems:
            typer.echo(f"  BREACH: {problem}", err=True)
        if problems:
            raise typer.Exit(code=1)


def _print_envelope(envelope: dict[str, Any]) -> None:
    hardware = envelope["hardware"]
    typer.echo(
        f"envelope measured {envelope['measured_at']} on {hardware['cpu']} "
        f"({hardware['logical_cpus']} cpus, {hardware['memory_mib']:.0f} MiB)"
    )
    for endpoint, numbers in sorted(envelope["api"]["endpoints"].items()):
        typer.echo(
            f"  {endpoint:<20} p50 {numbers['p50_ms']:>7.2f} ms  "
            f"p95 {numbers['p95_ms']:>7.2f} ms  p99 {numbers['p99_ms']:>7.2f} ms  "
            f"({numbers['samples']} samples at {numbers['achieved_rate_per_second']:.1f}/s)"
        )
    scan = envelope.get("scan")
    if scan:
        typer.echo(
            f"  scan: {scan['checks_run']} checks in {scan['elapsed_s']}s -> "
            f"{scan['checks_per_minute_per_agent']} checks/min/agent"
        )
    memory = envelope["memory"]
    typer.echo(
        f"  peak RSS {memory['benchmark_process_peak_rss_mib']:.0f} MiB "
        f"(ceiling {memory['scan_ceiling_mib']:.0f} MiB)"
    )


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(app())
