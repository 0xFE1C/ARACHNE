"""The nine M6 checks, driven against purpose-built fixtures (S11, docs/spec/05- M6).

Each check is run directly, the way the checks step would, over the asset kind it accepts:
a local web root or repository for the artifact checks, a live lab origin for the served half
of the webshell/GenAI checks, an operator version export for the estate correlations, and the
log/AD exports for the hunting checks. The assertions key on the machine-readable ``signal``
and are paired with a control (a benign file, a clean run, a switched-off deployment flag) so a
check that reports everything fails just as loudly as one that reports nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.helpers.checks import asset_for, run_check, settings_for_checks
from tests.helpers.m6 import make_m6_harness
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.core.config import M6Settings, WebSettings
from arachne.modules.context import ModuleConfig
from arachne.modules.m6 import M6_CHECKS
from arachne.modules.m6.webshell import scan_script_text

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
WEBROOT = FIXTURES / "webroot"
REPO = FIXTURES / "repo"
LOGS = FIXTURES / "logs"
AD = FIXTURES / "ad"

CHECKS = {check.metadata.id: check for check in M6_CHECKS}


def _config(**m6: object) -> ModuleConfig:
    return ModuleConfig.from_settings(settings_for_checks(m6=M6Settings(**m6)))  # type: ignore[arg-type]


def _signals(results: list[object]) -> list[str]:
    found: list[str] = []
    for result in results:
        if getattr(result, "status", None) != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            signal = item.payload.get("signal")
            if signal:
                found.append(str(signal))
    return found


async def _run_repo(check_id: str, path: Path, *, config: ModuleConfig | None = None) -> list:
    check = CHECKS[check_id]
    asset = asset_for("cloud", f"repo:{path}")
    results, _ = await run_check(check, asset, config=config or _config())
    return results


# --------------------------------------------------------------------------- webshell
def test_the_script_scanner_flags_a_shell_and_ignores_a_benign_file() -> None:
    from arachne.modules.m6.corpus import load_corpus

    corpus = load_corpus()
    severities = {signature.id: signature.severity for signature in corpus.webshell_signatures()}
    shell = scan_script_text((WEBROOT / "uploads" / "shell.php").read_text(), corpus)
    assert shell.suspicious
    assert "php-encoded-eval" in {item.split(":", 1)[1] for item in shell.signatures}
    assert shell.heuristics  # the behaviour half also fired
    assert shell.confidence(severities) >= 0.9

    benign = scan_script_text((WEBROOT / "index.php").read_text(), corpus)
    assert not benign.suspicious


async def test_webshell_yara_finds_the_planted_webroot_fixture() -> None:
    """DONE criterion 1: the obfuscated PHP fixture is detected, its neighbours are not."""
    results = await _run_repo("m6.webshell-yara", WEBROOT)
    found = {result.title for result in results if result.status == "vulnerable"}
    assert any("shell.php" in title for title in found)
    assert any("tool.php" in title for title in found)
    assert not any("index.php" in title or "clean.php" in title for title in found)
    assert all(signal == "webshell" for signal in _signals(results))


async def test_webshell_yara_finds_a_served_shell(web: WebLab) -> None:
    harness = make_m6_harness(asset=asset_for("url", web.base_url))
    try:
        await harness.prepare([web.base_url])
        ctx = harness.context(CHECKS["m6.webshell-yara"]())
        results = [result async for result in CHECKS["m6.webshell-yara"]().run(ctx)]
    finally:
        await harness.aclose()
    served = [result for result in results if result.status == "vulnerable"]
    assert any("/uploads/shell.php" in result.title for result in served)


async def test_a_webroot_without_scripts_reports_clean(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("no scripts here\n", encoding="utf-8")
    results = await _run_repo("m6.webshell-yara", tmp_path)
    assert [result.status for result in results] == ["not_vulnerable"]


# --------------------------------------------------------------------------- GenAI
async def test_genai_finds_a_shipped_agent_config() -> None:
    results = await _run_repo("m6.attack-surface-genai", REPO)
    assert "genai-agent-config" in _signals(results)


async def test_genai_finds_the_served_surface(web: WebLab) -> None:
    harness = make_m6_harness(asset=asset_for("url", web.base_url), web=WebSettings(max_pages=40))
    try:
        await harness.prepare([web.base_url])
        ctx = harness.context(CHECKS["m6.attack-surface-genai"]())
        results = [result async for result in CHECKS["m6.attack-surface-genai"]().run(ctx)]
    finally:
        await harness.aclose()
    signals = _signals(results)
    assert "genai-endpoint" in signals
    assert "genai-prompt-surface" in signals


# --------------------------------------------------------------------------- secrets
async def test_secret_scan_finds_committed_credentials_in_the_repo_fixture() -> None:
    results = await _run_repo("m6.secret-scan-at-scale", REPO)
    kinds = {
        item.payload.get("kind")
        for result in results
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "repo-secret"
    }
    assert {"aws-access-key-id", "private-key"} <= kinds


async def test_secret_scan_reads_git_history_objects(tmp_path: Path) -> None:
    """A secret removed from the working tree but still in a loose git object is found."""
    import zlib

    objects = tmp_path / ".git" / "objects" / "ab"
    objects.mkdir(parents=True)
    blob = b"commit\x00AKIAIOSFODNN7EXAMPLE leaked then removed\n"
    (objects / ("c" * 38)).write_bytes(zlib.compress(blob))
    results = await _run_repo("m6.secret-scan-at-scale", tmp_path)
    history = [
        result
        for result in results
        if result.status == "vulnerable"
        and any(item.payload.get("in_history") for item in result.evidence)
    ]
    assert history, "the git-history scan found nothing in a loose object"


async def test_ci_secret_scan_finds_the_leaked_log() -> None:
    results = await _run_repo("m6.ci-secret-leak", REPO)
    assert "ci-secret-leak" in _signals(results)


async def test_ci_secret_scan_skips_when_no_logs_are_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    results = await _run_repo("m6.ci-secret-leak", tmp_path)
    assert [result.status for result in results] == ["info"]  # skipped


# --------------------------------------------------------------------------- estate
async def test_cve_epss_correlation_uses_the_version_export() -> None:
    config = _config(resolved_versions=str(LOGS / "resolved.json"))
    results = await _run_repo("m6.cve-epss-correlation", REPO, config=config)
    artifacts = [
        item.payload
        for result in results
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "epss-correlated"
    ]
    assert artifacts
    assert all(item["patch_gap"] is True for item in artifacts)
    assert any(item.get("epss") for item in artifacts)


async def test_lpe_discovery_matches_the_kernel_and_polkit() -> None:
    config = _config(resolved_versions=str(LOGS / "resolved.json"))
    results = await _run_repo("m6.lpe-discovery", REPO, config=config)
    cves = {
        item.payload.get("cve")
        for result in results
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "lpe-cve"
    }
    assert {"CVE-2021-4034", "CVE-2022-0847"} <= cves


async def test_the_estate_checks_skip_when_an_asset_is_not_the_owner() -> None:
    """A second declared asset must not produce a duplicate estate finding."""
    from tests.helpers.checks import make_step_context

    from arachne.modules.base import Asset
    from arachne.modules.context import CheckContext

    step, _memory = make_step_context(seed=[("cloud", "repo:/a"), ("cloud", "repo:/b")])
    asset = Asset.from_meta("cloud", "repo:/b", {"declared": True})
    context = CheckContext(
        step=step, module=CHECKS["m6.lpe-discovery"](), asset=asset, config=_config()
    )
    results = [result async for result in CHECKS["m6.lpe-discovery"]().run(context)]
    assert len(results) == 1
    assert any(item.payload.get("skipped") for item in results[0].evidence)


# --------------------------------------------------------------------------- hunting
async def test_sigma_ships_the_rule_set_without_log_access() -> None:
    results = await _run_repo("m6.sigma-hunt-rules", LOGS)
    info = [result for result in results if result.status == "info"]
    assert any(
        item.payload.get("signal") == "sigma-ruleset" for result in info for item in result.evidence
    )
    assert any(item.payload.get("skipped") for result in info for item in result.evidence)


async def test_sigma_hunts_the_exported_telemetry_when_granted() -> None:
    config = _config(log_access=True, log_paths=(str(LOGS),))
    results = await _run_repo("m6.sigma-hunt-rules", LOGS, config=config)
    hits = {
        item.payload.get("rule_id")
        for result in results
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "sigma-hit"
    }
    assert len(hits) >= 5  # Kerberoasting, AS-REP, LSASS, worker-shell, lateral, persistence


async def test_deception_is_off_until_the_switch_is_set() -> None:
    off = await _run_repo("m6.deception-listeners", LOGS)
    assert any(item.payload.get("skipped") for result in off for item in result.evidence)
    on = await _run_repo(
        "m6.deception-listeners", LOGS, config=_config(deception=True, log_paths=(str(LOGS),))
    )
    tokens = {
        item.payload.get("decoy")
        for result in on
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "honeytoken-trigger"
    }
    assert {"canary-aws-key-01", "canary-s3-bucket-02"} <= tokens


async def test_ad_attack_path_finds_the_escalation_to_domain_admin() -> None:
    results = await _run_repo("m6.ad-attack-path", AD)
    artifacts = [
        item.payload
        for result in results
        if result.status == "vulnerable"
        for item in result.evidence
        if item.payload.get("signal") == "ad-path"
    ]
    assert artifacts
    assert any(item["start"] == "ALICE@CORP.LOCAL" for item in artifacts)
    assert all(item["goal"] == "Domain Admins" for item in artifacts)


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def web() -> WebLab:
    with start_web_lab() as lab:
        yield lab
