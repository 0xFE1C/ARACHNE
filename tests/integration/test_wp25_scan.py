"""WP-25 acceptance: the WordPress ecosystem family meets its lab ground truth (REQ-DET-018).

The requirement's acceptance criteria are the shape of this module:

* **at least 24 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source *and* on the
  wire: the fixture records every request it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on either
  decoy — the decoys are the requirement's own: a stock hardened installation and a
  WAF-fronted one (``tests/lab/wordpress_lab.py``);
* the registry total is printed for the handoff.

One test drives all twenty-six checks against all three installations, reusing one crawl per
installation: the family is a bounded path-probe family, so a crawl per check would add nothing
the shared inventory does not already hold.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import M5Harness, make_m5_harness
from tests.lab.wordpress_lab import WordPressLab, start_wordpress_lab

from arachne.core.config import WebSettings
from arachne.core.proof import ProofLevel
from arachne.modules.context import CheckContext
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3.support import safe_fetch
from arachne.modules.registry import ModuleRegistry

#: Every check the WP-25 family registers (REQ-DET-018), in the order the module lists them.
WP25_IDS: tuple[str, ...] = tuple(
    check.metadata.id for check in M3_CHECKS if check.metadata.id.startswith("m3.wp-")
)

#: The fixture mode that plants each signal, and the two decoys the requirement names.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("hardened", "waf")

#: The module that carries the family (the source-level read-only assertion reads it).
WP_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"

#: The safe request methods the family may send. ``OPTIONS`` is safe by HTTP semantics
#: (RFC 9110 §9.3.7), which is what lets the cron check report reachability without issuing
#: the GET that would run a scheduled job.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class _Installation:
    lab: WordPressLab
    harness: M5Harness


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[str, WordPressLab]]:
    """One installation per mode, started once for the module."""
    running: dict[str, WordPressLab] = {}
    stack = []
    try:
        for mode in (POSITIVE, *DECOYS):
            manager = start_wordpress_lab(mode)
            running[mode] = manager.__enter__()
            stack.append(manager)
        yield running
    finally:
        for manager in reversed(stack):
            manager.__exit__(None, None, None)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M3_CHECKS}


async def _run(harness: M5Harness, check_id: str) -> list[Any]:
    check = _by_id()[check_id]
    return [result async for result in check().run(harness.context(check()))]


def _findings(results: list[Any]) -> list[Any]:
    return [result for result in results if result.status == "vulnerable"]


async def _measure(installations: dict[str, WordPressLab]) -> dict[str, dict[str, int]]:
    """Run every family check against every installation, counting its findings."""
    counts: dict[str, dict[str, int]] = {}
    for mode, lab in installations.items():
        harness = make_m5_harness(
            asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=40)
        )
        try:
            await harness.prepare([lab.base_url])
            for check_id in WP25_IDS:
                found = len(_findings(await _run(harness, check_id)))
                counts.setdefault(check_id, {})[mode] = found
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(installations: dict[str, WordPressLab]) -> dict[str, dict[str, int]]:
    """One run of the whole family against all three installations (runtime budget)."""
    return asyncio.run(_measure(installations))


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_four_checks() -> None:
    """REQ-DET-018: at least 24 new checks in this family."""
    assert len(WP25_IDS) >= 24, WP25_IDS
    assert len(set(WP25_IDS)) == len(WP25_IDS)
    registry = ModuleRegistry.discover()
    for check_id in WP25_IDS:
        assert registry.get(check_id) is not None, check_id
    print(f"\nregistry total: {len(registry.checks())} checks; WP-25 family: {len(WP25_IDS)}")


def test_every_check_reports_its_positive_and_stays_silent_on_both_decoys(
    measured: dict[str, dict[str, int]],
) -> None:
    """The requirement's acceptance core: a planted signal is found, both decoys are silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    for check_id in WP25_IDS:
        counts = measured[check_id]
        if counts.get(POSITIVE, 0) < 1:
            misses.append(f"{check_id}: no finding on the vulnerable installation")
        for mode in DECOYS:
            if counts.get(mode, 0) != 0:
                false_positives.append(f"{check_id}: {counts[mode]} finding(s) on the {mode} decoy")
    assert not misses, misses
    assert not false_positives, false_positives
    print(
        f"\n{len(WP25_IDS)} checks x {1 + len(DECOYS)} installations: "
        f"every positive found, 0 findings on {len(DECOYS)} decoys"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-018: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP25_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is ProofLevel.L1, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith(("WSTG-", "API")) for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch03#"), check_id


def test_the_cron_probe_is_gated_like_every_other_non_get_interaction() -> None:
    """The family's one non-GET verb is the OPTIONS of ``m3.wp-cron-surface`` (F-01-09).

    It is read-only — OPTIONS is safe by HTTP semantics, which is why it exists: the check
    reports the cron endpoint's reachability without the GET that would run a due job — and
    it is gated behind the active-checks opt-in exactly like ``m4.webdav-verbs``, so a
    default scan still sends nothing but GETs.
    """
    metadata = _by_id()["m3.wp-cron-surface"].metadata
    assert metadata.type == "active"
    assert metadata.requires_active_checks is True
    assert metadata.safe is True
    others = [
        check_id
        for check_id in WP25_IDS
        if _by_id()[check_id].metadata.requires_active_checks and check_id != "m3.wp-cron-surface"
    ]
    assert others == [], others


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no state-changing verb and no ``method=`` choice."""
    source = (WP_SOURCE / "wordpress.py").read_text(encoding="utf-8")
    for verb in (
        '"POST"',
        "'POST'",
        '"PUT"',
        "'PUT'",
        '"PATCH"',
        "'PATCH'",
        '"DELETE"',
        "'DELETE'",
    ):
        assert verb not in source, f"the family names a state-changing verb: {verb}"
    # The single request shape is ``_fetch(..., method=self.method)``; the only method the
    # family declares is the safe OPTIONS of the cron probe.
    assert source.count("method=self.method") == 1
    assert re.search(r'^    method = "OPTIONS"$', source, re.MULTILINE), (
        "the only declared method must be the safe OPTIONS of the cron probe"
    )


def test_no_state_changing_request_reached_any_installation(
    installations: dict[str, WordPressLab],
) -> None:
    """The read-only claim on the wire: every request the fixture answered was safe."""
    offenders: list[str] = []
    for mode, lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{mode}: {request}")
    assert not offenders, offenders


async def test_the_waf_decoy_is_a_real_trap(installations: dict[str, WordPressLab]) -> None:
    """The WAF decoy echoes the request path, so body-content matching would fire on it.

    The probe goes through the scanner's own scoped client, so the protocol, host and address
    boundaries the scanner enforces are the ones exercised here — the fixture is reached the
    same way a check reaches it, never with a raw URL opener.
    """
    lab = installations["waf"]
    harness = make_m5_harness(asset=asset_for("url", lab.base_url))
    try:
        exchange = await safe_fetch(harness.context(None), f"{lab.origin}/wp-config.php.bak")
        assert exchange is not None, "the scoped client refused the loopback probe"
        assert exchange.status_code == 403
        assert "/wp-config.php.bak" in exchange.body, "the block page must echo the path"
        assert "WordPress" in exchange.body, "the block page must name the platform"
    finally:
        await harness.aclose()


async def test_the_checks_are_deterministic(installations: dict[str, WordPressLab]) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    lab = installations[POSITIVE]
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=40))
    try:
        await harness.prepare([lab.base_url])

        def signature(results: list[Any]) -> list[tuple[str, str]]:
            return sorted((result.status, result.title) for result in results)

        for check_id in WP25_IDS:
            first = signature(await _run(harness, check_id))
            second = signature(await _run(harness, check_id))
            assert first == second, check_id
    finally:
        await harness.aclose()


async def test_a_dry_run_sends_nothing(installations: dict[str, WordPressLab]) -> None:
    """F-01-10: with no HTTP client the family yields a skip, never a probe."""
    lab = installations[POSITIVE]
    harness = make_m5_harness(asset=asset_for("url", lab.base_url))
    try:
        await harness.prepare([lab.base_url])
        before = len(lab.requests)
        # A dry run has no HTTP client and no crawl (F-01-10): the step context carries
        # neither, which is what the checks step hands a check in dry-run mode.
        dry_step = replace(harness.step, http=None, web=None)
        for check_id in WP25_IDS:
            check = _by_id()[check_id]
            context = CheckContext(
                step=dry_step, module=check(), asset=harness.asset, config=harness.config
            )
            results = [result async for result in check().run(context)]
            assert len(results) == 1 and results[0].status == "info", check_id
        assert len(lab.requests) == before, "a dry run reached the target"
    finally:
        await harness.aclose()
