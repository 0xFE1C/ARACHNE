"""WP-26 acceptance: the CMS family B meets its lab ground truth (REQ-DET-019).

The requirement's acceptance criteria are the shape of this module:

* **at least 24 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source *and* on the
  wire: every fixture records the requests it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoys are the requirement's own ("one hardened instance per CMS",
  ``tests/lab/cms_lab.py``), plus a WAF-fronted instance per system and the five vulnerable
  installations, which are decoys for one another's checks;
* the registry total is printed for the handoff.

One measurement drives all thirty checks against all fifteen installations (five systems, three
modes each), reusing one crawl per installation: the family is a bounded path-probe family, so a
crawl per check would add nothing the shared inventory does not already hold.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import M5Harness, make_m5_harness
from tests.lab.cms_lab import CMS_PLATFORMS, CmsLab, start_cms_lab

from arachne.core.config import WebSettings
from arachne.core.proof import ProofLevel
from arachne.modules.context import CheckContext
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3.support import safe_fetch
from arachne.modules.registry import ModuleRegistry

#: The five systems the family covers (REQ-DET-019).
CMS_PREFIXES: tuple[str, ...] = CMS_PLATFORMS

#: Every check the WP-26 family registers, in the order the module lists them.
WP26_IDS: tuple[str, ...] = tuple(
    check.metadata.id
    for check in M3_CHECKS
    if check.metadata.name.startswith(tuple(f"{cms}-" for cms in CMS_PREFIXES))
)

#: The fixture mode that plants each signal, and the decoys: one hardened instance per system
#: and one WAF-fronted instance per system.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("hardened", "waf")

#: The module that carries the family (the source-level read-only assertion reads it).
CMS_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"

#: The lab module the fixture-shape assertion reads.
LAB_SOURCE = Path(__file__).resolve().parents[1] / "lab" / "cms_lab.py"

#: The safe request methods the family may send. The family is GET-only.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def _owner(check_id: str) -> str:
    """The system a family check belongs to (``m3.joomla-config-source`` → ``joomla``)."""
    name = check_id.removeprefix("m3.")
    return next(cms for cms in CMS_PREFIXES if name.startswith(f"{cms}-"))


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], CmsLab]]:
    """One running installation per (system, mode), started once for the module."""
    running: dict[tuple[str, str], CmsLab] = {}
    stack = []
    try:
        for cms in CMS_PREFIXES:
            for mode in (POSITIVE, *DECOYS):
                manager = start_cms_lab(cms, mode)
                running[(cms, mode)] = manager.__enter__()
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


async def _measure(
    installations: dict[tuple[str, str], CmsLab],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings.

    A harness (and so an HTTP client and a crawl) is created per installation *inside* this
    coroutine and closed here: a client is bound to the loop that built it, so a module-scoped
    fixture cannot hold one.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for (cms, mode), lab in installations.items():
        harness = make_m5_harness(
            asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=40)
        )
        try:
            await harness.prepare([lab.base_url])
            for check_id in WP26_IDS:
                counts[(cms, mode, check_id)] = len(_findings(await _run(harness, check_id)))
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], CmsLab],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all fifteen installations (runtime budget)."""
    return asyncio.run(_measure(installations))


async def _harness(lab: CmsLab, *, prepare: bool = True) -> M5Harness:
    """A prepared harness for one installation."""
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=40))
    if prepare:
        await harness.prepare([lab.base_url])
    return harness


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_four_checks() -> None:
    """REQ-DET-019: at least 24 new checks in this family."""
    assert len(WP26_IDS) >= 24, WP26_IDS
    assert len(set(WP26_IDS)) == len(WP26_IDS)
    for cms in CMS_PREFIXES:
        owned = [check_id for check_id in WP26_IDS if _owner(check_id) == cms]
        assert len(owned) >= 4, (cms, owned)
    registry = ModuleRegistry.discover()
    for check_id in WP26_IDS:
        assert registry.get(check_id) is not None, check_id
    print(
        f"\nregistry total: {len(registry.checks())} checks; "
        f"WP-26 family: {len(WP26_IDS)} across {len(CMS_PREFIXES)} systems"
    )


def test_every_check_reports_its_positive_and_stays_silent_on_every_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The requirement's acceptance core: a planted signal is found, every decoy is silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    cross_system = 0
    for check_id in WP26_IDS:
        owner = _owner(check_id)
        if measured[(owner, POSITIVE, check_id)] < 1:
            misses.append(f"{check_id}: no finding on the {owner} installation")
        for cms in CMS_PREFIXES:
            for mode in (POSITIVE, *DECOYS):
                if (cms, mode) == (owner, POSITIVE):
                    continue
                found = measured[(cms, mode, check_id)]
                if found != 0:
                    false_positives.append(f"{check_id}: {found} finding(s) on {cms}/{mode}")
                    continue
                if mode == POSITIVE:
                    cross_system += 1
    assert not misses, misses
    assert not false_positives, false_positives
    assert cross_system == len(WP26_IDS) * (len(CMS_PREFIXES) - 1)
    print(
        f"\n{len(WP26_IDS)} checks x {len(CMS_PREFIXES) * (1 + len(DECOYS))} installations: "
        f"every positive found, 0 findings on every decoy "
        f"({len(CMS_PREFIXES)} hardened, {len(CMS_PREFIXES)} WAF-fronted, {cross_system} "
        "cross-system)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-019: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP26_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is ProofLevel.L1, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.requires_active_checks is False, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith(("WSTG-", "API")) for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch03#"), check_id
        owner = _owner(check_id)
        assert metadata.name.startswith(f"{owner}-"), check_id
        assert metadata.id == f"m3.{metadata.name}", check_id


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no state-changing verb and no ``method=`` choice."""
    source = (CMS_SOURCE / "cms_family_b.py").read_text(encoding="utf-8")
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
    # The single request shape is the family's own ``_fetch``, and the only verb it may name is
    # the safe GET.
    assert source.count("method=") == 1, "the family declares a request method of its own"
    assert source.count('method="GET"') == 1


def test_no_state_changing_request_reached_any_installation(
    installations: dict[tuple[str, str], CmsLab],
) -> None:
    """The read-only claim on the wire: every request the fixtures answered was safe."""
    offenders: list[str] = []
    for (cms, mode), lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{cms}/{mode}: {request}")
    assert not offenders, offenders


async def test_the_waf_decoy_is_a_real_trap(
    installations: dict[tuple[str, str], CmsLab],
) -> None:
    """The WAF decoy echoes the request path and names the platform, so body matching fires.

    The probe goes through the scanner's own scoped client, so the protocol, host and address
    boundaries the scanner enforces are the ones exercised here — the fixture is reached the
    same way a check reaches it, never with a raw URL opener.
    """
    lab = installations[("drupal", "waf")]
    harness = await _harness(lab, prepare=False)
    try:
        exchange = await safe_fetch(
            harness.context(None), f"{lab.origin}/sites/default/settings.php.bak"
        )
        assert exchange is not None, "the scoped client refused the loopback probe"
        assert exchange.status_code == 403
        assert "/sites/default/settings.php.bak" in exchange.body, (
            "the block page must echo the path"
        )
        assert "Drupal" in exchange.body, "the block page must name the platform"
    finally:
        await harness.aclose()


async def test_the_checks_are_deterministic(
    installations: dict[tuple[str, str], CmsLab],
) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    harness = await _harness(installations[("magento", POSITIVE)])
    try:

        def signature(results: list[Any]) -> list[tuple[str, str]]:
            return sorted((result.status, result.title) for result in results)

        for check_id in WP26_IDS:
            first = signature(await _run(harness, check_id))
            second = signature(await _run(harness, check_id))
            assert first == second, check_id
    finally:
        await harness.aclose()


async def test_a_dry_run_sends_nothing(
    installations: dict[tuple[str, str], CmsLab],
) -> None:
    """F-01-10: with no HTTP client the family yields a skip, never a probe."""
    lab = installations[("moodle", POSITIVE)]
    harness = await _harness(lab)
    try:
        before = len(lab.requests)
        # A dry run has no HTTP client and no crawl (F-01-10): the step context carries
        # neither, which is what the checks step hands a check in dry-run mode.
        dry_step = replace(harness.step, http=None, web=None)
        for check_id in WP26_IDS:
            check = _by_id()[check_id]
            context = CheckContext(
                step=dry_step, module=check(), asset=harness.asset, config=harness.config
            )
            results = [result async for result in check().run(context)]
            assert len(results) == 1 and results[0].status == "info", check_id
        assert len(lab.requests) == before, "a dry run reached the target"
    finally:
        await harness.aclose()


def test_the_lab_serves_every_system_and_no_route_authenticates() -> None:
    """The fixture is the ground truth: five systems, three modes, and no login anywhere."""
    source = LAB_SOURCE.read_text(encoding="utf-8")
    assert len(CMS_PREFIXES) == 5
    for verb in ("do_PUT", "do_DELETE", "do_PATCH"):
        assert verb not in source, f"the fixture implements {verb}"
    # ``do_POST`` exists to refuse every POST with 405 and never routes a request.
    assert re.search(r"def do_POST.*?405", source, re.DOTALL), (
        "do_POST must answer 405 without routing"
    )
