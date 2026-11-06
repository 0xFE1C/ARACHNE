"""WP-27 acceptance: the application-server family meets its lab ground truth (REQ-DET-020).

The requirement's acceptance criteria are the shape of this module:

* **at least 22 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source *and* on the
  wire: every fixture records the requests it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoys are the requirement's own ("each framework ships a production-configured
  decoy", ``tests/lab/app_server_lab.py``), plus a WAF-fronted instance per framework and the
  nine vulnerable installations, which are decoys for one another's checks;
* the registry total is printed for the handoff.

One measurement drives all twenty-five checks against all twenty-seven installations (nine
frameworks, three modes each), reusing one crawl per installation: the family is a bounded
path-probe family, so a crawl per check would add nothing the shared inventory does not already
hold.
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
from tests.lab.app_server_lab import FRAMEWORKS, AppServerLab, start_app_server_lab

from arachne.core.config import WebSettings
from arachne.core.proof import ProofLevel
from arachne.modules.context import CheckContext
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3.support import safe_fetch
from arachne.modules.registry import ModuleRegistry

#: The check-name prefix that names each framework, mapped to the lab's framework key. The
#: payload section and the lab key are the same word (``spring_boot``); the check name is the
#: kebab form (``spring-boot-``), which is why the two are spelled out here.
PREFIX_TO_FRAMEWORK: dict[str, str] = {
    "spring-boot-": "spring_boot",
    "django-": "django",
    "rails-": "rails",
    "laravel-": "laravel",
    "tomcat-": "tomcat",
    "jboss-": "jboss",
    "weblogic-": "weblogic",
    "coldfusion-": "coldfusion",
    "iis-": "iis",
}

#: Every check the WP-27 family registers, in the order the module lists them.
WP27_IDS: tuple[str, ...] = tuple(
    check.metadata.id
    for check in M3_CHECKS
    if any(check.metadata.name.startswith(prefix) for prefix in PREFIX_TO_FRAMEWORK)
)

#: The fixture mode that plants each signal, and the decoys: one production-configured instance
#: per framework and one WAF-fronted instance per framework.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("production", "waf")

#: The module that carries the family (the source-level read-only assertion reads it).
FAMILY_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"

#: The lab module the fixture-shape assertion reads.
LAB_SOURCE = Path(__file__).resolve().parents[1] / "lab" / "app_server_lab.py"

#: The safe request methods the family may send. The family is GET-only.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def _owner(check_id: str) -> str:
    """The framework a family check belongs to.

    ``m3.spring-boot-actuator-index`` → ``spring_boot``: the check name's kebab prefix maps to
    the lab's snake-case framework key through :data:`PREFIX_TO_FRAMEWORK`.
    """
    name = check_id.removeprefix("m3.")
    return next(
        PREFIX_TO_FRAMEWORK[prefix] for prefix in PREFIX_TO_FRAMEWORK if name.startswith(prefix)
    )


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], AppServerLab]]:
    """One running installation per (framework, mode), started once for the module."""
    running: dict[tuple[str, str], AppServerLab] = {}
    stack = []
    try:
        for framework in FRAMEWORKS:
            for mode in (POSITIVE, *DECOYS):
                manager = start_app_server_lab(framework, mode)
                running[(framework, mode)] = manager.__enter__()
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
    installations: dict[tuple[str, str], AppServerLab],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings.

    A harness (and so an HTTP client and a crawl) is created per installation *inside* this
    coroutine and closed here: a client is bound to the loop that built it, so a module-scoped
    fixture cannot hold one.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for (framework, mode), lab in installations.items():
        harness = make_m5_harness(
            asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=25)
        )
        try:
            await harness.prepare([lab.base_url])
            for check_id in WP27_IDS:
                counts[(framework, mode, check_id)] = len(_findings(await _run(harness, check_id)))
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], AppServerLab],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all twenty-seven installations (runtime budget)."""
    return asyncio.run(_measure(installations))


async def _harness(lab: AppServerLab, *, prepare: bool = True) -> M5Harness:
    """A prepared harness for one installation."""
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=25))
    if prepare:
        await harness.prepare([lab.base_url])
    return harness


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_two_checks() -> None:
    """REQ-DET-020: at least 22 new checks in this family."""
    assert len(WP27_IDS) >= 22, WP27_IDS
    assert len(set(WP27_IDS)) == len(WP27_IDS)
    for framework in FRAMEWORKS:
        owned = [check_id for check_id in WP27_IDS if _owner(check_id) == framework]
        assert len(owned) >= 2, (framework, owned)
    registry = ModuleRegistry.discover()
    for check_id in WP27_IDS:
        assert registry.get(check_id) is not None, check_id
    print(
        f"\nregistry total: {len(registry.checks())} checks; "
        f"WP-27 family: {len(WP27_IDS)} across {len(FRAMEWORKS)} frameworks"
    )


def test_every_check_reports_its_positive_and_stays_silent_on_every_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The requirement's acceptance core: a planted signal is found, every decoy is silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    cross_framework = 0
    for check_id in WP27_IDS:
        owner = _owner(check_id)
        if measured[(owner, POSITIVE, check_id)] < 1:
            misses.append(f"{check_id}: no finding on the {owner} installation")
        for framework in FRAMEWORKS:
            for mode in (POSITIVE, *DECOYS):
                if (framework, mode) == (owner, POSITIVE):
                    continue
                found = measured[(framework, mode, check_id)]
                if found != 0:
                    false_positives.append(f"{check_id}: {found} finding(s) on {framework}/{mode}")
                    continue
                if mode == POSITIVE:
                    cross_framework += 1
    assert not misses, misses
    assert not false_positives, false_positives
    assert cross_framework == len(WP27_IDS) * (len(FRAMEWORKS) - 1)
    print(
        f"\n{len(WP27_IDS)} checks x {len(FRAMEWORKS) * (1 + len(DECOYS))} installations: "
        f"every positive found, 0 findings on every decoy "
        f"({len(FRAMEWORKS)} production, {len(FRAMEWORKS)} WAF-fronted, {cross_framework} "
        "cross-framework)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-020: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP27_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is ProofLevel.L1, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.requires_active_checks is False, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith(("WSTG-", "API")) for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch03#"), check_id
        owner = _owner(check_id)
        assert metadata.name.startswith(
            next(prefix for prefix, key in PREFIX_TO_FRAMEWORK.items() if key == owner)
        ), check_id
        assert metadata.id == f"m3.{metadata.name}", check_id


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no state-changing verb and no ``method=`` choice."""
    source = (FAMILY_SOURCE / "app_servers.py").read_text(encoding="utf-8")
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
    installations: dict[tuple[str, str], AppServerLab],
) -> None:
    """The read-only claim on the wire: every request the fixtures answered was safe."""
    offenders: list[str] = []
    for (framework, mode), lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{framework}/{mode}: {request}")
    assert not offenders, offenders


async def test_the_waf_decoy_is_a_real_trap(
    installations: dict[tuple[str, str], AppServerLab],
) -> None:
    """The WAF decoy echoes the request path and names the framework, so body matching fires.

    The probe goes through the scanner's own scoped client, so the protocol, host and address
    boundaries the scanner enforces are the ones exercised here — the fixture is reached the
    same way a check reaches it, never with a raw URL opener.
    """
    lab = installations[("spring_boot", "waf")]
    harness = await _harness(lab, prepare=False)
    try:
        exchange = await safe_fetch(harness.context(None), f"{lab.origin}/actuator/heapdump")
        assert exchange is not None, "the scoped client refused the loopback probe"
        assert exchange.status_code == 403
        assert "/actuator/heapdump" in exchange.body, "the block page must echo the path"
        assert "Spring Boot" in exchange.body, "the block page must name the framework"
    finally:
        await harness.aclose()


async def test_the_checks_are_deterministic(
    installations: dict[tuple[str, str], AppServerLab],
) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    harness = await _harness(installations[("tomcat", POSITIVE)])
    try:

        def signature(results: list[Any]) -> list[tuple[str, str]]:
            return sorted((result.status, result.title) for result in results)

        for check_id in WP27_IDS:
            first = signature(await _run(harness, check_id))
            second = signature(await _run(harness, check_id))
            assert first == second, check_id
    finally:
        await harness.aclose()


async def test_a_dry_run_sends_nothing(
    installations: dict[tuple[str, str], AppServerLab],
) -> None:
    """F-01-10: with no HTTP client the family yields a skip, never a probe."""
    lab = installations[("jboss", POSITIVE)]
    harness = await _harness(lab)
    try:
        before = len(lab.requests)
        # A dry run has no HTTP client and no crawl (F-01-10): the step context carries
        # neither, which is what the checks step hands a check in dry-run mode.
        dry_step = replace(harness.step, http=None, web=None)
        for check_id in WP27_IDS:
            check = _by_id()[check_id]
            context = CheckContext(
                step=dry_step, module=check(), asset=harness.asset, config=harness.config
            )
            results = [result async for result in check().run(context)]
            assert len(results) == 1 and results[0].status == "info", check_id
        assert len(lab.requests) == before, "a dry run reached the target"
    finally:
        await harness.aclose()


def test_the_lab_serves_every_framework_and_no_route_authenticates() -> None:
    """The fixture is the ground truth: nine frameworks, three modes, and no login anywhere."""
    source = LAB_SOURCE.read_text(encoding="utf-8")
    assert len(FRAMEWORKS) == 9
    for verb in ("do_PUT", "do_DELETE", "do_PATCH"):
        assert verb not in source, f"the fixture implements {verb}"
    # ``do_POST`` exists to refuse every POST with 405 and never routes a request.
    assert re.search(r"def do_POST.*?405", source, re.DOTALL), (
        "do_POST must answer 405 without routing"
    )
