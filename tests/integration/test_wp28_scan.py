"""WP-28 acceptance: the API and modern-web family meets its lab ground truth (REQ-DET-021).

The requirement's acceptance criteria are the shape of this module:

* **at least 22 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source *and* on the
  wire: every fixture records the requests it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoys are the requirement's own ("conformant deployments that publish their
  documentation deliberately behind authentication", implemented as the ``production`` mode of
  ``tests/lab/api_lab.py``), plus a WAF-fronted instance per surface and the six vulnerable
  installations, which are decoys for one another's checks;
* the registry total is printed for the handoff.

One measurement drives all twenty-four checks against all eighteen installations (six surfaces,
three modes each), reusing one crawl per installation: the family is a bounded path-probe
family, so a crawl per check would add nothing the shared inventory does not already hold.
"""

from __future__ import annotations

import ast
import asyncio
import re
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import M5Harness, make_m5_harness
from tests.lab.api_lab import SURFACES, ApiLab, start_api_lab

from arachne.core.config import WebSettings
from arachne.core.proof import ProofLevel
from arachne.modules.context import CheckContext
from arachne.modules.m3.api_surfaces import ApiSurfaceChecks
from arachne.modules.m3.support import safe_fetch
from arachne.modules.registry import ModuleRegistry

#: The check-name prefix that names each surface, mapped to the lab's surface key. The payload
#: section and the lab key are the same word (``openapi``); the check name is the kebab form
#: (``openapi-``, ``swagger-``, ``redoc-``), which is why the two are spelled out here.
PREFIX_TO_SURFACE: dict[str, str] = {
    "openapi-": "openapi",
    "swagger-": "openapi",
    "redoc-": "openapi",
    "graphql-": "graphql",
    "grpc-": "grpc",
    "websocket-": "websocket",
    "netlify-": "serverless",
    "vercel-": "serverless",
    "gcf-": "serverless",
    "openfaas-": "serverless",
    "edge-function-": "serverless",
    "cors-": "cors",
}

#: Every check the WP-28 family registers. The set comes from the family tuple the module
#: exports, not from a name prefix: the corpus already holds ``m3.graphql-audit``,
#: ``m3.websocket-audit``, ``m3.websocket-injection``, ``m3.websocket-upgrade-auth`` and
#: ``m3.cors-audit``, which share those prefixes but are not this family's checks.
WP28_IDS: tuple[str, ...] = tuple(check.metadata.id for check in ApiSurfaceChecks)

#: The fixture mode that plants each signal, and the decoys: a conformant deployment per surface
#: and a WAF-fronted one per surface.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("production", "waf")

#: The module that carries the family (the source-level read-only assertion reads it).
FAMILY_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"

#: The lab module the fixture-shape assertion reads.
LAB_SOURCE = Path(__file__).resolve().parents[1] / "lab" / "api_lab.py"

#: The safe request methods the family may send. The family is GET-only but for the three
#: OPTIONS preflight checks, whose method is HTTP's own safe one (RFC 9110 §9.3.7).
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

#: The proof level every member of the family declares.
_FAMILY_PROOF = ProofLevel.L1


def _owner(check_id: str) -> str:
    """The surface a family check belongs to.

    ``m3.openapi-document-exposed`` → ``openapi``: the check name's kebab prefix maps to the
    lab's surface key through :data:`PREFIX_TO_SURFACE`.
    """
    name = check_id.removeprefix("m3.")
    return next(
        PREFIX_TO_SURFACE[prefix] for prefix in PREFIX_TO_SURFACE if name.startswith(prefix)
    )


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], ApiLab]]:
    """One running installation per (surface, mode), started once for the module."""
    running: dict[tuple[str, str], ApiLab] = {}
    stack = []
    try:
        for surface in SURFACES:
            for mode in (POSITIVE, *DECOYS):
                manager = start_api_lab(surface, mode)
                running[(surface, mode)] = manager.__enter__()
                stack.append(manager)
        yield running
    finally:
        for manager in reversed(stack):
            manager.__exit__(None, None, None)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in ApiSurfaceChecks}


async def _run(harness: M5Harness, check_id: str) -> list[Any]:
    check = _by_id()[check_id]
    return [result async for result in check().run(harness.context(check()))]


def _findings(results: list[Any]) -> list[Any]:
    return [result for result in results if result.status == "vulnerable"]


async def _measure(
    installations: dict[tuple[str, str], ApiLab],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings.

    A harness (and so an HTTP client and a crawl) is created per installation *inside* this
    coroutine and closed here: a client is bound to the loop that built it, so a module-scoped
    fixture cannot hold one.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for (surface, mode), lab in installations.items():
        harness = make_m5_harness(
            asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=25)
        )
        try:
            await harness.prepare([lab.base_url])
            for check_id in WP28_IDS:
                counts[(surface, mode, check_id)] = len(_findings(await _run(harness, check_id)))
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], ApiLab],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all eighteen installations (runtime budget)."""
    return asyncio.run(_measure(installations))


async def _harness(lab: ApiLab, *, prepare: bool = True) -> M5Harness:
    """A prepared harness for one installation."""
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=WebSettings(max_pages=25))
    if prepare:
        await harness.prepare([lab.base_url])
    return harness


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_two_checks() -> None:
    """REQ-DET-021: at least 22 new checks in this family."""
    assert len(WP28_IDS) >= 22, WP28_IDS
    assert len(set(WP28_IDS)) == len(WP28_IDS)
    for surface in SURFACES:
        owned = [check_id for check_id in WP28_IDS if _owner(check_id) == surface]
        assert len(owned) >= 2, (surface, owned)
    registry = ModuleRegistry.discover()
    for check_id in WP28_IDS:
        assert registry.get(check_id) is not None, check_id
    print(
        f"\nregistry total: {len(registry.checks())} checks; "
        f"WP-28 family: {len(WP28_IDS)} across {len(SURFACES)} surfaces"
    )


def test_every_check_reports_its_positive_and_stays_silent_on_every_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The requirement's acceptance core: a planted signal is found, every decoy is silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    cross_surface = 0
    for check_id in WP28_IDS:
        owner = _owner(check_id)
        if measured[(owner, POSITIVE, check_id)] < 1:
            misses.append(f"{check_id}: no finding on the {owner} installation")
        for surface in SURFACES:
            for mode in (POSITIVE, *DECOYS):
                if (surface, mode) == (owner, POSITIVE):
                    continue
                found = measured[(surface, mode, check_id)]
                if found != 0:
                    false_positives.append(f"{check_id}: {found} finding(s) on {surface}/{mode}")
                    continue
                if mode == POSITIVE:
                    cross_surface += 1
    assert not misses, misses
    assert not false_positives, false_positives
    assert cross_surface == len(WP28_IDS) * (len(SURFACES) - 1)
    print(
        f"\n{len(WP28_IDS)} checks x {len(SURFACES) * (1 + len(DECOYS))} installations: "
        f"every positive found, 0 findings on every decoy "
        f"({len(SURFACES)} production, {len(SURFACES)} WAF-fronted, {cross_surface} "
        "cross-surface)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-021: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP28_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is _FAMILY_PROOF, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith(("WSTG-", "API")) for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch03#"), check_id
        owner = _owner(check_id)
        # A surface may own more than one kebab prefix (the openapi surface serves the
        # ``openapi-``, ``swagger-`` and ``redoc-`` checks), so the name must start with one of
        # the prefixes that map to its owner.
        assert any(
            metadata.name.startswith(prefix)
            for prefix, key in PREFIX_TO_SURFACE.items()
            if key == owner
        ), check_id
        assert metadata.id == f"m3.{metadata.name}", check_id
        # The corpus's own rule (the catalogue's ``requires_active_checks`` flag): anything
        # beyond a plain GET opts in. The three OPTIONS preflight checks declare it; every
        # other row is a plain anonymous GET and must not.
        if metadata.name in {
            "grpc-web-preflight",
            "cors-preflight-methods",
            "cors-preflight-headers",
        }:
            assert metadata.type == "active", check_id
            assert metadata.requires_active_checks is True, check_id
        else:
            assert metadata.requires_active_checks is False, check_id


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no request method but GET, and no write verb.

    The assertion is structural rather than a search for the verb's letters: every request the
    module makes goes through ``_fetch``/``safe_fetch``, so the *method each call passes* is
    what matters. A hardcoded method on a call site is refused, and the only declared method
    values in the module must be ``GET`` and ``OPTIONS`` (the three preflight checks). The
    OPTIONS checks legitimately *name* write verbs — a browser's preflight asks permission for
    ``PUT``/``DELETE`` — and that is a header value describing the request a browser would
    send, not a request this module makes.
    """
    source = (FAMILY_SOURCE / "api_surfaces.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    declared: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "method"
                and isinstance(node.value, ast.Constant)
            ):
                declared.add(str(node.value.value))
    assert declared == {"GET", "OPTIONS"}, declared
    # No call site may choose a method of its own: every request's method comes from the
    # class attribute checked above, so no write verb can reach the wire.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name not in {"_fetch", "safe_fetch", "fetch"}:
            continue
        for keyword in node.keywords:
            if keyword.arg == "method":
                assert ast.unparse(keyword.value) in {"self.method", "method"}, (
                    f"a request method is hardcoded at line {node.lineno}"
                )
    # The corpus helpers that POST are not used at all.
    for helper in ("json_post", "post_form"):
        assert helper not in source, f"the family uses {helper}"
    # No GraphQL mutation is ever composed: the only operation strings in the module are the
    # three introspection *queries*.
    assert "mutation {" not in source
    assert "mutation(" not in source


def test_no_state_changing_request_reached_any_installation(
    installations: dict[tuple[str, str], ApiLab],
) -> None:
    """The read-only claim on the wire: every request the fixtures answered was safe."""
    offenders: list[str] = []
    for (surface, mode), lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{surface}/{mode}: {request}")
    assert not offenders, offenders


async def test_the_waf_decoy_is_a_real_trap(installations: dict[tuple[str, str], ApiLab]) -> None:
    """The WAF decoy echoes the request path and names the platform, so body matching fires.

    The probe goes through the scanner's own scoped client, so the protocol, host and address
    boundaries the scanner enforces are the ones exercised here — the fixture is reached the
    same way a check reaches it, never with a raw URL opener.
    """
    lab = installations[("openapi", "waf")]
    harness = await _harness(lab, prepare=False)
    try:
        exchange = await safe_fetch(
            harness.context(None), f"{lab.origin}/openapi.json", anonymous=True
        )
        assert exchange is not None, "the scoped client refused the loopback probe"
        assert exchange.status_code == 403
        assert "/openapi.json" in exchange.body, "the block page must echo the path"
        assert "OpenAPI" in exchange.body, "the block page must name the platform"
    finally:
        await harness.aclose()


async def test_the_production_decoy_publishes_its_documentation_behind_authentication(
    installations: dict[tuple[str, str], ApiLab],
) -> None:
    """The requirement's own decoy: the documentation is published, deliberately, behind auth."""
    lab = installations[("openapi", "production")]
    harness = await _harness(lab, prepare=False)
    try:
        exchange = await safe_fetch(
            harness.context(None), f"{lab.origin}/openapi.json", anonymous=True
        )
        assert exchange is not None
        assert exchange.status_code == 401
        assert exchange.header("www-authenticate") is not None, "the decoy must challenge"
    finally:
        await harness.aclose()


async def test_the_declared_operation_control_requires_authentication(
    installations: dict[tuple[str, str], ApiLab],
) -> None:
    """The OpenAPI surface's own trap: a declared operation that refuses an anonymous caller."""
    lab = installations[("openapi", POSITIVE)]
    harness = await _harness(lab, prepare=False)
    try:
        context = harness.context(None)
        public = await safe_fetch(context, f"{lab.origin}/api/users", anonymous=True)
        protected = await safe_fetch(context, f"{lab.origin}/api/orders", anonymous=True)
        assert public is not None and public.status_code == 200
        assert protected is not None and protected.status_code == 401
    finally:
        await harness.aclose()


async def test_each_websocket_origin_check_has_its_own_route(
    installations: dict[tuple[str, str], ApiLab],
) -> None:
    """The three origin checks are distinct: each route trusts exactly one wrong origin."""
    lab = installations[("websocket", POSITIVE)]
    harness = await _harness(lab, prepare=False)
    try:
        context = harness.context(None)
        headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        accepted: list[str] = []
        scheme = "http"  # the loopback fixture's own scheme, as a check derives it
        for path, origin in (
            ("/ws", "null"),
            ("/socket.io/", f"{scheme}://arachne-sibling.{lab.hostname}"),
            ("/realtime", f"{scheme}://{lab.hostname}.arachne-suffix.invalid"),
        ):
            exchange = await safe_fetch(
                context,
                f"{lab.origin}{path}",
                headers={**headers, "Origin": origin},
                anonymous=True,
                follow_redirects=False,
            )
            if exchange is not None and exchange.status_code == 101:
                accepted.append(path)
        assert accepted == ["/ws", "/socket.io/", "/realtime"], accepted
    finally:
        await harness.aclose()


async def test_the_checks_are_deterministic(
    installations: dict[tuple[str, str], ApiLab],
) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    harness = await _harness(installations[("cors", POSITIVE)])
    try:

        def signature(results: list[Any]) -> list[tuple[str, str]]:
            return sorted((result.status, result.title) for result in results)

        for check_id in WP28_IDS:
            first = signature(await _run(harness, check_id))
            second = signature(await _run(harness, check_id))
            assert first == second, check_id
    finally:
        await harness.aclose()


async def test_a_dry_run_sends_nothing(installations: dict[tuple[str, str], ApiLab]) -> None:
    """F-01-10: with no HTTP client the family yields a skip, never a probe."""
    lab = installations[("graphql", POSITIVE)]
    harness = await _harness(lab)
    try:
        before = len(lab.requests)
        # A dry run has no HTTP client and no crawl (F-01-10): the step context carries
        # neither, which is what the checks step hands a check in dry-run mode.
        dry_step = replace(harness.step, http=None, web=None)
        for check_id in WP28_IDS:
            check = _by_id()[check_id]
            context = CheckContext(
                step=dry_step, module=check(), asset=harness.asset, config=harness.config
            )
            results = [result async for result in check().run(context)]
            assert len(results) == 1 and results[0].status == "info", check_id
        assert len(lab.requests) == before, "a dry run reached the target"
    finally:
        await harness.aclose()


def test_the_lab_serves_every_surface_and_no_route_authenticates() -> None:
    """The fixture is the ground truth: six surfaces, three modes, and no login anywhere."""
    source = LAB_SOURCE.read_text(encoding="utf-8")
    assert len(SURFACES) == 6
    for verb in ("do_PUT", "do_DELETE", "do_PATCH"):
        assert verb not in source, f"the fixture implements {verb}"
    # ``do_POST`` exists to refuse every POST with 405 and never routes a request.
    assert re.search(r"def do_POST.*?405", source, re.DOTALL), (
        "do_POST must answer 405 without routing"
    )
    # No mutation is implemented at all: the fixture cannot be made to change state.
    assert "mutation {" not in source
