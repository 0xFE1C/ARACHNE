"""WP-30 acceptance: the server/platform family meets its lab ground truth (REQ-DET-023).

The requirement's acceptance criteria are the shape of this module:

* **at least 22 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source, where the
  module may declare no verb but ``GET``, and on the wire, where every fixture records the
  requests it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoy is the requirement's own ("one hardened server per family", implemented as
  the ``hardened`` mode of ``tests/lab/server_lab.py``, where every management path answers
  ``401`` with a challenge), plus the broken-backend mode and the nine vulnerable
  installations, which are decoys for one another's checks;
* **a container daemon is asked for its version and nothing else** — the pitfall makes a
  command through the socket permanently out of scope, so the fixture's own request log is
  asserted to contain no path beyond the version endpoints;
* the registry total is printed for the handoff.

One measurement drives all twenty-four checks against all twenty-seven installations (nine
areas, three modes each), reusing one crawl per installation: the family is a bounded
path-probe family, so a crawl per check would add nothing the shared inventory does not
already hold. The ``echo-404`` trap gets its own focused test over all nine areas, because it
is about a single mechanism.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
from tests.helpers.m4 import M4Harness, make_m4_harness
from tests.lab.server_lab import AREAS, PATHS_BY_AREA, ServerLab, start_server_lab

from arachne.core.proof import ProofLevel
from arachne.modules.m4.servers import (
    AREA_OF_CHECK,
    GROUPS_BY_AREA,
    HEADER_CHECK_NAMES,
    ServerChecks,
)
from arachne.modules.m4.servers import AREAS as MODULE_AREAS

#: Every check the WP-30 family registers, from the family tuple the module exports.
WP30_IDS: tuple[str, ...] = tuple(check.metadata.id for check in ServerChecks)

#: Every check's name → the scope area it covers, from the module's own declaration.
NAME_OF_ID: dict[str, str] = {check.metadata.id: check.metadata.name for check in ServerChecks}

#: The fixture mode that plants each area's signals, and the decoy modes the matrix runs.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("hardened", "error-page")

#: The proof level every member of the family declares.
_FAMILY_PROOF = ProofLevel.L1

#: The module that carries the family (the source-level read-only assertion reads it).
FAMILY_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m4"

#: The safe request methods the family may send. The family is GET-only.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

#: The helpers that would let a request carry a body or choose its own verb.
UNSAFE_HELPERS: frozenset[str] = frozenset({"json_post", "post_form", "request_raw"})

#: The version endpoints the container-runtime checks may ask for — the *only* paths this
#: family is permitted to send to a container daemon (the pitfall: a read-only version query
#: is the finding; a command through the socket is permanently out of scope).
CONTAINER_VERSION_PATHS: tuple[str, ...] = (
    "/version",
    "/v1.24/version",
    "/v1.41/version",
    "/v1.43/version",
    "/v1.44/version",
    "/v1.45/version",
    "/libpod/version",
    "/v1.40.0/libpod/version",
    "/v1.41.0/libpod/version",
    "/v4.4.0/libpod/version",
    "/v4.9.0/libpod/version",
)


def _owner(check_id: str) -> str:
    """The area a family check belongs to, read from the module's own declaration."""
    return AREA_OF_CHECK[NAME_OF_ID[check_id]]


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], ServerLab]]:
    """One running installation per (area, mode), started once for the module."""
    running: dict[tuple[str, str], ServerLab] = {}
    stack = []
    try:
        for area in AREAS:
            for mode in (POSITIVE, *DECOYS):
                manager = start_server_lab(area, mode)
                running[(area, mode)] = manager.__enter__()
                stack.append(manager)
        yield running
    finally:
        for manager in reversed(stack):
            manager.__exit__(None, None, None)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in ServerChecks}


async def _run(harness: M4Harness, check_id: str) -> list[Any]:
    check = _by_id()[check_id]
    return [result async for result in check().run(harness.context(check()))]


def _findings(results: list[Any]) -> list[Any]:
    return [result for result in results if result.status == "vulnerable"]


def _artifact(result: Any) -> dict[str, Any]:
    for item in result.evidence:
        if item.kind == "artifact":
            return dict(item.payload)
    return {}


async def _harness(lab: ServerLab, *, prepare: bool = True) -> M4Harness:
    harness = make_m4_harness(lab)
    if prepare:
        await harness.prepare()
    return harness


async def _measure(
    installations: dict[tuple[str, str], ServerLab],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings."""
    counts: dict[tuple[str, str, str], int] = {}
    for (area, mode), lab in installations.items():
        harness = await _harness(lab)
        try:
            for check_id in WP30_IDS:
                counts[(area, mode, check_id)] = len(_findings(await _run(harness, check_id)))
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], ServerLab],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all twenty-seven installations."""
    return asyncio.run(_measure(installations))


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_two_checks(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """REQ-DET-023: at least 22 new checks in this family."""
    assert len(WP30_IDS) >= 22, WP30_IDS
    assert len(set(WP30_IDS)) == len(WP30_IDS)
    assert set(GROUPS_BY_AREA) == set(AREAS) == set(MODULE_AREAS), sorted(GROUPS_BY_AREA)
    assert set(AREA_OF_CHECK) == set(NAME_OF_ID.values()), sorted(AREA_OF_CHECK)
    # Every area the requirement's scope names owns at least one check, and every check
    # belongs to exactly one area.
    for area in AREAS:
        owned = [check_id for check_id in WP30_IDS if _owner(check_id) == area]
        assert owned, area
    decoy_cells = len(WP30_IDS) * (len(AREAS) * (1 + len(DECOYS)) - 1)
    print(
        f"\nregistry total: {_registry_total()} checks; "
        f"WP-30 family: {len(WP30_IDS)} across {len(AREAS)} areas; "
        f"decoy-clean cells: {decoy_cells}"
    )


def _registry_total() -> int:
    from arachne.modules.registry import ModuleRegistry

    return len(ModuleRegistry.discover().checks())


def test_every_check_reports_its_positive_and_stays_silent_on_every_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The acceptance core: a planted signal is found, every decoy is silent."""
    misses: list[str] = []
    false_positives: list[str] = []
    cross_area = 0
    for check_id in WP30_IDS:
        owner = _owner(check_id)
        if measured[(owner, POSITIVE, check_id)] < 1:
            misses.append(f"{check_id}: no finding on the {owner} installation")
        for area in AREAS:
            for mode in (POSITIVE, *DECOYS):
                if (area, mode) == (owner, POSITIVE):
                    continue
                found = measured[(area, mode, check_id)]
                if found != 0:
                    false_positives.append(f"{check_id}: {found} finding(s) on {area}/{mode}")
                    continue
                if mode == POSITIVE:
                    cross_area += 1
    assert not misses, misses
    assert not false_positives, false_positives
    assert cross_area == len(WP30_IDS) * (len(AREAS) - 1)
    decoy_cells = len(WP30_IDS) * (len(AREAS) * (1 + len(DECOYS)) - 1)
    print(
        f"\n{len(WP30_IDS)} checks x {len(AREAS) * (1 + len(DECOYS))} installations: "
        f"every positive found, 0 findings on every decoy ({decoy_cells} decoy-clean cells: "
        f"{len(AREAS)} hardened, {len(AREAS)} error-page, "
        f"{cross_area} cross-area)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-023: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP30_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is _FAMILY_PROOF, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith("WSTG-") for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch04#"), check_id
        assert metadata.requires_active_checks is False, check_id
        assert metadata.type == "hybrid", check_id
        assert metadata.id == f"m4.{metadata.name}", check_id
        assert metadata.module == "M4", check_id


def test_the_family_module_constructs_only_safe_requests() -> None:
    """The read-only claim at the source: no verb but GET, and no request body.

    Every request the module makes goes through ``probe_paths`` (which defaults to ``GET``),
    so what matters is that nothing in the module *chooses* a method or hands a body to a
    request helper.
    """
    source = (FAMILY_SOURCE / "servers.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    declared: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if (
                isinstance(target, ast.Name)
                and target.id in {"method", "verb"}
                and isinstance(node.value, ast.Constant)
            ):
                declared.add(str(node.value.value))
    assert declared == set(), f"the family declares a request method: {declared}"
    calls = {
        func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for func in (node.func,)
    }
    assert not (calls & UNSAFE_HELPERS), sorted(calls & UNSAFE_HELPERS)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name not in {"probe_paths", "fetch_page", "safe_fetch"}:
            continue
        assert not [keyword for keyword in node.keywords if keyword.arg == "method"], (
            f"a request method is chosen at line {node.lineno}"
        )
        assert not [keyword for keyword in node.keywords if keyword.arg == "content"], (
            f"a request body is sent at line {node.lineno}"
        )
    assert "POST" not in source


def test_no_state_changing_request_reached_any_installation(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """The read-only claim on the wire: every request the fixtures answered was safe."""
    offenders: list[str] = []
    for (area, mode), lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{area}/{mode}: {request}")
    assert not offenders, offenders


def test_the_container_runtime_checks_ask_only_for_a_version(
    measured: dict[tuple[str, str, str], int],
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """The pitfall, made structural: a daemon is asked its version and nothing else.

    A container daemon socket that answers a read-only version query is the finding; issuing
    any command through it is not permitted at L1 and is out of scope permanently. So the
    fixture's own request log for the container-runtime installation must contain no path
    beyond the version endpoints the corpus names — no container list, no inspect, no exec,
    no images, no secrets. ``measured`` is a parameter on purpose: it guarantees the matrix has
    driven every check before this log is read.
    """
    del measured
    lab = installations[("container-runtime", POSITIVE)]
    # What could a reader actually reach on this daemon? Every path it answered with a 2xx.
    successful: set[str] = set()
    for entry in lab.requests:
        request, _, status = entry.rpartition(" ")
        if not status.startswith("2") or " " not in request:
            continue
        successful.add(unquote(request.split(" ", 1)[1].split("?", 1)[0]))
    # The site root is the installation's own front page; every other readable path must be a
    # version endpoint. The family's own path inventory is asserted to name nothing else by
    # ``test_the_family_names_no_path_a_container_daemon_answers_beyond_a_version``, and every
    # request was a GET (the wire test above), so no command can have been issued.
    unexpected = sorted(successful - set(CONTAINER_VERSION_PATHS) - {"/"})
    assert not unexpected, unexpected
    # The two version documents were actually read, so the assertion above is not vacuous.
    assert {"/version", "/libpod/version"} <= successful, sorted(successful)


def test_the_hardened_installation_answers_a_challenge(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """The requirement's decoy is a *hardened* server: the path exists, a challenge answers.

    This is the pitfall's second half — "a default page is not always a finding" — so the
    decoy is asserted to be a challenge rather than an absence: the hardened nginx
    installation answers ``401`` with ``WWW-Authenticate`` for its status path, and none of the
    family's findings on it exists (the matrix asserts the second half).
    """
    lab = installations[("nginx", "hardened")]
    probe = "/nginx_status"

    async def measure() -> tuple[int, str, int]:
        harness = await _harness(lab, prepare=False)
        try:
            from arachne.modules.m3.support import safe_fetch

            exchange = await safe_fetch(
                harness.context(None), f"{lab.origin}{probe}", anonymous=True
            )
            assert exchange is not None
            findings = 0
            for check_id in WP30_IDS:
                findings += len(_findings(await _run(harness, check_id)))
            challenge = exchange.response_headers.get("www-authenticate", "")
            return exchange.status_code, challenge, findings
        finally:
            await harness.aclose()

    status, challenge, findings = asyncio.run(measure())
    assert status == 401, status
    assert "basic" in challenge.lower(), challenge
    assert findings == 0, findings


def test_the_echo_404_trap_is_silent() -> None:
    """The pitfall's own decoy: a 200 that echoes the requested path is not an exposure.

    Every area's every path answers ``200 OK`` with a short body that quotes the path it was
    asked for. The body is deliberately too short to look like the not-found reference, so the
    family's not-found comparison cannot be what keeps the checks silent: what does is that no
    marker is a substring of the path it probes.
    """
    failures: list[str] = []
    for area in AREAS:
        with start_server_lab(area, "echo-404") as lab:
            failures.extend(asyncio.run(_trap(area, lab)))
    assert not failures, failures


async def _trap(area: str, lab: ServerLab) -> list[str]:
    harness = await _harness(lab)
    try:
        from arachne.modules.m3.support import safe_fetch

        # A path the area actually publishes where there is one (so the trap is driven with a
        # path a check really probes), otherwise a path another area's checks probe.
        probe = next((item for item in PATHS_BY_AREA[area] if item != "/"), "/version")
        exchange = await safe_fetch(harness.context(None), f"{lab.origin}{probe}", anonymous=True)
        assert exchange is not None
        assert exchange.status_code == 200, (area, exchange.status_code)
        assert probe in exchange.body, (area, "the trap must echo the requested path")
        failures: list[str] = []
        for check_id in WP30_IDS:
            findings = _findings(await _run(harness, check_id))
            failures.extend(
                f"{area}: {check_id} -> {_artifact(result).get('path')}" for result in findings
            )
        return failures
    finally:
        await harness.aclose()


def test_a_session_response_without_a_cache_directive_is_silent(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """The false-positive lesson the shared lab taught this family.

    The first draft of ``m4.cacheable-session-response`` reported *any* session-bearing
    response that omitted ``Cache-Control`` — which the shared M4 lab
    (``tests/integration/test_m4_scan.py``) measured at a 42 % false-positive rate, because
    "no header at all" is the common case on a dynamic page. The check now requires positive
    evidence that a shared cache may store the response (a public/max-age/s-maxage directive,
    or an Expires date) with no privatising directive beside it. This test pins all four
    branches, so a future widening fails here before it fails on the lab.
    """
    from arachne.core.http import CookieInfo
    from arachne.modules.m3.inventory import Page

    lab = installations[("header-defaults", "hardened")]

    async def measure() -> dict[str, int]:
        harness = await _harness(lab, prepare=False)
        try:
            check = _by_id()["m4.cacheable-session-response"]()
            counts: dict[str, int] = {}
            cases = {
                "no-directive": {},
                "explicit-public": {"Cache-Control": "public, max-age=600"},
                "explicit-no-store": {"Cache-Control": "no-store"},
                "expires": {"Expires": "Wed, 01 Jan 2026 00:00:00 GMT"},
            }
            for name, headers in cases.items():
                inventory = harness.inventory
                inventory.pages.clear()
                inventory.order.clear()
                inventory.add_page(
                    Page(
                        url=lab.base_url,
                        status=200,
                        headers={"Content-Type": "text/html", **headers},
                        body="<html><body>session page</body></html>",
                        content_type="text/html",
                        elapsed_ms=1.0,
                        cookies=(CookieInfo(name="PHPSESSID"),),
                    )
                )
                harness.step.web = inventory
                counts[name] = len(_findings([r async for r in check.run(harness.context(check))]))
            return counts
        finally:
            await harness.aclose()

    counts = asyncio.run(measure())
    assert counts["no-directive"] == 0, counts
    assert counts["explicit-public"] == 1, counts
    assert counts["expires"] == 1, counts
    assert counts["explicit-no-store"] == 0, counts


def test_the_checks_are_deterministic(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    lab = installations[("apache", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab)
        try:

            def signature(results: list[Any]) -> list[tuple[str, str]]:
                return sorted((result.status, result.title) for result in results)

            for check_id in WP30_IDS:
                first = signature(await _run(harness, check_id))
                second = signature(await _run(harness, check_id))
                assert first == second, check_id
        finally:
            await harness.aclose()

    asyncio.run(measure())


def test_a_dry_run_sends_nothing(installations: dict[tuple[str, str], ServerLab]) -> None:
    """F-01-10: no client, no request, and every check says so rather than pretending."""
    lab = installations[("nginx", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab, prepare=False)
        harness.step.http = None
        try:
            for check_id in WP30_IDS:
                results = await _run(harness, check_id)
                assert results, check_id
                assert all(
                    any(dict(item.payload).get("skipped") for item in result.evidence)
                    for result in results
                ), check_id
        finally:
            await harness.aclose()

    asyncio.run(measure())


def test_every_reported_path_is_one_the_fixture_publishes(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """A finding's path is a published artefact path, not the fixture's refusal page."""
    lab = installations[("container-runtime", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab)
        try:
            reported: set[str] = set()
            for check_id in WP30_IDS:
                for result in _findings(await _run(harness, check_id)):
                    reported.add(str(_artifact(result)["path"]).rstrip("/"))
            assert reported, "the container-runtime installation plants two daemons"
            assert reported <= set(PATHS_BY_AREA["container-runtime"]), sorted(reported)
        finally:
            await harness.aclose()

    asyncio.run(measure())


def test_the_banner_checks_claim_no_vulnerability(
    installations: dict[tuple[str, str], ServerLab],
) -> None:
    """FP-3: a version/banner match is a signal, never a severity claim on its own."""
    lab = installations[("header-defaults", POSITIVE)]

    async def measure() -> dict[str, dict[str, Any]]:
        harness = await _harness(lab)
        try:
            seen: dict[str, dict[str, Any]] = {}
            for check_id in ("m4.server-version-disclosure", "m4.stack-header-disclosure"):
                findings = _findings(await _run(harness, check_id))
                assert findings, check_id
                payload = _artifact(findings[0])
                seen[check_id] = payload
            return seen
        finally:
            await harness.aclose()

    payloads = asyncio.run(measure())
    by_id = _by_id()
    for check_id, payload in payloads.items():
        assert payload["version_claim"] is False, check_id
        assert by_id[check_id].metadata.severity_hint == "low", check_id
    assert payloads["m4.server-version-disclosure"]["product_version"].startswith("nginx/")
    assert payloads["m4.stack-header-disclosure"]["header"] in {
        "x-powered-by",
        "x-aspnet-version",
    }


def test_the_family_source_is_the_only_place_the_checks_are_declared() -> None:
    """One definition of the family: the module's tuple is the registry's set."""
    from arachne.modules.registry import ModuleRegistry

    registry = ModuleRegistry.discover()
    for check_id in WP30_IDS:
        assert registry.get(check_id) is not None, check_id
    assert len(WP30_IDS) == len(set(WP30_IDS))


def test_every_corpus_group_covers_its_check() -> None:
    """One group per probe check, every probe carrying the marker that proves it."""
    from arachne.modules.m4.corpus import load_corpus

    corpus = load_corpus()
    groups = [group for groups in GROUPS_BY_AREA.values() for group in groups]
    assert len(groups) == len(WP30_IDS) - len(HEADER_CHECK_NAMES)
    for group in groups:
        probes = corpus.server_probes(group)
        assert probes, group
        assert all(probe.path.startswith("/") for probe in probes), group
        # Every probe is confirmable without decoding a body: it carries its own content
        # marker. (No group in this family is decided by a suffix or by the redactor.)
        assert all(probe.markers for probe in probes), group
    # An unknown group degrades to "no probes" rather than raising, so an operator corpus
    # without the section still runs every other M4 check.
    assert corpus.server_probes("no-such-group") == ()
    assert corpus.server_min_bytes() > 0
    assert corpus.server_version_regex() is not None


def test_no_marker_is_derived_from_the_probed_path() -> None:
    """A marker may not be a substring of its own path: that is the echo-404 false positive.

    The pitfall warns that a refusal page which echoes the requested path is not an exposure.
    A marker that appears in the path it probes matches that echo, which is exactly how a soft
    404 becomes a finding. ``test_the_echo_404_trap_is_silent`` measures the trap; this test
    makes the rule structural, so the next batch cannot reintroduce one.
    """
    from arachne.modules.m4.corpus import load_corpus

    corpus = load_corpus()
    offenders: list[str] = []
    for groups in GROUPS_BY_AREA.values():
        for group in groups:
            for probe in corpus.server_probes(group):
                lowered = probe.path.lower()
                for marker in probe.markers:
                    if marker.lower() in lowered:
                        offenders.append(f"{group}: {probe.path} marker {marker!r} is in the path")
    assert not offenders, offenders


def test_every_probe_path_reaches_the_server_unchanged() -> None:
    """A probe path must be the path the server is asked for, whatever a URL does to it.

    ``#`` is a *fragment* delimiter and a dot-segment or a doubled slash is folded away by a
    URL parser, so a corpus path that does not survive the round trip asks the server for
    something else — and a marker match on whatever came back would be a false positive. The
    comparison is on the *decoded* path, which is the path the server sees.
    """
    import httpx

    from arachne.modules.m4.corpus import load_corpus
    from arachne.modules.m4.support import path_url

    corpus = load_corpus()
    offenders: list[str] = []
    for groups in GROUPS_BY_AREA.values():
        for group in groups:
            for probe in corpus.server_probes(group):
                parsed = httpx.URL(path_url("https://example.invalid", probe.path))
                raw_path, _, query = probe.path.partition("?")
                if parsed.fragment:
                    offenders.append(f"{group}: {probe.path} is sent as a URL fragment")
                elif unquote(parsed.path).rstrip("/") != unquote(raw_path).rstrip("/"):
                    offenders.append(f"{group}: {probe.path} is sent as {unquote(parsed.path)}")
                elif unquote(parsed.query) != unquote(query):
                    offenders.append(f"{group}: {probe.path} is sent as ?{unquote(parsed.query)}")
    assert not offenders, offenders


def test_the_family_names_no_path_a_container_daemon_answers_beyond_a_version() -> None:
    """The scope boundary is in the data, not only in the prose.

    The corpus's container-runtime groups are the version endpoints and nothing else: a future
    edit that added ``/containers/json`` or ``/images/json`` would fail here before it could
    ship a command against somebody's daemon.
    """
    from arachne.modules.m4.corpus import load_corpus

    corpus = load_corpus()
    for group in ("docker_api_exposed", "podman_api_exposed"):
        for probe in corpus.server_probes(group):
            assert probe.path in CONTAINER_VERSION_PATHS, probe.path
            assert "version" in probe.path, probe.path
