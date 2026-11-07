"""WP-29 acceptance: the infrastructure-artifact family meets its lab ground truth (REQ-DET-022).

The requirement's acceptance criteria are the shape of this module:

* **at least 24 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes target state (checked at the source, where the
  module may declare no verb but ``GET``, and on the wire, where every fixture records the
  requests it answered);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on a
  decoy — the decoys are the requirement's own ("servers that answer every artifact path with
  a generic 404 or an error page that echoes nothing", implemented as the ``not-found`` and
  ``error-page`` modes of ``tests/lab/artifact_lab.py``), plus the eight vulnerable
  installations, which are decoys for one another's checks;
* **no check downloads a file larger than the client's body limit** to confirm it — every
  finding records the bytes it captured and the limit it read under, and the family module
  may not call the raw-bytes entry point that bypasses the cap;
* evidence for a **secret-bearing artifact is redacted at capture** — the fixture's planted
  values appear in no evidence payload, and the redactor's detector names are what the
  finding carries instead;
* the registry total is printed for the handoff.

One measurement drives all twenty-four checks against all twenty-four installations (eight
areas, three modes each), reusing one crawl per installation: the family is a bounded
path-probe family, so a crawl per check would add nothing the shared inventory does not
already hold. The ``echo-404`` trap and the oversized artifact get their own focused tests
rather than a place in the matrix, because each is about a single mechanism.
"""

from __future__ import annotations

import ast
import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
from tests.helpers.m4 import M4Harness, make_m4_harness
from tests.lab.artifact_lab import (
    AREAS,
    OVERSIZED_PLAN_BYTES,
    PATHS_BY_AREA,
    PLANTED_SECRETS,
    ArtifactLab,
    start_artifact_lab,
)

from arachne.core.proof import ProofLevel
from arachne.modules.m4.artifacts import GROUPS_BY_AREA, ArtifactChecks

#: Every check the WP-29 family registers, from the family tuple the module exports.
WP29_IDS: tuple[str, ...] = tuple(check.metadata.id for check in ArtifactChecks)

#: The corpus group each check sweeps → the requirement's scope area. The map is the module's
#: own declaration, reversed here so a test can ask "whose positive is this?".
AREA_OF_GROUP: dict[str, str] = {
    group: area for area, groups in GROUPS_BY_AREA.items() for group in groups
}

#: The fixture mode that plants each area's signals, and the decoy modes.
POSITIVE = "vulnerable"
DECOYS: tuple[str, ...] = ("not-found", "error-page")

#: The proof level every member of the family declares.
_FAMILY_PROOF = ProofLevel.L1

#: The module that carries the family (the source-level read-only assertion reads it).
FAMILY_SOURCE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m4"

#: The safe request methods the family may send. The family is GET-only.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

#: The raw-bytes client entry points that bypass the capture cap. The family may not call one:
#: "read the whole file to confirm it" is exactly what the exit criterion forbids.
RAW_FETCH_CALLS: frozenset[str] = frozenset(
    {"request_bytes", "get_bytes", "fetch_binary", "read_bytes", "stream"}
)

#: The helpers that would let a request carry a body or choose its own verb.
UNSAFE_HELPERS: frozenset[str] = frozenset({"json_post", "post_form", "request_raw"})

#: The area whose Terraform plan fixture is deliberately larger than the client's body limit.
OVERSIZED_AREA = "terraform"
OVERSIZED_PATH = "/terraform.tfplan"


def _owner(check_id: str) -> str:
    """The area a family check belongs to, read from the module's own group declaration."""
    check = next(item for item in ArtifactChecks if item.metadata.id == check_id)
    return AREA_OF_GROUP[check.group]


@pytest.fixture(scope="module")
def installations() -> Iterator[dict[tuple[str, str], ArtifactLab]]:
    """One running installation per (area, mode), started once for the module."""
    running: dict[tuple[str, str], ArtifactLab] = {}
    stack = []
    try:
        for area in AREAS:
            for mode in (POSITIVE, *DECOYS):
                manager = start_artifact_lab(area, mode)
                running[(area, mode)] = manager.__enter__()
                stack.append(manager)
        yield running
    finally:
        for manager in reversed(stack):
            manager.__exit__(None, None, None)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in ArtifactChecks}


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


def _evidence_blob(results: list[Any]) -> str:
    """Every evidence payload of every result, serialised — what a reviewer would read."""
    return json.dumps(
        [[dict(item.payload) for item in result.evidence] for result in results],
        default=str,
    )


async def _harness(lab: ArtifactLab, *, prepare: bool = True) -> M4Harness:
    harness = make_m4_harness(lab)
    if prepare:
        await harness.prepare()
    return harness


async def _measure(
    installations: dict[tuple[str, str], ArtifactLab],
) -> dict[tuple[str, str, str], int]:
    """Run every family check against every installation, counting its findings.

    A harness (and so an HTTP client and a crawl) is created per installation *inside* this
    coroutine and closed here: a client is bound to the loop that built it, so a module-scoped
    fixture cannot hold one.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for (area, mode), lab in installations.items():
        harness = await _harness(lab)
        try:
            for check_id in WP29_IDS:
                counts[(area, mode, check_id)] = len(_findings(await _run(harness, check_id)))
        finally:
            await harness.aclose()
    return counts


@pytest.fixture(scope="module")
def measured(
    installations: dict[tuple[str, str], ArtifactLab],
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against all twenty-four installations (runtime budget)."""
    return asyncio.run(_measure(installations))


# --------------------------------------------------------------------------- the acceptance run
def test_the_family_registers_at_least_twenty_four_checks() -> None:
    """REQ-DET-022: at least 24 new checks in this family."""
    assert len(WP29_IDS) >= 24, WP29_IDS
    assert len(set(WP29_IDS)) == len(WP29_IDS)
    assert set(GROUPS_BY_AREA) == set(AREAS), sorted(GROUPS_BY_AREA)
    # Every area the requirement's scope names owns at least three checks, and every check
    # belongs to exactly one area.
    for area in AREAS:
        owned = [check_id for check_id in WP29_IDS if _owner(check_id) == area]
        assert len(owned) >= 3, (area, owned)
    groups = [group for groups in GROUPS_BY_AREA.values() for group in groups]
    assert len(groups) == len(set(groups)) == len(WP29_IDS), groups
    print(
        f"\nregistry total: {_registry_total()} checks; "
        f"WP-29 family: {len(WP29_IDS)} across {len(AREAS)} areas"
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
    for check_id in WP29_IDS:
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
    assert cross_area == len(WP29_IDS) * (len(AREAS) - 1)
    decoy_cells = len(WP29_IDS) * (len(AREAS) * (1 + len(DECOYS)) - 1)
    print(
        f"\n{len(WP29_IDS)} checks x {len(AREAS) * (1 + len(DECOYS))} installations: "
        f"every positive found, 0 findings on every decoy "
        f"({decoy_cells} decoy-clean cells: {len(AREAS)} not-found, {len(AREAS)} error-page, "
        f"{cross_area} cross-area)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-022: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP29_IDS:
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
    """The read-only claim at the source: no verb but GET, and no raw-bytes fetch.

    The assertion is structural rather than a search for the verb's letters: every request the
    module makes goes through ``probe_paths``/``fetch_page`` (which default to ``GET``), so what
    matters is that nothing in the module *chooses* a method, and that the raw-bytes entry
    point — the one way to read a body past the capture cap — is never called.
    """
    source = (FAMILY_SOURCE / "artifacts.py").read_text(encoding="utf-8")
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
    assert not (calls & RAW_FETCH_CALLS), sorted(calls & RAW_FETCH_CALLS)
    assert not (calls & UNSAFE_HELPERS), sorted(calls & UNSAFE_HELPERS)
    # No request-building call site may pass its own method: the probes are the shared ones.
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
    # The corpus data the module reads names no verb either.
    assert "POST" not in source.replace("POSTGRES", "")


def test_no_state_changing_request_reached_any_installation(
    installations: dict[tuple[str, str], ArtifactLab],
) -> None:
    """The read-only claim on the wire: every request the fixtures answered was safe."""
    offenders: list[str] = []
    for (area, mode), lab in installations.items():
        for request in lab.requests:
            method = request.split(" ", 1)[0].upper()
            if method not in SAFE_METHODS:
                offenders.append(f"{area}/{mode}: {request}")
    assert not offenders, offenders


def test_nothing_larger_than_the_body_limit_was_read(
    installations: dict[tuple[str, str], ArtifactLab],
) -> None:
    """REQ-DET-022: no check downloads a file larger than the client's body limit.

    Two halves. **On the wire**: the Terraform plan fixture is deliberately larger than the
    client's limit, and the check that reports it still reports it — with ``captured_bytes``
    at the limit and ``truncated`` set, which is what proves the confirmation did not need the
    bytes. **In the evidence**: every finding of the whole matrix records a capture no larger
    than the limit it was read under.
    """
    lab = installations[(OVERSIZED_AREA, POSITIVE)]
    measured = asyncio.run(_oversized_measurements(lab))
    limit = measured["limit"]
    assert limit > 0
    assert limit < OVERSIZED_PLAN_BYTES, (
        "the fixture must be larger than the limit for this test to mean anything"
    )
    plan = next(item for item in measured["captures"] if item["path"] == OVERSIZED_PATH)
    assert plan["bytes"] == limit, plan
    assert plan["truncated"] is True, plan
    over = [item for item in measured["captures"] if item["bytes"] > item["limit"]]
    assert not over, over


async def _oversized_measurements(lab: ArtifactLab) -> dict[str, Any]:
    """Every finding the family reports on the oversized fixture, with its capture bound."""
    harness = await _harness(lab)
    try:
        captures: list[dict[str, Any]] = []
        limit = 0
        for check_id in WP29_IDS:
            for result in _findings(await _run(harness, check_id)):
                payload = _artifact(result)
                limit = int(payload["body_limit"])
                captures.append(
                    {
                        "check": check_id,
                        "path": str(payload["path"]),
                        "bytes": int(payload["captured_bytes"]),
                        "limit": int(payload["body_limit"]),
                        "truncated": bool(payload["truncated"]),
                    }
                )
        assert captures, "the oversized plan artifact must be reported"
        return {"limit": limit, "captures": captures}
    finally:
        await harness.aclose()


def test_the_secret_bearing_artifacts_are_redacted_at_capture(
    installations: dict[tuple[str, str], ArtifactLab],
) -> None:
    """Every planted credential is redacted before a check sees it, and proven so.

    The fixture plants the *shapes* the capture path redacts (a GitHub token in a remote URL,
    provider access keys, a credentialed connection string, a JSON web token, a PEM block).
    This test drives the whole matrix and asserts that no planted value appears in any
    evidence payload of any result, and that the two checks whose claim *is* the credential
    fired on the detector names rather than on a value.
    """
    leaked: list[str] = []
    detected: set[str] = set()
    detector_checks: set[str] = set()

    async def measure() -> None:
        for (area, mode), lab in installations.items():
            if mode != POSITIVE:
                continue
            harness = await _harness(lab)
            try:
                for check_id in WP29_IDS:
                    results = await _run(harness, check_id)
                    blob = _evidence_blob(results)
                    for secret in PLANTED_SECRETS:
                        if secret in blob:
                            leaked.append(f"{check_id} on {area}: a planted value survived")
                    for result in _findings(results):
                        payload = _artifact(result)
                        detected.update(str(item) for item in payload.get("detectors", []))
                        if payload.get("detectors"):
                            detector_checks.add(check_id)
            finally:
                await harness.aclose()

    asyncio.run(measure())
    assert not leaked, leaked
    # The redactor is what the findings report: the detector names are present, the values are
    # not. Both checks whose claim is the credential are among the ones that saw a detector.
    assert {"aws-access-key-id", "github-token"} <= detected, sorted(detected)
    assert {"m4.git-credentials-exposed", "m4.ci-pipeline-secret-exposed"} <= detector_checks, (
        sorted(detector_checks)
    )


def test_the_checks_are_deterministic(
    installations: dict[tuple[str, str], ArtifactLab],
) -> None:
    """Two runs against the same fixture produce the same verdicts."""
    lab = installations[("env-variants", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab)
        try:

            def signature(results: list[Any]) -> list[tuple[str, str]]:
                return sorted((result.status, result.title) for result in results)

            for check_id in WP29_IDS:
                first = signature(await _run(harness, check_id))
                second = signature(await _run(harness, check_id))
                assert first == second, check_id
        finally:
            await harness.aclose()

    asyncio.run(measure())


def test_a_dry_run_sends_nothing(installations: dict[tuple[str, str], ArtifactLab]) -> None:
    """F-01-10: no client, no request, and every check says so rather than pretending."""
    lab = installations[("credential-files", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab, prepare=False)
        harness.step.http = None
        try:
            for check_id in WP29_IDS:
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
    installations: dict[tuple[str, str], ArtifactLab],
) -> None:
    """A finding's path is a published artifact path, not the fixture's refusal page."""
    lab = installations[("dvcs", POSITIVE)]

    async def measure() -> None:
        harness = await _harness(lab)
        try:
            reported: set[str] = set()
            for check_id in WP29_IDS:
                for result in _findings(await _run(harness, check_id)):
                    reported.add(str(_artifact(result)["path"]))
            assert reported, "the dvcs installation plants at least one artifact"
            assert reported <= set(PATHS_BY_AREA["dvcs"]), sorted(reported)
        finally:
            await harness.aclose()

    asyncio.run(measure())


def test_the_echo_404_trap_is_silent() -> None:
    """The pitfall's own decoy: a 200 that echoes the requested path is not an exposure.

    Every artifact path answers ``200 OK`` with a page that quotes the path it was asked for
    and says the resource was not found. A check that fired on the status, or on the path
    appearing in the body, would report the fixture's refusal as a finding.
    """
    with start_artifact_lab("terraform", "echo-404") as lab:
        harness = asyncio.run(_trap_harness(lab))
    assert harness["echoes"] is True, "the trap must echo the requested path"
    assert harness["status"] == 200, "the trap must answer 200, or it is not the pitfall"
    assert harness["findings"] == [], harness["findings"]


async def _trap_harness(lab: ArtifactLab) -> dict[str, Any]:
    harness = await _harness(lab)
    try:
        path = PATHS_BY_AREA["terraform"][0]
        from arachne.modules.m3.support import safe_fetch

        exchange = await safe_fetch(harness.context(None), f"{lab.origin}{path}", anonymous=True)
        assert exchange is not None
        findings: list[str] = []
        for check_id in WP29_IDS:
            findings.extend(
                f"{check_id}: {_artifact(result)['path']}"
                for result in _findings(await _run(harness, check_id))
            )
        return {
            "status": exchange.status_code,
            "echoes": path in exchange.body,
            "findings": findings,
        }
    finally:
        await harness.aclose()


def test_the_decoy_bodies_echo_nothing(installations: dict[tuple[str, str], ArtifactLab]) -> None:
    """The requirement's decoy is a refusal that names no artifact and quotes no path."""
    suppressed = sorted(PLANTED_SECRETS)

    async def measure() -> None:
        for mode in DECOYS:
            lab = installations[("terraform", mode)]
            harness = await _harness(lab, prepare=False)
            try:
                from arachne.modules.m3.support import safe_fetch

                path = OVERSIZED_PATH
                exchange = await safe_fetch(
                    harness.context(None), f"{lab.origin}{path}", anonymous=True
                )
                assert exchange is not None
                body = exchange.body
                assert path not in body, f"{mode} echoes the requested path"
                assert not any(secret in body for secret in suppressed), mode
                for marker in ("terraform_version", "planned_values", "format_version"):
                    assert marker not in body, (mode, marker)
            finally:
                await harness.aclose()

    asyncio.run(measure())


def test_the_family_source_is_the_only_place_the_checks_are_declared() -> None:
    """One definition of the family: the module's tuple is the registry's set."""
    from arachne.modules.registry import ModuleRegistry

    registry = ModuleRegistry.discover()
    for check_id in WP29_IDS:
        assert registry.get(check_id) is not None, check_id
    assert len(WP29_IDS) == len(set(WP29_IDS))


def test_the_family_uses_the_declared_binary_suffixes() -> None:
    """A binary artifact is confirmed from its suffix, never from a decoded body."""
    from arachne.modules.m4.corpus import load_corpus

    corpus = load_corpus()
    extensions = set(corpus.artifact_binary_extensions())
    assert {".tfplan", ".swp", ".ds_store"} <= extensions, sorted(extensions)
    detector_groups = {check.group for check in ArtifactChecks if check.detector_required}
    for group in sorted(AREA_OF_GROUP):
        probes = corpus.artifact_probes(group)
        assert probes, group
        for probe in probes:
            # Every probe is confirmable without decoding a body: it carries its own content
            # marker, or its suffix is declared binary, or its check's claim is the credential
            # the redactor reports (the two detector-required groups). A probe with none of
            # the three could only be "confirmed" by reading bytes this family may not read.
            suffix = probe.path.rpartition(".")[2].lower()
            confirmable = probe.markers or f".{suffix}" in extensions or group in detector_groups
            assert confirmable, probe.path


def test_no_marker_is_derived_from_the_probed_path() -> None:
    """A marker may not be a substring of its own path: that is the echo-404 false positive.

    The pitfall is explicit — "a 404 that echoes the requested path is NOT exposure". A marker
    that appears in the path (``Modules`` for ``/.terraform/modules/modules.json``,
    ``accessToken`` for ``/.azure/accessTokens.json``) matches the refusal page's echo of the
    path it was asked for, which is exactly how a soft 404 becomes a finding. The
    ``echo-404`` fixture caught two such markers when this family was first measured; this
    test makes the rule structural so the next batch cannot reintroduce one.
    """
    from arachne.modules.m4.corpus import load_corpus

    corpus = load_corpus()
    offenders: list[str] = []
    for group in sorted(AREA_OF_GROUP):
        for probe in corpus.artifact_probes(group):
            lowered = probe.path.lower()
            for marker in probe.markers:
                if marker.lower() in lowered:
                    offenders.append(f"{group}: {probe.path} marker {marker!r} is in the path")
    assert not offenders, offenders


def test_every_probe_path_reaches_the_server_unchanged() -> None:
    """A probe path must be the path the server is asked for, whatever a URL does to it.

    ``#`` is a *fragment* delimiter, so an Emacs lock name (``.#index.php``) written literally
    sends ``GET /`` with a fragment — the artefact is never asked for, and a marker match on
    the homepage would be a false positive. The same is true of any dot-segment or doubled
    slash the URL parser folds away. The safety suite's
    ``test_a_scan_with_osint_disabled_queries_no_third_party`` caught this family's two Emacs
    paths doing exactly that; this test makes the rule structural, and the corpus spells those
    two names the way a URL must carry them (percent-encoded). The comparison is on the
    *decoded* path, which is the file name the server sees.
    """
    import httpx

    from arachne.modules.m4.corpus import load_corpus
    from arachne.modules.m4.support import path_url

    corpus = load_corpus()
    offenders: list[str] = []
    for group in sorted(AREA_OF_GROUP):
        for probe in corpus.artifact_probes(group):
            parsed = httpx.URL(path_url("https://example.invalid", probe.path))
            if parsed.fragment:
                offenders.append(f"{group}: {probe.path} is sent as a URL fragment")
            elif unquote(parsed.path) != unquote(probe.path):
                offenders.append(
                    f"{group}: {probe.path} is sent as {unquote(parsed.path)} "
                    "(a URL parser folded it; percent-encode it)"
                )
    assert not offenders, offenders
