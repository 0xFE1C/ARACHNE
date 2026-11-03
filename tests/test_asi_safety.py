"""The Agentic Top 10 family is read-only — by source shape and on the wire (REQ-DET-013).

The requirement's hard limit is that an ASI check must not authenticate to, write to or start a
target agent. That is easy to say and easy to break: the cheapest way to "prove" tool misuse
would be to POST a JSON-RPC call to the agent's tool endpoint, and the cheapest way to "prove"
identity abuse would be to replay a credential the target handed out. This suite pins the line
three ways:

* **source shape** — for every *registered* check that maps an ``ASI<N>:2026`` item, the
  module it lives in constructs no non-GET request, carries no ``method=`` and **no**
  ``headers=`` argument into a fetch (so it cannot forward a header the target supplied), and
  names no ``Authorization`` header;
* **the wire** — running the family against the planted lab records every request the scoped
  client made: all ``GET``, no ``Authorization`` header, and nothing but ``GET`` reaching the
  lab itself;
* **the family shape** — four checks, each L0 or L1, opt-out-able, mapped to a real ASI item,
  with a positive on the planted lab and a silent control on the hardened one.

It also asserts the requirement's coverage floor: the registered set maps at least six ASI
items, including the six the work package prioritises.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from typing import Any

import pytest

from arachne.modules.m6 import M6_CHECKS
from arachne.modules.m6.agentic import AGENTIC_CHECKS, AGENTIC_PROBE_PATHS, asi_items
from arachne.modules.registry import ModuleRegistry
from tests.helpers.checks import asset_for
from tests.helpers.m6 import make_m6_harness
from tests.lab.web_lab import start_web_lab

#: The methods the family must never construct (GET and HEAD are the read-only pair).
FORBIDDEN_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

#: The functions a check uses to reach the target; none of them may be handed a method or a
#: header mapping by an ASI check.
FETCH_FUNCTIONS = {"request", "fetch", "safe_fetch", "fetch_page", "tls", "tcp"}

#: The six items REQ-DET-013 prioritises.
PRIORITY_ITEMS = (
    "ASI02:2026",
    "ASI03:2026",
    "ASI06:2026",
    "ASI07:2026",
    "ASI09:2026",
    "ASI10:2026",
)

REPO = Path(__file__).resolve().parents[1]


def _asi_mapped_checks() -> list[type[Any]]:
    """Every *registered* check whose framework mapping names an ASI item."""
    mapped = [
        check
        for check in ModuleRegistry.discover().checks()
        if any(re.fullmatch(r"ASI\d{2}:2026", item) for item in check.metadata.framework)
    ]
    assert mapped, "no registered check maps an ASI item; the assertions below would be vacuous"
    return mapped


def _asi_module_paths() -> dict[Path, tuple[str, ...]]:
    """``{module file: check ids}`` for the modules that declare an ASI mapping."""
    paths: dict[Path, list[str]] = {}
    for check in _asi_mapped_checks():
        path = Path(inspect.getfile(check)).resolve()
        paths.setdefault(path, []).append(check.metadata.id)
    return {path: tuple(sorted(ids)) for path, ids in paths.items()}


def _signals(results: list[Any]) -> list[str]:
    found: list[str] = []
    for result in results:
        if getattr(result, "status", None) != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            signal = item.payload.get("signal")
            if signal:
                found.append(str(signal))
    return found


async def _run(
    check: type[Any], base_url: str
) -> tuple[list[Any], list[tuple[str, dict[str, str]]]]:
    """Run one check against ``base_url`` and record every request it issued."""
    harness = make_m6_harness(asset=asset_for("url", base_url))
    recorded: list[tuple[str, dict[str, str]]] = []
    original = harness.client.request

    async def spy(method: str, url: str, **kwargs: object) -> Any:
        recorded.append((method.upper(), dict(kwargs.get("headers") or {})))  # type: ignore[arg-type]
        return await original(method, url, **kwargs)  # type: ignore[arg-type]

    harness.client.request = spy  # type: ignore[method-assign]
    try:
        await harness.prepare([base_url])
        ctx = harness.context(check())
        results = [result async for result in check().run(ctx)]
    finally:
        await harness.aclose()
    return results, recorded


# ------------------------------------------------------------------ coverage floor
def test_at_least_six_asi_items_are_mapped_by_registered_checks() -> None:
    mapped: set[str] = set()
    for check in _asi_mapped_checks():
        mapped.update(
            item for item in check.metadata.framework if re.fullmatch(r"ASI\d{2}:2026", item)
        )
    assert len(mapped) >= 6, sorted(mapped)


def test_every_priority_item_is_backed_by_a_registered_check() -> None:
    """The six prioritised items each have at least one registered check behind them."""
    mapped: dict[str, list[str]] = {}
    for check in _asi_mapped_checks():
        for item in check.metadata.framework:
            if item in PRIORITY_ITEMS:
                mapped.setdefault(item, []).append(check.metadata.id)
    assert sorted(mapped) == sorted(PRIORITY_ITEMS)
    assert all(mapped[item] for item in PRIORITY_ITEMS)


def test_this_module_maps_four_items() -> None:
    assert asi_items() == ("ASI02:2026", "ASI06:2026", "ASI09:2026", "ASI10:2026")


# ------------------------------------------------------------------ family shape
def test_the_family_is_four_checks_at_l0_or_l1() -> None:
    assert len(AGENTIC_CHECKS) == 4
    for check in AGENTIC_CHECKS:
        assert check.metadata.proof.value in {"L0", "L1"}, check.metadata.id
        assert check.metadata.enabled_by_default, check.metadata.id  # opt-out-able
        assert check.metadata.safe, check.metadata.id
        assert not check.metadata.requires_state_attestation, check.metadata.id
        assert not check.metadata.requires_active_checks, check.metadata.id
        assert not check.metadata.requires_credentials, check.metadata.id


def test_the_family_is_registered_in_m6() -> None:
    registered = {check.metadata.id for check in M6_CHECKS}
    assert {check.metadata.id for check in AGENTIC_CHECKS} <= registered


def test_every_check_declares_the_asi_item_it_serves() -> None:
    for check in AGENTIC_CHECKS:
        items = [item for item in check.metadata.framework if item.startswith("ASI")]
        assert len(items) == 1, (check.metadata.id, items)


@pytest.mark.parametrize("check_id", [check.metadata.id for check in AGENTIC_CHECKS])
def test_each_check_has_a_documented_safety_sentence(check_id: str) -> None:
    metadata = {check.metadata.id: check.metadata for check in AGENTIC_CHECKS}[check_id]
    assert "Read-only" in metadata.description or "read-only" in metadata.description


def test_every_check_probes_a_bounded_declared_path_set() -> None:
    """The plan's request estimate is exactly the number of GETs the check can issue."""
    for check in AGENTIC_CHECKS:
        assert 0 < check.metadata.estimated_requests <= 8
    total = sum(len(paths) for paths in AGENTIC_PROBE_PATHS.values())
    assert total == sum(check.metadata.estimated_requests for check in AGENTIC_CHECKS)


# ------------------------------------------------------------------ source shape
def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _literals(tree: ast.AST) -> set[str]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def test_no_asi_check_constructs_a_non_get_request() -> None:
    for path, check_ids in _asi_module_paths().items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name in ("post", "put", "patch", "delete"):
            assert not any(_call_name(call) == name for call in _calls(tree)), (path, check_ids)
        literals = _literals(tree)
        for method in FORBIDDEN_METHODS:
            assert method not in literals, (path, check_ids, method)


def test_no_asi_check_names_an_authorization_header() -> None:
    """No authorization-header literal anywhere in a module that maps an ASI item.

    A check cannot source a header from the target if it names no such header at all, which is
    the reading of REQ-DET-013's "no ``Authorization`` header sourced from the target" that is
    verifiable without a data-flow analysis.
    """
    for path, check_ids in _asi_module_paths().items():
        literals = _literals(ast.parse(path.read_text(encoding="utf-8")))
        offenders = {
            value
            for value in literals
            if value.lower() == "authorization"
            or value.lower().startswith("authorization:")
            or re.match(r"^bearer\s", value, re.IGNORECASE)
        }
        assert not offenders, (path, check_ids, offenders)


def test_no_asi_check_forwards_a_method_or_a_header_into_a_fetch() -> None:
    """Every fetch is the helper's default method and carries no custom headers.

    ``headers=`` would be the channel through which a header taken from one response is sent in
    the next request. No ASI check has one, so the channel does not exist.
    """
    for path, check_ids in _asi_module_paths().items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in _calls(tree):
            if _call_name(call) not in FETCH_FUNCTIONS:
                continue
            keywords = {keyword.arg for keyword in call.keywords}
            assert "method" not in keywords, (path, check_ids, ast.dump(call))
            assert "headers" not in keywords, (path, check_ids, ast.dump(call))


def test_no_asi_module_contains_a_write_or_exploit_primitive() -> None:
    """No ASI module names an instruction-loading or agent-starting primitive."""
    forbidden = ("jsonrpc", "prompt_payload", "start_agent", "invoke_tool", "call_tool")
    for path, check_ids in _asi_module_paths().items():
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in text, (path, check_ids, token)


# ------------------------------------------------------------------ the wire
async def test_every_request_the_family_makes_is_a_get_without_credentials() -> None:
    with start_web_lab() as lab:
        requests: list[tuple[str, dict[str, str]]] = []
        for check in AGENTIC_CHECKS:
            _results, recorded = await _run(check, lab.base_url)
            requests.extend(recorded)
        assert requests, "the checks issued no request; the assertion would be vacuous"
        for method, headers in requests:
            assert method == "GET"
            assert not any(name.lower() == "authorization" for name in headers)
        assert not any(
            entry.startswith(("POST ", "PUT ", "PATCH ", "DELETE ")) for entry in lab.requests
        ), [entry for entry in lab.requests if not entry.startswith("GET ")]


async def test_no_asi_check_sends_any_header_of_its_own() -> None:
    """The sharpest form of the requirement: the family sends no header at all."""
    with start_web_lab() as lab:
        for check in AGENTIC_CHECKS:
            _results, recorded = await _run(check, lab.base_url)
            for method, headers in recorded:
                assert method == "GET", check.metadata.id
                assert not headers, check.metadata.id


# ------------------------------------------------------------------ positives and decoys
async def test_the_planted_lab_produces_each_signal() -> None:
    """Every check has a positive: the fixture that exhibits its weakness fires it."""
    with start_web_lab() as lab:
        for check in AGENTIC_CHECKS:
            results, _recorded = await _run(check, lab.base_url)
            assert _signals(results), check.metadata.id


async def test_the_hardened_lab_is_silent() -> None:
    """The false-positive trap: a hardened deployment must produce nothing (the decoy)."""
    with start_web_lab(agentic_hardened=True) as lab:
        for check in AGENTIC_CHECKS:
            results, _recorded = await _run(check, lab.base_url)
            assert _signals(results) == [], check.metadata.id
            assert [result.status for result in results] == ["not_vulnerable"], check.metadata.id


async def test_the_benign_sibling_routes_are_not_reported() -> None:
    """The planted lab also serves the benign twin of each surface; neither may be reported."""
    with start_web_lab() as lab:
        results, _recorded = await _run(AGENTIC_CHECKS[0], lab.base_url)
        urls = {
            str(item.payload.get("endpoint"))
            for result in results
            if result.status == "vulnerable"
            for item in result.evidence
            if item.payload.get("signal") == "agentic-tool-manifest"
        }
        assert not any(url.endswith("/mcp/tools") for url in urls)
        assert any(url.endswith("/.well-known/mcp.json") for url in urls)


def test_the_repo_root_resolves_for_the_source_assertions() -> None:
    """A guard: this suite reads source from the checkout, so the root must resolve."""
    assert (REPO / "pyproject.toml").is_file()
