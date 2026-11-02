"""The MCP check family is read-only — by source shape and on the wire (REQ-DET-005).

The claim the MCP checks make is about authentication posture, so it would be very easy for
them to cross the line they report on: authenticate to the target, POST a JSON-RPC request, or
follow the URL the target advertised (that last one is the SSRF class itself). This suite pins
both halves:

* **source shape** — the module constructs no non-GET request and names no ``Authorization``
  header, so a future edit that reaches for ``post()`` fails here before it ships;
* **the wire** — running every check against the planted lab records every request the scoped
  client made: all ``GET``, no ``Authorization`` header, and every URL still on the target's own
  origin (nothing advertised by the target is ever fetched).

It also asserts the family's shape: three checks, all L0 or L1, all opt-out-able, and a
positive on the planted server with a silent control on the conformant one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from arachne.modules.m6 import M6_CHECKS
from arachne.modules.m6.mcp import MCP_CHECKS
from tests.helpers.checks import asset_for
from tests.helpers.m6 import make_m6_harness
from tests.lab.web_lab import start_web_lab

MCP_MODULE = Path(__file__).resolve().parents[1] / "src" / "arachne" / "modules" / "m6" / "mcp.py"

#: The methods the family must never construct (GET and HEAD are the read-only pair).
FORBIDDEN_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


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


async def _run(check, base_url: str) -> tuple[list[object], list[tuple[str, dict[str, str]]]]:
    """Run one check against ``base_url`` and record every request it issued."""
    harness = make_m6_harness(asset=asset_for("url", base_url))
    recorded: list[tuple[str, dict[str, str]]] = []
    original = harness.client.request

    async def spy(method: str, url: str, **kwargs: object):  # type: ignore[no-untyped-def]
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


# ------------------------------------------------------------------ family shape
def test_the_family_is_three_checks_at_l0_or_l1() -> None:
    assert len(MCP_CHECKS) == 3
    for check in MCP_CHECKS:
        assert check.metadata.proof.value in {"L0", "L1"}, check.metadata.id
        assert check.metadata.enabled_by_default, check.metadata.id  # opt-out-able
        assert check.metadata.safe, check.metadata.id
        assert not check.metadata.requires_state_attestation, check.metadata.id


def test_the_family_is_registered_in_m6() -> None:
    registered = {check.metadata.id for check in M6_CHECKS}
    assert {check.metadata.id for check in MCP_CHECKS} <= registered


def test_every_mcp_check_names_a_framework_item() -> None:
    for check in MCP_CHECKS:
        assert check.metadata.framework


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


def test_no_mcp_check_constructs_a_non_get_request() -> None:
    """A source-level guard: no POST/PUT/PATCH/DELETE call and no such method literal."""
    tree = ast.parse(MCP_MODULE.read_text(encoding="utf-8"))
    for name in ("post", "put", "patch", "delete"):
        assert not any(_call_name(call) == name for call in _calls(tree)), name
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for method in FORBIDDEN_METHODS:
        assert method not in literals, method
    # Every fetch is the helper's default method: no `method=` argument anywhere means GET.
    for call in _calls(tree):
        if _call_name(call) in {"request", "fetch", "safe_fetch", "fetch_page"}:
            assert not any(keyword.arg == "method" for keyword in call.keywords), ast.dump(call)


def test_no_mcp_check_names_an_authorization_header() -> None:
    tree = ast.parse(MCP_MODULE.read_text(encoding="utf-8"))
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not any(value.lower() == "authorization" for value in literals)
    assert not any(value.lower().startswith("bearer ") for value in literals)


# ------------------------------------------------------------------ the wire
async def test_every_request_the_family_makes_is_a_get_without_credentials() -> None:
    with start_web_lab() as lab:
        requests: list[tuple[str, dict[str, str]]] = []
        for check in MCP_CHECKS:
            _results, recorded = await _run(check, lab.base_url)
            requests.extend(recorded)
        assert requests, "the checks issued no request; the assertion would be vacuous"
        for method, headers in requests:
            assert method == "GET"
            assert not any(name.lower() == "authorization" for name in headers)
        # Nothing the target advertised is ever fetched: every URL stays on its origin.
        assert all(entry.startswith("GET ") for entry in lab.requests)
        assert not any(
            request.startswith(("POST ", "PUT ", "PATCH ", "DELETE ")) for request in lab.requests
        )


# ------------------------------------------------------------------ positives and decoys
async def test_the_planted_server_produces_each_signal() -> None:
    with start_web_lab() as lab:
        for check in MCP_CHECKS:
            results, _recorded = await _run(check, lab.base_url)
            assert _signals(results), check.metadata.id


async def test_the_conformant_server_is_silent() -> None:
    """The false-positive trap: a server that follows the MCP spec must produce nothing."""
    with start_web_lab(mcp_conformant=True) as lab:
        for check in MCP_CHECKS:
            results, _recorded = await _run(check, lab.base_url)
            assert _signals(results) == [], check.metadata.id
            assert [result.status for result in results] == ["not_vulnerable"]


@pytest.mark.parametrize("check_id", [check.metadata.id for check in MCP_CHECKS])
def test_each_check_has_a_documented_safety_sentence(check_id: str) -> None:
    metadata = {check.metadata.id: check.metadata for check in MCP_CHECKS}[check_id]
    assert "Read-only" in metadata.description or "read-only" in metadata.description
