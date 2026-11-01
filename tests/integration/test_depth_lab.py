"""Acceptance: the S29 depth-expansion families meet the lab's ground truth.

REQ-DEPTH-001 and REQ-DEPTH-002 ask for GraphQL and WebSocket checks whose findings "meet
ground truth" on a lab fixture. This module drives each new check against the shared stdlib
lab (``tests/lab/web_lab.py``), whose GraphQL routes are served by a real engine
(``tests/lab/graphql_lab.py``) and whose WebSocket routes speak real RFC 6455 framing, and
asserts:

* every planted signal is reported (``DEPTH_GROUND_TRUTH``);
* the hardened counterparts are **not** reported (``DEPTH_FALSE_POSITIVE_TRAPS``);
* the switches really gate the checks (nothing is sent while they are off);
* the probes stay content-free (no response body asks for a document field).

The checks are driven directly, as the checks step would, through
:func:`tests.helpers.depth.make_depth_harness`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.depth import make_depth_harness
from tests.lab.web_lab import (
    DEPTH_FALSE_POSITIVE_TRAPS,
    DEPTH_GROUND_TRUTH,
    WebLab,
    start_web_lab,
)

from arachne.core.config import WebSettings
from arachne.core.proof import ProofLevel
from arachne.modules.m3 import M3_CHECKS

#: The crawl roots the depth checks read: the planted routes first, then the hardened ones.
ROOTS: tuple[str, ...] = (
    "/",
    "/graphql",
    "/graphql-safe",
    "/ws",
    "/ws-safe",
    # The client-side bundle and the two API routes it names (REQ-DEPTH-004).
    "/app.js",
    "/api/internal/users",
    "/api/orders",
)


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _roots(lab: WebLab) -> list[str]:
    return [f"{lab.base_url.rstrip('/')}{path}" for path in ROOTS]


def _web(**overrides: Any) -> WebSettings:
    """The depth probes are opt-in behind a switch; every test opens it explicitly."""
    return replace(
        WebSettings(
            max_pages=40,
            graphql_probe=True,
            ws_probe=True,
        ),
        **overrides,
    )


async def _run(lab: WebLab, check_id: str, *, web: WebSettings | None = None) -> list:
    check_cls = _by_id()[check_id]
    harness = make_depth_harness(asset=asset_for("url", lab.base_url), web=web or _web())
    try:
        await harness.prepare(_roots(lab))
        ctx = harness.context(check_cls())
        return [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()


def _blob(results: list) -> str:
    parts: list[str] = []
    for result in results:
        if result.status != "vulnerable":
            continue
        for item in result.evidence:
            for key, value in item.payload.items():
                parts.append(f"{key}={value}")
    return " ".join(parts)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M3_CHECKS}


async def test_every_depth_family_reports_its_planted_signal(lab: WebLab) -> None:
    """Every planted depth signal is found: the two P0 families meet their ground truth."""
    for check_id, marker in DEPTH_GROUND_TRUTH:
        results = await _run(lab, check_id)
        blob = _blob(results)
        assert marker in blob, f"{check_id} did not report {marker!r}: {[r.title for r in results]}"


async def test_the_hardened_routes_are_not_reported(lab: WebLab) -> None:
    """REQ-DEPTH-001/002 control: the hardened routes must produce no candidate."""
    for check_id, trap in DEPTH_FALSE_POSITIVE_TRAPS:
        results = await _run(lab, check_id)
        blob = _blob(results)
        assert trap not in blob, f"{check_id} reported the hardened route {trap!r}"


async def test_the_graphql_probe_asks_for_no_document_field(lab: WebLab) -> None:
    """The safety property of REQ-DEPTH-001: only the ``__typename`` meta-field is selected."""
    results = await _run(lab, "m3.graphql-resolver-auth")
    assert results, "the resolver-auth check produced no result at all"
    asserted = 0
    for result in results:
        if result.status != "vulnerable":
            continue
        for item in result.evidence:
            if item.payload.get("content_requested") is not None:
                assert item.payload["content_requested"] is False
                asserted += 1
            if item.payload.get("anonymous_request") is not None:
                assert item.payload["anonymous_request"] is True
    assert asserted, "no artifact carried the content_requested flag the claim rests on"


async def test_the_switches_are_real_gates(lab: WebLab) -> None:
    """With the deployment switches off, no crafted query and no frame is ever sent."""
    disabled = replace(WebSettings(max_pages=40), graphql_probe=False, ws_probe=False)
    for check_id in ("m3.graphql-depth-abuse", "m3.graphql-resolver-auth"):
        results = await _run(lab, check_id, web=disabled)
        assert all(result.status != "vulnerable" for result in results), (
            f"{check_id} reported a finding with ARACHNE_WEB_GRAPHQL_PROBE off"
        )
        assert any("ARACHNE_WEB_GRAPHQL_PROBE" in (r.detail or "") for r in results), (
            f"{check_id} did not say which switch would enable it"
        )
    before = len(lab.ws_messages)
    injection = await _run(lab, "m3.websocket-injection", web=disabled)
    assert all(result.status != "vulnerable" for result in injection)
    assert any("ARACHNE_WEB_WS_PROBE" in (r.detail or "") for r in injection)
    # Nothing was sent: the lab records every message it received.
    assert len(lab.ws_messages) == before, "a frame was sent with ARACHNE_WEB_WS_PROBE off"


async def test_the_websocket_injection_probe_sends_exactly_one_frame(lab: WebLab) -> None:
    """The ladder claim of REQ-DEPTH-002: one inert marker frame, no payload executed."""
    before = len(lab.ws_messages)
    results = await _run(lab, "m3.websocket-injection")
    assert any(result.status == "vulnerable" for result in results)
    sent = lab.ws_messages[before:]
    assert len(sent) == 1, f"expected exactly one message, the lab saw {sent!r}"
    assert sent[0].startswith("ARACHNE_POC_")
    for result in results:
        for item in result.evidence:
            if item.payload.get("payload_executed") is not None:
                assert item.payload["payload_executed"] is False
            if item.payload.get("messages_sent") is not None:
                assert item.payload["messages_sent"] == 1


# --------------------------------------------------------------------------- REQ-DEPTH-004
async def test_the_planted_bundle_secret_is_found_statically(lab: WebLab) -> None:
    """REQ-DEPTH-004, static half: the served bundle's hardcoded credential is reported.

    The lab's ``/app.js`` carries an access-key-id shape. The evidence must name the *detector*
    that fired — never the value (F-08-04) — and must record the DOM sink/source shapes the
    static pass read, together with the fact that no JavaScript engine ran.
    """
    from arachne.modules.m1 import M1_CHECKS

    check_cls = {check.metadata.id: check for check in M1_CHECKS}["m1.js-asset-scan"]
    harness = make_depth_harness(asset=asset_for("url", f"{lab.base_url.rstrip('/')}/app.js"))
    try:
        await harness.prepare([f"{lab.base_url.rstrip('/')}/app.js"])
        ctx = harness.context(check_cls())
        results = [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()
    blob = " ".join(
        f"{key}={value}"
        for result in results
        for item in result.evidence
        for key, value in item.payload.items()
    )
    assert "aws-access-key-id" in blob, [r.title for r in results]
    assert "innerHTML" in blob, "the DOM sink shapes were not recorded"
    assert "dom_analysis" in blob
    assert "AKIA" not in blob, "the credential value reached the evidence"


async def test_the_bundle_secret_is_verified_dynamically(lab: WebLab) -> None:
    """REQ-DEPTH-004, dynamic half: the endpoint behind the bundle answers without credentials.

    The finding proves *impact* — the route the bundle calls answers a caller presenting
    nothing — while the route that does require a credential is the control. The check is L2,
    so the run supplies the proof capability boundary the checks step would build.
    """
    from arachne.modules.m3.client_secret import ClientSecretVerify

    harness = make_depth_harness(asset=asset_for("url", lab.base_url))
    try:
        await harness.prepare(_roots(lab))
        ctx = harness.context(ClientSecretVerify())
        ctx.proof = _proof_access(lab, ctx)
        results = [result async for result in ClientSecretVerify().run(ctx)]
    finally:
        await harness.aclose()
    blob = " ".join(
        f"{key}={value}"
        for result in results
        for item in result.evidence
        for key, value in item.payload.items()
    )
    assert "/api/internal/users" in blob, [r.title for r in results]
    assert "/api/orders" not in blob, "the credential-protected route was reported"
    assert "anonymous_request=True" in blob
    assert "replayed_value=False" in blob


def _proof_access(lab: WebLab, ctx: Any) -> Any:
    """A real :class:`ProofAccess` at L2 with a callback base — what the checks step builds.

    Built through the same constructor the orchestrator uses (rather than a stand-in), so the
    capability boundary the check runs against is the shipped one.
    """
    from arachne.core.lifecycle import MemoryScanStateStore
    from arachne.proof.access import ProofAccess
    from arachne.proof.ledger import ProofLedger

    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    return ProofAccess(
        level=ProofLevel.L2,
        check_id="m3.client-secret-verify",
        scan_id=record.id,
        ledger=ProofLedger(store, record.id),
        callback_base=lab.callback_base or "https://callback.arachne-lab.test",
    )
