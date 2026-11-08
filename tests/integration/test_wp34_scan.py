"""WP-34 acceptance: the AI-era surface fires on the planted lab and is silent on every decoy.

REQ-DET-027 asks for at least 24 new registered checks with a framework mapping, a proof level
of L1 or lower, a positive fixture and a decoy it produces **zero** findings on — and, for this
family, that **no check sends a prompt, an instruction or any payload to a model endpoint**.
This suite drives all of them through the real ``CheckContext`` against real HTTP, so the three
claims are measured rather than asserted in prose:

* **positives** — the bare installation answers every covered service's own document, and every
  check reports it;
* **decoys** — the hardened installation (a ``401`` + challenge on every path), the
  network-restricted installation (a ``403`` on every path) and the echoing soft-404 (``200``
  with the requested path as body) produce **nothing** from any check, and each service is also
  run alone so every other check must stay silent on its document;
* **the wire** — the lab records every request line it answered: all ``GET``, and the probe
  paths are exactly the status/index documents the family declares (never an inference route).
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m6 import make_m6_harness
from tests.lab.ai_lab import MODES, SERVICES, published_paths, start_ai_lab

from arachne.modules.m6.ai_surface import (
    AI_SURFACE_CHECKS,
    INFERENCE_PATH_SEGMENTS,
    SERVICE_OF_CHECK,
    probe_paths_of,
)
from arachne.modules.registry import ModuleRegistry

pytestmark = pytest.mark.timeout(300)

REQUIRED_FRAMEWORK_PREFIXES = ("WSTG-", "API", "CWE-", "ATT&CK-", "LLM", "ASI")


def _signals(results: list[Any]) -> list[dict[str, Any]]:
    """Every exposure artifact a check produced (its status is ``vulnerable``)."""
    found: list[dict[str, Any]] = []
    for result in results:
        if getattr(result, "status", None) != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            payload = dict(item.payload)
            if payload.get("signal") == "ai-service-exposure":
                found.append(payload)
    return found


async def _run_check(check: type[Any], harness: Any) -> list[Any]:
    return [result async for result in check().run(harness.context(check()))]


async def _run_all(base_url: str) -> dict[str, list[Any]]:
    """Run every family check against one origin, over one shared harness."""
    harness = make_m6_harness(asset=asset_for("url", base_url))
    try:
        return {check.metadata.id: await _run_check(check, harness) for check in AI_SURFACE_CHECKS}
    finally:
        await harness.aclose()


# --------------------------------------------------------------------------- registry shape
def test_the_registry_reports_the_wp34_total() -> None:
    registry = ModuleRegistry.discover()
    assert len(registry.checks()) == 448


def test_the_family_is_registered_in_m6() -> None:
    from arachne.modules.m6 import M6_CHECKS

    registered = {check.metadata.id for check in M6_CHECKS}
    assert {check.metadata.id for check in AI_SURFACE_CHECKS} <= registered


def test_every_check_is_l1_hybrid_read_only_and_credential_free() -> None:
    for check in AI_SURFACE_CHECKS:
        metadata = check.metadata
        assert metadata.proof.value in {"L0", "L1"}, metadata.id
        assert metadata.safe, metadata.id
        assert not metadata.requires_state_attestation, metadata.id
        assert not metadata.requires_active_checks, metadata.id
        assert not metadata.requires_credentials, metadata.id
        assert metadata.type == "hybrid", metadata.id
        assert metadata.enabled_by_default, metadata.id


def test_every_check_carries_a_framework_mapping() -> None:
    for check in AI_SURFACE_CHECKS:
        mapping = check.metadata.framework
        assert mapping, check.metadata.id
        assert any(item.startswith(REQUIRED_FRAMEWORK_PREFIXES) for item in mapping), (
            check.metadata.id,
            mapping,
        )
        assert check.metadata.cwe in mapping, (check.metadata.id, mapping)


def test_every_check_serves_one_named_service() -> None:
    for check in AI_SURFACE_CHECKS:
        assert SERVICE_OF_CHECK[check.metadata.id] in SERVICES


def test_no_probe_path_names_an_inference_operation() -> None:
    """The structural control: no declared path names a model operation, by segment."""
    for check in AI_SURFACE_CHECKS:
        for path in probe_paths_of(check):
            segments = {segment.split(".")[0] for segment in path.lower().split("/") if segment}
            assert not (segments & INFERENCE_PATH_SEGMENTS), (check.metadata.id, path)


def test_an_inference_path_cannot_even_be_declared() -> None:
    """A check that tried to probe ``/api/generate`` is refused at import."""
    from arachne.modules.m6.ai_surface import AiSurfaceCheck, AiSurfaceError, ai_surface_metadata

    with pytest.raises(AiSurfaceError, match="inference operation"):

        class Forbidden(AiSurfaceCheck):
            probe_paths = ("/api/generate",)
            metadata = ai_surface_metadata(
                name="forbidden",
                title="t",
                description="d",
                research_ref="ch06#14",
                cwe="CWE-306",
                framework=("LLM01:2025", "CWE-306"),
                compliance=(),
                severity="high",
                estimated_requests=1,
            )


def test_the_family_has_no_write_verb_in_its_source() -> None:
    """No HTTP method literal other than GET appears in the family's module."""
    import inspect
    from pathlib import Path

    source = Path(inspect.getfile(AI_SURFACE_CHECKS[0])).read_text(encoding="utf-8")
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        assert verb not in source, verb


# --------------------------------------------------------------------------- positives
async def test_every_check_reports_its_planted_service() -> None:
    with start_ai_lab() as lab:
        results = await _run_all(lab.base_url)
    reported = {
        check_id: [payload["endpoint"] for payload in _signals(items)]
        for check_id, items in results.items()
    }
    for check in AI_SURFACE_CHECKS:
        endpoints = reported[check.metadata.id]
        assert endpoints, check.metadata.id
        service = SERVICE_OF_CHECK[check.metadata.id]
        for endpoint in endpoints:
            path = endpoint.split(lab.base_url, 1)[-1]
            assert path in published_paths(service), (check.metadata.id, path)


async def test_every_endpoint_reported_is_the_check_s_own_document() -> None:
    """No check reports a path that belongs to another service (the cross-service control)."""
    with start_ai_lab() as lab:
        results = await _run_all(lab.base_url)
    path_owner = {path: service for service in SERVICES for path in published_paths(service)}
    for check in AI_SURFACE_CHECKS:
        service = SERVICE_OF_CHECK[check.metadata.id]
        for payload in _signals(results[check.metadata.id]):
            path = str(payload["endpoint"]).split(lab.base_url, 1)[-1]
            assert path_owner[path] == service, (check.metadata.id, path)


# --------------------------------------------------------------------------- decoys
async def test_a_single_service_installation_fires_only_its_own_checks() -> None:
    """Every service alone: its own checks report, every other check stays silent."""
    cells = 0
    for service in SERVICES:
        with start_ai_lab(only=service) as lab:
            results = await _run_all(lab.base_url)
        for check in AI_SURFACE_CHECKS:
            check_id = check.metadata.id
            fired = bool(_signals(results[check_id]))
            if SERVICE_OF_CHECK[check_id] == service:
                assert fired, check_id
            else:
                assert not fired, (check_id, service)
            cells += 1
    assert cells == len(AI_SURFACE_CHECKS) * len(SERVICES)


@pytest.mark.parametrize("mode", ["hardened", "restricted", "soft404"])
async def test_every_decoy_installation_is_silent(mode: str) -> None:
    """The requirement's decoys: authenticated, network-restricted, and the soft-404 trap."""
    with start_ai_lab(mode=mode) as lab:
        results = await _run_all(lab.base_url)
    for check in AI_SURFACE_CHECKS:
        assert _signals(results[check.metadata.id]) == [], (check.metadata.id, mode)
        assert [result.status for result in results[check.metadata.id]] == ["not_vulnerable"], (
            check.metadata.id,
            mode,
        )


async def test_the_hardened_installation_answers_a_challenge() -> None:
    """The decoy is a live deployment refusing an anonymous caller, not an absence."""
    import httpx

    with start_ai_lab(mode="hardened") as lab:
        for service in SERVICES:
            for path in published_paths(service):
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{lab.base_url}{path}")
                assert response.status_code == 401, (service, path)
                assert response.headers.get("www-authenticate"), (service, path)


async def test_the_restricted_installation_refuses() -> None:
    import httpx

    with start_ai_lab(mode="restricted") as lab:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{lab.base_url}{published_paths('ollama')[0]}")
    assert response.status_code == 403


# --------------------------------------------------------------------------- the wire
async def test_every_request_the_family_makes_is_a_get() -> None:
    with start_ai_lab() as lab:
        await _run_all(lab.base_url)
    assert lab.requests, "the checks issued no request; the assertion would be vacuous"
    assert all(entry.startswith("GET ") for entry in lab.requests), [
        entry for entry in lab.requests if not entry.startswith("GET ")
    ]


async def test_the_paths_probed_are_exactly_the_declared_status_documents() -> None:
    with start_ai_lab() as lab:
        await _run_all(lab.base_url)
    probed = {entry.split(" ", 1)[1] for entry in lab.requests}
    declared = {path for check in AI_SURFACE_CHECKS for path in probe_paths_of(check)}
    assert probed == declared
    for path in probed:
        assert path in declared


def test_the_mode_vocabulary_is_closed() -> None:
    assert MODES == ("bare", "hardened", "restricted", "soft404")
