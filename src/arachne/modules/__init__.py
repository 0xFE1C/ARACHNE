"""The ARACHNE plugin API: write a check, register it, get a report (F-09-01).

A check is a :class:`~arachne.modules.base.Module` subclass with declared metadata and one
async generator:

.. code-block:: python

    from arachne.core.target import TargetKind
    from arachne.modules.base import CheckMetadata, Module
    from arachne.modules.context import CheckContext

    class MyCheck(Module):
        metadata = CheckMetadata(
            id="m4.my-check",
            module="M4",
            name="my-check",
            version="1.0",
            title="My check",
            description="Requests /status and looks for a debug banner.",
            research_ref="chNN#M",  # the corpus reference, e.g. "ch04#6"
            proof="L1",  # the proof ladder: how far the check may go (L0..L4)
            cwe="CWE-489",
            target_kinds=(TargetKind.URL,),
            type="active",
            requires_active_checks=True,
            estimated_requests=1,
        )

        async def run(self, ctx: CheckContext):
            response = await ctx.http.get(ctx.asset.value + "status")
            if "debug" in response.body:
                yield ctx.candidate(
                    "debug banner exposed",
                    confidence=0.6,
                    evidence=[ctx.evidence("http_response", response.to_dict())],
                )

Package it as an ``arachne.modules`` entry point returning your
:class:`~arachne.modules.registry.ModuleGroup` (or the check classes) and
``ModuleRegistry.discover()`` picks it up (F-02-10, F-09-01).

Three rules the framework enforces, so a plugin cannot quietly break the scanner:

* metadata is validated when the class is defined;
* a check never decides severity and never writes prose — it yields candidates with
  evidence, and the analyzer scores them (ADR-02);
* every outbound request goes through ``ctx.http`` / ``ctx.osint`` — no check imports an
  HTTP library (ADR-05).
"""

from __future__ import annotations

from arachne.modules.base import (
    ASSET_KINDS,
    Asset,
    CheckMetadata,
    CheckType,
    Module,
    ProofLevel,
    SeverityHint,
)
from arachne.modules.context import CheckContext, ModuleConfig, mask_secret, require_osint
from arachne.modules.registry import (
    ENTRY_POINT_GROUP,
    ModuleGroup,
    ModuleRegistry,
    catalog_from_registry,
)

__all__ = [
    "ASSET_KINDS",
    "ENTRY_POINT_GROUP",
    "Asset",
    "CheckContext",
    "CheckMetadata",
    "CheckType",
    "Module",
    "ModuleConfig",
    "ModuleGroup",
    "ModuleRegistry",
    "ProofLevel",
    "SeverityHint",
    "catalog_from_registry",
    "mask_secret",
    "require_osint",
]
