"""A complete, minimal ARACHNE check plugin (F-09-01).

This package is the worked example from ``docs/plugin-developer-guide.md``. It adds one
check to the built-in M4 module and registers it through the ``arachne.modules`` entry-point
group, so ``ModuleRegistry.discover()`` finds it without ARACHNE knowing anything about this
package.

It obeys the three framework rules:

* **metadata is validated at class-definition time** — ``CheckMetadata.__post_init__`` runs
  when :class:`ExampleVersionBanner` is defined, so a bad id or an active check without an
  opt-in fails at import, not mid-scan;
* **a check detects, the analyzer decides** (ADR-02) — ``run`` yields a *candidate* with
  evidence and never sets a severity or writes prose;
* **no HTTP library is imported** (ADR-05) — the check uses ``ctx.http``, the shared scoped
  client; ``tests/unit/test_http_hygiene.py`` fails the build if any module imports
  ``requests``/``httpx``/``urllib.request``/...
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.registry import ModuleGroup

__all__ = ["PLUGIN_GROUP", "ExampleVersionBanner"]

#: A marker only a debug build emits on its status page. Real checks keep their markers in
#: managed data (``templates/``), not in code — see the guide's "managed data" section.
_DEBUG_MARKERS: tuple[str, ...] = ("server-status", "debug:", "x-debug-token")


class ExampleVersionBanner(Module):
    """``m4.example-version-banner`` — reports a status path that leaks a debug banner.

    GET-only and inert: the check reads two well-known paths and compares the response with
    the marker set. It never guesses a severity — the analyzer does (ADR-02).
    """

    metadata = CheckMetadata(
        id="m4.example-version-banner",
        module="M4",
        name="example-version-banner",
        version="1.0",
        title="Exposed debug/version banner",
        description=(
            "Requests /server-status and /debug and reports a response that exposes a debug "
            "banner. Read-only: it never changes state and never submits a payload."
        ),
        research_ref="ch04#7",
        # REQ-DET-002: a check that declares no framework item is refused at registration, so
        # the worked example names the WSTG item its evidence bears on (CONF-05, admin/debug
        # interface enumeration) alongside its CWE.
        framework=("WSTG-CONF-05", "CWE-489"),
        cwe="CWE-489",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",  # GET reads only; hybrid needs no active-checks opt-in
        safe=True,
        verifiable=True,
        estimated_requests=2,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client = ctx.http
        if client is None:
            # Dry-run mode: no client exists because nothing may be sent.
            yield ctx.skipped("no HTTP client (dry-run mode)")
            return

        origin = ctx.asset.value.rstrip("/")
        for path in ("/server-status", "/debug"):
            exchange = await client.get(origin + path)
            if exchange.status_code >= 400:
                continue
            body = exchange.body.lower()
            marker = next((item for item in _DEBUG_MARKERS if item in body), None)
            if marker is None:
                continue
            yield ctx.candidate(
                f"debug banner exposed at {path}",
                detail=f"HTTP {exchange.status_code} with marker {marker!r}",
                confidence=0.6,
                evidence=[ctx.evidence("http_response", exchange.to_dict(), source=ctx.asset.key)],
            )


#: The module group the entry point exports. Its id (``M4``) matches the checks' metadata
#: ``module``, so discovery *merges* it into the built-in M4 module rather than refusing it
#: (``ModuleRegistry._merge_by_module``); the group's ``origin`` records where the extra
#: checks came from.
PLUGIN_GROUP = ModuleGroup(
    id="M4",
    title="M4 (example plugin)",
    description="The example-version-banner check, supplied by the plugin guide.",
    version="0.1.0",
    checks=(ExampleVersionBanner,),
    research_chapter="ch04",
    origin="example-plugin",
)
