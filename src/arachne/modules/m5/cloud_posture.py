"""M5 continuous cloud-config posture (S23, REQ-POSTURE-001) — one read-only GET per run.

``m5.cloud-posture`` is the module's *watching* check. Where the other cloud checks probe
for exposure once, this one reads a cloud-config **state snapshot** — the normalized
export a read-only collector endpoint serves, or an AWS/Azure/GCP read-only list response
directly — and does two things with it:

1. **Point-in-time posture**: the estate policies (corpus section ``posture.policies``)
   are evaluated over the normalized resources, and a breach is a finding like any other.
2. **Drift** (the continuous half): the snapshot is diffed against the *last baseline*
   the previous run committed (``posture_baselines``, through :class:`PostureAccess`),
   and every change is emitted with **before/after** in its artifact — a finding when the
   new state violates a policy, an observation otherwise. Removals are observed too: a
   resource vanishing is exactly the "did the fix land?" signal the fix-verification
   loop closes on.

Safety contract: one bounded GET per configured snapshot path (read-only, through the
scoped client, like every M5 request); the optional bearer token rides the environment
(``ARACHNE_M5_POSTURE_TOKEN``) and reaches only the ``Authorization`` header; the
snapshot body is bounded and the evidence carries the *redacted* document, never a
credential. Without a wired baseline store the check degrades to stateless (policies
only, note recorded) — drift needs the deployment's continuous wiring, which is what
keeps a plain scan from ever inventing a baseline.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import (
    EndpointCheck,
    corpus_for,
    fetch_page,
    finding_cap,
    http_or_skip,
    m5_candidate,
    skip,
)
from arachne.posture.state import (
    CloudSnapshot,
    PolicyViolation,
    ResourceDelta,
    config_violates,
    evaluate_policies,
    parse_snapshot_document,
)

__all__ = ["CloudPosture"]


class CloudPosture(EndpointCheck, Module):
    """``m5.cloud-posture`` — continuous cloud-config posture + drift (ch05#1)."""

    metadata = CheckMetadata(
        id="m5.cloud-posture",
        module="M5",
        name="cloud-posture",
        version="1.0",
        title="Cloud configuration posture and drift",
        description=(
            "Reads a cloud-config state snapshot with one bounded read-only GET (the "
            "normalized export a read-only collector endpoint serves, or an AWS/Azure/GCP "
            "list response), evaluates the estate policies over it, and — when the "
            "deployment wires the continuous baseline store — diffs it against the last "
            "baseline and emits delta findings carrying before/after. On schedules this is "
            "the continuous mode: findings on changes, not only point-in-time state. The "
            "snapshot endpoint is declared (a URL target or endpoint:<url>); nothing is "
            "written anywhere, to the target or the cloud."
        ),
        research_ref="ch05#1",
        cwe="CWE-16",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        base = self._endpoint(ctx)
        if base is None:
            yield skip(
                ctx,
                "no cloud-config snapshot endpoint: declare a URL target or endpoint:<url> "
                "(a provider reference alone names no read-only endpoint)",
            )
            return
        document = await self._fetch_snapshot(
            ctx, base, corpus.posture_snapshot_paths(), self._headers(ctx)
        )
        if document is None:
            yield skip(
                ctx,
                f"no cloud-config snapshot served at {base} (or its configured snapshot "
                "paths); read-only GET only, nothing else was sent",
            )
            return
        try:
            snapshot = parse_snapshot_document(document, source=base)
        except Exception as exc:  # a malformed snapshot is data, not a crash
            yield ctx.error(exc)
            return
        snapshot = self._bounded(ctx, snapshot)

        findings = 0
        for violation in evaluate_policies(snapshot, corpus.posture_policies())[: finding_cap(ctx)]:
            findings += 1
            yield self._policy_candidate(ctx, violation)

        deltas: tuple[ResourceDelta, ...] = ()
        access = getattr(ctx, "posture", None)
        if access is not None and getattr(access, "available", False):
            if not getattr(access, "drift_enabled", True):
                yield ctx.info(
                    "Drift detection disabled",
                    detail=(
                        "drift is disabled for this deployment; ran point-in-time posture only"
                    ),
                )
            else:
                deltas = access.observe(snapshot)
                policies = {policy.id: policy for policy in corpus.posture_policies()}
                for delta in deltas[: finding_cap(ctx)]:
                    findings += 1
                    yield self._delta_result(ctx, delta, policies)
        else:
            yield ctx.info(
                "Drift detection unavailable",
                detail=(
                    "no continuous baseline store is wired for this step; ran point-in-time "
                    "posture only (continuous mode needs a schedule over a deployment with "
                    "the posture store)"
                ),
            )
        if not findings:
            yield ctx.clean(
                "no posture violation or drift found",
                detail=(
                    f"evaluated {len(snapshot.resources)} resource(s) against the estate policies"
                ),
            )

    # ------------------------------------------------------------------ pieces
    def _endpoint(self, ctx: CheckContext) -> str | None:
        value = ctx.asset.value.strip()
        if ctx.asset.kind == "url":
            return value
        provider, _, reference = value.partition(":")
        if provider.lower() == "endpoint" and reference:
            return reference if "://" in reference else f"https://{reference}"
        return None

    def _headers(self, ctx: CheckContext) -> dict[str, str]:
        token = ctx.config.m5.posture_token
        if token is None:
            return {}
        value = token.get_secret_value().strip()
        return {"Authorization": f"Bearer {value}"} if value else {}

    async def _fetch_snapshot(
        self,
        ctx: CheckContext,
        base: str,
        paths: tuple[str, ...],
        headers: Mapping[str, str],
    ) -> Any:
        """The first candidate URL serving a JSON object (bounded GETs, in order).

        Candidates: the declared URL itself (when an operator points the target at the
        snapshot directly), then the URL joined with each configured snapshot path.
        """
        root = base.rstrip("/")
        candidates = [root]
        if not any(root.endswith(path) for path in paths):
            candidates.extend(
                root + "/" + path.lstrip("/") for path in paths or ("/posture/snapshot",)
            )
        for url in candidates:
            page = await fetch_page(ctx, url, session=False, headers=dict(headers))
            if page is None or page.status != 200:
                continue
            try:
                document = json.loads(page.body)
            except json.JSONDecodeError:
                continue
            if isinstance(document, Mapping):
                return document
        return None

    def _bounded(self, ctx: CheckContext, snapshot: CloudSnapshot) -> CloudSnapshot:
        """Cap the inventory at the deployment's bound (a snapshot must not become a dump)."""
        limit = ctx.config.m5.posture_max_resources
        if len(snapshot.resources) <= limit:
            return snapshot
        return CloudSnapshot(
            provider=snapshot.provider,
            resources=tuple(snapshot.resources[:limit]),
            source=snapshot.source,
            collected_at=snapshot.collected_at,
            account=snapshot.account,
        )

    def _policy_candidate(self, ctx: CheckContext, violation: PolicyViolation) -> CheckResult:
        return m5_candidate(
            ctx,
            f"Cloud posture: {violation.policy_id} on {violation.resource_key}",
            artifact={
                "signal": "cloud-posture",
                "family": "posture",
                "policy": violation.policy_id,
                "severity_hint": violation.severity,
                "resource": violation.resource_key,
                "provider": violation.provider,
                "service": violation.service,
                "observed": violation.observed,
            },
            confidence=0.85,
            detail=violation.hint
            or f"{violation.policy_id} breach observed in the live configuration",
            source=violation.resource_key,
        )

    def _delta_result(
        self,
        ctx: CheckContext,
        delta: ResourceDelta,
        policies: Mapping[str, Any],
    ) -> CheckResult:
        """One drift delta: before/after in the artifact, finding when policy-relevant."""
        after = dict(delta.after or {})
        breaches = sorted(
            {
                policy_id
                for policy_id, policy in policies.items()
                if config_violates(after, policy)
            }
        )
        artifact: dict[str, Any] = {
            "signal": "cloud-config-drift",
            "family": "posture",
            "change": delta.change,
            "resource": delta.resource_key,
            "provider": delta.provider,
            "service": delta.service,
            "changed_keys": list(delta.changed_keys),
            "before": delta.before,
            "after": delta.after,
            "policies_after": breaches,
        }
        if delta.change == "removed":
            return ctx.info(
                f"Cloud resource removed: {delta.resource_key}",
                detail=(
                    f"{delta.resource_key} is no longer in the estate snapshot; if it carried "
                    "an open finding, run the fix verification to close it on this evidence"
                ),
                evidence=[ctx.evidence("artifact", artifact, source=delta.resource_key)],
            )
        if breaches:
            return m5_candidate(
                ctx,
                f"Cloud drift introduced a policy breach: {delta.resource_key}",
                artifact=artifact,
                confidence=0.9,
                detail=(
                    f"{delta.change} of {delta.resource_key} changed "
                    f"{', '.join(delta.changed_keys) or 'the configuration'}; the new state "
                    f"breaches {', '.join(breaches)}"
                ),
                source=delta.resource_key,
            )
        return ctx.info(
            f"Cloud configuration changed: {delta.resource_key}",
            detail=(
                f"{delta.change} of {delta.resource_key} changed "
                f"{', '.join(delta.changed_keys) or 'the configuration'}; the new state passes "
                "the estate policies"
            ),
            evidence=[ctx.evidence("artifact", artifact, source=delta.resource_key)],
        )
