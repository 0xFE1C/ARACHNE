"""The scan plan and the dry-run planner (F-01-03, F-01-10).

The planner turns a target definition plus module selection into an ordered, inspectable
:class:`ScanPlan`: which pipeline steps will run, which checks are included, which are
withheld and why, and how many requests the scan is expected to make.

**It never touches the network.** Every estimate is either declared in the catalogue
(``estimated_requests``) or computed arithmetically from the target definition — a CIDR's
host count comes from ``ipaddress``, never from a probe. This is what makes
``arachne scan --dry-run`` a true zero-request mode (F-01-10) and what lets an operator
plan a scan before an attestation exists.

Steps are the ordered pipeline of F-01-03; ``ScanStep`` lives here because the plan *is*
the pipeline, and the lifecycle machine (``core/lifecycle.py``) drives exactly these steps.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from arachne.core.catalog import CheckSpec, PlanningCatalog
from arachne.core.config import PlannerSettings
from arachne.core.proof import ProofLevel
from arachne.core.safety import Scope
from arachne.core.target import ScanRequest, TargetKind, TargetSelector

__all__ = [
    "DEFAULT_PIPELINE",
    "MODULE_STEP",
    "PLAN_VERSION",
    "AssetEstimate",
    "PlanStep",
    "PlanTotals",
    "PlannedCheck",
    "Planner",
    "ScanPlan",
    "ScanStep",
]

#: Bumped when the serialized plan changes shape.
PLAN_VERSION: Final = "1.0"

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")


class ScanStep(StrEnum):
    """The ordered scan pipeline (F-01-03)."""

    RECON = "recon"
    DISCOVERY = "discovery"
    CHECKS = "checks"
    ANALYSIS = "analysis"
    CORRELATION = "correlation"
    #: S21 (area AGENT): the agentic expansion step. It is **not** in the default pipeline:
    #: the orchestrator appends it only for a scan that enabled agentic reasoning, so a
    #: default scan's step list is byte-for-byte what it was before S21.
    HYPOTHESIS = "hypothesis"
    REPORTING = "reporting"


#: F-01-03's pipeline, in order. The optional verification and diff stages of the
#: lifecycle diagram belong to later phases and are not steps here.
#: ``HYPOTHESIS`` (S21) is deliberately absent — it is opt-in per scan, see the enum.
DEFAULT_PIPELINE: Final[tuple[ScanStep, ...]] = (
    ScanStep.RECON,
    ScanStep.DISCOVERY,
    ScanStep.CHECKS,
    ScanStep.ANALYSIS,
    ScanStep.CORRELATION,
    ScanStep.REPORTING,
)


#: Where the agentic step goes when a scan enables it: after correlation (hypotheses are
#: derived from analysed, correlated findings) and before reporting (its extra findings must
#: reach the report).
HYPOTHESIS_STEP_POSITION: Final[int] = DEFAULT_PIPELINE.index(ScanStep.CORRELATION) + 1


def pipeline_with_hypotheses(pipeline: Sequence[ScanStep]) -> tuple[ScanStep, ...]:
    """``pipeline`` with the agentic step inserted before reporting, once."""
    if ScanStep.HYPOTHESIS in pipeline:
        return tuple(pipeline)
    ordered = list(pipeline)
    position = (
        ordered.index(ScanStep.CORRELATION) + 1 if ScanStep.CORRELATION in ordered else len(ordered)
    )
    ordered.insert(position, ScanStep.HYPOTHESIS)
    return tuple(ordered)


#: Which pipeline step a module's checks belong to (/"Detect").
MODULE_STEP: Final[dict[str, ScanStep]] = {
    "M1": ScanStep.RECON,
    "M2": ScanStep.DISCOVERY,
    "M3": ScanStep.CHECKS,
    "M4": ScanStep.CHECKS,
    "M5": ScanStep.CHECKS,
    "M6": ScanStep.CHECKS,
}

_STEP_DESCRIPTIONS: Final[dict[ScanStep, str]] = {
    ScanStep.RECON: "Passive reconnaissance and OSINT (M1)",
    ScanStep.DISCOVERY: "Host, port and service discovery (M2)",
    ScanStep.CHECKS: "Per-module vulnerability checks (M3-M6)",
    ScanStep.ANALYSIS: "Analyzer triage, scoring and narrative",
    ScanStep.CORRELATION: "Cross-signal correlation into compound findings",
    ScanStep.HYPOTHESIS: "Agentic hypothesis expansion (S21, opt-in)",
    ScanStep.REPORTING: "Report rendering",
}

#: Steps whose handler does real work without needing an *implemented* check behind it:
#: ``recon`` and ``discovery`` also do the built-in offline work (seeding the declared targets,
#: deriving endpoint candidates), ``analysis``/``correlation`` operate on whatever the
#: earlier steps produced, and ``hypothesis`` (S21) derives its own work from the analysed
#: findings. A handled step outside this set still needs at least one implemented
#: check, otherwise its handler would run and immediately report a skip.
_SELF_CONTAINED_STEPS: Final[frozenset[ScanStep]] = frozenset(
    {
        ScanStep.RECON,
        ScanStep.DISCOVERY,
        ScanStep.ANALYSIS,
        ScanStep.CORRELATION,
        ScanStep.HYPOTHESIS,
    }
)


class AssetEstimate(BaseModel):
    """What one target selector contributes to the plan, computed offline."""

    model_config = _MODEL_CONFIG

    kind: TargetKind
    value: str
    #: Concrete hosts known without discovery (1 for a name, the range size for a CIDR).
    host_count: int = Field(ge=0)
    #: Hosts used for request estimation — ``host_count`` plus declared assumptions.
    request_units: int = Field(ge=0)
    #: True when the range was larger than ``max_hosts_per_network`` and was capped.
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "host_count": self.host_count,
            "request_units": self.request_units,
            "capped": self.capped,
        }


#: Why a planned check is not part of the scan. Structured, so a consumer (the CLI, the
#: API of S12, a test) does not have to match on prose.
SkipCode = Literal[
    "module-not-selected",
    "no-applicable-target",
    "active-checks-not-opted-in",
    "active-checks-not-authorized",
    #: S15 (REQ-PROOF-001/003): an L3/L4 check is never planned into a scan that did not
    #: name it — planning is module-granular for L1 checks, but a state-changing proof is
    #: opted in per check, exactly as the runtime selects it.
    "proof-not-opted-in",
    #: S21 (REQ-AGENT-001/005): ``options.modules.only`` is an exact allowlist, so every
    #: check outside it is withheld. A hypothesis run uses this to execute exactly the
    #: probes reasoning asked for and nothing else.
    "check-not-allowlisted",
]


class PlannedCheck(BaseModel):
    """One catalogue check as it appears in a plan: included, or withheld with a reason."""

    model_config = _MODEL_CONFIG

    module: str
    name: str
    version: str
    title: str
    research_ref: str
    cwe: str | None = None
    requires_active_checks: bool = False
    #: The check's declared proof level (REQ-PROOF-001) — how far it *may* go.
    proof: ProofLevel = ProofLevel.L1
    #: What this plan will actually let it do: the declared level minus any downgrade
    #: (an L2 check without a configured OOB service runs at L1, with a recorded note).
    #: Never higher than :attr:`proof` — an upgrade cannot happen silently (REQ-PROOF-003).
    proof_effective: ProofLevel = ProofLevel.L1
    #: Why ``proof_effective`` differs from ``proof``, or the attestation an L3/L4 check
    #: demands of a live scan (REQ-PROOF-004: printed, and refused when missing).
    proof_note: str | None = None
    #: False for a check the catalogue plans but this build cannot execute (S3 makes the
    #: M1 checks implemented and leaves M2-M6 planned). Reported so a plan never promises
    #: work the binary cannot do.
    implemented: bool = False
    included: bool
    skip_code: SkipCode | None = None
    skip_reason: str | None = None
    applicable_assets: int = Field(ge=0)
    estimated_requests: int = Field(ge=0)

    @property
    def key(self) -> str:
        return f"{self.module}/{self.name}@{self.version}"


class PlanStep(BaseModel):
    """One pipeline step in the plan."""

    model_config = _MODEL_CONFIG

    step: ScanStep
    order: int = Field(ge=1)
    description: str
    estimated_requests: int = Field(ge=0)
    #: True when a handler is registered for this step in this build.
    executable: bool = True
    skipped: bool = False
    skip_reason: str | None = None
    checks: tuple[str, ...] = ()
    #: How many of ``checks`` this build cannot execute yet.
    planned_only: int = Field(default=0, ge=0)


class PlanTotals(BaseModel):
    """The plan's bottom line."""

    model_config = _MODEL_CONFIG

    targets: int = Field(ge=0)
    exclusions: int = Field(ge=0)
    assets: int = Field(ge=0)
    hosts: int = Field(ge=0)
    modules: tuple[str, ...] = ()
    included_checks: int = Field(ge=0)
    withheld_checks: int = Field(ge=0)
    #: Included checks this build cannot execute yet (planned-only, S3+ modules).
    planned_only_checks: int = Field(default=0, ge=0)
    active_checks: int = Field(ge=0)
    estimated_requests: int = Field(ge=0)
    capped_networks: int = Field(ge=0)
    #: Included checks at L2+ (out-of-band, one-shot command, state change) and at L3/L4
    #: (each demands the state-change attestation), plus how many were downgraded below
    #: their declared level (REQ-PROOF-003/004: printed in every plan).
    proof_l2plus: int = Field(default=0, ge=0)
    proof_state_changes: int = Field(default=0, ge=0)
    proof_downgrades: int = Field(default=0, ge=0)


class ScanPlan(BaseModel):
    """A complete, reviewable description of what a scan would do."""

    model_config = _MODEL_CONFIG

    plan_version: str = PLAN_VERSION
    dry_run: bool
    target_name: str
    engine: str
    created_at: datetime
    scope: dict[str, list[str]]
    deployment_scope: dict[str, list[str]] | None = None
    attestation: dict[str, Any] | None = None
    #: True when a live scan would pass the authorization gate right now.
    live_ready: bool = False
    warnings: tuple[str, ...] = ()
    assets: tuple[AssetEstimate, ...] = ()
    steps: tuple[PlanStep, ...] = ()
    checks: tuple[PlannedCheck, ...] = ()
    totals: PlanTotals

    @property
    def estimated_requests(self) -> int:
        return self.totals.estimated_requests

    @property
    def included_checks(self) -> tuple[PlannedCheck, ...]:
        return tuple(check for check in self.checks if check.included)

    @property
    def withheld_checks(self) -> tuple[PlannedCheck, ...]:
        return tuple(check for check in self.checks if not check.included)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe document (the ``--json`` dry-run output)."""
        return self.model_dump(mode="json")


def expand_targets(
    targets: tuple[TargetSelector, ...], settings: PlannerSettings
) -> tuple[AssetEstimate, ...]:
    """Estimate each selector's asset count without any network access.

    * a domain or host pattern is one host, plus ``assumed_subdomains_per_domain`` for
      request estimation only (the plan prints the assumption);
    * a CIDR's size is arithmetic (``ipaddress``); IPv4 network and broadcast addresses are
      excluded for prefixes that have them, and the result is capped at
      ``max_hosts_per_network`` so a wide range cannot produce a nonsense plan;
    * a Git or cloud reference is one unit and contributes no host.
    """
    assumed = settings.assumed_subdomains_per_domain
    estimates: list[AssetEstimate] = []
    for selector in targets:
        kind = selector.kind
        if kind is TargetKind.DOMAIN:
            estimates.append(
                AssetEstimate(
                    kind=kind, value=selector.value, host_count=1, request_units=1 + assumed
                )
            )
        elif kind is TargetKind.DOMAIN_PATTERN:
            # A glob cannot be enumerated offline; the assumption covers it either way.
            units = 1 + assumed if selector.value.startswith("*.") else max(1, assumed or 1)
            estimates.append(
                AssetEstimate(kind=kind, value=selector.value, host_count=1, request_units=units)
            )
        elif kind is TargetKind.URL or kind is TargetKind.IP:
            estimates.append(
                AssetEstimate(kind=kind, value=selector.value, host_count=1, request_units=1)
            )
        elif kind is TargetKind.CIDR:
            estimates.append(_estimate_network(selector.value, settings))
        else:  # GIT / CLOUD: a reference, not a host.
            estimates.append(
                AssetEstimate(kind=kind, value=selector.value, host_count=0, request_units=1)
            )
    return tuple(estimates)


def _estimate_network(value: str, settings: PlannerSettings) -> AssetEstimate:
    network = ipaddress.ip_network(value, strict=False)
    if network.version == 4 and network.prefixlen <= 30:
        # Network and broadcast addresses are not host addresses in a usable IPv4 subnet.
        size = max(network.num_addresses - 2, 0)
    else:
        size = network.num_addresses
    capped = size > settings.max_hosts_per_network
    units = min(size, settings.max_hosts_per_network)
    return AssetEstimate(
        kind=TargetKind.CIDR, value=value, host_count=units, request_units=units, capped=capped
    )


class Planner:
    """Builds :class:`ScanPlan` objects from a scan request (F-01-10)."""

    def __init__(
        self,
        catalog: PlanningCatalog,
        *,
        settings: PlannerSettings | None = None,
    ) -> None:
        self.catalog = catalog
        self.settings = settings or PlannerSettings()

    def plan(
        self,
        request: ScanRequest,
        *,
        dry_run: bool,
        scope: Scope,
        deployment_scope: Scope | None = None,
        active_checks_allowed: bool,
        handled_steps: frozenset[ScanStep],
        implemented_checks: frozenset[str] = frozenset(),
        pipeline: tuple[ScanStep, ...] = DEFAULT_PIPELINE,
        now: datetime | None = None,
        oob_available: bool = False,
        state_changes_authorized: bool = False,
    ) -> ScanPlan:
        """Compute the plan.

        ``scope`` is the effective scope (the definition's scope intersected with the
        deployment allowlist, when one is configured); ``active_checks_allowed`` must
        already fold together the operator's opt-in and the attestation's authorization,
        because those are policy decisions the planner must not make on its own.
        ``implemented_checks`` is the set of ``module/name@version`` keys the module
        registry can execute in this build; a planned check outside it is reported as
        planned-only rather than as work that will happen. ``oob_available`` and
        ``state_changes_authorized`` are the proof gate's plan-time inputs (S15): an
        unavailable capability downgrades a check with a recorded note, and a missing
        state-change attestation is printed as a live-scan refusal (REQ-PROOF-003/004).
        """
        moment = (now or datetime.now(UTC)).astimezone(UTC)
        definition = request.target
        options = request.options
        assets = expand_targets(definition.targets, self.settings)
        kinds = frozenset(asset.kind for asset in assets)
        units_by_kind: dict[TargetKind, int] = {}
        for asset in assets:
            units_by_kind[asset.kind] = units_by_kind.get(asset.kind, 0) + asset.request_units

        named_checks = frozenset(options.modules.checks)
        only = options.modules.only
        planned = tuple(
            self._plan_check(
                check,
                kinds=kinds,
                units_by_kind=units_by_kind,
                selected=options.modules.allows(check.id),
                not_allowlisted=bool(only) and check.id not in only,
                active_checks_allowed=active_checks_allowed,
                active_checks_requested=options.active_checks,
                implemented=check.key in implemented_checks,
                oob_available=oob_available,
                state_changes_authorized=state_changes_authorized,
                # S21 note: ``options.proof_approved`` deliberately does **not** name a check
                # for the main plan. It authorizes a *proposal*; the proposal's own subset plan
                # names it, and that plan still has to pass the proof gate. Naming it here
                # would make an approved L3 check part of every scan the operator admitted it
                # for — a widening of what a scan does, which is the opposite of the point.
                named=(
                    check.key in named_checks
                    or f"{check.module.lower()}.{check.name}" in named_checks
                ),
            )
            for check in self.catalog.checks
        )
        steps = self._plan_steps(
            planned,
            handled_steps=handled_steps,
            implemented_steps=self._implemented_steps(planned, handled_steps),
            pipeline=pipeline,
        )
        totals = PlanTotals(
            targets=len(definition.targets),
            exclusions=len(definition.exclusions),
            assets=len(assets),
            hosts=sum(asset.host_count for asset in assets),
            modules=tuple(dict.fromkeys(check.module for check in planned if check.included)),
            included_checks=sum(1 for check in planned if check.included),
            withheld_checks=sum(1 for check in planned if not check.included),
            planned_only_checks=sum(
                1 for check in planned if check.included and not check.implemented
            ),
            active_checks=sum(
                1 for check in planned if check.included and check.requires_active_checks
            ),
            estimated_requests=sum(check.estimated_requests for check in planned if check.included),
            capped_networks=sum(1 for asset in assets if asset.capped),
            proof_l2plus=sum(
                1 for check in planned if check.included and check.proof_effective.is_opt_in
            ),
            proof_state_changes=sum(
                1 for check in planned if check.included and check.proof.needs_state_attestation
            ),
            proof_downgrades=sum(
                1 for check in planned if check.proof_effective.rank < check.proof.rank
            ),
        )
        return ScanPlan(
            dry_run=dry_run,
            target_name=definition.name,
            engine=options.engine.value,
            created_at=moment,
            scope=scope.describe(),
            deployment_scope=deployment_scope.describe() if deployment_scope is not None else None,
            attestation=definition.attestation.summary() if definition.attestation else None,
            live_ready=definition.is_live_ready(active_checks=options.active_checks, now=moment),
            warnings=self._warnings(
                request, planned, assets, active_checks_allowed, state_changes_authorized
            ),
            assets=assets,
            steps=steps,
            checks=planned,
            totals=totals,
        )

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _plan_check(
        check: CheckSpec,
        *,
        kinds: frozenset[TargetKind],
        units_by_kind: dict[TargetKind, int],
        selected: bool,
        not_allowlisted: bool = False,
        active_checks_allowed: bool,
        active_checks_requested: bool,
        implemented: bool,
        oob_available: bool = False,
        state_changes_authorized: bool = False,
        named: bool = False,
    ) -> PlannedCheck:
        applicable = sum(units_by_kind.get(kind, 0) for kind in check.target_kinds if kind in kinds)
        code: SkipCode | None = None
        reason: str | None = None
        if not selected:
            if not_allowlisted:
                code = "check-not-allowlisted"
                reason = (
                    "this scan sets an exact check allowlist (options.modules.only) and "
                    f"{check.id} is not on it"
                )
            else:
                code = "module-not-selected"
                reason = f"module {check.module} is not selected for this scan"
        elif applicable == 0:
            code = "no-applicable-target"
            reason = "no applicable target in scope"
        elif check.proof.needs_state_attestation and not named:
            # An L3/L4 check changes (or proves execution on) the target: it runs only when
            # the operator named it, exactly as the runtime's opt-in selects it (REQ-PROOF-001).
            code = "proof-not-opted-in"
            reason = (
                "a state-changing proof is never planned unless the check is named "
                "(options.modules.checks) and the attestation authorizes state changes"
            )
        elif check.requires_active_checks and not active_checks_allowed:
            if active_checks_requested:
                code = "active-checks-not-authorized"
                reason = "active checks were requested but the attestation does not authorize them"
            else:
                code = "active-checks-not-opted-in"
                reason = "requires active checks (opt-in and an authorizing attestation)"
        included = code is None
        # The proof ladder (S15, REQ-PROOF-003/004): the effective level starts at the
        # declaration and can only go *down*. An L2 check without a configured OOB service
        # is downgraded to its in-band L1 behaviour with a recorded note — never silently
        # upgraded, and never upgraded by the planner at all. L3/L4 stay declared in the
        # plan (a dry run prints what they would need); the orchestrator refuses a *live*
        # scan that lacks the attestation.
        proof = check.proof
        proof_effective = proof
        proof_note: str | None = None
        if included and proof.is_opt_in and proof.rank == ProofLevel.L2.rank and not oob_available:
            proof_effective = ProofLevel.L1
            proof_note = (
                "downgraded to L1: no out-of-band callback service is configured "
                "(ARACHNE_WEB_SSRF_CALLBACK); the out-of-band half of this check will not run"
            )
        elif included and proof.needs_state_attestation and not state_changes_authorized:
            proof_note = (
                "requires an attestation that authorizes state changes "
                "(state_changes_authorized); a live scan including it is refused"
            )
        return PlannedCheck(
            module=check.module,
            name=check.name,
            version=check.version,
            title=check.title,
            research_ref=check.research_ref,
            cwe=check.cwe,
            requires_active_checks=check.requires_active_checks,
            proof=proof,
            proof_effective=proof_effective,
            proof_note=proof_note,
            implemented=implemented,
            included=included,
            skip_code=code,
            skip_reason=reason,
            applicable_assets=applicable,
            estimated_requests=check.estimated_requests * applicable if included else 0,
        )

    @staticmethod
    def _implemented_steps(
        planned: tuple[PlannedCheck, ...], handled_steps: frozenset[ScanStep]
    ) -> frozenset[ScanStep]:
        """Steps that will have work at runtime: a handler plus something it can run."""
        implemented = {
            MODULE_STEP[check.module] for check in planned if check.included and check.implemented
        }
        return frozenset(
            step for step in handled_steps if step in _SELF_CONTAINED_STEPS or step in implemented
        )

    @staticmethod
    def _plan_steps(
        planned: tuple[PlannedCheck, ...],
        *,
        handled_steps: frozenset[ScanStep],
        implemented_steps: frozenset[ScanStep],
        pipeline: tuple[ScanStep, ...],
    ) -> tuple[PlanStep, ...]:
        steps: list[PlanStep] = []
        for order, step in enumerate(pipeline, start=1):
            in_step = tuple(
                check for check in planned if check.included and MODULE_STEP[check.module] is step
            )
            keys = tuple(check.key for check in in_step)
            requests = sum(check.estimated_requests for check in in_step)
            planned_only = sum(1 for check in in_step if not check.implemented)
            executable = step in handled_steps
            if step not in handled_steps:
                skipped, reason = True, "no step handler is registered in this build"
            elif step not in implemented_steps:
                skipped, reason = (
                    (True, "no implemented check targets this step in this build")
                    if keys
                    else (True, "no check applies to this step's modules")
                )
            else:
                skipped, reason = False, None
            steps.append(
                PlanStep(
                    step=step,
                    order=order,
                    description=_STEP_DESCRIPTIONS[step],
                    estimated_requests=requests,
                    executable=executable,
                    skipped=skipped,
                    skip_reason=reason,
                    checks=keys,
                    planned_only=planned_only,
                )
            )
        return tuple(steps)

    def _warnings(
        self,
        request: ScanRequest,
        planned: tuple[PlannedCheck, ...],
        assets: tuple[AssetEstimate, ...],
        active_checks_allowed: bool,
        state_changes_authorized: bool = False,
    ) -> tuple[str, ...]:
        warnings: list[str] = []
        if request.target.attestation is None:
            warnings.append(
                "no authorization attestation: a live scan would be refused (dry run only)"
            )
        if request.options.active_checks and not active_checks_allowed:
            withheld = sum(
                1 for check in planned if check.skip_code == "active-checks-not-authorized"
            )
            warnings.append(
                "active checks were requested but the attestation does not authorize them; "
                f"{withheld} check(s) are excluded from this plan"
            )
        else:
            withheld = sum(
                1 for check in planned if check.skip_code == "active-checks-not-opted-in"
            )
            if withheld:
                warnings.append(f"{withheld} active check(s) withheld pending opt-in")
        l34 = [check for check in planned if check.included and check.proof.needs_state_attestation]
        if l34 and not state_changes_authorized:
            names = ", ".join(f"{check.module}.{check.name}" for check in l34)
            warnings.append(
                f"{len(l34)} L3/L4 check(s) in this plan ({names}) require an attestation "
                "that authorizes state changes; a live scan including them is refused"
            )
        downgraded = sum(1 for check in planned if check.proof_effective.rank < check.proof.rank)
        if downgraded:
            warnings.append(
                f"{downgraded} check(s) downgraded below their declared proof level "
                "(an unavailable capability downgrades with a note; it never blocks, "
                "and no check is ever upgraded)"
            )
        if any(asset.capped for asset in assets):
            warnings.append(
                "host counts for wide networks were capped at "
                f"{self.settings.max_hosts_per_network} to bound the estimate"
            )
        if self.settings.assumed_subdomains_per_domain:
            warnings.append(
                "subdomain requests are estimated with the assumption of "
                f"{self.settings.assumed_subdomains_per_domain} extra host(s) per domain "
                "(ARACHNE_PLAN_ASSUMED_SUBDOMAINS)"
            )
        return tuple(warnings)
