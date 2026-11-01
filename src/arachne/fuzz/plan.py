"""The fuzzing plan document (S30, area FUZZ).

A fuzzing run is described in a file rather than in CLI flags, for the same reason a scan is: what
was authorized, what was targeted and within which bounds is a record an operator should be able
to review, diff and attach to a change ticket — not a shell history line. One document carries both
grants (the scan's ``target:`` block, which is the *inherited* gate, and a ``fuzz:`` block, which
is the area's own) plus the wire and HTTP targets to fuzz.

``load_fuzz_plan`` is also the refusal boundary for input: a malformed document, an unknown grammar,
a missing grant or an unknown engine family is a :class:`~arachne.core.errors.ConfigurationError`
naming what is wrong, raised before anything dials. Authorization itself is *not* decided here —
that is :func:`arachne.fuzz.attestation.authorize_fuzz`'s job, and it audits its own refusals.
"""

from __future__ import annotations

from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError
from arachne.core.target import TargetDefinition, load_scan_request_from_text
from arachne.fuzz.attestation import FuzzingAttestation
from arachne.fuzz.bounds import FuzzBudget
from arachne.fuzz.http_params import ALL_FAMILIES, HttpFuzzPlan, HttpParameter
from arachne.fuzz.runner import FuzzPlan, WireTargetSpec
from arachne.fuzz.wire import GRAMMARS

__all__ = ["FuzzPlanDocument", "load_fuzz_plan", "render_fuzz_plan"]

_MODEL = ConfigDict(extra="forbid", frozen=True)


class WireTargetDocument(BaseModel):
    """One wire-protocol endpoint to fuzz."""

    model_config = _MODEL

    label: str = Field(min_length=1, max_length=120)
    grammar: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    transport: str = "tcp"
    asset: str | None = Field(default=None, max_length=512)
    verifier: str | None = Field(default=None, max_length=120)
    notes: str = Field(default="", max_length=500)


class HttpParameterDocument(BaseModel):
    """One injectable HTTP parameter."""

    model_config = _MODEL

    url: str = Field(min_length=8, max_length=2048)
    parameter: str = Field(min_length=1, max_length=120)
    method: str = "GET"
    baseline_value: str = Field(default="1", max_length=200)
    kind: str = "generic"


class HttpTargetDocument(BaseModel):
    """One origin's HTTP fuzzing plan."""

    model_config = _MODEL

    label: str = Field(min_length=1, max_length=120)
    asset: str | None = Field(default=None, max_length=512)
    parameters: tuple[HttpParameterDocument, ...] = Field(min_length=1)
    families: tuple[str, ...] = (
        "boundary",
        "sqli-error",
        "xss-reflection",
        "traversal",
    )
    notes: str = Field(default="", max_length=500)


class BudgetDocument(BaseModel):
    """The bounds a plan asks for. Always clamped down to the deployment's ceiling."""

    model_config = _MODEL

    max_cases: int | None = Field(default=None, ge=1)
    max_requests: int | None = Field(default=None, ge=1)
    max_seconds: float | None = Field(default=None, gt=0)
    batch_size: int | None = Field(default=None, ge=1)


class FuzzPlanDocument(BaseModel):
    """A whole fuzzing plan: the two grants, the bounds and the targets."""

    model_config = _MODEL

    schema_version: str = "1.0"
    fuzz: FuzzingAttestation
    target: dict[str, Any]
    wire: tuple[WireTargetDocument, ...] = ()
    http: tuple[HttpTargetDocument, ...] = ()
    budget: BudgetDocument = BudgetDocument()
    engine: str | None = Field(default=None, max_length=64)
    scan_id: int | None = Field(default=None, ge=1)
    notes: str = Field(default="", max_length=2000)


def load_fuzz_plan(text: str, *, source: str = "<memory>") -> FuzzPlan:
    """Parse a fuzzing plan document into a :class:`~arachne.fuzz.runner.FuzzPlan`.

    Raises :class:`ConfigurationError` for anything a run must not guess at: an unparseable
    document, a plan with no targets, an unknown grammar or an unknown payload family. A *safe*
    malformed plan is still refused loudly, because the alternative — a run that quietly fuzzes
    nothing, or worse, something else — is the failure mode this check exists for.
    """
    document = _parse(text, source=source)
    try:
        parsed = FuzzPlanDocument.model_validate(document)
    except ValidationError as exc:
        raise ConfigurationError(f"{source}: invalid fuzzing plan: {exc}") from exc

    definition = _definition(parsed.target, source=source)
    if not parsed.wire and not parsed.http:
        msg = f"{source}: a fuzzing plan needs at least one wire or http target"
        raise ConfigurationError(msg)

    wire_targets: list[WireTargetSpec] = []
    for wire_entry in parsed.wire:
        # The *registry*, not the shipped declaration list: a deployment may register a grammar
        # of its own (that is what the lab tests do), and the plan loader should accept anything
        # the run could actually resolve rather than only what this build ships.
        if wire_entry.grammar not in GRAMMARS:
            msg = (
                f"{source}: unknown grammar {wire_entry.grammar!r} "
                f"(registered: {', '.join(sorted(GRAMMARS))})"
            )
            raise ConfigurationError(msg)
        if wire_entry.transport not in ("tcp", "udp"):
            msg = f"{source}: transport must be 'tcp' or 'udp', got {wire_entry.transport!r}"
            raise ConfigurationError(msg)
        wire_targets.append(
            WireTargetSpec(
                label=wire_entry.label,
                grammar=wire_entry.grammar,
                host=wire_entry.host,
                port=wire_entry.port,
                transport=wire_entry.transport,
                asset=wire_entry.asset,
                verifier=wire_entry.verifier,
                notes=wire_entry.notes,
            )
        )

    http_plans: list[HttpFuzzPlan] = []
    for http_entry in parsed.http:
        unknown = [family for family in http_entry.families if family not in ALL_FAMILIES]
        if unknown:
            msg = (
                f"{source}: unknown payload family/families {', '.join(unknown)} "
                f"(this build offers: {', '.join(ALL_FAMILIES)})"
            )
            raise ConfigurationError(msg)
        http_plans.append(
            HttpFuzzPlan(
                label=http_entry.label,
                asset=http_entry.asset,
                families=http_entry.families,
                notes=http_entry.notes,
                parameters=tuple(
                    HttpParameter(
                        url=parameter.url,
                        parameter=parameter.parameter,
                        method=parameter.method,
                        baseline_value=parameter.baseline_value,
                        kind=parameter.kind,
                    )
                    for parameter in http_entry.parameters
                ),
            )
        )

    return FuzzPlan(
        definition=definition,
        attestation=parsed.fuzz,
        wire_targets=tuple(wire_targets),
        http_plans=tuple(http_plans),
        budget=FuzzBudget(
            **_budget_payload(parsed.budget),
        ),
        engine=parsed.engine,
        scan_id=parsed.scan_id,
        notes=parsed.notes,
    )


def _budget_payload(document: BudgetDocument) -> dict[str, Any]:
    """The requested bounds, defaulting to the deployment's when the plan says nothing.

    The defaults here are the deployment's own defaults only because ``FuzzBudget``'s are: the
    ceiling clamping happens in the runner, against the live settings, so a plan cannot raise a
    bound by omitting one.
    """
    payload: dict[str, Any] = {}
    if document.max_cases is not None:
        payload["max_cases"] = document.max_cases
    if document.max_requests is not None:
        payload["max_requests"] = document.max_requests
    if document.max_seconds is not None:
        payload["max_seconds"] = document.max_seconds
    if document.batch_size is not None:
        payload["batch_size"] = document.batch_size
    return payload


def _definition(target: dict[str, Any], *, source: str) -> TargetDefinition:
    """The scan's own target document, parsed by the scan parser (one definition of the schema).

    Re-parsing through ``load_scan_request_from_text`` rather than validating the block here is
    deliberate: there is exactly one target-definition schema in this program, and a fuzzing plan
    that accepted a shape a scan would not would be a second one.
    """
    try:
        # The scan parser takes a whole scan *request* document (``target:`` plus ``options:``),
        # so this block is re-wrapped as one rather than re-validated here.
        request = load_scan_request_from_text(yaml.safe_dump({"target": target}), source=source)
    except (ConfigurationError, ValueError) as exc:
        raise ConfigurationError(f"{source}: invalid target definition: {exc}") from exc
    return request.target


def _parse(text: str, *, source: str) -> dict[str, Any]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        msg = f"{source}: a fuzzing plan must be a mapping, got {type(document).__name__}"
        raise ConfigurationError(msg)
    return document


def render_fuzz_plan(plan: FuzzPlan, *, budget: FuzzBudget | None = None) -> str:
    """The plan as an operator reads it before approving the run. Sends nothing."""
    lines: list[str] = []
    lines.append(f"definition:    {plan.definition.name}")
    lines.append(f"scan id:       {plan.scan_id if plan.scan_id is not None else '-'}")
    lines.append(f"engine:        {plan.engine or DEFAULT_ENGINE_LABEL}")
    if plan.attestation is not None:
        granted = plan.attestation
        lines.append(f"authorized by: {granted.attested_by}")
        lines.append(
            f"environment:   {granted.environment} ({granted.environment_class}"
            f"{', production permitted' if granted.allow_production else ''})"
        )
        lines.append(f"valid targets: {', '.join(granted.allowed_targets)}")
        if granted.expires_at is not None:
            lines.append(f"expires:       {granted.expires_at.isoformat()}")
    else:
        lines.append("authorized by: <none — the run will be refused>")
    resolved = budget or plan.budget
    if resolved is not None:
        lines.append(
            f"bounds:        {resolved.max_cases} cases, {resolved.max_requests} requests, "
            f"{resolved.max_seconds:g}s, batches of {resolved.batch_size}"
        )
    for target in plan.wire_targets:
        lines.append(
            f"wire target:   {target.label}  {target.transport} {target.target} "
            f"grammar={target.grammar} verifier={target.verifier or '-'}"
        )
    for http_plan in plan.http_plans:
        lines.append(
            f"http target:   {http_plan.label}  {http_plan.resolved_asset} "
            f"families={','.join(http_plan.families)}"
        )
        for parameter in http_plan.parameters:
            lines.append(
                f"  parameter:   {parameter.method} {parameter.url} "
                f"({parameter.parameter}, {parameter.kind})"
            )
    if plan.notes:
        lines.append(f"notes:         {plan.notes}")
    return "\n".join(lines)


#: Rendered when a plan names no engine (the runner resolves the default from settings).
DEFAULT_ENGINE_LABEL = "<deployment default>"
