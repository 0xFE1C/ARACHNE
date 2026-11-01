"""The fuzzing attestation: area FUZZ's own gate (S30, REQ-FUZZ-001).

Fuzzing inherits every gate a scan has and adds one of its own. The inherited half is the
ordinary :class:`~arachne.core.target.AuthorizationAttestation` — the scope, the target list,
the active-checks permission, the expiry — and :func:`authorize_fuzz` refuses a fuzzing request
against a definition that carries none, using the very same method a live scan uses
(``TargetDefinition.authorization_errors``). The added half is :class:`FuzzingAttestation`:
a second, separate grant that says "and you may *fuzz* these targets", held to a stricter
default than the scan it accompanies.

Two independent safety properties live here, and both are defaults rather than options:

**Non-production by default.** Fuzzing is the one capability in this program whose *purpose*
is to send inputs a normal scan would not, so the default grant covers non-production targets
only. The declared ``environment`` is the hint that decides it: a value in
:data:`NON_PRODUCTION_TAGS` is accepted, a value in :data:`PRODUCTION_TAGS` is refused unless
the attestation explicitly sets ``allow_production``, and a value that is neither is refused
too — an unclassified environment is not silently treated as a lab. Setting
``allow_production`` is not sufficient on its own: the *deployment* must also have opted in
(``FuzzSettings.allow_production``), so one mis-scoped grant cannot turn a lab-only install
into a production fuzzer.

**Coverage is the scan's rule.** ``allowed_targets`` is read by
:func:`~arachne.core.target.entry_covers_selector`, the same function that decides whether the
scan attestation covers a target. A fuzzing grant can therefore never cover a host the scan
grant does not, and the two grants cannot drift apart about what the estate is.

A refusal is audited as a blocked ``fuzz.refused`` event **before** it is raised, so
"unattested fuzzing happened" is a question the trail answers on its own. The audit call is
inside :func:`authorize_fuzz` rather than left to the caller, because a gate a caller can
forget to log is a gate with a hole in it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import FuzzSettings
from arachne.core.errors import FuzzRefused
from arachne.core.target import (
    AuthorizationAttestation,
    TargetDefinition,
    TargetSelector,
    _classify_attested_entry,
    entry_covers_selector,
)

__all__ = [
    "NON_PRODUCTION_TAGS",
    "PRODUCTION_TAGS",
    "FuzzAuthorization",
    "FuzzingAttestation",
    "authorize_fuzz",
    "classify_environment",
    "fuzz_authorization_errors",
]

#: Environment labels that are non-production by construction: a lab, a test estate, a
#: staging tier, a sandbox. Membership is what the default grant needs; it is a *hint* the
#: operator declares, not something ARACHNE can verify, which is why it is one gate of
#: several rather than the gate.
NON_PRODUCTION_TAGS: Final[frozenset[str]] = frozenset(
    {
        "lab",
        "laboratory",
        "lab-fixture",
        "test",
        "testing",
        "dev",
        "development",
        "staging",
        "stage",
        "qa",
        "uat",
        "preprod",
        "pre-production",
        "sandbox",
        "demo",
        "ephemeral",
        "canary",
        "training",
        "internal-lab",
    }
)

#: Environment labels that name live customer traffic. A grant that carries one of these is
#: refused unless it explicitly opts in *and* the deployment has.
PRODUCTION_TAGS: Final[frozenset[str]] = frozenset(
    {"prod", "production", "live", "live-production", "customer", "customer-facing"}
)


def classify_environment(value: str) -> str:
    """``"non-production"``, ``"production"`` or ``"unknown"`` (the fail-closed fallback)."""
    normalized = value.strip().lower()
    if normalized in PRODUCTION_TAGS:
        return "production"
    if normalized in NON_PRODUCTION_TAGS:
        return "non-production"
    return "unknown"


class FuzzingAttestation(BaseModel):
    """A separate grant for fuzzing a target definition (REQ-FUZZ-001).

    It is a *second* attestation on purpose. The scan attestation says "you may test this
    estate"; this one says "you may fuzz it", and the second question is the harder one to
    answer `yes` to. It carries the same identity fields as the scan grant — who signed it,
    when, what scope it states, and an authorization reference — because an auditor asking
    "who authorized the fuzzing" must get the same quality of answer as for a scan.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attested_by: str = Field(min_length=3, max_length=256)
    attested_at: datetime
    scope_statement: str = Field(min_length=10, max_length=4000)
    #: The targets this grant covers, spelled the way a scan attestation spells them.
    allowed_targets: tuple[str, ...] = Field(min_length=1)
    #: The environment the targets are believed to be. Decides production-ness together with
    #: :attr:`allow_production`; an unclassified value is refused rather than assumed.
    environment: str = Field(default="lab", min_length=1, max_length=64)
    #: Extra labels the operator declares for the same estate, as further hints.
    environment_tags: tuple[str, ...] = ()
    #: The explicit opt-in to fuzz a production target. Default ``False``, and setting it is
    #: still not enough: the deployment ceiling (``FuzzSettings.allow_production``) must
    #: agree, so a mis-scoped grant cannot widen a lab-only installation.
    allow_production: bool = False
    #: Optional tightening of the deployment's budget. A grant may ask for *less*; a value
    #: above the ceiling is clamped and reported, never granted.
    max_cases: int | None = Field(default=None, ge=1)
    max_requests: int | None = Field(default=None, ge=1)
    max_seconds: float | None = Field(default=None, gt=0)
    authorization_ref: str | None = Field(default=None, max_length=256)
    contact: str | None = Field(default=None, max_length=256)
    expires_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("attested_at", "expires_at")
    @classmethod
    def _require_tz(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "fuzzing attestation timestamps must include a timezone (RFC 3339)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_window(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.attested_at:
            msg = "expires_at must be after attested_at"
            raise ValueError(msg)
        for entry in self.allowed_targets:
            _classify_attested_entry(entry)  # raises ValueError on a malformed entry
        return self

    # ------------------------------------------------------------------ readings
    @property
    def environment_class(self) -> str:
        return classify_environment(self.environment)

    def is_future_dated(self, now: datetime) -> bool:
        return self.attested_at > now

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def covers(self, selector: TargetSelector) -> bool:
        """True when some entry of this grant covers ``selector`` (same rule as a scan's)."""
        return any(entry_covers_selector(entry, selector) for entry in self.allowed_targets)

    def uncovered(self, selectors: tuple[TargetSelector, ...]) -> tuple[TargetSelector, ...]:
        return tuple(selector for selector in selectors if not self.covers(selector))

    def budget_overrides(self) -> dict[str, float]:
        """The bounds this grant tightens, as keyword arguments for ``FuzzBudget.narrowed``."""
        overrides: dict[str, float] = {}
        if self.max_cases is not None:
            overrides["max_cases"] = self.max_cases
        if self.max_requests is not None:
            overrides["max_requests"] = self.max_requests
        if self.max_seconds is not None:
            overrides["max_seconds"] = self.max_seconds
        return overrides

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "attested_by": self.attested_by,
            "attested_at": self.attested_at.isoformat(),
            "scope_statement": self.scope_statement,
            "allowed_targets": list(self.allowed_targets),
            "environment": self.environment,
            "environment_class": self.environment_class,
            "environment_tags": list(self.environment_tags),
            "allow_production": self.allow_production,
        }
        for name in ("max_cases", "max_requests", "max_seconds"):
            value = getattr(self, name)
            if value is not None:
                payload[name] = value
        if self.authorization_ref:
            payload["authorization_ref"] = self.authorization_ref
        if self.contact:
            payload["contact"] = self.contact
        if self.expires_at is not None:
            payload["expires_at"] = self.expires_at.isoformat()
        if self.notes:
            payload["notes"] = self.notes
        return payload

    def summary(self) -> dict[str, Any]:
        """The short form for a plan, a report or an audit line."""
        return {
            "attested_by": self.attested_by,
            "attested_at": self.attested_at.isoformat(),
            "environment": self.environment,
            "environment_class": self.environment_class,
            "allow_production": self.allow_production,
            "authorization_ref": self.authorization_ref,
            "allowed_targets": list(self.allowed_targets),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass(frozen=True, slots=True)
class FuzzAuthorization:
    """The grant a run proceeds under, plus the two things it had to satisfy."""

    definition: TargetDefinition
    attestation: FuzzingAttestation
    #: The inherited half: the scan attestation's own reading of this definition.
    inherited: AuthorizationAttestation
    environment_class: str
    #: Bounds the grant tightened, and any the ceiling pulled back down.
    overrides: dict[str, float]
    clamped: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fuzz": self.attestation.summary(),
            "scan": self.inherited.summary(),
            "environment_class": self.environment_class,
            "budget_overrides": dict(self.overrides),
            "clamped_fields": list(self.clamped),
        }


def fuzz_authorization_errors(
    definition: TargetDefinition,
    attestation: FuzzingAttestation | None,
    *,
    settings: FuzzSettings | None = None,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """Every reason a fuzzing run against ``definition`` would be refused; empty when allowed.

    Pure and total: it reports *all* the reasons rather than raising at the first, so a plan
    can show an operator the whole picture, and a test can assert on a specific one.
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    errors: list[str] = []
    # The inherited half first: without a scan attestation there is nothing for a fuzzing
    # grant to extend, and the message should say so rather than blame the missing fuzz grant.
    if definition.attestation is None:
        return (
            "no authorization attestation is attached to this target definition: a fuzzing "
            "run inherits the scan's authorization and cannot be authorized without it",
        )
    errors.extend(definition.authorization_errors(active_checks=True, now=moment))
    if attestation is None:
        errors.append(
            "no fuzzing attestation: fuzzing is refused every target definition that does not "
            "carry an explicit grant for it"
        )
        return tuple(errors)
    if attestation.is_future_dated(moment):
        errors.append(
            f"fuzzing attestation is dated in the future ({attestation.attested_at.isoformat()})"
        )
    if attestation.is_expired(moment) and attestation.expires_at is not None:
        errors.append(
            f"fuzzing attestation expired at {attestation.expires_at.isoformat()}"
        )
    uncovered = attestation.uncovered(definition.targets)
    if uncovered:
        rendered = ", ".join(f"{selector.kind.value}:{selector.value}" for selector in uncovered)
        errors.append(f"fuzzing attestation does not cover every declared target ({rendered})")
    environment_class = attestation.environment_class
    if not attestation.allow_production:
        if environment_class == "production":
            errors.append(
                f"environment {attestation.environment!r} is production and the fuzzing "
                "attestation does not permit production targets"
            )
        elif environment_class == "unknown":
            errors.append(
                f"environment {attestation.environment!r} is neither a declared non-production "
                f"label nor a production one: an unclassified environment is refused "
                f"(non-production labels: {', '.join(sorted(NON_PRODUCTION_TAGS))})"
            )
    elif settings is not None and not settings.allow_production:
        errors.append(
            "the fuzzing attestation permits production targets but this deployment has not "
            "opted in (ARACHNE_FUZZ_ALLOW_PRODUCTION)"
        )
    return tuple(errors)


def authorize_fuzz(
    definition: TargetDefinition,
    attestation: FuzzingAttestation | None,
    *,
    settings: FuzzSettings | None = None,
    auditor: Auditor | None = None,
    now: datetime | None = None,
    run_id: str | None = None,
) -> FuzzAuthorization:
    """Authorize a fuzzing run, or refuse it — auditing the refusal before raising.

    Order matters: the audit line is written first and the exception second, so a caller that
    lets the exception escape still leaves a record of the attempt. A refusal is recorded
    *blocked*, never *allowed*: "someone asked to fuzz without a grant" is a security event,
    and the runner calls this before it constructs a client or opens a socket.
    """
    errors = fuzz_authorization_errors(definition, attestation, settings=settings, now=now)
    if errors:
        reason = "; ".join(errors)
        if auditor is not None:
            auditor.record(
                AuditAction.FUZZ_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                target=definition.name,
                reason=reason,
                meta={
                    "run_id": run_id,
                    "reasons": list(errors),
                    "attestation_present": attestation is not None,
                    "environment": attestation.environment if attestation is not None else None,
                },
            )
        raise FuzzRefused(f"fuzzing refused: {reason}", reason=reason)
    assert attestation is not None  # narrowed by the errors above
    assert definition.attestation is not None
    overrides = attestation.budget_overrides()
    if auditor is not None:
        auditor.record(
            AuditAction.FUZZ_AUTHORIZED,
            outcome=AuditOutcome.ALLOWED,
            target=definition.name,
            meta={
                "run_id": run_id,
                "environment": attestation.environment,
                "environment_class": attestation.environment_class,
                "allow_production": attestation.allow_production,
                "authorization_ref": attestation.authorization_ref,
                "allowed_targets": list(attestation.allowed_targets),
                "budget_overrides": overrides,
            },
        )
    return FuzzAuthorization(
        definition=definition,
        attestation=attestation,
        inherited=definition.attestation,
        environment_class=attestation.environment_class,
        overrides=overrides,
    )
