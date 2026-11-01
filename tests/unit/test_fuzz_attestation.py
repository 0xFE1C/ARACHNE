"""The fuzzing attestation (S30, area FUZZ, REQ-FUZZ-001).

Fuzzing inherits every gate a scan has and adds one of its own, and the *added* gate has a
stricter default than the scan it accompanies: non-production targets only. These tests pin both
halves — the inherited one (a fuzzing grant cannot authorize a definition the scan grant does not)
and the added one (production, an unclassified environment, an expired grant, an uncovered target)
— plus the audit line each outcome leaves.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from arachne.core.audit import AuditAction, Auditor, AuditOutcome, MemoryAuditSink
from arachne.core.config import FuzzSettings
from arachne.core.errors import FuzzRefused
from arachne.core.target import (
    AuthorizationAttestation,
    TargetDefinition,
    TargetKind,
    TargetSelector,
)
from arachne.fuzz.attestation import (
    NON_PRODUCTION_TAGS,
    PRODUCTION_TAGS,
    FuzzingAttestation,
    authorize_fuzz,
    classify_environment,
    fuzz_authorization_errors,
)

ALLOWED_AT = datetime(2026, 10, 1, tzinfo=UTC)
NOW = datetime(2026, 11, 1, tzinfo=UTC)


#: Distinguishes "no attestation" from "the default attestation" in :func:`definition`.
_DEFAULT = object()


def definition(
    *,
    targets: tuple[str, ...] = ("lab.example.test",),
    attestation: object = _DEFAULT,
    active: bool = True,
) -> TargetDefinition:
    resolved = (
        AuthorizationAttestation(
            attested_by="owner <owner@example.test>",
            attested_at=ALLOWED_AT,
            scope_statement="Authorization for the fuzzing attestation tests",
            allowed_targets=list(targets),
            active_checks_authorized=active,
        )
        if attestation is _DEFAULT
        else attestation
    )
    return TargetDefinition(
        name="attestation-fixture",
        targets=tuple(TargetSelector(kind=TargetKind.DOMAIN, value=value) for value in targets),
        attestation=resolved,  # type: ignore[arg-type]
    )


def fuzz_grant(**overrides: object) -> FuzzingAttestation:
    payload: dict[str, object] = {
        "attested_by": "owner <owner@example.test>",
        "attested_at": ALLOWED_AT,
        "scope_statement": "Authorization to fuzz the lab",
        "allowed_targets": ["lab.example.test"],
        "environment": "lab",
    }
    payload.update(overrides)
    return FuzzingAttestation(**payload)


def test_an_environment_label_is_classified_and_an_unknown_one_is_not_a_lab() -> None:
    for tag in ("lab", "LAB", " staging ", "sandbox", "preprod"):
        assert classify_environment(tag) == "non-production"
    for tag in ("prod", "Production", "live"):
        assert classify_environment(tag) == "production"
    for tag in ("", "unknown", "dmz-3", "ops"):
        assert classify_environment(tag) == "unknown"
    assert "lab" in NON_PRODUCTION_TAGS
    assert "production" in PRODUCTION_TAGS


def test_fuzzing_without_a_fuzzing_attestation_is_refused() -> None:
    errors = fuzz_authorization_errors(definition(), None)
    assert errors == (
        "no fuzzing attestation: fuzzing is refused every target definition that does not "
        "carry an explicit grant for it",
    )


def test_fuzzing_is_refused_when_the_scan_attestation_is_missing() -> None:
    """The inherited half first: a fuzzing grant cannot authorize what the scan grant does not."""
    bare = definition(attestation=None)
    errors = fuzz_authorization_errors(bare, fuzz_grant())
    assert len(errors) == 1
    assert "inherits the scan's authorization" in errors[0]


def test_a_scan_attestation_that_does_not_authorize_active_checks_refuses_fuzzing() -> None:
    errors = fuzz_authorization_errors(definition(active=False), fuzz_grant())
    assert any("active checks" in reason for reason in errors)


def test_a_fuzzing_grant_that_does_not_cover_every_target_is_refused() -> None:
    errors = fuzz_authorization_errors(
        definition(targets=("lab.example.test", "other.example.test")),
        fuzz_grant(allowed_targets=["lab.example.test"]),
    )
    assert errors == (
        "fuzzing attestation does not cover every declared target "
        "(domain:other.example.test)",
    )


def test_a_production_target_is_refused_by_default() -> None:
    errors = fuzz_authorization_errors(definition(), fuzz_grant(environment="production"))
    assert len(errors) == 1
    assert "does not permit production targets" in errors[0]


def test_an_unclassified_environment_is_refused_rather_than_assumed() -> None:
    errors = fuzz_authorization_errors(definition(), fuzz_grant(environment="dmz-3"))
    assert len(errors) == 1
    assert "neither a declared non-production label nor a production one" in errors[0]


def test_production_needs_both_the_grant_and_the_deployment_to_agree() -> None:
    grant = fuzz_grant(environment="production", allow_production=True)
    assert fuzz_authorization_errors(definition(), grant, settings=FuzzSettings()) == (
        "the fuzzing attestation permits production targets but this deployment has not "
        "opted in (ARACHNE_FUZZ_ALLOW_PRODUCTION)",
    ), "one mis-scoped grant must not turn a lab-only install into a production fuzzer"
    permissive = FuzzSettings(allow_production=True)
    assert fuzz_authorization_errors(definition(), grant, settings=permissive) == ()


def test_an_expired_or_future_dated_grant_is_refused() -> None:
    expired = fuzz_grant(expires_at=datetime(2026, 10, 15, tzinfo=UTC))
    errors = fuzz_authorization_errors(definition(), expired, now=NOW)
    assert any("expired at" in reason for reason in errors)

    future = fuzz_grant(attested_at=datetime(2027, 1, 1, tzinfo=UTC))
    errors = fuzz_authorization_errors(definition(), future, now=NOW)
    assert any("dated in the future" in reason for reason in errors)


def test_a_grant_may_tighten_the_budget_it_runs_under() -> None:
    grant = fuzz_grant(max_cases=7, max_requests=9, max_seconds=3.5)
    assert grant.budget_overrides() == {
        "max_cases": 7,
        "max_requests": 9,
        "max_seconds": 3.5,
    }


def test_a_grant_must_include_a_non_empty_environment_and_target_list() -> None:
    with pytest.raises(ValueError):
        fuzz_grant(environment="")
    with pytest.raises(ValueError):
        FuzzingAttestation(
            attested_by="owner <owner@example.test>",
            attested_at=ALLOWED_AT,
            scope_statement="Authorization with no targets at all",
            allowed_targets=[],
        )


def test_a_naive_timestamp_is_refused() -> None:
    with pytest.raises(ValueError):
        fuzz_grant(attested_at=datetime(2026, 10, 1))


def test_authorizing_records_an_allowed_line_and_refusing_records_a_blocked_one() -> None:
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    authorization = authorize_fuzz(definition(), fuzz_grant(), auditor=auditor, now=NOW)
    assert authorization.environment_class == "non-production"
    actions = [(event.action, event.outcome) for event in sink.events]
    assert actions == [(AuditAction.FUZZ_AUTHORIZED, AuditOutcome.ALLOWED)]
    assert sink.events[0].meta["allowed_targets"] == ["lab.example.test"]

    sink.events.clear()
    with pytest.raises(FuzzRefused):
        authorize_fuzz(definition(), None, auditor=auditor, now=NOW)
    assert [(event.action, event.outcome) for event in sink.events] == [
        (AuditAction.FUZZ_REFUSED, AuditOutcome.BLOCKED)
    ]
    assert sink.events[0].meta["attestation_present"] is False


def test_the_refusal_precedes_the_exception_so_a_lost_exception_is_still_audited() -> None:
    """The audit line is written *first*: a caller that lets the raise escape leaves a record."""
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    with pytest.raises(FuzzRefused) as caught:
        authorize_fuzz(
            definition(), fuzz_grant(environment="live"), auditor=auditor, now=NOW
        )
    assert len(sink.events) == 1
    assert "fuzzing refused:" in str(caught.value)
    assert caught.value.reason


def test_the_grant_reads_out_the_state_it_was_authorized_in() -> None:
    authorization = authorize_fuzz(definition(), fuzz_grant(max_cases=5), now=NOW)
    payload = authorization.to_dict()
    assert payload["environment_class"] == "non-production"
    assert payload["budget_overrides"] == {"max_cases": 5}
    assert payload["scan"]["active_checks_authorized"] is True
    assert payload["fuzz"]["authorization_ref"] is None
