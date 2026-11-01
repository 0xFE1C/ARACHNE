"""Detection-window enforcement and the attestation class (S24, REQ-VALID-001).

The window is the authorization boundary of a detection test, so it is tested as a
boundary: absent, not-yet-open, exactly-open, exactly-closed, and past. The attestation
invariants are tested too — a purple window must sit inside the authorization that carries
it, so a test can never outlive its authority.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from arachne.core.errors import DetectionWindowError
from arachne.core.target import (
    AuthorizationAttestation,
    DetectionWindow,
    PurpleRunOptions,
    ScanOptions,
    TargetDefinition,
    TargetKind,
    TargetSelector,
)
from arachne.purple.window import (
    WindowState,
    assert_window_open,
    describe_window,
    window_payload,
    window_state,
)

START = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
END = START + timedelta(hours=1)


def _window(*, starts: datetime = START, ends: datetime = END) -> DetectionWindow:
    return DetectionWindow(
        starts_at=starts,
        ends_at=ends,
        coordinator="soc-lead@corp",
        defender="blue-team@corp",
        reference="CHG-4242",
    )


def test_the_three_states_are_exact_at_both_edges() -> None:
    window = _window()
    assert window_state(window, START - timedelta(microseconds=1)) is WindowState.PENDING
    assert window_state(window, START) is WindowState.OPEN
    assert window_state(window, END) is WindowState.OPEN
    assert window_state(window, END + timedelta(microseconds=1)) is WindowState.CLOSED


def test_no_window_is_closed_never_implicitly_open() -> None:
    """The absence of a coordinated window is the strongest refusal, not a default grant."""
    assert window_state(None, START) is WindowState.CLOSED
    with pytest.raises(DetectionWindowError, match="no detection window is attached"):
        assert_window_open(None, START)


def test_a_purple_action_is_refused_before_and_after_the_window() -> None:
    window = _window()
    with pytest.raises(DetectionWindowError, match="has not opened yet"):
        assert_window_open(window, START - timedelta(minutes=5), what="purple action X")
    with pytest.raises(DetectionWindowError, match="closed at"):
        assert_window_open(window, END + timedelta(minutes=5), what="purple action X")
    assert_window_open(window, START + timedelta(minutes=1))  # inside: no raise


def test_the_refusal_message_names_the_moment_and_the_window() -> None:
    """A refusal an operator has to reverse-engineer at 3am is a bad refusal."""
    window = _window()
    with pytest.raises(DetectionWindowError) as excinfo:
        assert_window_open(window, END + timedelta(minutes=1))
    message = str(excinfo.value)
    assert window.ends_at.isoformat() in message
    assert (END + timedelta(minutes=1)).isoformat() in message


def test_the_window_payload_carries_the_state_for_reports_and_audit() -> None:
    window = _window()
    inside = window_payload(window, START + timedelta(minutes=5))
    assert inside["present"] is True and inside["state_at"] == "open"
    assert inside["coordinator"] == "soc-lead@corp" and inside["defender"] == "blue-team@corp"
    assert window_payload(None, START) == {"present": False}
    assert "coordinated with soc-lead@corp" in describe_window(window)
    assert "no detection window" in describe_window(None)


def test_a_window_must_be_well_formed_and_tz_aware() -> None:
    with pytest.raises(ValidationError, match="after starts_at"):
        DetectionWindow(starts_at=END, ends_at=START, coordinator="soc")
    with pytest.raises(ValidationError, match="timezone"):
        DetectionWindow(
            starts_at=datetime(2026, 10, 31, 12, 0), ends_at=END, coordinator="soc"
        )
    with pytest.raises(ValidationError, match="coordinator"):
        DetectionWindow(starts_at=START, ends_at=END, coordinator="")


def _attestation(**overrides: object) -> AuthorizationAttestation:
    payload: dict[str, object] = {
        "attested_by": "ciso@corp",
        "attested_at": START - timedelta(days=1),
        "scope_statement": "coordinated purple-team window over the lab",
        "allowed_targets": ("127.0.0.1",),
        "active_checks_authorized": True,
    }
    payload.update(overrides)
    return AuthorizationAttestation.model_validate(payload)


def _definition(attestation: AuthorizationAttestation) -> TargetDefinition:
    return TargetDefinition(
        name="lab",
        targets=(TargetSelector(kind=TargetKind.IP, value="127.0.0.1"),),
        attestation=attestation,
    )


def test_a_purple_window_must_sit_inside_its_own_authorization() -> None:
    """A detection test may not be scheduled before its grant or past its expiry."""
    with pytest.raises(ValidationError, match="must not precede attested_at"):
        _attestation(detection_window=_window(starts=START - timedelta(days=2)))
    with pytest.raises(ValidationError, match="must not be after the attestation's expires_at"):
        _attestation(
            detection_window=_window(),
            expires_at=START + timedelta(minutes=30),
        )
    # Inside the authorization: fine.
    assert _attestation(
        detection_window=_window(), expires_at=END + timedelta(hours=1)
    ).detection_window is not None


def test_the_attestation_round_trips_the_window_into_every_stored_form() -> None:
    attestation = _attestation(detection_window=_window())
    assert attestation.to_dict()["detection_window"]["coordinator"] == "soc-lead@corp"
    assert attestation.summary()["detection_window"]["reference"] == "CHG-4242"
    rebuilt = AuthorizationAttestation.model_validate(attestation.to_dict())
    assert rebuilt.detection_window == attestation.detection_window


def test_purple_mode_is_refused_without_the_detection_window_class() -> None:
    """REQ-VALID-001's acceptance, at the authorization gate: no window, no purple team."""
    plain = _definition(_attestation())
    errors = plain.authorization_errors(active_checks=True, purple=True)
    assert any("detection-window attestation" in item for item in errors)
    assert plain.authorization_errors(active_checks=True, purple=True) != ()
    # The same definition is authorized for an ordinary active scan.
    assert plain.authorization_errors(active_checks=True) == ()

    windowed = _definition(_attestation(detection_window=_window()))
    assert windowed.authorization_errors(active_checks=True, purple=True) == ()


def test_purple_mode_also_needs_the_active_checks_authority() -> None:
    definition = _definition(
        _attestation(detection_window=_window(), active_checks_authorized=False)
    )
    errors = definition.authorization_errors(active_checks=True, purple=True)
    assert any("does not authorize active checks" in item for item in errors)


def test_purple_run_options_validate_their_own_shape() -> None:
    with pytest.raises(ValidationError, match="campaign id"):
        PurpleRunOptions(campaign="Not A Campaign", actions=("m3.cmdi-oob",))
    with pytest.raises(ValidationError, match="is not a check id"):
        PurpleRunOptions(campaign="c1", actions=("nope",))
    with pytest.raises(ValidationError, match="at least 1 item"):
        PurpleRunOptions(campaign="c1", actions=())
    with pytest.raises(ValidationError, match="purple nonce"):
        PurpleRunOptions(campaign="c1", actions=("m3.cmdi-oob",), nonce="short")
    options = PurpleRunOptions(campaign="c1", actions=("m3.cmdi-oob", "m3.cmdi-oob"))
    assert options.actions == ("m3.cmdi-oob",), "duplicate actions collapse"


def test_purple_mode_requires_the_operator_active_checks_opt_in() -> None:
    """A purple run replays active proof actions: the scan's own opt-in is one of the two
    switches (F-01-09), and it cannot be implied by the attestation."""
    with pytest.raises(ValidationError, match="requires active_checks=True"):
        ScanOptions(purple=PurpleRunOptions(campaign="c1", actions=("m3.cmdi-oob",)))
    assert ScanOptions(
        active_checks=True, purple=PurpleRunOptions(campaign="c1", actions=("m3.cmdi-oob",))
    ).purple is not None
