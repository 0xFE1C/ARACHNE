"""PII detection and masking under a per-project policy (S25, REQ-TRUST-006).

REQ-TRUST-006's accept criterion is "seeded-PII evidence masked per policy; fuzz-covered", so
this file has three halves: the detectors (including the two checksum validators that keep
a version string from being mistaken for a card number), the three masking actions, and a
fuzz pass that seeds every category into every carrier shape a payload can take and asserts
that *nothing* survives.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from arachne.core.config import PII_KNOWN_CATEGORIES, PiiSettings
from arachne.core.errors import ConfigurationError
from arachne.core.pii import CATEGORIES, PIIPolicy, detect, mask_payload, mask_text

#: Seed values, one per category. Real formats, so the validators are exercised — except
#: ``card`` and ``iban``, which are *valid* check digits computed for the test.
SEEDS: dict[str, str] = {
    "email": "jane.operator@example.com",
    "phone": "+1 415 555 0142",
    "ssn": "123-45-6789",
    "credit-card": "4111 1111 1111 1111",  # a Luhn-valid Visa test number
    "iban": "GB82 WEST 1234 5698 7654 32",  # a mod-97-valid example
    "ipv4": "203.0.113.7",
}


def test_the_category_table_is_the_configuration_vocabulary() -> None:
    assert CATEGORIES == PII_KNOWN_CATEGORIES


# --------------------------------------------------------------------------- detection
@pytest.mark.parametrize("category", sorted(SEEDS))
def test_every_seeded_category_is_detected(category: str) -> None:
    findings = detect(f"value = {SEEDS[category]} end", categories=(category,))
    assert findings, f"{category} was not detected"
    assert {finding.category for finding in findings} == {category}
    # The finding carries a fingerprint, never the value.
    assert SEEDS[category] not in findings[0].masked


def test_detection_is_bounded_to_the_named_categories() -> None:
    text = f"{SEEDS['email']} {SEEDS['ssn']}"
    assert {f.category for f in detect(text, categories=("email",))} == {"email"}
    assert {f.category for f in detect(text, categories=("ssn",))} == {"ssn"}


def test_a_number_that_fails_luhn_is_not_a_card() -> None:
    # Sixteen digits, wrong check digit: a version string, an id, not a payment card.
    assert not detect("build 1234 5678 9012 3456 shipped", categories=("credit-card",))
    # The same digits with a valid check digit *are* one.
    assert detect("4111 1111 1111 1111", categories=("credit-card",))


def test_an_iban_with_a_bad_checksum_is_not_an_iban() -> None:
    assert not detect("GB82 WEST 1234 5698 7654 33", categories=("iban",))
    assert detect(SEEDS["iban"], categories=("iban",))


def test_impossible_ssn_areas_are_not_ssns() -> None:
    for bad in ("000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000"):
        assert not detect(bad, categories=("ssn",)), bad
    assert detect("123-45-6789", categories=("ssn",))


def test_an_impossible_address_is_not_an_ipv4() -> None:
    assert not detect("999.1.1.1", categories=("ipv4",))
    assert detect("198.51.100.9", categories=("ipv4",))


def test_a_bare_digit_run_is_not_a_phone_number() -> None:
    # Ten digits with no grouping: far more often an id than a phone number.
    assert not detect("order 6035550123 confirmed", categories=("phone",))
    assert detect("+1 415 555 0142", categories=("phone",))


def test_detection_is_linear_in_the_input() -> None:
    """A target-controlled body must not be a denial of service (the redaction discipline)."""
    import time

    small = "lorem ipsum " * 1_000
    large = "lorem ipsum " * 60_000
    start = time.perf_counter()
    detect(small)
    small_seconds = time.perf_counter() - start
    start = time.perf_counter()
    detect(large)
    large_seconds = time.perf_counter() - start
    # 60x the input must not cost more than ~600x the time (a quadratic scan would).
    assert large_seconds < max(0.05, small_seconds * 600)


# --------------------------------------------------------------------------- masking
def test_mask_replaces_the_value_with_a_labelled_placeholder() -> None:
    policy = PIIPolicy(enabled=True, categories=("email",), action="mask")
    masked, counts = mask_payload({"note": f"contact {SEEDS['email']} now"}, policy)
    assert SEEDS["email"] not in json.dumps(masked)
    assert "[PII:email]" in masked["note"]
    assert counts == {"email": 1}


def test_drop_removes_the_value_entirely() -> None:
    policy = PIIPolicy(enabled=True, categories=("email",), action="drop")
    masked, _ = mask_payload({"note": f"contact {SEEDS['email']} now"}, policy)
    assert masked["note"] == "contact  now"


def test_hash_is_a_deterministic_pseudonym_that_needs_the_salt() -> None:
    policy = PIIPolicy(enabled=True, categories=("email",), action="hash", salt="unit-salt")
    masked, _ = mask_payload({"a": SEEDS["email"], "b": SEEDS["email"]}, policy)
    # Deterministic (so two occurrences stay correlatable) but unreadable.
    assert masked["a"] == masked["b"]
    assert SEEDS["email"] not in masked["a"]
    # A different salt produces a different pseudonym: the salt is what makes enumeration
    # expensive, which is why an unsalted hash policy is refused at validation.
    other = PIIPolicy(enabled=True, categories=("email",), action="hash", salt="other-salt")
    assert mask_text(SEEDS["email"], other) != masked["a"]


def test_hash_without_a_salt_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="requires a salt"):
        PIIPolicy(enabled=True, categories=("email",), action="hash")


def test_an_unknown_category_or_action_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="unknown PII categor"):
        PIIPolicy(enabled=True, categories=("passport",))
    with pytest.raises(ConfigurationError, match="must be mask, hash or drop"):
        PIIPolicy(enabled=True, categories=("email",), action="encrypt")  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="at least one category"):
        PIIPolicy(enabled=True, categories=())


def test_an_inactive_policy_changes_nothing() -> None:
    payload = {"body": f"{SEEDS['email']} {SEEDS['ssn']}"}
    masked, counts = mask_payload(payload, PIIPolicy())
    assert masked == payload and counts == {}


def test_mask_payload_walks_nested_structures() -> None:
    policy = PIIPolicy(enabled=True, categories=("email",), action="mask")
    payload = {"rows": [{"contact": SEEDS["email"]}], "headers": {"x": [SEEDS["email"]]}}
    masked, counts = mask_payload(payload, policy)
    assert SEEDS["email"] not in json.dumps(masked)
    assert counts == {"email": 2}


def test_policy_from_settings_reads_the_deployment_default() -> None:
    policy = PIIPolicy.from_settings(
        PiiSettings(enabled=True, categories=("email",), action="hash", salt=_secret("s3cr3t"))
    )
    assert policy.active and policy.action == "hash"


def test_policy_to_dict_never_carries_the_salt() -> None:
    policy = PIIPolicy(enabled=True, categories=("email",), action="hash", salt="top-secret")
    assert "top-secret" not in json.dumps(policy.to_dict())
    assert policy.to_dict()["salted"] is True


def test_a_project_record_reports_its_policy_without_the_salt() -> None:
    """The API/report view of a project must not leak the hash salt (S25, REQ-TRUST-006).

    The *stored* document carries the salt — it is what makes a pseudonym expensive to
    reverse — but `ProjectRecord.to_dict` is what the API returns and what a report renders,
    so it reports the policy through the validated view instead.
    """
    from arachne.data.project_store import ProjectRecord

    record = ProjectRecord(
        id=1,
        slug="acme",
        name="Acme",
        pii={"enabled": True, "categories": ["email"], "action": "hash", "salt": "top-secret"},
        residency_region="eu-west-1",
    )
    rendered = json.dumps(record.to_dict())
    assert "top-secret" not in rendered
    assert record.to_dict()["pii"] == {
        "enabled": True,
        "categories": ["email"],
        "action": "hash",
        "salted": True,
    }
    assert record.to_dict()["residency_region"] == "eu-west-1"


# --------------------------------------------------------------------------- fuzz
def test_no_seeded_pii_survives_any_carrier() -> None:
    """The fuzz pass: every category, in every shape a payload can carry it."""
    policy = PIIPolicy(enabled=True, categories=tuple(SEEDS), action="mask")
    for category, value in SEEDS.items():
        carriers: list[object] = [
            value,
            f"prefix {value} suffix",
            {"field": value},
            {"nested": {"deep": [value]}},
            json.dumps({"field": value}),
            f"a\nb\r\n{value}\ttabbed",
            {"list": [value, value], "tuple": (value,)},
        ]
        for carrier in carriers:
            masked, counts = mask_payload({"carrier": carrier}, policy)
            rendered = json.dumps(masked, default=str, ensure_ascii=False)
            assert value not in rendered, f"{category} survived {carrier!r}"
            assert counts.get(category, 0) >= 1


def test_masking_is_idempotent() -> None:
    policy = PIIPolicy(enabled=True, categories=tuple(SEEDS), action="mask")
    once, _ = mask_payload({"v": SEEDS["email"]}, policy)
    twice, counts = mask_payload(once, policy)
    assert twice == once
    assert counts == {}


def test_masking_every_category_at_once_counts_each() -> None:
    policy = PIIPolicy(enabled=True, categories=tuple(SEEDS), action="mask")
    text = " ".join(SEEDS.values())
    _, counts = mask_payload({"all": text}, policy)
    assert set(counts) == set(SEEDS)
    assert sum(counts.values()) == len(SEEDS)


def test_pii_detection_does_not_touch_a_timestamp_or_a_version() -> None:
    """The false-positive guard the validators exist for (a report must stay readable)."""
    payload = {
        "captured_at": datetime(2026, 10, 31, tzinfo=UTC).isoformat(),
        "server": "nginx/1.25.3",
        "checksum": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "id": "12345678901234567890",
    }
    policy = PIIPolicy(enabled=True, categories=tuple(SEEDS), action="mask")
    masked, counts = mask_payload(payload, policy)
    assert masked == payload
    assert counts == {}


def _secret(value: str) -> object:
    from pydantic import SecretStr

    return SecretStr(value)
