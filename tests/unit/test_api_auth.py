"""Unit tests for the API's auth, rate limiting and CI-gate policy (S12, F-07-02/05).

No ASGI app here: these are the small, pure parts — key parsing and constant-time
verification, the role ladder, the non-blocking token bucket, and the exit-code policy — so
a failure points at the logic rather than at a route.
"""

from __future__ import annotations

import time

import pytest

from arachne.api.auth import ApiKeyStore, Role, hash_secret
from arachne.api.ratelimit import ApiRateLimiter
from arachne.cli.ci import (
    EXIT_AT_OR_ABOVE,
    EXIT_BELOW_THRESHOLD,
    EXIT_CLEAN,
    counts_at_or_above,
    gate_exit_code,
    gate_summary,
    parse_threshold,
)
from arachne.core.config import ApiSettings
from arachne.core.errors import ConfigurationError


# --------------------------------------------------------------------------- auth
def test_a_key_store_parses_labels_roles_and_digests() -> None:
    store = ApiKeyStore(["ops:admin:aaa", "ci:scanner:bbb", "read:viewer:ccc"])
    assert len(store) == 3
    assert store.enabled
    assert store.labels() == ("ops", "ci", "read")
    assert store.verify("aaa") is not None
    assert store.verify("aaa").role is Role.ADMIN  # type: ignore[union-attr]
    assert store.verify("bbb").role is Role.SCANNER  # type: ignore[union-attr]
    assert store.verify("ccc").role is Role.VIEWER  # type: ignore[union-attr]


def test_a_wrong_or_missing_key_is_rejected() -> None:
    store = ApiKeyStore(["ops:admin:aaa"])
    assert store.verify("nope") is None
    assert store.verify("") is None
    assert store.verify(None) is None
    # The digest never stores the plaintext.
    assert "aaa" not in store._keys[0].digest


def test_an_empty_key_store_is_closed() -> None:
    store = ApiKeyStore([])
    assert not store.enabled
    assert store.verify("anything") is None


def test_hash_secret_is_stable_and_not_reversible() -> None:
    assert hash_secret("s3cret") == hash_secret("s3cret")
    assert hash_secret("s3cret") != hash_secret("s3cret ")
    assert len(hash_secret("x")) == 64


def test_roles_are_ordered_and_inclusive() -> None:
    from arachne.api.auth import Principal

    viewer = Principal(label="v", role=Role.VIEWER)
    scanner = Principal(label="s", role=Role.SCANNER)
    admin = Principal(label="a", role=Role.ADMIN)
    assert viewer.allows(Role.VIEWER)
    assert not viewer.allows(Role.SCANNER)
    assert scanner.allows(Role.VIEWER) and scanner.allows(Role.SCANNER)
    assert not scanner.allows(Role.ADMIN)
    assert admin.allows(Role.ADMIN) and admin.is_admin


def test_settings_reject_a_malformed_key_or_unknown_role() -> None:
    with pytest.raises(ConfigurationError):
        ApiSettings(keys=("no-colons",))
    with pytest.raises(ConfigurationError):
        ApiSettings(keys=("label:superuser:secret",))
    with pytest.raises(ConfigurationError):
        ApiSettings(keys=("label:admin:",))


def test_settings_require_cert_and_key_together() -> None:
    with pytest.raises(ConfigurationError):
        ApiSettings(tls_certfile="/tmp/cert.pem")
    assert ApiSettings(tls_certfile="/tmp/cert.pem", tls_keyfile="/tmp/key.pem").tls_configured


# --------------------------------------------------------------------------- rate limit
class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_the_rate_limiter_allows_the_burst_then_refuses() -> None:
    clock = _Clock()
    limiter = ApiRateLimiter(per_minute=60, burst=3, clock=clock)
    assert [limiter.check("k").allowed for _ in range(3)] == [True, True, True]
    denied = limiter.check("k")
    assert not denied.allowed
    assert denied.retry_after_s > 0
    assert denied.limit == 60


def test_the_rate_limiter_refills_over_time() -> None:
    clock = _Clock()
    limiter = ApiRateLimiter(per_minute=60, burst=1, clock=clock)
    assert limiter.check("k").allowed
    assert not limiter.check("k").allowed
    clock.advance(1.1)  # 60/min == 1/s
    assert limiter.check("k").allowed


def test_identities_have_independent_buckets() -> None:
    clock = _Clock()
    limiter = ApiRateLimiter(per_minute=60, burst=1, clock=clock)
    assert limiter.check("a").allowed
    assert limiter.check("b").allowed
    assert not limiter.check("a").allowed


def test_the_rate_limiter_bounds_its_memory() -> None:
    limiter = ApiRateLimiter(per_minute=60, burst=1, max_identities=4)
    for index in range(40):
        limiter.check(f"identity-{index}")
    assert len(limiter._buckets) <= 4


def test_the_rate_limiter_never_sleeps() -> None:
    clock = _Clock()
    limiter = ApiRateLimiter(per_minute=1, burst=1, clock=clock)
    limiter.check("k")
    started = time.monotonic()
    decision = limiter.check("k")
    assert not decision.allowed
    assert time.monotonic() - started < 0.1  # a refusal returns immediately


# --------------------------------------------------------------------------- ci gate
@pytest.mark.parametrize(
    ("counts", "threshold", "expected"),
    [
        ({}, "high", EXIT_CLEAN),
        ({"low": 3}, "high", EXIT_BELOW_THRESHOLD),
        ({"high": 1}, "high", EXIT_AT_OR_ABOVE),
        ({"critical": 2}, "high", EXIT_AT_OR_ABOVE),
        ({"critical": 9}, "none", EXIT_CLEAN),
        ({"info": 1}, "info", EXIT_AT_OR_ABOVE),
    ],
)
def test_the_gate_maps_counts_to_the_documented_exit_codes(
    counts: dict[str, int], threshold: str, expected: int
) -> None:
    assert gate_exit_code(counts, threshold) == expected


def test_the_gate_treats_an_unanalysed_row_as_not_a_finding() -> None:
    # A candidate the analyzer has not touched is not a confirmed finding.
    assert gate_exit_code({"unanalysed": 5}, "low") == EXIT_CLEAN


def test_counts_at_or_above_is_inclusive() -> None:
    assert counts_at_or_above({"high": 2, "critical": 1, "medium": 9}, "high") == 3


def test_gate_summary_is_machine_readable() -> None:
    summary = gate_summary({"high": 2}, "high")
    assert summary["enabled"] is True
    assert summary["at_or_above"] == 2
    assert summary["exit_code"] == EXIT_AT_OR_ABOVE
    assert set(summary["counts"]) == {"info", "low", "medium", "high", "critical"}


def test_parse_threshold_rejects_an_unknown_value() -> None:
    assert parse_threshold(None) == "none"
    assert parse_threshold("HIGH") == "high"
    with pytest.raises(ValueError):
        parse_threshold("blocker")
