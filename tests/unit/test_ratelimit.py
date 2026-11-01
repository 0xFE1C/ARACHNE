"""Rate-limiter unit tests (F-01-07) — exact, because the clock is injected."""

from __future__ import annotations

import pytest
from tests.conftest import FakeClock

from arachne.core.ratelimit import HostRateLimiter, RateLimitSettings, TokenBucket


async def test_burst_is_available_immediately() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=10.0, burst=5, clock=clock.monotonic, sleep=clock.sleep)
    for _ in range(5):
        assert await bucket.acquire() == 0.0
    assert clock.sleep_calls == 0


async def test_waits_one_interval_after_burst_is_spent() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=10.0, burst=1, clock=clock.monotonic, sleep=clock.sleep)
    await bucket.acquire()
    waited = await bucket.acquire()
    assert waited == pytest.approx(0.1, abs=0.001)
    assert clock.now == pytest.approx(0.1, abs=0.001)


async def test_bucket_refills_over_time() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=2.0, burst=2, clock=clock.monotonic, sleep=clock.sleep)
    await bucket.acquire()
    await bucket.acquire()
    clock.advance(1.0)  # two tokens' worth of time
    assert await bucket.acquire() == 0.0
    assert await bucket.acquire() == 0.0


async def test_acquire_more_than_capacity_is_rejected() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate=1.0, burst=2, clock=clock.monotonic, sleep=clock.sleep)
    with pytest.raises(ValueError, match="capacity"):
        await bucket.acquire(2.5)


@pytest.mark.parametrize(
    ("rate", "burst"),
    [(0.0, 1), (-1.0, 1), (1.0, 0)],
)
def test_invalid_bucket_parameters_rejected(rate: float, burst: int) -> None:
    with pytest.raises(ValueError):
        TokenBucket(rate=rate, burst=burst)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"per_host_rate": 0.0},
        {"global_rate": -5.0},
        {"per_host_burst": 0},
        {"global_burst": 0},
    ],
)
def test_invalid_settings_rejected(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        RateLimitSettings(**kwargs)  # type: ignore[arg-type]


def test_host_normalization_ignores_case_port_and_trailing_dot() -> None:
    assert HostRateLimiter.normalize_host("Example.COM") == "example.com"
    assert HostRateLimiter.normalize_host("example.com:8443") == "example.com"
    assert HostRateLimiter.normalize_host("example.com.") == "example.com"


async def test_per_host_budgets_are_independent() -> None:
    clock = FakeClock()
    limiter = HostRateLimiter(
        RateLimitSettings(
            per_host_rate=10.0, per_host_burst=1, global_rate=1000.0, global_burst=1000
        ),
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    assert await limiter.acquire("a.example.com:443") == 0.0
    assert await limiter.acquire("b.example.com:443") == 0.0  # own bucket, no wait
    waited = await limiter.acquire("a.example.com:443")
    assert waited == pytest.approx(0.1, abs=0.001)


async def test_global_budget_applies_across_hosts() -> None:
    clock = FakeClock()
    limiter = HostRateLimiter(
        RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=10.0, global_burst=1
        ),
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    await limiter.acquire("a.example.com")
    waited = await limiter.acquire("b.example.com")
    assert waited == pytest.approx(0.1, abs=0.001)


async def test_same_host_shares_one_bucket_regardless_of_port() -> None:
    clock = FakeClock()
    limiter = HostRateLimiter(
        RateLimitSettings(
            per_host_rate=10.0, per_host_burst=1, global_rate=1000.0, global_burst=1000
        ),
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    await limiter.acquire("example.com:443")
    waited = await limiter.acquire("example.com:80")
    assert waited == pytest.approx(0.1, abs=0.001)
