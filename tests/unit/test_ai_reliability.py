"""Retries, backoff, pacing and the circuit breaker (F-04-06).

The policy is narrow on purpose and these tests pin the narrowness: retry **only** transient
failures, honour ``Retry-After``, never retry a validation failure or a bad credential, and stop
calling a provider that is down instead of spending one timeout per candidate.
"""

from __future__ import annotations

import pytest

from arachne.ai.reliability import RetryingProvider, RetryPolicy
from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
    Usage,
)
from arachne.core.ratelimit import TokenBucket

REQUEST = CompletionRequest(model="m", system="s", messages=({"role": "user", "content": "u"},))


class Recorder:
    """A provider whose answer (or failure) is scripted per call."""

    def __init__(self, *outcomes: object) -> None:
        self.name = "scripted"
        self.model = "scripted-1"
        self.calls = 0
        self._outcomes = list(outcomes)

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        del request
        self.calls += 1
        outcome = self._outcomes.pop(0) if self._outcomes else "ok"
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome == "ok":
            return CompletionResult(text="{}", usage=Usage(1, 1, 2, 0.0), model=self.model)
        raise AssertionError(f"unexpected scripted outcome {outcome!r}")


class Sleeper:
    """Records the delays instead of waiting them."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def policy(**overrides: object) -> RetryPolicy:
    base: dict[str, object] = {
        "attempts": 3,
        "base_delay_s": 0.5,
        "jitter": 0.0,
        "failure_threshold": 3,
    }
    base.update(overrides)
    return RetryPolicy(**base)  # type: ignore[arg-type]


async def test_a_transient_failure_is_retried_and_then_succeeds() -> None:
    sleeper = Sleeper()
    provider = Recorder(ProviderUnavailableError("503", provider="p"), "ok")
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    result = await wrapper.complete(REQUEST)
    assert result.text == "{}"
    assert provider.calls == 2
    assert sleeper.delays == [0.5]


async def test_backoff_doubles_between_attempts() -> None:
    sleeper = Sleeper()
    provider = Recorder(
        ProviderUnavailableError("503"),
        ProviderUnavailableError("503"),
        "ok",
    )
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    await wrapper.complete(REQUEST)
    assert sleeper.delays == [0.5, 1.0]
    assert wrapper.total_retries == 2


async def test_retry_after_wins_over_the_exponential_delay() -> None:
    sleeper = Sleeper()
    provider = Recorder(ProviderRateLimitError("429", retry_after=7.0), "ok")
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    await wrapper.complete(REQUEST)
    assert sleeper.delays == [7.0]


async def test_the_attempts_budget_is_used_up_then_it_raises() -> None:
    sleeper = Sleeper()
    provider = Recorder(*[ProviderUnavailableError("503") for _ in range(5)])
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    with pytest.raises(ProviderUnavailableError):
        await wrapper.complete(REQUEST)
    assert provider.calls == 3


async def test_a_non_transient_error_is_not_retried() -> None:
    """A rejected credential cannot be fixed by trying again ."""
    sleeper = Sleeper()
    provider = Recorder(ProviderAuthError("401", provider="p"))
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    with pytest.raises(ProviderAuthError):
        await wrapper.complete(REQUEST)
    assert provider.calls == 1
    assert sleeper.delays == []


async def test_validation_failures_are_not_provider_errors_and_are_not_retried() -> None:
    from arachne.ai.types import StructuredOutputError

    sleeper = Sleeper()
    provider = Recorder(StructuredOutputError("bad shape"))
    wrapper = RetryingProvider(provider, policy=policy(), sleep=sleeper)
    with pytest.raises(StructuredOutputError):
        await wrapper.complete(REQUEST)
    assert provider.calls == 1


async def test_a_down_provider_is_marked_degraded_and_stops_being_called() -> None:
    sleeper = Sleeper()
    provider = Recorder(*[ProviderUnavailableError("503") for _ in range(20)])
    wrapper = RetryingProvider(
        provider, policy=policy(attempts=1, failure_threshold=2), sleep=sleeper
    )
    for _ in range(2):
        with pytest.raises(ProviderUnavailableError):
            await wrapper.complete(REQUEST)
    assert wrapper.degraded is True
    assert "ProviderUnavailableError" in wrapper.degraded_reason
    calls_before = provider.calls
    with pytest.raises(ProviderUnavailableError, match="degraded"):
        await wrapper.complete(REQUEST)
    assert provider.calls == calls_before  # the breaker short-circuits the call


async def test_a_success_resets_the_failure_counter() -> None:
    sleeper = Sleeper()
    provider = Recorder(
        ProviderUnavailableError("503"),
        "ok",
        ProviderUnavailableError("503"),
        ProviderUnavailableError("503"),
    )
    wrapper = RetryingProvider(provider, policy=policy(attempts=2), sleep=sleeper)
    await wrapper.complete(REQUEST)
    assert wrapper.consecutive_failures == 0
    with pytest.raises(ProviderUnavailableError):
        await wrapper.complete(REQUEST)
    assert wrapper.degraded is False


async def test_reset_forgets_the_breaker() -> None:
    wrapper = RetryingProvider(Recorder(ProviderUnavailableError("503")), policy=policy(attempts=1))
    with pytest.raises(ProviderUnavailableError):
        await wrapper.complete(REQUEST)
    wrapper.reset()
    assert wrapper.degraded is False
    assert wrapper.snapshot()["degraded"] is False


async def test_the_per_provider_bucket_paces_calls() -> None:
    bucket = TokenBucket(rate=1000.0, burst=1)
    provider = Recorder()
    wrapper = RetryingProvider(provider, policy=policy(), limiter=bucket)
    await wrapper.complete(REQUEST)
    assert bucket.tokens < 1.0


def test_the_delay_is_jittered_within_bounds() -> None:
    jittered = policy(jitter=0.5)
    for _ in range(20):
        delay = jittered.delay_for(1)
        assert 0.5 <= delay <= 0.75


def test_an_invalid_policy_is_refused() -> None:
    with pytest.raises(ValueError, match="attempts"):
        RetryPolicy(attempts=0)
    with pytest.raises(ValueError, match="jitter"):
        RetryPolicy(jitter=2.0)
    with pytest.raises(ValueError, match="failure_threshold"):
        RetryPolicy(failure_threshold=0)


def test_the_snapshot_names_the_provider_and_the_breaker_state() -> None:
    wrapper = RetryingProvider(Recorder(), policy=policy())
    assert wrapper.snapshot() == {
        "provider": "scripted",
        "model": "scripted-1",
        "attempts": 0,
        "retries": 0,
        "degraded": False,
        "degraded_reason": None,
    }


def test_a_provider_error_carries_its_classification() -> None:
    transient = ProviderError("x", transient=True)
    permanent = ProviderError("y", transient=False)
    assert transient.transient is True
    assert permanent.transient is False
