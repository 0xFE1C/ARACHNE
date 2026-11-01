"""Cost control: the per-scan ledger, the cache and the metrics (F-04-07)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arachne.ai.budget import (
    BudgetLedger,
    Metrics,
    PriceTable,
    estimate_prompt_tokens,
    load_price_table,
)
from arachne.ai.cache import RequestCache, cache_key
from arachne.ai.types import Usage
from arachne.core.errors import BudgetExhaustedError, ConfigurationError


def usage(tokens: int = 1000, cost: float = 0.01) -> Usage:
    return Usage(
        prompt_tokens=tokens // 2,
        completion_tokens=tokens - tokens // 2,
        total_tokens=tokens,
        cost_usd=cost,
    )


# --------------------------------------------------------------------------- prices


def test_the_shipped_price_table_prices_and_falls_back() -> None:
    prices = load_price_table()
    assert prices.price_for("gpt-4o-mini").input > 0
    assert prices.price_for("ollama/qwen3:32b").input == 0  # wildcard
    assert prices.price_for("qwen3:32b").input == 0  # wildcard by prefix
    assert prices.price_for("some-unknown-model").input == 0  # explicit default


def test_cost_is_per_million_tokens() -> None:
    prices = PriceTable.model_validate(
        {
            "version": "test",
            "per_million_tokens": {"m": {"input": 1.0, "output": 2.0}},
        }
    )
    price = prices.price_for("m")
    assert price.cost(1_000_000, 0) == pytest.approx(1.0)
    assert price.cost(0, 1_000_000) == pytest.approx(2.0)


def test_a_broken_price_table_is_a_configuration_error(tmp_path: Path) -> None:
    path = tmp_path / "prices.yaml"
    path.write_text("per_million_tokens: [not-a-mapping]\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="invalid price table"):
        load_price_table(str(path))


def test_the_prompt_token_estimate_is_conservative() -> None:
    assert estimate_prompt_tokens("a" * 400) == 101
    assert estimate_prompt_tokens("", "") == 1


# --------------------------------------------------------------------------- gates


def test_the_token_cap_is_enforced_before_the_call() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=1000, max_cost_usd=0)
    ledger.record(usage(900), stage="triage", provider="p", model="m", cached=False)
    with pytest.raises(BudgetExhaustedError, match="token budget of 1000"):
        ledger.check(usage(200), stage="narrative", model="m")
    assert ledger.refused == 1


def test_the_cost_cap_is_enforced_before_the_call() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=0, max_cost_usd=0.5)
    ledger.record(usage(cost=0.4), stage="triage", provider="p", model="m", cached=False)
    with pytest.raises(BudgetExhaustedError, match=r"cost budget of \$0.50"):
        ledger.check(usage(cost=0.2), stage="narrative", model="m")


def test_zero_disables_a_gate() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=0, max_cost_usd=0)
    ledger.check(usage(10**9, cost=1000.0), stage="anything", model="m")
    assert ledger.remaining_tokens == -1
    assert ledger.remaining_cost == -1.0


def test_a_call_that_fits_is_allowed() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=1000, max_cost_usd=1.0)
    ledger.check(usage(999), stage="triage", model="m")
    assert ledger.remaining_tokens == 1000


def test_low_water_triggers_at_eighty_percent() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=1000, max_cost_usd=0)
    assert not ledger.low_water
    ledger.record(usage(790), stage="triage", provider="p", model="m", cached=False)
    assert not ledger.low_water
    ledger.record(usage(20), stage="triage", provider="p", model="m", cached=False)
    assert ledger.low_water


def test_an_estimate_prices_the_call_from_the_table() -> None:
    ledger = BudgetLedger(prices=load_price_table())
    estimate = ledger.estimate("gpt-4o-mini", prompt_tokens=1000, max_tokens=1000)
    assert estimate.total_tokens == 2000
    assert estimate.cost_usd > 0


# --------------------------------------------------------------------------- recording


def test_a_cache_hit_is_counted_but_not_spent() -> None:
    ledger = BudgetLedger()
    ledger.record(usage(1000), stage="triage", provider="p", model="m", cached=True)
    assert ledger.cache_hits == 1
    assert ledger.requests == 0
    assert ledger.tokens_spent == 0


def test_the_snapshot_is_the_per_scan_budget_state() -> None:
    ledger = BudgetLedger(max_tokens_per_scan=1000, max_cost_usd=1.0)
    ledger.record(usage(400, 0.2), stage="triage", provider="p", model="m", cached=False)
    ledger.note_degraded()
    snapshot = ledger.snapshot()
    assert snapshot["requests"] == 1
    assert snapshot["degraded"] == 1
    assert snapshot["tokens"]["total_tokens"] == 400
    assert snapshot["remaining_tokens"] == 600
    assert snapshot["max_tokens_per_scan"] == 1000
    assert snapshot["low_water"] is False


# --------------------------------------------------------------------------- metrics


def test_metrics_count_and_observe() -> None:
    metrics = Metrics()
    metrics.inc("arachne_ai_requests_total", {"provider": "p"})
    metrics.inc("arachne_ai_requests_total", {"provider": "p"})
    metrics.observe("arachne_ai_latency_seconds", 0.25, {"provider": "p"})
    snapshot = metrics.snapshot()
    assert snapshot["counters"]['arachne_ai_requests_total{provider="p"}'] == 2.0
    latency = snapshot["latency"]['arachne_ai_latency_seconds{provider="p"}']
    assert latency == {"sum": 0.25, "count": 1}


def test_metrics_render_prometheus_text() -> None:
    metrics = Metrics()
    metrics.inc("c", {"a": "b"}, 3)
    metrics.observe("o", 1.5)
    rendered = metrics.render_prometheus()
    assert 'c{a="b"} 3' in rendered
    assert "o_sum 1.5" in rendered
    assert "o_count 1" in rendered


# --------------------------------------------------------------------------- cache


def test_the_cache_key_covers_everything_that_can_change_the_answer() -> None:
    base = {"stage": "triage", "template_version": "1.0", "model": "m", "prompt": "p"}
    key = cache_key(**base)
    assert key == cache_key(**base)
    assert key != cache_key(**(base | {"stage": "narrative"}))
    assert key != cache_key(**(base | {"template_version": "1.1"}))
    assert key != cache_key(**(base | {"model": "m2"}))
    assert key != cache_key(**(base | {"prompt": "p2"}))


def test_the_cache_is_a_bounded_lru() -> None:
    cache = RequestCache(max_entries=2)
    cache.put("a", {"v": 1})
    cache.put("b", {"v": 2})
    assert cache.get("a") == {"v": 1}  # touch a, so b is now the oldest
    cache.put("c", {"v": 3})
    assert cache.get("b") is None
    assert cache.get("a") == {"v": 1}
    assert cache.get("c") == {"v": 3}
    assert cache.hits == 3
    assert cache.misses == 1


def test_the_cache_persists_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    first = RequestCache(max_entries=4, path=str(path))
    first.put("k", {"severity": "high"})
    assert path.is_file()

    second = RequestCache(max_entries=4, path=str(path))
    assert second.get("k") == {"severity": "high"}
    assert json.loads(path.read_text())["version"]


def test_an_unreadable_cache_file_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("{not json", encoding="utf-8")
    cache = RequestCache(path=str(path))
    assert cache.size == 0
