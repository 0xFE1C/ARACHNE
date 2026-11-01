"""Cost control and observability for model calls (docs/spec/03- §7, F-04-07).

Two objects, one purpose each:

:class:`BudgetLedger`
    The per-scan token and cost budget. Every call is *estimated* before it is made and
    *recorded* after, so the cap is enforced rather than reported: a stage that would cross
    the cap raises :class:`~arachne.core.errors.BudgetExhaustedError` and the engine degrades
    that stage to the heuristic result (docs/spec/03- §7's degradation chain). ``low_water``
    is the signal the engine uses to skip the expensive stages (``explain``, ``narrative``)
    when the budget is nearly spent.

:class:`Metrics`
    Prometheus-friendly counters and latency observations, in the same spirit as the audit
    trail: an operator can answer "how many calls, how many tokens, how much did this scan
    cost, how often did we degrade" without reading a database. The names and label sets are
    stable, which is the part that matters for a dashboard.

Prices come from managed data (``templates/ai/pricing.yaml``, F-09-04): a deployment that pays
a different rate points ``ARACHNE_AI_PRICING`` at its own table. An unknown model costs 0 —
explicitly, so the budget gate never silently blocks on a guess — and the cost estimate for
one call is ``prompt characters / 4`` in plus ``max_tokens`` out, which is the conservative
direction for a per-scan cap.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field

from arachne.ai.types import Usage
from arachne.core.errors import BudgetExhaustedError, ConfigurationError

__all__ = [
    "DEFAULT_PRICING_RESOURCE",
    "BudgetLedger",
    "Metrics",
    "PriceTable",
    "estimate_prompt_tokens",
    "load_price_table",
]

DEFAULT_PRICING_RESOURCE: Final = ("ai", "pricing.yaml")

#: Rough characters-per-token ratio for the pre-call estimate. Deliberately token-frugal so
#: the estimate errs towards "this will cost more than you think".
CHARS_PER_TOKEN: Final = 4.0

_MODEL = ConfigDict(frozen=True, extra="forbid")


class ModelPrice(BaseModel):
    """``$`` per million tokens, in and out."""

    model_config = _MODEL

    input: float = Field(default=0.0, ge=0.0)
    output: float = Field(default=0.0, ge=0.0)

    def cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (prompt_tokens * self.input + completion_tokens * self.output) / 1_000_000.0


class PriceTable(BaseModel):
    """The managed price table."""

    model_config = _MODEL

    version: str = "1.0"
    currency: str = "usd"
    per_million_tokens: dict[str, ModelPrice] = Field(default_factory=dict)
    default: ModelPrice = Field(default_factory=ModelPrice)

    def price_for(self, model: str) -> ModelPrice:
        """Exact model first, then a ``prefix*`` wildcard, then the default (0)."""
        if model in self.per_million_tokens:
            return self.per_million_tokens[model]
        for pattern, price in self.per_million_tokens.items():
            if pattern.endswith("*") and model.startswith(pattern[:-1]):
                return price
        return self.default


def load_price_table(path: str | None = None) -> PriceTable:
    """Load the price table from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"AI price table {resolved} does not exist"
            raise ConfigurationError(msg)
        return _parse(resolved.read_text(encoding="utf-8"), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_PRICING_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled AI price table is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return _parse(text, source="/".join(DEFAULT_PRICING_RESOURCE))


def _parse(text: str, *, source: str) -> PriceTable:
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{source}: expected a mapping")
    try:
        return PriceTable.model_validate(data)
    except Exception as exc:  # pydantic's ValidationError
        raise ConfigurationError(f"{source}: invalid price table: {exc}") from exc


def estimate_prompt_tokens(*texts: str) -> int:
    """A conservative prompt-token estimate for one call."""
    return int(sum(len(text) for text in texts) / CHARS_PER_TOKEN) + 1


@dataclass
class BudgetLedger:
    """The per-scan token/cost ledger (F-04-07).

    ``max_tokens_per_scan`` of 0 means "no token gate" (a local model costs nothing but time);
    ``max_cost_usd`` of 0 means "no cost gate" — exactly the spec's ``0 disables cost gate``.
    """

    max_tokens_per_scan: int = 200_000
    max_cost_usd: float = 1.5
    prices: PriceTable = field(default_factory=PriceTable)
    #: Filled in as calls complete; ``calls`` holds one entry per provider call for the
    #: per-scan audit line and the step statistics.
    usage: Usage = field(default_factory=Usage)
    requests: int = 0
    cache_hits: int = 0
    degraded: int = 0
    refused: int = 0
    calls: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------ gates
    @property
    def tokens_spent(self) -> int:
        return self.usage.total_tokens

    @property
    def cost_spent(self) -> float:
        return self.usage.cost_usd

    @property
    def remaining_tokens(self) -> int:
        if self.max_tokens_per_scan <= 0:
            return -1
        return max(0, self.max_tokens_per_scan - self.tokens_spent)

    @property
    def remaining_cost(self) -> float:
        if self.max_cost_usd <= 0:
            return -1.0
        return max(0.0, self.max_cost_usd - self.cost_spent)

    def estimate(self, model: str, *, prompt_tokens: int, max_tokens: int) -> Usage:
        """The usage a call is expected to produce (used for the pre-call gate)."""
        price = self.prices.price_for(model)
        return Usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=max_tokens,
            total_tokens=prompt_tokens + max_tokens,
            cost_usd=price.cost(prompt_tokens, max_tokens),
        )

    def check(self, estimate: Usage, *, stage: str = "", model: str = "") -> None:
        """Refuse a call that would cross a cap (raises ``BudgetExhaustedError``)."""
        if self.max_tokens_per_scan > 0 and self.tokens_spent + estimate.total_tokens > (
            self.max_tokens_per_scan
        ):
            self.refused += 1
            msg = (
                f"per-scan token budget of {self.max_tokens_per_scan} would be exceeded "
                f"({self.tokens_spent} spent, ~{estimate.total_tokens} more for stage "
                f"{stage or 'call'})"
            )
            raise BudgetExhaustedError(msg)
        if self.max_cost_usd > 0 and self.cost_spent + estimate.cost_usd > self.max_cost_usd:
            self.refused += 1
            msg = (
                f"per-scan cost budget of ${self.max_cost_usd:.2f} would be exceeded "
                f"(${self.cost_spent:.4f} spent, ~${estimate.cost_usd:.4f} more for model "
                f"{model or 'unknown'})"
            )
            raise BudgetExhaustedError(msg)

    @property
    def low_water(self) -> bool:
        """True when the expensive stages should be skipped (docs/spec/03- §7).

        "Low" is 80% of either cap, or "no tokens left at all" when a cap is disabled and the
        ledger has still spent a lot of a local model's time.
        """
        if self.max_tokens_per_scan > 0 and (self.tokens_spent >= 0.8 * self.max_tokens_per_scan):
            return True
        return self.max_cost_usd > 0 and self.cost_spent >= 0.8 * self.max_cost_usd

    # ------------------------------------------------------------------ recording
    def record(self, usage: Usage, *, stage: str, provider: str, model: str, cached: bool) -> None:
        """Add one call's usage to the ledger."""
        if cached:
            self.cache_hits += 1
            return
        self.requests += 1
        self.usage = self.usage.merge(usage)
        self.calls.append(
            {
                "stage": stage,
                "provider": provider,
                "model": model,
                **usage.to_dict(),
            }
        )

    def note_degraded(self) -> None:
        self.degraded += 1

    def snapshot(self) -> dict[str, Any]:
        """The per-scan budget state, which the analysis step persists and audits."""
        return {
            "requests": self.requests,
            "cache_hits": self.cache_hits,
            "degraded": self.degraded,
            "refused": self.refused,
            "tokens": dict(self.usage.to_dict()),
            "max_tokens_per_scan": self.max_tokens_per_scan,
            "max_cost_usd": self.max_cost_usd,
            "remaining_tokens": self.remaining_tokens,
            "low_water": self.low_water,
        }


@dataclass
class Metrics:
    """Prometheus-friendly counters and latency observations (docs/spec/03- §7)."""

    counters: dict[str, float] = field(default_factory=dict)
    observations: dict[str, tuple[float, int]] = field(default_factory=dict)

    def inc(self, name: str, labels: Mapping[str, str] | None = None, value: float = 1.0) -> None:
        key = _metric_key(name, labels)
        self.counters[key] = self.counters.get(key, 0.0) + value

    def observe(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        key = _metric_key(name, labels)
        total, count = self.observations.get(key, (0.0, 0))
        self.observations[key] = (total + value, count + 1)

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(sorted(self.counters.items())),
            "latency": {
                key: {"sum": round(total, 6), "count": count}
                for key, (total, count) in sorted(self.observations.items())
            },
        }

    def render_prometheus(self) -> str:
        """The text exposition format, so an operator can scrape what the snapshot shows."""
        lines: list[str] = []
        for key, value in sorted(self.counters.items()):
            lines.append(f"{key} {value:g}")
        for key, (total, count) in sorted(self.observations.items()):
            lines.append(f"{key}_sum {total:g}")
            lines.append(f"{key}_count {count}")
        return "\n".join(lines) + ("\n" if lines else "")


def _metric_key(name: str, labels: Mapping[str, str] | None) -> str:
    if not labels:
        return name
    rendered = ",".join(f'{key}="{value}"' for key, value in sorted(labels.items()))
    return f"{name}{{{rendered}}}"
