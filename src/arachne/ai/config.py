"""Provider configuration: the provider YAML, with credentials from the environment.

The spec's block is a *file* of provider definitions and an *environment* of secrets::

    ai:
      engine: hybrid
      default_provider: openai_compatible
      budget:
        max_tokens_per_scan: 200_000
        max_cost_usd: 1.50          # 0 disables the cost gate
      providers:
        openai_compatible:
          base_url: https://api.openai.com/v1
          api_key_env: OPENAI_API_KEY      # never inline keys
          model: gpt-4o-mini

:func:`load_ai_config` reads exactly that (``ARACHNE_AI_CONFIG``), resolves each provider's
credential from the named environment variable (F-04-02, F-08-01) and lets a handful of
environment variables override the *default* provider, so ``--engine ai`` works with nothing
but env vars for the local path (``ARACHNE_AI_BASE_URL=http://localhost:11434``).

Three properties are enforced at load time, because each one is a silent-failure class:

* a provider's name must be one of the seven adapters;
* ``base_url`` must be an ``http(s)`` URL;
* a provider that needs a credential must name the environment variable that holds it — the
  key itself is never read from the file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator

from arachne.ai.privacy import PrivacyMode
from arachne.ai.types import ResponseFormat
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.core.redaction import redact_text

__all__ = [
    "ADAPTERS",
    "DEFAULT_API_KEY_ENV",
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODELS",
    "AiConfig",
    "BudgetConfig",
    "ProviderConfig",
    "ResolvedProvider",
    "load_ai_config",
    "parse_ai_config",
]

#: The seven adapters of in the spec's order.
ADAPTERS: Final[tuple[str, ...]] = (
    "openai",
    "openai_compatible",
    "anthropic",
    "gemini",
    "ollama",
    "mistral",
    "custom",
)

DEFAULT_BASE_URLS: Final[dict[str, str]] = {
    "openai": "https://api.openai.com/v1",
    "openai_compatible": "",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "ollama": "http://localhost:11434",
    "mistral": "https://api.mistral.ai/v1",
    "custom": "",
}

DEFAULT_MODELS: Final[dict[str, str]] = {
    "openai": "gpt-4o-mini",
    "openai_compatible": "",
    "anthropic": "claude-sonnet-4-5",
    "gemini": "gemini-2.5-pro",
    "ollama": "qwen3:32b",
    "mistral": "mistral-large-latest",
    "custom": "",
}

DEFAULT_API_KEY_ENV: Final[dict[str, str | None]] = {
    "openai": "OPENAI_API_KEY",
    "openai_compatible": None,
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "ollama": None,
    "mistral": "MISTRAL_API_KEY",
    "custom": None,
}

#: Providers that cannot work without a credential (checked at resolve time, not load time,
#: so a config file can list a provider a given deployment does not actually use).
_NEEDS_CREDENTIAL: Final[frozenset[str]] = frozenset({"openai", "anthropic", "gemini", "mistral"})

_MODEL = ConfigDict(frozen=True, extra="forbid")


class ProviderConfig(BaseModel):
    """One provider block of the provider YAML."""

    model_config = _MODEL

    name: str = ""
    base_url: str = ""
    #: The *name* of the environment variable holding the key — never the key (F-04-02).
    api_key_env: str | None = None
    model: str = ""
    timeout_s: float = Field(default=60.0, gt=0)
    max_tokens: int = Field(default=3000, gt=0)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    #: Force a structured-output mechanism instead of the adapter's default .
    response_format: ResponseFormat | None = None
    #: vLLM/llama.cpp style grammar-constrained decoding (``guided_json``).
    constrained_decoding: bool = False
    #: Azure OpenAI / custom gateways that carry the API version in the query string.
    api_version: str | None = None
    #: Requests per second this provider tolerates (the AI layer's own token bucket).
    requests_per_second: float = Field(default=5.0, gt=0)
    #: The ``custom`` adapter's JSON mapping (request template + response path), and any
    #: provider-specific extras an adapter documents.
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate(self) -> ProviderConfig:
        if not self.name:
            raise ValueError("provider name is required")
        if self.name not in ADAPTERS:
            raise ValueError(f"unknown provider {self.name!r}; known adapters: {list(ADAPTERS)}")
        # Fill the published defaults for this adapter so a file may
        # say just ``model: gpt-4o-mini`` under ``openai``.
        if not self.base_url:
            object.__setattr__(self, "base_url", DEFAULT_BASE_URLS.get(self.name, ""))
        if not self.model:
            object.__setattr__(self, "model", DEFAULT_MODELS.get(self.name, ""))
        if self.api_key_env is None:
            object.__setattr__(self, "api_key_env", DEFAULT_API_KEY_ENV.get(self.name))
        if not self.base_url:
            raise ValueError(
                f"provider {self.name!r}: base_url is required "
                "(this adapter has no default endpoint)"
            )
        parts = urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError(f"provider {self.name!r}: base_url must be an http(s) URL")
        if not self.model:
            raise ValueError(f"provider {self.name!r}: model is required")
        return self

    def resolved(self, env: Mapping[str, str]) -> ResolvedProvider:
        """Resolve the credential from ``env`` (F-08-01: env only, never the file)."""
        secret = _secret_from_env(env, self.api_key_env)
        if self.name in _NEEDS_CREDENTIAL and secret is None:
            msg = (
                f"provider {self.name!r} needs a credential in {self.api_key_env} "
                "(set it in the environment; keys are never read from the config file)"
            )
            raise ConfigurationError(msg)
        return ResolvedProvider(
            name=self.name,
            base_url=self.base_url.rstrip("/"),
            model=self.model,
            api_key=secret,
            timeout_s=self.timeout_s,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            response_format=self.response_format,
            constrained_decoding=self.constrained_decoding,
            api_version=self.api_version,
            requests_per_second=self.requests_per_second,
            extra=dict(self.extra),
        )

    def to_dict(self) -> dict[str, Any]:
        """The redacted, serializable form (safe for a plan or a log line)."""
        return {
            "name": self.name,
            "base_url": redact_text(self.base_url),
            "api_key_env": self.api_key_env,
            "model": self.model,
            "timeout_s": self.timeout_s,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "constrained_decoding": self.constrained_decoding,
            "requests_per_second": self.requests_per_second,
            "extra_keys": sorted(self.extra),
        }


class BudgetConfig(BaseModel):
    """The F-04-07 per-scan caps. ``max_cost_usd`` of 0 disables the cost gate."""

    model_config = _MODEL

    max_tokens_per_scan: int = Field(default=200_000, ge=0)
    max_cost_usd: float = Field(default=1.5, ge=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens_per_scan": self.max_tokens_per_scan,
            "max_cost_usd": self.max_cost_usd,
        }


@dataclass(frozen=True, slots=True)
class ResolvedProvider:
    """A provider block with its credential resolved and defaults applied."""

    name: str
    base_url: str
    model: str
    api_key: SecretStr | None = None
    timeout_s: float = 60.0
    max_tokens: int = 3000
    temperature: float = 0.0
    response_format: ResponseFormat | None = None
    constrained_decoding: bool = False
    api_version: str | None = None
    requests_per_second: float = 5.0
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": redact_text(self.base_url),
            "model": self.model,
            "credential": "env" if self.api_key is not None else "none",
            "constrained_decoding": self.constrained_decoding,
        }


class AiConfig(BaseModel):
    """The whole ``ai:`` block, validated."""

    model_config = _MODEL

    engine: str = "hybrid"
    default_provider: str = "openai_compatible"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    privacy: PrivacyMode = PrivacyMode.REDACT
    #: Which analysis stages the AI engine runs, in order.
    stages: tuple[str, ...] = ("triage", "explain", "remediate", "narrative")
    #: Retry attempts per provider call, including the first .
    retries: int = Field(default=3, ge=1, le=10)
    #: A correlation group of at least this many candidates gets an AI compound suggestion.
    correlate_threshold: int = Field(default=3, ge=2)
    #: Check modules/ids whose AI verdict is authoritative (empty: every check keeps the
    #: deterministic verdict, which is what determinism needs).
    authoritative_checks: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> AiConfig:
        if self.engine not in {"ai", "heuristic", "hybrid"}:
            raise ValueError(f"engine must be ai, heuristic or hybrid, got {self.engine!r}")
        for name, provider in self.providers.items():
            if provider.name != name:
                raise ValueError(
                    f"provider block {name!r} declares name {provider.name!r}; they must match"
                )
        if self.providers and self.default_provider not in self.providers:
            raise ValueError(
                f"default_provider {self.default_provider!r} is not configured; "
                f"configured providers: {sorted(self.providers)}"
            )
        return self

    # ------------------------------------------------------------------ resolution
    def provider(self, name: str | None, env: Mapping[str, str]) -> ResolvedProvider:
        """Resolve a provider block by name (default: ``default_provider``)."""
        wanted = name or self.default_provider
        block = self.providers.get(wanted)
        if block is None:
            known = ", ".join(sorted(self.providers)) or "none"
            msg = f"provider {wanted!r} is not configured (configured: {known})"
            raise ConfigurationError(msg)
        return block.resolved(env)

    @property
    def configured(self) -> bool:
        """True when at least one provider block exists (F-03-03: AI is explicit)."""
        return bool(self.providers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "default_provider": self.default_provider,
            "budget": self.budget.to_dict(),
            "privacy": self.privacy.value,
            "stages": list(self.stages),
            "retries": self.retries,
            "providers": {name: block.to_dict() for name, block in sorted(self.providers.items())},
        }


def _secret_from_env(env: Mapping[str, str], name: str | None) -> SecretStr | None:
    if not name:
        return None
    value = env.get(name, "").strip()
    return SecretStr(value) if value else None


def parse_ai_config(document: Any, *, source: str = "<memory>") -> AiConfig:
    """Validate an already-parsed ``ai:`` document (or a whole settings file)."""
    if not isinstance(document, dict):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    block = document.get("ai", document)
    if not isinstance(block, dict):
        msg = f"{source}: the 'ai' block must be a mapping"
        raise ConfigurationError(msg)
    providers = block.get("providers") or {}
    prepared: dict[str, Any] = dict(block)
    prepared["providers"] = {
        str(name): {**dict(value or {}), "name": str(name)}
        for name, value in dict(providers).items()
    }
    try:
        return AiConfig.model_validate(prepared)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(f"{source}: invalid ai config: {'; '.join(parts)}") from exc


def load_ai_config(
    settings: Settings | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> AiConfig:
    """Load the deployment's AI configuration (``ARACHNE_AI_CONFIG``), env-overridable.

    Precedence, most specific first: an explicit environment override for the default
    provider (``ARACHNE_AI_BASE_URL``/``ARACHNE_AI_MODEL``/``ARACHNE_AI_API_KEY_ENV``), the
    YAML file, the built-in defaults. With neither a file nor a base URL
    in the environment the result is *unconfigured* (``configured`` is False), which is how
    F-03-03 stays true: no provider configured means no call is ever made.
    """
    effective_env = env if env is not None else _environ()
    ai = settings.ai if settings is not None else None
    document: dict[str, Any] = {}
    source = "<defaults>"
    path = ai.config_path if ai is not None else None
    if path:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"AI config {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            loaded = yaml.safe_load(resolved.read_text(encoding="utf-8"))  # F-08-06: safe_load
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"{resolved}: not valid YAML: {exc}") from exc
        if loaded is None:
            loaded = {}
        document = parse_ai_config(loaded, source=str(resolved)).model_dump()
        source = str(resolved)

    config = parse_ai_config(document, source=source)
    return _apply_env_overrides(config, ai, effective_env)


def _environ() -> Mapping[str, str]:
    import os

    return os.environ


def _apply_env_overrides(config: AiConfig, ai: Any, env: Mapping[str, str]) -> AiConfig:
    """Overlay the environment onto the file's configuration ."""
    updates: dict[str, Any] = {}
    if ai is not None:
        if ai.engine:
            updates["engine"] = ai.engine
        if ai.default_provider:
            updates["default_provider"] = ai.default_provider
        if ai.privacy is not None:
            updates["privacy"] = ai.privacy
        if ai.stages:
            updates["stages"] = ai.stages
        if ai.retries is not None:
            updates["retries"] = ai.retries
        if ai.correlate_threshold is not None:
            updates["correlate_threshold"] = ai.correlate_threshold
        if ai.authoritative_checks:
            updates["authoritative_checks"] = ai.authoritative_checks
        if ai.budget_tokens is not None or ai.budget_cost_usd is not None:
            budget = config.budget.model_dump()
            if ai.budget_tokens is not None:
                budget["max_tokens_per_scan"] = ai.budget_tokens
            if ai.budget_cost_usd is not None:
                budget["max_cost_usd"] = ai.budget_cost_usd
            updates["budget"] = budget

    base_url = env.get("ARACHNE_AI_BASE_URL", "").strip()
    model = env.get("ARACHNE_AI_MODEL", "").strip()
    api_key_env = env.get("ARACHNE_AI_API_KEY_ENV", "").strip()
    explicit_provider = env.get("ARACHNE_AI_PROVIDER", "").strip()
    name = explicit_provider or updates.get("default_provider", config.default_provider)
    providers = {key: block.model_dump() for key, block in config.providers.items()}
    # A provider is synthesized from the environment only when the operator said something
    # provider-shaped. Without that, a deployment that configured nothing stays unconfigured
    # (F-03-03), and merely *reading* settings never produces an error about a missing model.
    if base_url or model or api_key_env or explicit_provider:
        if not name:
            name = "openai_compatible"
        block = dict(providers.get(name) or {})
        block.setdefault("name", name)
        block.setdefault("base_url", DEFAULT_BASE_URLS.get(name, ""))
        block.setdefault("model", DEFAULT_MODELS.get(name, ""))
        block.setdefault("api_key_env", DEFAULT_API_KEY_ENV.get(name))
        if base_url:
            block["base_url"] = base_url
        if model:
            block["model"] = model
        if api_key_env:
            block["api_key_env"] = api_key_env
        if not block.get("model"):
            msg = (
                f"provider {name!r} has no model; set ARACHNE_AI_MODEL or a model in the "
                "AI config file"
            )
            raise ConfigurationError(msg)
        if not block.get("base_url"):
            msg = (
                f"provider {name!r} has no base_url; set ARACHNE_AI_BASE_URL or a base_url "
                "in the AI config file"
            )
            raise ConfigurationError(msg)
        providers[name] = block
        updates["default_provider"] = name

    merged = {**config.model_dump(), **updates}
    if providers and merged.get("providers") != providers:
        merged["providers"] = providers
    # ``model_dump`` turns the enum into its string value; validation restores the enum.
    return parse_ai_config(merged, source="<env overrides>")
