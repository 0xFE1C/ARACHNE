"""Provider configuration: docs/spec/03- §3's file, credentials from the environment (F-04-02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.ai.config import (
    ADAPTERS,
    DEFAULT_API_KEY_ENV,
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    AiConfig,
    load_ai_config,
    parse_ai_config,
)
from arachne.ai.privacy import PrivacyMode
from arachne.ai.providers.registry import PROVIDER_CLASSES
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError


def test_the_shipped_adapters_are_exactly_the_specs_table() -> None:
    """docs/spec/03- §3 lists seven adapters; the registry must implement exactly those."""
    assert set(ADAPTERS) == {
        "openai",
        "openai_compatible",
        "anthropic",
        "gemini",
        "ollama",
        "mistral",
        "custom",
    }
    assert set(PROVIDER_CLASSES) == set(ADAPTERS)
    assert set(DEFAULT_BASE_URLS) == set(ADAPTERS)
    assert set(DEFAULT_MODELS) == set(ADAPTERS)
    assert set(DEFAULT_API_KEY_ENV) == set(ADAPTERS)


def test_nothing_configured_means_no_ai() -> None:
    """F-03-03: an empty environment yields an *unconfigured* config, never an error."""
    config = load_ai_config(Settings.from_env({}), env={})
    assert not config.configured
    assert config.providers == {}
    assert config.privacy is PrivacyMode.REDACT
    assert config.budget.max_tokens_per_scan == 200_000
    assert config.budget.max_cost_usd == 1.5


def test_the_spec_example_config_loads(tmp_path: Path) -> None:
    """The YAML of docs/spec/03- §3, verbatim in shape, resolves with env-only credentials."""
    path = tmp_path / "ai.yaml"
    path.write_text(
        """
ai:
  engine: hybrid
  default_provider: openai_compatible
  budget:
    max_tokens_per_scan: 200000
    max_cost_usd: 1.50
  providers:
    openai_compatible:
      base_url: https://api.openai.com/v1
      api_key_env: OPENAI_API_KEY
      model: gpt-4o-mini
      timeout_s: 60
      max_tokens: 3000
      temperature: 0.0
    ollama:
      base_url: http://localhost:11434
      model: qwen3:32b
    anthropic:
      base_url: https://api.anthropic.com
      api_key_env: ANTHROPIC_API_KEY
      model: claude-sonnet-4-5
    gemini:
      base_url: https://generativelanguage.googleapis.com
      api_key_env: GEMINI_API_KEY
      model: gemini-2.5-pro
""",
        encoding="utf-8",
    )
    settings = Settings.from_env({"ARACHNE_AI_CONFIG": str(path)})
    config = load_ai_config(settings, env={"OPENAI_API_KEY": "sk-test-123"})

    assert config.configured
    assert config.engine == "hybrid"
    assert config.default_provider == "openai_compatible"
    assert sorted(config.providers) == ["anthropic", "gemini", "ollama", "openai_compatible"]

    resolved = config.provider(None, {"OPENAI_API_KEY": "sk-test-123"})
    assert resolved.name == "openai_compatible"
    assert resolved.model == "gpt-4o-mini"
    assert resolved.api_key is not None
    assert resolved.api_key.get_secret_value() == "sk-test-123"
    assert resolved.max_tokens == 3000
    # The redacted form never carries the key.
    assert "sk-test-123" not in str(resolved.to_dict())
    assert resolved.to_dict()["credential"] == "env"

    local = config.provider("ollama", {})
    assert local.api_key is None
    assert local.base_url == "http://localhost:11434"


def test_a_hosted_provider_without_its_credential_is_refused() -> None:
    config = parse_ai_config(
        {
            "ai": {
                "default_provider": "openai",
                "providers": {"openai": {"base_url": DEFAULT_BASE_URLS["openai"], "model": "x"}},
            }
        }
    )
    with pytest.raises(ConfigurationError, match="needs a credential in OPENAI_API_KEY"):
        config.provider(None, {})


def test_the_credential_is_never_read_from_the_file() -> None:
    """F-04-02/F-08-01: an inline key is not a configuration key, so it is rejected."""
    with pytest.raises(ConfigurationError, match="invalid ai config"):
        parse_ai_config(
            {
                "ai": {
                    "providers": {
                        "openai": {
                            "base_url": "https://api.openai.com/v1",
                            "model": "gpt-4o-mini",
                            # the model forbids unknown fields: an inline key never loads
                            "api_key": "sk-live-should-not-be-here",
                        }
                    }
                }
            }
        )


def test_a_provider_block_must_name_a_known_adapter() -> None:
    with pytest.raises(ConfigurationError, match="unknown provider 'skynet'"):
        parse_ai_config({"ai": {"providers": {"skynet": {"base_url": "http://x", "model": "m"}}}})


def test_the_default_provider_must_be_configured() -> None:
    with pytest.raises(ConfigurationError, match="is not configured"):
        parse_ai_config(
            {
                "ai": {
                    "default_provider": "anthropic",
                    "providers": {"ollama": {"base_url": "http://localhost:11434", "model": "m"}},
                }
            }
        )


def test_base_url_must_be_http() -> None:
    with pytest.raises(ConfigurationError, match="base_url must be an http"):
        parse_ai_config(
            {"ai": {"providers": {"ollama": {"base_url": "localhost:11434", "model": "m"}}}}
        )


def test_the_environment_can_configure_a_local_provider_alone() -> None:
    """A local demo needs no config file: three variables are enough (docs/spec/03- §3)."""
    env = {
        "ARACHNE_AI_PROVIDER": "ollama",
        "ARACHNE_AI_BASE_URL": "http://localhost:11434",
        "ARACHNE_AI_MODEL": "qwen3:32b",
    }
    settings = Settings.from_env(env)
    config = load_ai_config(settings, env=env)
    resolved = config.provider(None, {})
    assert resolved.name == "ollama"
    assert resolved.base_url == "http://localhost:11434"
    assert resolved.model == "qwen3:32b"
    assert resolved.api_key is None  # a local endpoint needs no credential


def test_policy_knobs_come_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_AI_PRIVACY": "local-only",
            "ARACHNE_AI_MAX_TOKENS_PER_SCAN": "1000",
            "ARACHNE_AI_MAX_COST_USD": "0",
            "ARACHNE_AI_STAGES": "triage,narrative",
            "ARACHNE_AI_RETRIES": "1",
            "ARACHNE_AI_CORRELATE_THRESHOLD": "5",
            "ARACHNE_AI_AUTHORITATIVE_CHECKS": "m5.novel,m6.thing",
            "ARACHNE_AI_PROMPTS": "/etc/prompts",
            "ARACHNE_AI_PRICING": "/etc/pricing.yaml",
            "ARACHNE_AI_CACHE_DIR": "/tmp/cache",
        }
    )
    config = load_ai_config(settings, env={})
    assert config.privacy is PrivacyMode.LOCAL_ONLY
    assert config.budget.max_tokens_per_scan == 1000
    assert config.budget.max_cost_usd == 0.0
    assert config.stages == ("triage", "narrative")
    assert config.retries == 1
    assert config.correlate_threshold == 5
    assert config.authoritative_checks == ("m5.novel", "m6.thing")
    assert settings.ai.prompts == "/etc/prompts"
    assert settings.ai.pricing == "/etc/pricing.yaml"
    assert settings.ai.cache_dir == "/tmp/cache"


@pytest.mark.parametrize(
    "entry, expected",
    [
        ({"ARACHNE_AI_ENGINE": "magic"}, "ai.engine must be"),
        ({"ARACHNE_AI_PRIVACY": "leaky"}, "ai.privacy must be"),
        ({"ARACHNE_AI_RETRIES": "0"}, "ai.retries must be"),
        ({"ARACHNE_AI_CORRELATE_THRESHOLD": "1"}, "ai.correlate_threshold must be"),
    ],
)
def test_invalid_knobs_fail_at_settings_construction(entry: dict[str, str], expected: str) -> None:
    with pytest.raises(ConfigurationError, match=expected):
        Settings.from_env(entry)


def test_an_unknown_privacy_mode_from_the_file_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="invalid ai config"):
        parse_ai_config({"ai": {"privacy": "sneaky"}})


def test_the_config_summary_is_credential_free() -> None:
    config = parse_ai_config(
        {
            "ai": {
                "default_provider": "openai",
                "providers": {
                    "openai": {
                        "base_url": "https://api.openai.com/v1",
                        "api_key_env": "OPENAI_API_KEY",
                        "model": "gpt-4o-mini",
                    }
                },
            }
        }
    )
    summary = config.to_dict()
    assert summary["providers"]["openai"]["api_key_env"] == "OPENAI_API_KEY"
    assert "key" not in str(summary).lower() or "api_key_env" in str(summary)
    assert AiConfig.model_validate(config.model_dump()) == config
