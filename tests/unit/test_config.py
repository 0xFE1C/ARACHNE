"""Configuration tests (F-08-01, F-04-02): env-only, validated, deny-by-default."""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.config import (
    DEFAULT_USER_AGENT,
    HttpSettings,
    SafetySettings,
    Settings,
    get_settings,
    reset_settings_cache,
)
from arachne.core.errors import ConfigurationError
from arachne.core.safety import Scope


def test_defaults_are_safe() -> None:
    settings = Settings.from_env({})

    assert settings.database_url.startswith("sqlite:///")
    assert settings.safety.scope == Scope.deny_all()
    assert not settings.safety.policy.allow_private_ips
    assert not settings.safety.policy.allow_loopback
    assert settings.safety.redaction_enabled
    assert settings.http.user_agent == DEFAULT_USER_AGENT
    assert settings.log_json is True


def test_scope_lists_are_parsed_from_comma_separated_env() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_SCOPE_HOSTS": "a.example.com, b.example.com ,",
            "ARACHNE_SCOPE_DOMAINS": "example.com",
            "ARACHNE_SCOPE_EXCLUDE_HOSTS": "secret.example.com",
        }
    )
    assert settings.safety.scope.allowed_hosts == ("a.example.com", "b.example.com")
    assert settings.safety.scope.allowed_domains == ("example.com",)
    assert settings.safety.scope.excluded_hosts == ("secret.example.com",)


def test_numeric_and_boolean_env_parsing() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_DATABASE_URL": "postgresql://user@db/arachne",
            "ARACHNE_RATE_LIMIT_PER_HOST": "2.5",
            "ARACHNE_RATE_LIMIT_PER_HOST_BURST": "3",
            "ARACHNE_HTTP_TIMEOUT_S": "9",
            "ARACHNE_HTTP_MAX_BODY_BYTES": "1024",
            "ARACHNE_ALLOW_LOOPBACK": "yes",
            "ARACHNE_REDACTION_ENABLED": "off",
            "ARACHNE_LOG_JSON": "false",
            "ARACHNE_AUDIT_LOG_PATH": "/var/log/arachne/audit.jsonl",
        }
    )
    assert settings.database_url == "postgresql://user@db/arachne"
    assert settings.rate_limit.per_host_rate == 2.5
    assert settings.rate_limit.per_host_burst == 3
    assert settings.http.timeout_s == 9.0
    assert settings.http.max_body_bytes == 1024
    assert settings.safety.policy.allow_loopback is True
    assert settings.safety.redaction_enabled is False
    assert settings.log_json is False
    assert settings.audit_log_path == "/var/log/arachne/audit.jsonl"
    assert not settings.is_sqlite


@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({"ARACHNE_RATE_LIMIT_PER_HOST": "fast"}, "must be a number"),
        ({"ARACHNE_RATE_LIMIT_PER_HOST_BURST": "many"}, "must be an integer"),
        ({"ARACHNE_ALLOW_PRIVATE_IPS": "maybe"}, "must be a boolean"),
    ],
)
def test_invalid_env_values_raise_configuration_error(env: dict[str, str], match: str) -> None:
    with pytest.raises(ConfigurationError, match=match):
        Settings.from_env(env)


# --------------------------------------------------------------------------- SSO (S17)
def test_sso_is_off_by_default_and_closed() -> None:
    sso = Settings.from_env({}).sso
    assert not sso.enabled
    assert not sso.configured, "with no IdP the SSO surface must be absent (deny-by-default)"


def test_sso_env_is_parsed_and_maps_groups_to_roles() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_SSO_ENABLED": "true",
            "ARACHNE_SSO_ISSUER": "https://login.example.com",
            "ARACHNE_SSO_CLIENT_ID": "arachne",
            "ARACHNE_SSO_CLIENT_SECRET": "s3cret",
            "ARACHNE_SSO_GROUP_ROLES": "secops:admin, appsec:scanner",
            "ARACHNE_SSO_DEFAULT_ROLE": "viewer",
            "ARACHNE_SSO_ALGORITHMS": "RS256",
        }
    )
    sso = settings.sso
    assert sso.configured
    assert sso.client_secret_value == "s3cret"
    assert sso.algorithms == ("RS256",)
    assert sso.role_for(["appsec"]) == "scanner"
    assert sso.role_for(["secops", "appsec"]) == "admin"
    assert sso.role_for(["nothing"]) == "viewer"  # the configured default


def test_sso_rejects_an_unknown_role_binding_and_algorithm() -> None:
    with pytest.raises(ConfigurationError, match="group_roles"):
        Settings.from_env(
            {
                "ARACHNE_SSO_ENABLED": "true",
                "ARACHNE_SSO_ISSUER": "https://login.example.com",
                "ARACHNE_SSO_CLIENT_ID": "arachne",
                "ARACHNE_SSO_GROUP_ROLES": "secops:root",
            }
        )
    with pytest.raises(ConfigurationError, match="algorithms"):
        Settings.from_env(
            {
                "ARACHNE_SSO_ENABLED": "true",
                "ARACHNE_SSO_ISSUER": "https://login.example.com",
                "ARACHNE_SSO_CLIENT_ID": "arachne",
                "ARACHNE_SSO_ALGORITHMS": "none",
            }
        )


def test_invalid_settings_values_are_rejected() -> None:
    with pytest.raises(ConfigurationError):
        HttpSettings(timeout_s=0)
    with pytest.raises(ConfigurationError):
        HttpSettings(retries=-1)
    with pytest.raises(ConfigurationError):
        HttpSettings(max_body_bytes=0)


def test_sqlite_file_path_is_extracted(tmp_path: Path) -> None:
    db_file = tmp_path / "arachne-test.db"
    settings = Settings.from_env({"ARACHNE_DATABASE_URL": f"sqlite:///{db_file}"})
    assert settings.database_file() == db_file

    in_memory = Settings.from_env({"ARACHNE_DATABASE_URL": "sqlite:///:memory:"})
    assert in_memory.database_file() is None

    postgres = Settings.from_env({"ARACHNE_DATABASE_URL": "postgresql://db/arachne"})
    assert postgres.database_file() is None


def test_settings_are_frozen() -> None:
    settings = Settings.from_env({})
    with pytest.raises(Exception):  # noqa: B017 - dataclass frozen error type
        settings.log_level = "DEBUG"  # type: ignore[misc]


def test_get_settings_is_cached_and_resettable(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_settings_cache()
    monkeypatch.setenv("ARACHNE_ACTOR", "first")
    assert get_settings().actor == "first"

    monkeypatch.setenv("ARACHNE_ACTOR", "second")
    assert get_settings().actor == "first"  # cached

    reset_settings_cache()
    assert get_settings().actor == "second"
    reset_settings_cache()


def test_permissive_local_safety_settings_are_explicitly_opt_in() -> None:
    permissive = SafetySettings.permissive_local()
    assert permissive.policy.allow_loopback and permissive.policy.allow_private_ips
    assert permissive.scope == Scope.deny_all()  # scope still has to be declared
