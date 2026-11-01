"""Unit: the ``arachne serve`` guardrails (S12, F-08-02).

The command is not started here (that would bind a socket); what is tested is the decision it
makes *before* binding: TLS by default, plain HTTP only on loopback or with an explicit
``--insecure``, and a warning when no API key is configured.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import ApiSettings, Settings, reset_settings_cache
from arachne.core.errors import ConfigurationError


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _settings(**overrides: object) -> Settings:
    return Settings(api=ApiSettings(**overrides))  # type: ignore[arg-type]


class _FakeServices:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.closed = False

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def stub_uvicorn(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Replace uvicorn.run, build_services and create_app with recording stubs."""
    calls: dict[str, object] = {}

    import uvicorn

    import arachne.api.app as app_module
    import arachne.data.services as services

    def fake_run(app_instance: object, **kwargs: object) -> None:
        calls["run"] = kwargs

    def fake_build(settings: Settings) -> _FakeServices:
        instance = _FakeServices(settings)
        calls["services"] = instance
        return instance

    def fake_create(services_obj: object, **kwargs: object) -> object:
        calls["create_app"] = kwargs
        return object()

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setattr(services, "build_services", fake_build)
    monkeypatch.setattr(app_module, "create_app", fake_create)
    return calls


def test_serving_a_public_interface_without_tls_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arachne.cli.serve as serve

    monkeypatch.setattr(serve, "get_settings", lambda: _settings(host="0.0.0.0", require_tls=True))
    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"])
    assert isinstance(result.exception, ConfigurationError)
    assert "without TLS" in str(result.exception)


def test_loopback_without_tls_is_allowed_but_warns_about_missing_keys(
    monkeypatch: pytest.MonkeyPatch, stub_uvicorn: dict[str, object]
) -> None:
    import arachne.cli.serve as serve

    monkeypatch.setattr(
        serve, "get_settings", lambda: _settings(host="127.0.0.1", require_tls=True)
    )
    result = CliRunner().invoke(app, ["serve"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert "warning: no API keys" in result.output
    assert stub_uvicorn["run"]["host"] == "127.0.0.1"  # type: ignore[index]
    assert stub_uvicorn["run"]["ssl_certfile"] is None  # type: ignore[index]
    assert stub_uvicorn["services"].closed is True  # type: ignore[union-attr]


def test_explicit_insecure_is_honoured_on_a_public_address(
    monkeypatch: pytest.MonkeyPatch, stub_uvicorn: dict[str, object]
) -> None:
    import arachne.cli.serve as serve

    monkeypatch.setattr(serve, "get_settings", lambda: _settings(host="10.0.0.5", require_tls=True))
    result = CliRunner().invoke(
        app, ["serve", "--host", "10.0.0.5", "--insecure"], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    assert stub_uvicorn["run"]["host"] == "10.0.0.5"  # type: ignore[index]


def test_tls_settings_are_passed_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch, stub_uvicorn: dict[str, object]
) -> None:
    import arachne.cli.serve as serve

    monkeypatch.setattr(
        serve,
        "get_settings",
        lambda: _settings(
            host="0.0.0.0",
            require_tls=True,
            tls_certfile="/tmp/cert.pem",
            tls_keyfile="/tmp/key.pem",
            keys=("ops:admin:secret",),
        ),
    )
    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert stub_uvicorn["run"]["ssl_certfile"] == "/tmp/cert.pem"  # type: ignore[index]
    assert "https://" in result.output
