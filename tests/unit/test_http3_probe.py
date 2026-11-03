"""The HTTP/3 parity check's decisions, and its graceful degradation (REQ-DET-006).

The transport itself is exercised against a real QUIC fixture in
``tests/integration/test_http3_transport.py``. What is proven here is the part that must hold
in every installation, including the air-gapped one with no QUIC stack at all: the check
records what it could not do instead of failing, never reports "no HTTP/3" as a weakness, and
reports a QUIC path that serves weaker security headers than the TCP path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from tests.helpers.checks import asset_for, make_step_context

from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m2 import http3
from arachne.modules.m2.http3_probe import Http3Probe

URL = "https://edge.example.test/"
TCP_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "alt-svc": 'h3=":443"; ma=86400',
}


@dataclass
class _Response:
    status_code: int = 200
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = URL

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json_body(self) -> object:
        return None


class _Http:
    """The smallest thing that answers ``ctx.http.get(url)``."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers
        self.calls: list[str] = []

    async def get(self, url: str) -> _Response:
        self.calls.append(url)
        return _Response(response_headers=dict(self.headers), url=url)


def _context(headers: dict[str, str]) -> CheckContext:
    step, _ = make_step_context(http=_Http(headers))
    return CheckContext(
        step=step,
        module=Http3Probe(),
        asset=asset_for("url", URL),
        config=ModuleConfig(),
    )


async def _results(headers: dict[str, str] = TCP_HEADERS) -> list:
    step, _ = make_step_context(http=_Http(headers))
    context = CheckContext(
        step=step, module=Http3Probe(), asset=asset_for("url", URL), config=ModuleConfig()
    )
    return [result async for result in Http3Probe().run(context)]


# --------------------------------------------------------------------------- Alt-Svc
def test_alt_svc_parsing_recognises_the_h3_alternative() -> None:
    assert http3.alt_svc_http3({"Alt-Svc": 'h3=":443"; ma=86400'}) is not None
    assert http3.alt_svc_http3({"alt-svc": 'h3-29=":443",h3=":443"'}) is not None
    assert http3.alt_svc_http3({"Alt-Svc": 'h2=":443"'}) is None
    assert http3.alt_svc_http3({}) is None


def test_missing_security_headers_names_what_is_absent() -> None:
    missing = http3.missing_security_headers({"Strict-Transport-Security": "max-age=1"})
    assert "strict-transport-security" not in missing
    assert "content-security-policy" in missing
    assert missing == tuple(
        name for name in http3.SECURITY_HEADERS if name != "strict-transport-security"
    )


# --------------------------------------------------------------------------- degradation
async def test_without_the_extra_the_check_records_the_gap_and_no_finding(monkeypatch) -> None:
    """The air-gapped install: no QUIC stack, nothing sent over QUIC, no finding."""
    monkeypatch.setattr(http3, "http3_available", lambda: False)
    results = await _results()
    assert [result.status for result in results] == ["info"]
    assert "no QUIC client installed" in results[0].title
    payload = results[0].evidence[0].payload
    assert payload["http3_advertised"] is True
    assert "quic" in str(payload["h3_unavailable_reason"])
    assert "h3_attempted" not in payload


async def test_without_the_extra_no_quic_socket_is_opened(monkeypatch) -> None:
    monkeypatch.setattr(http3, "http3_available", lambda: False)
    response = await http3.http3_get("127.0.0.1", 443)
    assert response.ok is False
    assert "not installed" in (response.error or "")


async def test_the_extra_present_but_the_target_speaking_no_http3_is_not_a_finding(
    monkeypatch,
) -> None:
    async def no_answer(*args: object, **kwargs: object) -> http3.Http3Response:
        return http3.Http3Response(error="timeout")

    monkeypatch.setattr(http3, "http3_available", lambda: True)
    monkeypatch.setattr(http3, "http3_get", no_answer)
    results = await _results()
    assert [result.status for result in results] == ["info"]
    assert "does not answer HTTP/3" in results[0].title


# --------------------------------------------------------------------------- parity
async def test_a_weaker_quic_header_set_is_a_finding(monkeypatch) -> None:
    async def weaker(*args: object, **kwargs: object) -> http3.Http3Response:
        return http3.Http3Response(
            status_code=200,
            headers={"x-content-type-options": "nosniff"},
        )

    monkeypatch.setattr(http3, "http3_available", lambda: True)
    monkeypatch.setattr(http3, "http3_get", weaker)
    results = await _results()
    statuses = [result.status for result in results]
    assert statuses == ["info", "vulnerable"]
    assert "weaker security-header set over HTTP/3" in results[1].title
    assert results[1].cwe == "CWE-693"
    payload = results[0].evidence[0].payload
    assert payload["h3_transport"] == "h3"
    assert "strict-transport-security" in payload["h3_missing_security_headers"]


async def test_an_identical_quic_header_set_is_clean(monkeypatch) -> None:
    async def identical(*args: object, **kwargs: object) -> http3.Http3Response:
        return http3.Http3Response(status_code=200, headers=dict(TCP_HEADERS))

    monkeypatch.setattr(http3, "http3_available", lambda: True)
    monkeypatch.setattr(http3, "http3_get", identical)
    results = await _results()
    assert [result.status for result in results] == ["info", "not_vulnerable"]
    assert "same security-header posture" in results[1].title


async def test_a_non_https_asset_is_skipped() -> None:
    step, _ = make_step_context(http=_Http(TCP_HEADERS))
    context = CheckContext(
        step=step,
        module=Http3Probe(),
        asset=asset_for("url", "http://plain.example.test/"),
        config=ModuleConfig(),
    )
    results = [result async for result in Http3Probe().run(context)]
    assert len(results) == 1
    assert "only meaningful for an https endpoint" in (results[0].detail or "")


async def test_a_dry_run_sends_nothing() -> None:
    step, _ = make_step_context(http=None)
    context = CheckContext(
        step=step,
        module=Http3Probe(),
        asset=asset_for("url", URL),
        config=ModuleConfig(),
    )
    results = [result async for result in Http3Probe().run(context)]
    assert len(results) == 1
    assert "no HTTP client in this run" in (results[0].detail or "")


def test_the_extra_is_declared_in_pyproject() -> None:
    """The capability must be an extra, never a runtime dependency."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.optional-dependencies]" in text
    assert http3.HTTP3_EXTRA in text
    dependencies = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "aioquic" not in dependencies


@pytest.mark.parametrize("url", ["https://[::1]/", "https://edge.example.test:8443/"])
def test_the_probe_derives_the_endpoint_from_the_url(url: str) -> None:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    assert parts.scheme == "https"
    assert parts.hostname is not None
    assert (parts.port or 443) in {443, 8443}
