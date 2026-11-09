"""Redaction unit tests (F-08-01, F-08-04)."""

from __future__ import annotations

import pytest

from arachne.core.redaction import (
    PLACEHOLDER,
    SENSITIVE_HEADERS,
    contains_secret,
    redact_headers,
    redact_mapping,
    redact_text,
    redact_url,
    redact_value,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
# Fake fixture only. The prefix is split (as above for the GitHub token) so secret
# scanners do not flag this test file; the runtime value is exactly what the redactor
# must catch.
STRIPE_KEY = "sk_" + "live_" + "51H8xQeJ2k3Lm4No5Pq6Rs7Tu8Vw9Xy"
#: Split for the same reason, and this one was missed when the three above were done: GitHub's
#: scanner raised an alert on the whole literal, which had to be resolved as "used in tests".
#: The runtime value is unchanged, so the test proves exactly what it proved before.
GOOGLE_API_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"


@pytest.mark.parametrize(
    "text",
    [
        f"aws_key={AWS_KEY}",
        f"token: {GITHUB_TOKEN}",
        f"Authorization: Bearer {JWT}",
        "postgres://admin:hunter2@db.internal:5432/app",
        'password="correct-horse-battery-staple"',
        GOOGLE_API_KEY,
        f"card_processor={STRIPE_KEY}",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\n-----END OPENSSH PRIVATE KEY-----",
    ],
)
def test_secret_patterns_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert "[REDACTED" in redacted
    assert not contains_secret(redacted)


def test_benign_text_is_untouched() -> None:
    text = "GET /index.html HTTP/1.1 -> 200 OK (application/json, 1234 bytes)"
    assert redact_text(text) == text
    assert not contains_secret(text)


def test_redact_url_removes_credentials_and_query_secrets() -> None:
    redacted = redact_url(f"https://alice:s3cret@example.com/login?token={AWS_KEY}&page=2#frag")
    assert "s3cret" not in redacted
    assert AWS_KEY not in redacted
    assert redacted.startswith("https://alice:[REDACTED:url-password]@example.com/login")
    assert "page=2" in redacted
    assert redacted.endswith("#frag")


def test_redact_url_handles_relative_and_odd_inputs() -> None:
    assert redact_url("/api/v1/users?key=abc123") == "/api/v1/users?key=[REDACTED:query-param]"
    assert redact_url("http://example.com") == "http://example.com"
    assert redact_url("http://example.com?x=1") == "http://example.com?x=1"


def test_redact_mapping_replaces_sensitive_keys_recursively() -> None:
    payload = {
        "username": "alice",
        "password": "hunter2",
        "nested": {"api_key": "abcdef123456", "note": "fine"},
        "items": [{"token": "zzz"}, {"value": f"key={AWS_KEY}"}],
    }
    redacted = redact_mapping(payload)
    assert redacted["username"] == "alice"
    assert redacted["password"] == "[REDACTED:value]"
    assert redacted["nested"]["api_key"] == "[REDACTED:value]"  # type: ignore[index]
    assert redacted["nested"]["note"] == "fine"  # type: ignore[index]
    assert AWS_KEY not in str(redacted)


def test_redact_headers_keeps_names_and_clears_values() -> None:
    headers = {
        "Authorization": f"Bearer {JWT}",
        "Cookie": "session=abc",
        "Set-Cookie": "session=abc",
        "X-Api-Key": AWS_KEY,
        "Content-Type": "text/html",
        "Server": "nginx/1.18.0",
    }
    redacted = redact_headers(headers)
    for name in ("Authorization", "Cookie", "Set-Cookie", "X-Api-Key"):
        assert name in SENSITIVE_HEADERS or name.lower() in SENSITIVE_HEADERS
        assert redacted[name].startswith("[REDACTED")
    assert redacted["Content-Type"] == "text/html"
    assert redacted["Server"] == "nginx/1.18.0"


def test_redact_value_handles_bytes_and_depth() -> None:
    assert "hunter2" not in str(redact_value(b"password=hunter2"))
    deep: object = "leaf"
    for _ in range(20):
        deep = {"wrap": deep}
    assert PLACEHOLDER in str(redact_value(deep)) or "[REDACTED" in str(redact_value(deep))


def test_redact_value_preserves_non_string_scalars() -> None:
    assert redact_value(42) == 42
    assert redact_value(None) is None
    assert redact_value(3.5) == 3.5
    assert redact_value(True) is True


BLOCK_SECRETS = (
    # (label, text, raw secret that must not survive)
    ("yaml-block", "db_password:\n  hunter2secret\n", "hunter2secret"),
    ("yaml-block-scalar", "password: |\n  hunter2secret\n", "hunter2secret"),
    ("yaml-nested-single", "service:\n  api_key: abcdef123456\n", "abcdef123456"),
    ("yaml-nested-deep", "a:\n  b:\n    secret_key:\n      hunter2secret\n", "hunter2secret"),
    ("k8s-stringData", "stringData:\n  password: sup3rs3cret\n", "sup3rs3cret"),
    ("k8s-literal", "stringData:\n  password: |\n    sup3rs3cret\n", "sup3rs3cret"),
    ("ini-block", "[db]\npassword=\nsup3rs3cret\n", "sup3rs3cret"),
    ("crlf-block", "password: \r\n  hunter2secret\r\n", "hunter2secret"),
)


@pytest.mark.parametrize(("label", "text", "secret"), BLOCK_SECRETS)
def test_block_style_assignments_are_redacted(label: str, text: str, secret: str) -> None:
    """A sensitive key whose value sits on the next line is still redacted (S13 review).

    The inline ``key: value`` pattern stops at the newline so a non-sensitive outer key
    cannot swallow an inner ``api_key:``; ``_BLOCK_ASSIGNMENT_RE`` covers the block form
    that choice leaves behind. Both a nested single level (``service:\\n  api_key: ...``)
    and a plain block (``db_password:\\n  hunter2``) must yield to one of the two.
    """
    redacted = redact_text(text)
    assert secret not in redacted, f"{label}: {secret!r} survived redaction"
    assert "[REDACTED" in redacted
    assert contains_secret(text)


def test_a_colon_bearing_value_is_not_mistaken_for_a_nested_key() -> None:
    """A value that merely contains ``:`` (JWT-ish, ``scheme:part``) is still redacted."""
    redacted = redact_text("token: foo:bar:bazqux")
    assert "foo:bar:bazqux" not in redacted
    assert "[REDACTED" in redacted
