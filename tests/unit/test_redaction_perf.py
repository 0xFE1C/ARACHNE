"""Redaction must stay linear in the input length (DoS resistance).

Body text and headers are *target-controlled*. A redaction pattern with catastrophic
backtracking would therefore let a hostile target hang the scanner by returning a
carefully shaped 64 KB response — a denial-of-service vector against the tool itself.
These tests pin the cost with adversarial inputs; they fail loudly if someone adds a
pattern like ``[a-z]*secret[a-z]*`` or a lazy ``.*?`` over an unbounded span.
"""

from __future__ import annotations

import time

import pytest

from arachne.core.redaction import contains_secret, redact_text

#: Generous ceiling: a linear implementation finishes a 512 KB worst case in a few
#: milliseconds. Anything superlinear blows through it by orders of magnitude.
MAX_SECONDS = 1.0
BIG = 512 * 1024

ADVERSARIAL_INPUTS: dict[str, str] = {
    "uppercase-run": "A" * BIG,
    "lowercase-run": "a" * BIG,
    "alnum-run": ("abc123" * (BIG // 6))[:BIG],
    "key-value-run": ("password=x;" * (BIG // 11))[:BIG],
    "assignment-prefix": ("aws_secret_access_key" * (BIG // 21))[:BIG],
    "pem-headers": ("-----BEGIN RSA PRIVATE KEY-----" * (BIG // 31))[:BIG],
    "pem-unterminated": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * BIG,
    "jwt-prefix": ("eyJ" * (BIG // 3))[:BIG],
    "bearer-prefix": ("bearer " * (BIG // 7))[:BIG],
    "github-prefix": ("ghp_" * (BIG // 4))[:BIG],
    "json-ish": ('{"token": "' + "z" * BIG + '"}'),
    "quotes-and-colons": ('":' * (BIG // 2))[:BIG],
}


@pytest.mark.parametrize("label", sorted(ADVERSARIAL_INPUTS))
def test_redaction_is_linear_on_adversarial_input(label: str) -> None:
    text = ADVERSARIAL_INPUTS[label]
    started = time.perf_counter()
    redact_text(text)
    elapsed = time.perf_counter() - started
    assert elapsed < MAX_SECONDS, f"{label}: redaction took {elapsed:.2f}s (superlinear?)"


@pytest.mark.parametrize("label", sorted(ADVERSARIAL_INPUTS))
def test_contains_secret_is_linear_on_adversarial_input(label: str) -> None:
    text = ADVERSARIAL_INPUTS[label]
    started = time.perf_counter()
    contains_secret(text)
    elapsed = time.perf_counter() - started
    assert elapsed < MAX_SECONDS, f"{label}: contains_secret took {elapsed:.2f}s (superlinear?)"


def test_unterminated_pem_block_is_still_redacted() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n" + "not-a-real-key\n" * 10
    redacted = redact_text(text)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
    assert "[REDACTED" in redacted


def test_terminated_pem_block_is_redacted_whole() -> None:
    text = (
        "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nmore\n"
        "-----END RSA PRIVATE KEY-----\nafter"
    )
    redacted = redact_text(text)
    assert redacted.startswith("before")
    assert redacted.endswith("after")
    assert "MIIEow" not in redacted


def test_large_body_redaction_is_bounded() -> None:
    """The client truncates bodies; redaction of the retained slice stays cheap."""
    body = '{"rows": [' + ", ".join(f'{{"id": {i}, "name": "user{i}"}}' for i in range(5000)) + "]}"
    started = time.perf_counter()
    redacted = redact_text(body)
    assert time.perf_counter() - started < MAX_SECONDS
    assert "user4999" in redacted  # benign content survives
