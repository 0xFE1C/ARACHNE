"""Privacy modes (F-04-08): what may leave the process, and as what.

``redact`` is the default and the interesting one: it must replace the addressable evidence
(URLs, hosts, IPs, e-mails, credentials) with stable tokens, keep the local reverse mapping, and
*not* mangle the scanner's own vocabulary. ``local-only`` must refuse an external endpoint
before a call is made, and a prompt must never carry a configured provider key.
"""

from __future__ import annotations

import pytest

from arachne.ai.privacy import (
    PrivacyMode,
    Redactor,
    TokenMapper,
    apply_privacy,
    assert_no_provider_secrets,
    detokenize,
    enforce_local_only,
    trim,
)
from arachne.ai.types import PrivacyError


def test_the_default_mode_is_redact() -> None:
    assert PrivacyMode.parse(None) is PrivacyMode.REDACT
    assert PrivacyMode.parse("") is PrivacyMode.REDACT
    assert PrivacyMode.parse("local_only") is PrivacyMode.LOCAL_ONLY
    assert PrivacyMode.parse("DEFAULT") is PrivacyMode.DEFAULT


def test_an_unknown_mode_is_refused() -> None:
    with pytest.raises(PrivacyError, match="unknown privacy mode"):
        PrivacyMode.parse("vibes")


def test_redact_tokenizes_urls_hosts_ips_and_emails() -> None:
    text = (
        "asset https://target.example/.env reached 10.0.0.5 via mail admin@target.example "
        "and host api.target.example"
    )
    redacted = apply_privacy(text, mode=PrivacyMode.REDACT)
    assert "target.example" not in redacted
    assert "10.0.0.5" not in redacted
    assert "admin@" not in redacted
    assert "[U1]" in redacted


def test_tokens_are_stable_within_a_scan() -> None:
    mapper = TokenMapper()
    first = apply_privacy("https://a.example/x", mode=PrivacyMode.REDACT, mapper=mapper)
    second = apply_privacy("again https://a.example/x", mode=PrivacyMode.REDACT, mapper=mapper)
    assert first.strip() == "[U1]"
    assert second.endswith("[U1]")


def test_the_reverse_mapping_is_kept_locally() -> None:
    mapper = TokenMapper()
    redacted = apply_privacy(
        "see https://target.example/.env", mode=PrivacyMode.REDACT, mapper=mapper
    )
    assert mapper.mapping["[U1]"] == "https://target.example/.env"
    assert detokenize(redacted, mapper.mapping) == "see https://target.example/.env"


def test_credentials_are_tokenized_not_just_blanked() -> None:
    mapper = TokenMapper()
    redacted = apply_privacy(
        "key AKIAIOSFODNN7EXAMPLE and password=hunter2hunter2",
        mode=PrivacyMode.REDACT,
        mapper=mapper,
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "hunter2hunter2" not in redacted
    assert "[K1]" in redacted


def test_the_scanners_own_identifiers_are_not_tokenized() -> None:
    """``m4.env-file-probe`` looks like a hostname to a naive pattern; it must survive."""
    redacted = apply_privacy(
        "module: M4, check: m4.env-file-probe, cwe: CWE-200", mode=PrivacyMode.REDACT
    )
    assert "m4.env-file-probe" in redacted
    assert "CWE-200" in redacted


def test_a_token_is_not_double_tokenized() -> None:
    mapper = TokenMapper()
    once = apply_privacy("https://a.example/", mode=PrivacyMode.REDACT, mapper=mapper)
    twice = apply_privacy(once, mode=PrivacyMode.REDACT, mapper=mapper)
    assert twice == once


def test_default_mode_sends_the_text_unchanged() -> None:
    text = "https://target.example/.env 10.0.0.5"
    assert apply_privacy(text, mode=PrivacyMode.DEFAULT) == text


def test_local_only_accepts_local_endpoints() -> None:
    for url in (
        "http://localhost:11434",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:11434",
        "http://192.168.1.10:8080/v1",
        "http://ollama.local:11434",
    ):
        enforce_local_only(PrivacyMode.LOCAL_ONLY, [url])


def test_local_only_refuses_external_endpoints() -> None:
    with pytest.raises(PrivacyError, match="refuses non-local model endpoints"):
        enforce_local_only(PrivacyMode.LOCAL_ONLY, ["https://api.openai.com/v1"])


def test_local_only_refuses_a_mixed_configuration() -> None:
    with pytest.raises(PrivacyError, match=r"api\.openai\.com"):
        enforce_local_only(
            PrivacyMode.LOCAL_ONLY, ["http://localhost:11434", "https://api.openai.com/v1"]
        )


def test_redact_mode_accepts_external_endpoints() -> None:
    enforce_local_only(PrivacyMode.REDACT, ["https://api.openai.com/v1"])


def test_a_provider_credential_in_a_prompt_is_a_hard_refusal() -> None:
    with pytest.raises(PrivacyError, match="provider credential"):
        assert_no_provider_secrets(
            "system prompt mentioning sk-live-abcdef123456", ["sk-live-abcdef123456"]
        )


def test_a_short_value_is_not_treated_as_a_credential() -> None:
    """A 3-character "key" would match everywhere; the check only applies to real ones."""
    assert_no_provider_secrets("anything", ["abc"])


def test_the_redactor_exposes_its_mode_and_mapping() -> None:
    redactor = Redactor(mode=PrivacyMode.REDACT)
    redactor.transform("https://target.example/")
    snapshot = redactor.to_dict()
    assert snapshot["mode"] == "redact"
    assert snapshot["tokens"] == {"[U1]": "https://target.example/"}


def test_trim_reports_whether_it_cut() -> None:
    assert trim("abcdef", 10) == ("abcdef", False)
    assert trim("abcdef", 3) == ("abc", True)
    assert trim("abcdef", 0) == ("abcdef", False)
