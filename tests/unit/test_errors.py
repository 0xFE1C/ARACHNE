"""Error-model tests (docs/spec/07- §4, F-02-08 note)."""

from __future__ import annotations

import pytest

from arachne.core.errors import (
    ArachneError,
    CheckExecutionError,
    ConfigurationError,
    ErrorCategory,
    OutOfScopeError,
    RequestError,
    SafetyError,
    UnsafeUrlError,
    error_info,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (ConfigurationError("bad env"), ErrorCategory.CONFIGURATION),
        (UnsafeUrlError("bad url"), ErrorCategory.SAFETY),
        (OutOfScopeError("nope"), ErrorCategory.SCOPE),
        (RequestError("timeout"), ErrorCategory.TRANSPORT),
        (CheckExecutionError("check failed"), ErrorCategory.INTERNAL),
    ],
)
def test_categories_are_attached_to_the_exception_types(
    exc: ArachneError, category: ErrorCategory
) -> None:
    assert exc.category is category
    assert isinstance(exc, ArachneError)
    assert error_info(exc).category is category


def test_safety_error_keeps_url_and_reason() -> None:
    exc = UnsafeUrlError("blocked", url="http://10.0.0.1/", reason="private-address")
    assert isinstance(exc, SafetyError)
    assert exc.reason == "private-address"
    info = error_info(exc)
    assert info.reason == "private-address"
    assert info.to_dict()["reason"] == "private-address"


def test_reason_defaults_to_the_message() -> None:
    assert UnsafeUrlError("plain message").reason == "plain message"


def test_error_info_redacts_secrets() -> None:
    info = error_info(RuntimeError(f"upstream said {AWS_KEY}"), context={"host": "example.com"})
    assert AWS_KEY not in info.message
    assert AWS_KEY not in str(info.to_dict())
    assert info.context["host"] == "example.com"


def test_error_info_never_includes_a_traceback() -> None:
    try:
        raise ValueError("inner detail")
    except ValueError as exc:
        info = error_info(exc)
    assert "Traceback" not in info.summary()
    assert info.message == "inner detail"


def test_error_info_handles_empty_message() -> None:
    assert error_info(RuntimeError()).message == "RuntimeError"


def test_summary_is_single_line_and_prefixed() -> None:
    assert error_info(RequestError("boom")).summary() == "RequestError: boom"
