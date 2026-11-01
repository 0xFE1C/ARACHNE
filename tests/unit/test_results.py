"""CheckResult / Evidence / error-model tests (F-02-08 note)."""

from __future__ import annotations

import pytest

from arachne.core.errors import CheckExecutionError, ErrorCategory, error_info
from arachne.core.results import (
    CheckResult,
    Evidence,
    error_result,
    guard_check,
    sha256_of,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_check_result_defaults_and_flags() -> None:
    result = CheckResult(status="vulnerable", title="Exposed .env")
    assert result.is_finding
    assert result.confidence == 0.5
    assert result.evidence == ()
    assert result.error is None


def test_invalid_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid check status"):
        CheckResult(status="maybe", title="x")  # type: ignore[arg-type]


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_confidence_bounds_are_enforced(confidence: float) -> None:
    with pytest.raises(ValueError, match="confidence must be within"):
        CheckResult(status="info", title="x", confidence=confidence)


def test_from_error_produces_a_status_error_result() -> None:
    result = CheckResult.from_error("port-scan", RuntimeError(f"connect failed {AWS_KEY}"))

    assert result.status == "error"
    assert result.confidence == 0.0
    assert result.error is not None
    assert result.error.error_type == "RuntimeError"
    assert AWS_KEY not in (result.detail or "")
    assert "[REDACTED" in (result.detail or "")
    assert result.to_dict()["error"]["error_type"] == "RuntimeError"


def test_error_result_helper_matches_classmethod() -> None:
    exc = CheckExecutionError("check blew up")
    result = error_result("check", exc, check="c1", module="M3")
    assert result.status == "error"
    assert result.check == "c1"
    assert result.module == "M3"
    assert result.error is not None
    assert result.error.category is ErrorCategory.INTERNAL


def test_status_error_without_error_info_gets_a_placeholder() -> None:
    result = CheckResult(status="error", title="x", detail="boom")
    assert result.error is not None
    assert result.error.message == "boom"


async def test_guard_check_turns_a_raise_into_one_error_result() -> None:
    async def broken():  # type: ignore[no-untyped-def]
        yield CheckResult(status="info", title="first")
        raise RuntimeError("mid-stream failure")

    results = [result async for result in guard_check("my-check", broken(), module="M4")]

    assert [result.status for result in results] == ["info", "error"]
    assert results[-1].module == "M4"
    assert "mid-stream failure" in (results[-1].detail or "")


async def test_guard_check_passes_results_through_unchanged() -> None:
    async def fine():  # type: ignore[no-untyped-def]
        yield CheckResult(status="vulnerable", title="a")
        yield CheckResult(status="not_vulnerable", title="b")

    results = [result async for result in guard_check("ok", fine())]
    assert [result.status for result in results] == ["vulnerable", "not_vulnerable"]


def test_evidence_of_redacts_and_hashes() -> None:
    evidence = Evidence.of("http_response", {"body": f"key={AWS_KEY}", "status": 200})

    assert AWS_KEY not in str(evidence.payload)
    assert evidence.sha256 is not None
    assert len(evidence.sha256) == 64
    assert evidence.captured_at.tzinfo is not None


def test_evidence_requires_timezone_aware_timestamp() -> None:
    from datetime import datetime

    with pytest.raises(ValueError, match="timezone-aware"):
        Evidence(kind="note", captured_at=datetime(2026, 1, 1))


def test_evidence_hash_is_stable_and_content_addressed() -> None:
    assert sha256_of("abc") == sha256_of(b"abc")
    first = Evidence.of("note", {"x": "1"})
    second = Evidence.of("note", {"x": "1"})
    assert first.sha256 == second.sha256


def test_oversized_evidence_is_truncated() -> None:
    payload = {"body": "A" * 400_000}
    evidence = Evidence.of("artifact", payload)

    assert evidence.payload.get("truncated") is True
    assert len(str(evidence.payload)) < 400_000


def test_check_result_serialization_shape() -> None:
    result = CheckResult(
        status="vulnerable",
        title="t",
        detail="d",
        cwe="CWE-200",
        evidence=(Evidence.of("note", {"a": 1}),),
        check="env-file-probe",
        module="M4",
    )
    payload = result.to_dict()
    assert payload["status"] == "vulnerable"
    assert payload["cwe"] == "CWE-200"
    assert payload["check"] == "env-file-probe"
    assert len(payload["evidence"]) == 1
    assert "error" not in payload


def test_error_info_truncates_long_messages() -> None:
    info = error_info(RuntimeError("x" * 5000))
    assert len(info.message) <= 500
    assert info.to_dict()["error_type"] == "RuntimeError"
