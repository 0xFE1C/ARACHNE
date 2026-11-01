"""False-positive reduction (docs/spec/04- §2.6, F-05-07).

Three mechanisms, three sets of tests: the context filters (a placeholder page is not a
finding), verification (a second request either reproduces or contradicts), and the tuner
(operator feedback raises the confidence a check needs).
"""

from __future__ import annotations

from typing import Any

import pytest

from arachne.analyzer.fp import (
    FeedbackRecord,
    FpFlags,
    FpTuner,
    HttpVerifier,
    MemoryFeedbackStore,
    NullVerifier,
    classify,
    feedback_key,
    load_fp_filters,
    parse_fp_filters,
)
from arachne.analyzer.model import Candidate, EvidenceFact, FpStats, VerificationOutcome
from arachne.core.errors import ConfigurationError
from arachne.core.results import sha256_of

FILTERS = parse_fp_filters(
    {
        "version": "test",
        "filters": [
            {
                "id": "placeholder.default",
                "kind": "placeholder",
                "decisive": True,
                "detail": "default page",
                "patterns": ["Welcome to nginx"],
            },
            {
                "id": "waf.challenge",
                "kind": "waf",
                "patterns": ["Just a moment..."],
            },
            {
                "id": "wall.login",
                "kind": "login_wall",
                "patterns": ["please log in"],
            },
        ],
    }
)


def candidate(*, body: str = "", extra: tuple[EvidenceFact, ...] = ()) -> Candidate:
    return Candidate(
        scan_id=1,
        title="Sensitive environment file exposed",
        check_id="m4.env-file-probe",
        check_module="M4",
        check_name="env-file-probe",
        asset_kind="url",
        asset_value="https://example.com/.env",
        evidence=(
            EvidenceFact(
                "http_response",
                {"status_code": 200, "headers": {}, "body": body},
                source="https://example.com/.env",
            ),
            *extra,
        ),
    )


# --------------------------------------------------------------------------- filters


def test_a_default_page_is_classified_and_decisive() -> None:
    flags = classify(candidate(body="<h1>Welcome to nginx</h1>"), FILTERS)
    assert isinstance(flags, FpFlags)
    assert flags.placeholder is True
    assert flags.decisive is True
    assert "placeholder.default" in flags.matched


def test_a_waf_challenge_only_penalises() -> None:
    flags = classify(candidate(body="<html>Just a moment...</html>"), FILTERS)
    assert flags.waf is True
    assert flags.decisive is False


def test_a_login_wall_is_recognised() -> None:
    flags = classify(candidate(body="Please log in to continue"), FILTERS)
    assert flags.login_wall is True
    assert flags.any is True


def test_a_placeholder_is_not_decisive_when_structured_evidence_exists() -> None:
    """A banner or parsed response behind the body means the body is not the whole story."""
    flags = classify(
        candidate(
            body="Welcome to nginx",
            extra=(EvidenceFact("banner", {"service": "smtp", "text": "220 mail ESMTP"}),),
        ),
        FILTERS,
    )
    assert flags.placeholder is True
    assert flags.decisive is False


def test_a_candidate_with_no_text_is_not_flagged() -> None:
    flags = classify(
        Candidate(scan_id=1, title="t", asset_kind="host", asset_value="10.0.0.1"), FILTERS
    )
    assert flags.any is False
    assert flags.matched == ()


def test_an_unknown_filter_kind_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="kind"):
        parse_fp_filters(
            {"version": "1", "filters": [{"id": "x", "kind": "spam", "patterns": ["a"]}]}
        )


def test_the_shipped_filter_corpus_covers_the_known_noise() -> None:
    corpus = load_fp_filters()
    kinds = {item.kind for item in corpus.filters}
    assert kinds == {"placeholder", "waf", "login_wall"}
    assert any(item.decisive for item in corpus.of_kind("placeholder"))
    assert any(not item.decisive for item in corpus.of_kind("waf"))


# --------------------------------------------------------------------------- feedback


def test_the_tuner_raises_the_required_confidence_from_feedback() -> None:
    store = MemoryFeedbackStore()
    key = feedback_key(candidate())
    for _ in range(3):
        store.record(FeedbackRecord(key=key, is_fp=True))
    store.record(FeedbackRecord(key=key, is_fp=False))
    stats = store.stats([key])
    assert stats[key] == FpStats(total=4, false_positives=3)

    tuner = FpTuner.from_store(store, [key], threshold=55)
    # 75% FP rate * the 25-point cap = 18.75, rounded to 19, so the bar rises to 74.
    assert tuner.required_confidence(key) == 74
    assert "75%" in tuner.describe(key)


def test_the_tuner_penalty_is_capped_and_absent_without_feedback() -> None:
    tuner = FpTuner({feedback_key(candidate()): FpStats(total=100, false_positives=100)})
    assert tuner.penalty(feedback_key(candidate())) == -25
    assert tuner.required_confidence(feedback_key(candidate())) == 80
    fresh = FpTuner()
    assert fresh.penalty("unknown|url|none") == 0
    assert "no operator feedback" in fresh.describe("unknown|url|none")


def test_the_feedback_key_names_check_asset_kind_and_signature() -> None:
    key = feedback_key(candidate(), signature="exposed-env-file")
    assert key == "m4.env-file-probe|url|exposed-env-file"


# --------------------------------------------------------------------------- verification


class FakeClient:
    """A stand-in for the scoped HTTP client: records calls, returns one exchange."""

    def __init__(
        self, status: int = 200, body: str = "DB_PASSWORD=x", raises: Exception | None = None
    ):
        self.status = status
        self.body = body
        self.raises = raises
        self.calls: list[tuple[str, str]] = []

    async def request(self, method: str, url: str, **_: Any) -> Any:
        self.calls.append((method, url))
        if self.raises is not None:
            raise self.raises

        class Exchange:
            def __init__(self, status_code: int, body: str) -> None:
                self.status_code = status_code
                self.body = body

        return Exchange(self.status, self.body)


@pytest.mark.asyncio
async def test_http_verifier_confirms_a_reproduction() -> None:
    body = "DB_PASSWORD=x"
    target = candidate(body=body)
    client = FakeClient(body=body)
    outcome = await HttpVerifier(client).verify(target)
    assert outcome.attempted is True
    assert outcome.reproducible is True
    assert outcome.contradicted is False
    assert outcome.count == 2
    assert client.calls == [("GET", "https://example.com/.env")]
    _ = sha256_of


@pytest.mark.asyncio
async def test_http_verifier_reports_a_status_contradiction() -> None:
    target = candidate(body="DB_PASSWORD=x")
    outcome = await HttpVerifier(FakeClient(status=404)).verify(target)
    assert outcome.contradicted is True
    assert outcome.reproducible is False
    assert "HTTP 404" in (outcome.detail or "")


@pytest.mark.asyncio
async def test_http_verifier_reports_a_body_contradiction() -> None:
    target = candidate(body="DB_PASSWORD=x")
    outcome = await HttpVerifier(FakeClient(body="something else")).verify(target)
    assert outcome.contradicted is True
    assert "different body" in (outcome.detail or "")


@pytest.mark.asyncio
async def test_a_failed_verification_request_is_data_not_a_crash() -> None:
    target = candidate(body="x")
    outcome = await HttpVerifier(FakeClient(raises=RuntimeError("boom"))).verify(target)
    assert outcome.attempted is True
    assert outcome.contradicted is False
    assert "RuntimeError" in (outcome.detail or "")


@pytest.mark.asyncio
async def test_verification_is_bounded() -> None:
    target = candidate(body="x")
    verifier = HttpVerifier(FakeClient(body="x"), max_verifications=1)
    first = await verifier.verify(target)
    second = await verifier.verify(target)
    assert first.attempted is True
    assert second.attempted is False
    assert "budget" in (second.detail or "")


@pytest.mark.asyncio
async def test_a_candidate_without_a_captured_url_is_not_verified() -> None:
    target = Candidate(scan_id=1, title="t", asset_kind="host", asset_value="10.0.0.1")
    outcome = await HttpVerifier(FakeClient()).verify(target)
    assert outcome.attempted is False
    assert "captured request URL" in (outcome.detail or "")


@pytest.mark.asyncio
async def test_the_null_verifier_claims_nothing() -> None:
    outcome = await NullVerifier().verify(candidate(body="x"))
    assert outcome == VerificationOutcome(count=1, attempted=False, reproducible=False)
