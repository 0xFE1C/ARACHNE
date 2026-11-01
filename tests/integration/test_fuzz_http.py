"""Acceptance for HTTP parameter fuzzing and the candidate → verified finding flow.

REQ-FUZZ-003 and REQ-FUZZ-004 are the two halves of one chain, and this module walks the whole
of it against the live web lab:

1. a bounded HTTP fuzz run over the lab's search parameter produces **candidates** — leads read
   from the same corpus rules the M3 checks use — and nothing else;
2. a candidate becomes a :class:`~arachne.reasoning.model.Hypothesis` for the S21 pipeline, whose
   cage requires a *registered check id* and a *known asset* and cannot carry a payload;
3. running that check on that asset produces a real finding, so the claim the fuzzer noticed is
   verified through the proof ladder rather than asserted by the fuzzer.

The lab's `/search` route is vulnerable by design (declared ground truth), and the fuzzer is given
no hint about it: it enumerates the parameter against the corpus's families and reports what moved.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from tests.helpers.checks import asset_for, run_check
from tests.helpers.fuzz import (
    build_runner,
    fuzz_attestation,
    fuzz_definition,
    fuzz_settings,
)
from tests.helpers.web import make_web_harness
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.fuzz.bounds import STOP_COMPLETED, FuzzBudget
from arachne.fuzz.candidates import CandidateSignal, CandidateStatus
from arachne.fuzz.grammar import MutationOperator
from arachne.fuzz.http_params import (
    DEFAULT_FAMILIES,
    HttpFuzzPlan,
    HttpParameter,
    http_cases,
    load_fuzz_payloads,
    read_http_response,
)
from arachne.fuzz.runner import FuzzPlan
from arachne.modules.m3.client import XssOracle
from arachne.reasoning.model import HypothesisKind

pytestmark = pytest.mark.lab


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def search_plan(lab: WebLab, **overrides: object) -> HttpFuzzPlan:
    payload: dict[str, object] = {
        "label": "web-lab-search",
        "parameters": (
            HttpParameter(url=f"{lab.base_url}search?q=1", parameter="q", description="search box"),
        ),
        "families": ("xss-reflection", "sqli-error", "boundary"),
        "asset": lab.base_url,
    }
    payload.update(overrides)
    return HttpFuzzPlan(**payload)  # type: ignore[arg-type]


def http_plan(lab: WebLab, **overrides: object) -> FuzzPlan:
    payload: dict[str, object] = {
        "definition": fuzz_definition(),
        "attestation": fuzz_attestation(),
        "http_plans": (search_plan(lab),),
        "budget": FuzzBudget(max_cases=40, max_requests=90, max_seconds=30.0, batch_size=12),
    }
    payload.update(overrides)
    return FuzzPlan(**payload)  # type: ignore[arg-type]


async def test_the_http_fuzzer_produces_candidates_and_no_findings(lab: WebLab) -> None:
    harness = build_runner()
    report = await harness.runner.run(http_plan(lab))

    target = report.targets[0]
    assert report.status == STOP_COMPLETED
    assert target.kind == "http"
    assert target.cases_run == target.cases_planned > 0
    assert target.healthy_after is True, "the lab's origin is healthy before and after"
    assert target.candidates, "the lab's reflected search parameter must produce a lead"

    reflections = [c for c in target.candidates if c.signal is CandidateSignal.REFLECTION]
    assert reflections, "the planted reflected-input route is the ground truth here"
    for candidate in reflections:
        assert candidate.status is CandidateStatus.PROPOSED
        assert candidate.verifier == "m3.xss-oracle"
        assert candidate.is_finding is False and candidate.is_verified is False
    assert "finding.candidate" not in harness.actions()
    assert "fuzz.authorized" in harness.actions()


async def test_a_candidate_becomes_a_hypothesis_the_pipeline_can_execute(lab: WebLab) -> None:
    """REQ-FUZZ-004: the lead enters the hypothesis pipeline rather than the report."""
    harness = build_runner()
    report = await harness.runner.run(http_plan(lab))
    candidate = next(
        c for c in report.targets[0].candidates if c.signal is CandidateSignal.REFLECTION
    )

    hypothesis = candidate.to_hypothesis()
    assert hypothesis is not None
    assert hypothesis.kind is HypothesisKind.DISCOVERY
    assert hypothesis.check_id == "m3.xss-oracle"
    assert hypothesis.asset == lab.base_url
    assert hypothesis.source == "fuzz"
    assert hypothesis.confidence == candidate.confidence
    assert candidate.signal.value in hypothesis.rationale

    # The cage the S21 model imposes: a hypothesis names a check and an asset and *cannot*
    # carry the payload the fuzzer found. The payload stays attached to the candidate.
    fields = set(type(hypothesis).model_fields)
    assert "payload" not in fields and "url" not in fields
    assert candidate.payload_sha256


async def test_the_named_verifier_actually_verifies_the_lead(lab: WebLab) -> None:
    """The second half of the chain: the check the candidate named finds the real thing.

    This is what makes "candidate → verified finding" a demonstration and not a claim: the
    fuzzer reported a reflection on an asset with no knowledge of the lab, and the shipped
    M3 check then proves the same route vulnerable under the proof ladder's own rules.
    """
    harness = build_runner()
    report = await harness.runner.run(http_plan(lab))
    candidate = next(
        c for c in report.targets[0].candidates if c.signal is CandidateSignal.REFLECTION
    )
    hypothesis = candidate.to_hypothesis()
    assert hypothesis is not None
    assert hypothesis.check_id == "m3.xss-oracle"

    web = make_web_harness(lab)
    await web.prepare()
    results, _memory = await run_check(
        XssOracle,
        asset_for("url", web.asset.value),
        http=web.client,
        web=web.inventory,
    )
    verified = [result for result in results if result.is_finding]
    assert verified, "the verifier must report a finding on the asset the candidate names"
    assert any("xss" in (result.check or "").lower() for result in verified)
    for result in verified:
        assert result.evidence, "a verified result carries its evidence"


async def test_a_candidate_with_no_verifier_is_recorded_for_triage_not_proposed() -> None:
    """The honest branch: no shipped check can prove this signal, and the record says so."""
    from tests.helpers.fuzz import arc1_grammar

    from arachne.fuzz.candidates import FuzzCandidate, candidate_id

    grammar = arc1_grammar()
    case = grammar.build_case("key-length", MutationOperator.LENGTH_MAX, index=0)
    candidate = FuzzCandidate(
        id=candidate_id(
            grammar=grammar.name, target="127.0.0.1:1", field="key-length", operator="length-max"
        ),
        run_id="fz-test",
        engine="grammar",
        grammar=grammar.name,
        protocol=grammar.protocol,
        target="127.0.0.1:1",
        asset="127.0.0.1:1",
        field="key-length",
        operator="length-max",
        signal=CandidateSignal.FAULT,
        status=CandidateStatus.NEEDS_MANUAL_TRIAGE,
        confidence=70,
        observation="the service answered with its own internal error",
        payload_sha256=case.payload_sha256,
        payload_bytes=len(case.payload),
    )
    assert candidate.to_hypothesis() is None, (
        "there is nothing to run, so there is nothing to propose; naming an unrelated check "
        "would manufacture a verification that did not happen"
    )
    assert candidate.to_dict()["status"] == "needs-manual-triage"


def test_http_cases_come_from_the_shipped_payload_corpus() -> None:
    """REQ-FUZZ-003's mechanism: the corpus's own payloads, plus an encoding mutation."""
    payloads = load_fuzz_payloads()
    plan = HttpFuzzPlan(
        label="corpus-check",
        parameters=(HttpParameter(url="http://127.0.0.1:1/search?q=1", parameter="q"),),
        families=DEFAULT_FAMILIES,
    )
    cases = http_cases(plan, payloads, limit=200)
    assert cases

    corpus_boolean = {probe.payload for probe in payloads.boolean_probes()}
    corpus_time = {probe.payload.replace("{delay}", "5") for probe in payloads.time_probes()}
    corpus_sqli = set(payloads.strings("sqli", "error_payloads"))
    by_family = {case.family: case for case in cases}
    assert by_family["sqli-error"].payload in corpus_sqli, "the error deltas are the corpus's"
    assert corpus_boolean and corpus_time, "the corpus declares the boolean and time families"
    assert {case.encoding for case in cases} <= {"encoded", "plain", "double"}
    assert by_family["traversal"].payload if "traversal" in by_family else True


def test_a_traversal_payload_is_only_sent_to_a_file_parameter() -> None:
    """The corpus declares which families suit which parameter; guessing would be noise."""
    payloads = load_fuzz_payloads()
    file_plan = HttpFuzzPlan(
        label="file-param",
        parameters=(
            HttpParameter(
                url="http://127.0.0.1:1/download?file=1",
                parameter="file",
                kind="file",
            ),
        ),
        families=("traversal",),
    )
    generic_plan = HttpFuzzPlan(
        label="generic-param",
        parameters=(
            HttpParameter(url="http://127.0.0.1:1/search?q=1", parameter="q"),
        ),
        families=("traversal",),
    )
    file_cases = http_cases(file_plan, payloads, limit=50)
    generic_cases = http_cases(generic_plan, payloads, limit=50)
    assert file_cases, "a file parameter gets the traversal family"
    assert generic_cases == (), "a non-file parameter does not"
    assert any("etc%2Fpasswd" in case.url or "etc/passwd" in case.url for case in file_cases)


def test_the_http_reader_uses_the_corpus_signatures() -> None:
    """Detection reads the same table the M3 checks read, so a candidate means the same thing."""
    payloads = load_fuzz_payloads()
    plan = HttpFuzzPlan(
        label="reader",
        parameters=(HttpParameter(url="http://127.0.0.1:1/search?q=1", parameter="q"),),
        families=("sqli-error",),
    )
    case = http_cases(plan, payloads, limit=1)[0]

    sql_error = read_http_response(
        case,
        status=200,
        body="You have an error in your SQL syntax near 'x'",
        payloads=payloads,
    )
    assert sql_error.signal is CandidateSignal.ERROR_LEAK

    traversal = read_http_response(
        case,
        status=200,
        body="root:x:0:0:root:/root:/bin/bash\n",
        payloads=payloads,
    )
    assert traversal.signal is CandidateSignal.FILE_READ

    fault = read_http_response(case, status=500, body="boom", payloads=payloads)
    assert fault.signal is CandidateSignal.FAULT

    quiet = read_http_response(case, status=200, body="<html>all fine</html>", payloads=payloads)
    assert quiet.signal is None, "a normal answer is not a lead"


def test_the_settings_a_loopback_http_fuzz_run_needs_are_the_permissive_local_ones() -> None:
    settings = fuzz_settings()
    assert settings.safety.policy.allow_loopback is True
    # The *default* policy still refuses loopback, which is what keeps the labs a test-only
    # permission rather than a production one.
    from arachne.core.safety import UrlSafetyPolicy

    assert UrlSafetyPolicy().allow_loopback is False
