"""The differential-oracle conformance kit (REQ-PROOF-020).

Nine M3 injection families used to each carry their own answer to "does this response change
because of my input?". This suite is the single place that answer is checked: it drives the
*same* payload set, against the *same* scripted responses, through several families, and
requires them all to reach the same verdict.

Three properties, which are exactly the requirement's acceptance criteria:

* **agreement** — for one response set, every family of the same class reaches the same
  verdict (``test_every_family_agrees_on_the_same_response_set``);
* **the decoy yields nothing** — a response that is identical for every input ("always
  returns 200") produces zero positives in every family
  (``test_the_always_200_decoy_yields_zero_positives``);
* **divergence is caught** — an implementation of the same oracle that confirms where the
  shared one refuses is reported as a divergence, so a family cannot quietly loosen the
  rule (``test_a_divergent_implementation_is_reported``).

The families are driven through the real check classes with a scripted ``ctx.http``, so what
is tested is the shipped decision path, not a copy of it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.helpers.checks import run_check

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.modules.base import Asset, Module
from arachne.modules.m3.hardening import DirectoryTraversal, NosqlOracle
from arachne.modules.m3.injection import SqliOracle
from arachne.modules.m3.injection_families import XpathInjectionOracle
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.oracle import DEFAULT_ORACLE, DifferentialOracle

#: The two bodies every responder is built from. ``BENIGN`` is the application's normal
#: response; ``NEGATIVE`` is what it renders when the injected predicate matches nothing.
# ``<li class="record">`` is the marker the XPath and LDAP families count, so the shared
# fixture is a page those families can legitimately read a record count from.
BENIGN = "<html><body><h1>catalog</h1>" + '<li class="record">item</li>' * 40 + "</body></html>"
NEGATIVE = "<html><body><h1>catalog</h1><p>no matching records</p></body></html>"

#: Predicates that mean "match nothing" (the false half of a boolean pair). Tried first.
_FALSE_MARKERS = ('="2', "='2", "=2)", "1=2", "= 2")
#: Predicates that mean "match everything" (the true half). The benign baseline also lives
#: here, because a true predicate must look like the untouched page.
_TRUE_MARKERS = ('="1', "='1", "=1)", "1=1")

SEARCH_URL = "http://lab.example/search?id=1"
TRAVERSAL_URL = "http://lab.example/download?file=report.txt"


def _exchange(url: str, body: str, *, status: int = 200) -> HttpExchange:
    return HttpExchange(
        method="GET",
        url=url,
        status_code=status,
        response_headers={"content-type": "text/html"},
        body=body,
    )


def _value_of(url: str, parameter: str) -> str:
    return parse_qs(urlsplit(url).query, keep_blank_values=True).get(parameter, [""])[0]


class _ScriptedClient:
    """A ``ctx.http`` that answers from a responder and records every URL it was asked."""

    def __init__(self, responder: Callable[[str], HttpExchange]) -> None:
        self._responder = responder
        self.requests: list[str] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: object = None,
        content: object = None,
        follow_redirects: object = None,
    ) -> HttpExchange:
        self.requests.append(url)
        return self._responder(url)


def _inventory(url: str) -> WebInventory:
    """A one-page crawl carrying the parameter under test."""
    inventory = WebInventory(origin=origin_of(url), roots=(url,))
    inventory.add_page(
        Page(
            url=url,
            status=200,
            headers={"content-type": "text/html"},
            body=BENIGN,
            content_type="text/html",
            elapsed_ms=1.0,
        )
    )
    return inventory


def _asset(url: str) -> Asset:
    return Asset.from_meta("url", url, {"declared": True})


def differential_responder(url: str, *, parameter: str) -> HttpExchange:
    """One responder for every family: true/benign input → the page, false input → nothing.

    The rule is deliberately family-agnostic, which is the point of the kit: the same
    response set must produce the same verdict whichever check is looking at it.
    """
    value = _value_of(url, parameter)
    lowered = value.lower()
    if any(marker in lowered for marker in _FALSE_MARKERS):
        return _exchange(url, NEGATIVE)
    if any(marker in lowered for marker in _TRUE_MARKERS) or value.isdigit():
        return _exchange(url, BENIGN)
    return _exchange(url, NEGATIVE)


def decoy_responder(url: str) -> HttpExchange:
    """The decoy: one page, 200, for every input — including the baseline."""
    return _exchange(url, BENIGN)


def traversal_responder(url: str) -> HttpExchange:
    """The marker family's differential: a canary only the traversal payload can reach."""
    value = _value_of(url, "file")
    if "passwd" in value.lower():
        return _exchange(url, "root:x:0:0:root:/root:/bin/bash\n")
    return _exchange(url, "report not found")


@dataclass(frozen=True, slots=True)
class _Family:
    """One family under conformance: its check class, its URL and its parameter."""

    name: str
    check: type[Module]
    url: str
    parameter: str = "id"


FAMILIES: tuple[_Family, ...] = (
    _Family("sqli", SqliOracle, SEARCH_URL),
    _Family("xpath", XpathInjectionOracle, SEARCH_URL),
    _Family("nosql", NosqlOracle, SEARCH_URL),
    _Family("traversal", DirectoryTraversal, TRAVERSAL_URL, parameter="file"),
)


async def _positive(family: _Family, responder: Callable[[str], HttpExchange]) -> bool:
    """Run one family against a responder; True when it raised at least one candidate."""
    results, _ = await run_check(
        family.check,
        _asset(family.url),
        http=_ScriptedClient(responder),
        web=_inventory(family.url),
    )
    return any(result.status == "vulnerable" for result in results)


def _responder_for(family: _Family) -> Callable[[str], HttpExchange]:
    if family.name == "traversal":
        return traversal_responder
    return lambda url: differential_responder(url, parameter=family.parameter)


# ------------------------------------------------------------------ agreement
async def test_every_family_agrees_on_the_same_response_set() -> None:
    """The same differential must be a positive in every family, or the kit fails.

    This is REQ-PROOF-020's "identical payload sets produce identical verdicts across checks
    of the same class": one response set, four families, one verdict each — and they must
    all be the same verdict.
    """
    verdicts = {}
    for family in FAMILIES:
        verdicts[family.name] = await _positive(family, _responder_for(family))
    assert verdicts, "the kit must cover at least three families"
    assert len(FAMILIES) >= 3, "REQ-PROOF-020 requires three families or more"
    assert all(verdicts.values()), f"families disagreed about the same differential: {verdicts}"


async def test_the_always_200_decoy_yields_zero_positives() -> None:
    """A page that returns 200 with the same body for every input is never a positive."""
    positives = {}
    for family in FAMILIES:
        positives[family.name] = await _positive(family, decoy_responder)
    assert not any(positives.values()), f"the decoy produced a positive: {positives}"


async def test_the_decoy_is_the_only_difference_from_the_positive_case() -> None:
    """The two cases differ *only* in the responder — the evidence that the kit is meaningful.

    Without this, a bug that makes every case a negative would pass the decoy test.
    """
    for family in FAMILIES:
        assert await _positive(family, _responder_for(family)), family.name
        assert not await _positive(family, decoy_responder), family.name


# ------------------------------------------------------------------ divergence
def _page(body: str, status: int = 200) -> Page:
    return Page(
        url="http://lab.example/search",
        status=status,
        headers={"content-type": "text/html"},
        body=body,
        content_type="text/html",
        elapsed_ms=1.0,
    )


@dataclass(frozen=True, slots=True)
class _Case:
    """One boolean-pair case the kit can put to two implementations."""

    name: str
    baseline: Page
    true_page: Page
    false_page: Page


CASES: tuple[_Case, ...] = (
    _Case("differential", _page(BENIGN), _page(BENIGN), _page(NEGATIVE)),
    _Case("decoy", _page(BENIGN), _page(BENIGN), _page(BENIGN)),
    _Case("server-error", _page(BENIGN), _page(BENIGN, status=500), _page(NEGATIVE)),
)


def _decide(oracle: DifferentialOracle, case: _Case) -> bool:
    return oracle.boolean(
        baseline=case.baseline, true_page=case.true_page, false_page=case.false_page
    ).confirmed


def _divergences(
    implementations: Mapping[str, Callable[[_Case], bool]], cases: Sequence[_Case]
) -> list[str]:
    """Every ``(case, implementation)`` where an implementation disagrees with the first.

    The kit's comparison rule: the first implementation is the reference (the shared oracle),
    and any other implementation that reaches a different verdict on a case is a divergence,
    named with the case and both verdicts so the failure is actionable.
    """
    names = list(implementations)
    reference = implementations[names[0]]
    out: list[str] = []
    for case in cases:
        expected = reference(case)
        for name in names[1:]:
            if implementations[name](case) != expected:
                out.append(
                    f"{name} disagrees with {names[0]} on {case.name!r}: "
                    f"{implementations[name](case)} != {expected}"
                )
    return out


def test_two_implementations_of_the_same_oracle_agree_case_by_case() -> None:
    """The shipped oracle against itself: no divergence, on every case."""
    shared = lambda case: _decide(DEFAULT_ORACLE, case)  # noqa: E731 - a named reference
    implementations = {"shared": shared, "shared-again": lambda case: _decide(DEFAULT_ORACLE, case)}
    assert _divergences(implementations, CASES) == []


def test_a_divergent_implementation_is_reported() -> None:
    """A family that confirms where the shared oracle refuses fails the conformance kit.

    The divergent implementation is the shape the requirement worries about: a comparison
    that treats "the response differed at all" as proof, so the always-200 decoy — and every
    parameter the application happens to react to — becomes a finding.
    """
    implementations = {
        "shared": lambda case: _decide(DEFAULT_ORACLE, case),
        "loose": lambda case: (
            case.true_page.body != case.baseline.body + "never" or case.true_page.status != 599
        ),
    }
    reported = _divergences(implementations, CASES)
    assert reported, "the kit did not detect a divergence it must detect"
    assert any("decoy" in line for line in reported), reported


@pytest.mark.parametrize("family", FAMILIES, ids=lambda family: family.name)
async def test_an_error_response_is_not_confirmable(family: _Family) -> None:
    """A responder that answers 500 to everything is an error, never a finding."""

    def broken(url: str) -> HttpExchange:
        return _exchange(url, "internal server error", status=500)

    assert await _positive(family, broken) is False


def test_the_oracle_thresholds_are_fields_not_literals() -> None:
    """The thresholds a family used to hard-code now live on the oracle (REQ-PROOF-020)."""
    strict = DifferentialOracle(min_ratio_drop=0.5, margin=0.5)
    assert strict != DEFAULT_ORACLE
    assert DEFAULT_ORACLE.margin == 0.1


def test_no_family_keeps_a_private_boolean_threshold() -> None:
    """The migrated families route their decision through the shared oracle.

    A source-level assertion, because the divergence this requirement targets is a *copy* of
    the comparison: a family that re-implements ``true_ratio - false_ratio < 0.1`` inline has
    silently left the shared rule, whatever its behaviour happens to be today.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m3"
    offenders: list[str] = []
    for name in ("injection.py", "injection_families.py", "hardening.py"):
        text = (root / name).read_text(encoding="utf-8")
        if "DEFAULT_ORACLE" not in text:
            offenders.append(f"{name}: does not call the shared oracle")
        # The boolean margin and the shared noise floor are the oracle's now; a module that
        # still carries either has left the shared rule. (The error-signature oracle's own
        # "the page is not identical to the baseline" guard is a different rule — a signature
        # match, not a differential — and stays where it is.)
        if "BOOLEAN_MARGIN" in text or "min_ratio_drop=0.05" in text:
            offenders.append(f"{name}: still carries the shared differential threshold inline")
    assert offenders == [], (
        "these families re-implement the shared differential threshold inline: " + str(offenders)
    )


def _results_statuses(results: Sequence[CheckResult]) -> list[str]:
    return [result.status for result in results]
