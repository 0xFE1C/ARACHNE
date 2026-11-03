"""The shared differential oracle (REQ-PROOF-020).

Injection checks answer one question in one of a few shapes: *does the response change
because of my input, in a way the input alone does not explain?* Nine M3 families grew their
own answer to it — five different boolean thresholds, a count-based comparison, a
content-marker rule, a timing rule and a regex-only rule — and divergence between them is a
silent false-positive source: the same response pair can be a finding in one family and
noise in the next.

This module is the one place the *decision* lives. A family measures; the oracle decides:

:meth:`DifferentialOracle.boolean`
    A true/false predicate pair: the two responses must differ materially from each other
    **and** the true one must resemble the untouched baseline more than the false one. This
    is the SQLi and XPath rule.
:meth:`DifferentialOracle.query`
    A single probe against a baseline, where the change must be larger than simple noise and
    must not be the probe simply echoed back. This is the NoSQL/query-family rule.
:meth:`DifferentialOracle.marker`
    A canary that appears in the probe and not in the baseline (path traversal, local file
    inclusion, XXE, SSTI). The marker must be *absent* from the baseline, which is what
    separates "the file was read" from "the page already said that".

**The decoy property is structural, not a special case.** A response that is identical for
every input — the "always returns 200" page, the SPA catch-all, the WAF interstitial —
produces a pair delta of zero, so :meth:`boolean` cannot confirm it, and gives
:meth:`query` nothing above the noise floor. ``tests/unit/test_oracle_conformance.py``
drives the same payload set through three families against both a differential fixture and
that decoy, and asserts positives on the first and none on the second.

Every threshold is a field of the oracle rather than a literal in a check, so a review of
"why did this confirm?" reads one dataclass instead of nine files.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.core.http import HttpExchange
from arachne.modules.m3.inventory import Page
from arachne.modules.m3.support import BodyDelta, compare_pages

__all__ = [
    "DEFAULT_ORACLE",
    "DifferentialOracle",
    "OracleVerdict",
]

#: Named signals a verdict can carry, so a caller's artifact says which rule fired.
SIGNAL_BOOLEAN: Final = "boolean-differential"
SIGNAL_QUERY: Final = "query-differential"
SIGNAL_MARKER: Final = "content-marker"
SIGNAL_DECOY: Final = "no-differential"


@dataclass(frozen=True, slots=True)
class OracleVerdict:
    """What one oracle call decided, with the numbers it decided on.

    ``metrics`` is what a finding's artifact and the verification record's observations are
    built from, so a reviewer can see *why* the oracle confirmed rather than only that it
    did. ``refused`` names the reason a pair was rejected, and is empty when it confirmed.
    """

    confirmed: bool
    signal: str
    metrics: dict[str, Any] = field(default_factory=dict)
    refused: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"signal": self.signal, "confirmed": self.confirmed}
        if self.refused:
            payload["refused"] = self.refused
        payload.update(self.metrics)
        return payload


@dataclass(frozen=True, slots=True)
class DifferentialOracle:
    """The shared decision procedure, parameterised so a family need not re-implement it.

    ``min_ratio_drop`` is how much shorter a response must be before the difference counts
    (a fraction of the baseline's length); ``min_length_delta`` the absolute floor;
    ``margin`` the minimum baseline-similarity gap between the true and false halves of a
    boolean pair. The defaults are the SQLi family's, which are the strictest of the nine.
    """

    min_ratio_drop: float = 0.05
    min_length_delta: int = 1
    margin: float = 0.1
    #: How much longer than the echoed probe a response may be and still count as "the probe
    #: was reflected, nothing else happened".
    max_reflection_slack: int = 16

    # ------------------------------------------------------------------ boolean
    def boolean(
        self,
        *,
        baseline: Page,
        true_page: Page,
        false_page: Page,
        extra: bool = True,
    ) -> OracleVerdict:
        """Decide a true/false predicate pair.

        ``extra`` is a family-specific corroboration the caller has already evaluated (XPath
        counts the application's own records, for instance). It is a *conjunct*: a family can
        make the decision stricter, never looser — which is what keeps a shared oracle from
        widening a stricter family's false-positive surface.
        """
        if true_page.status >= 500 or false_page.status >= 500:
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                refused="a 5xx on either half is the error oracle's business",
            )
        pair: BodyDelta = compare_pages(true_page, false_page)
        metrics: dict[str, Any] = {
            "pair_ratio": pair.ratio,
            "pair_status_changed": pair.status_changed,
        }
        if not pair.significant(min_ratio_drop=self.min_ratio_drop):
            # The decoy case, and any parameter the application ignores: the two halves are
            # the same response.
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                metrics=metrics,
                refused="the true and false halves are the same response",
            )
        true_ratio = compare_pages(baseline, true_page).ratio
        false_ratio = compare_pages(baseline, false_page).ratio
        metrics.update(
            {"true_ratio": true_ratio, "false_ratio": false_ratio, "margin": self.margin}
        )
        if true_ratio - false_ratio < self.margin:
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                metrics=metrics,
                refused="the true half does not track the baseline more closely than the false one",
            )
        if not extra:
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                metrics=metrics,
                refused="the family's own corroboration did not hold",
            )
        return OracleVerdict(confirmed=True, signal=SIGNAL_BOOLEAN, metrics=metrics)

    # ------------------------------------------------------------------ query
    def query(
        self,
        *,
        baseline: Page | HttpExchange,
        probe: Page | HttpExchange,
        probe_text: str = "",
        min_length_delta: int | None = None,
    ) -> OracleVerdict:
        """Decide one probe against a baseline, discounting a pure reflection of the probe."""
        delta: BodyDelta = compare_pages(baseline, probe)
        metrics: dict[str, Any] = {
            "ratio": delta.ratio,
            "length_delta": delta.length_delta,
            "status_changed": delta.status_changed,
        }
        floor = self.min_length_delta if min_length_delta is None else min_length_delta
        if not delta.significant(min_ratio_drop=self.min_ratio_drop, min_length_delta=floor):
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                metrics=metrics,
                refused="no difference above the page's own rendering noise",
            )
        if self._is_pure_reflection(baseline, probe, probe_text, delta):
            metrics["reflection"] = True
            return OracleVerdict(
                confirmed=False,
                signal=SIGNAL_DECOY,
                metrics=metrics,
                refused="the only change is the probe echoed back",
            )
        return OracleVerdict(confirmed=True, signal=SIGNAL_QUERY, metrics=metrics)

    def _is_pure_reflection(
        self,
        baseline: Page | HttpExchange,
        probe: Page | HttpExchange,
        probe_text: str,
        delta: BodyDelta,
    ) -> bool:
        """True when the only change is ``probe_text`` echoed verbatim, not a query effect."""
        if delta.status_changed or not probe_text:
            return False
        return (
            probe_text in probe.body
            and abs(delta.length_delta) <= len(probe_text) + self.max_reflection_slack
        )

    # ------------------------------------------------------------------ marker
    def marker(
        self,
        *,
        baseline_body: str,
        probe_body: str,
        patterns: Sequence[re.Pattern[str]],
    ) -> OracleVerdict:
        """The first canary in the probe body that the baseline body does not carry.

        A marker already present in the baseline proves nothing — that is the whole reason
        the baseline is fetched first — so a match requires both halves of the condition.
        """
        for pattern in patterns:
            match = pattern.search(probe_body)
            if match is None:
                continue
            if pattern.search(baseline_body) is not None:
                return OracleVerdict(
                    confirmed=False,
                    signal=SIGNAL_MARKER,
                    metrics={"marker": match.group(0)[:160], "in_baseline": True},
                    refused="the canary is already in the baseline response",
                )
            return OracleVerdict(
                confirmed=True,
                signal=SIGNAL_MARKER,
                metrics={"marker": match.group(0)[:160], "in_baseline": False},
            )
        return OracleVerdict(
            confirmed=False, signal=SIGNAL_MARKER, refused="no known canary in the response"
        )

    def marker_text(
        self, *, baseline_body: str, probe_body: str, markers: Mapping[str, str]
    ) -> str:
        """The matched canary's text, or ``""`` (the shape the traversal families want)."""
        patterns = [re.compile(str(expression), re.IGNORECASE) for expression in markers.values()]
        verdict = self.marker(baseline_body=baseline_body, probe_body=probe_body, patterns=patterns)
        return str(verdict.metrics.get("marker") or "")


#: The deployment's oracle. A check that needs different thresholds constructs its own
#: ``DifferentialOracle(...)`` rather than passing literals around.
DEFAULT_ORACLE: Final = DifferentialOracle()
