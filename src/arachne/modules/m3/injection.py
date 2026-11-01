"""SQL-injection oracle (research ch03#1, CWE-89).

The check implements the *differential* methodology of research ch03#1 and nothing beyond it:
it confirms that an input reaches a SQL statement by observing a difference the input caused,
and it never attempts extraction or exploitation.

Three oracles, in the order the research names them, each cheaper than the next:

1. **Error-based.** A single-character delta (``'``, ``"``, ``\\``) is appended to the
   parameter's value; a response whose body now matches a database error signature — and whose
   status/body differs from the benign baseline — proves the quote reached the parser. The
   signature table is data (``templates/m3/payloads.yaml``) and covers MySQL, PostgreSQL,
   MSSQL, Oracle and SQLite.
2. **Boolean.** ``1' AND '1'='1`` (true) versus ``1' AND '1'='2`` (false): the true request
   must resemble the benign baseline and the false one must not, by a configured margin. This
   is the "body/status delta" oracle of the research, not a guess on a single probe.
3. **Time-based.** Only reached when the first two did not confirm, capped at two parameters
   per run, with one blocking-sleep payload per DB family and a measured excess of
   ``ARACHNE_TIME_DELTA_S`` over the baseline (research ch03#1's timing oracle).

Scope of the probe: **query-string parameters of pages the crawl fetched.** Injection into
POST bodies is deliberately out of scope for this stage — it would mean sending request bodies
to state-changing endpoints, which docs/spec/05- M3's safety text ("no data modification
beyond benign requests") and F-02's safe defaults rule out. The limitation is recorded in
ADR-100.4.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    compare_pages,
    exchange_from_page,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["SqliOracle"]

#: How many blocking-sleep probes one run may spend (the slowest oracle, so tightly capped).
MAX_TIME_PROBES = 2

#: A boolean differential needs the true request to resemble the baseline at least this much
#: more closely than the false one — a margin, so rendering jitter cannot pass as an oracle.
BOOLEAN_MARGIN = 0.1


@dataclass(frozen=True, slots=True)
class _ErrorHit:
    """An error-oracle positive (a small value object, kept out of the result path)."""

    page: Page
    exchange: Any
    signature: str
    family: str | None


class SqliOracle(WebCheck, Module):
    """``m3.sqli-oracle`` — error/boolean/time differentials (ch03#1)."""

    metadata = CheckMetadata(
        id="m3.sqli-oracle",
        module="M3",
        name="sqli-oracle",
        version="1.0",
        title="SQL injection oracle",
        description=(
            "Confirms that query-string parameters reach a SQL statement by differential "
            "oracles only: a single-character delta whose response carries a database error "
            "signature, a true/false predicate pair whose responses diverge, or a "
            "blocking-sleep probe whose timing exceeds the baseline. No data is read, "
            "extracted or modified."
        ),
        research_ref="ch03#1",
        cwe="CWE-89",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=24,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None

        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(limit=ctx.config.web.max_params_per_check)
            if origin_of(url) == origin
        ]
        if not targets:
            yield ctx.clean(
                "no query parameter to probe",
                detail="the crawl found no parameter on this origin",
            )
            return

        payloads = payloads_for(ctx)
        error_signatures = payloads.sqli_error_signatures()
        error_payloads = payloads.strings("sqli", "error_payloads")[:2]
        benign_values = payloads.strings("sqli", "benign_values") or ("1",)
        boolean = payloads.boolean_probes()
        true_probes = [item for item in boolean if item.truth]
        false_probes = [item for item in boolean if not item.truth]
        time_probes = payloads.time_probes()
        time_spent = 0
        findings = 0

        for url, param in targets:
            baseline = await self._get(ctx, probe_url(url, param, benign_values[0]))
            if baseline is None:
                continue

            error_page = await self._error_oracle(
                ctx, url, param, baseline, error_payloads, error_signatures
            )
            if error_page is not None:
                findings += 1
                yield self._finding(
                    ctx,
                    technique="error-based",
                    url=url,
                    param=param,
                    payload_class="single-character-delta",
                    delta=compare_pages(baseline, error_page.page),
                    exchanges=(exchange_from_page(baseline), error_page.exchange),
                    extra={"error_signature": error_page.signature, "db_family": error_page.family},
                )
                continue

            boolean_hit = await self._boolean_oracle(
                ctx, url, param, baseline, true_probes, false_probes
            )
            if boolean_hit is not None:
                true_page, false_page, true_ex, false_ex = boolean_hit
                findings += 1
                yield self._finding(
                    ctx,
                    technique="boolean-based",
                    url=url,
                    param=param,
                    payload_class="predicate-true-vs-false",
                    delta=compare_pages(true_page, false_page),
                    exchanges=(exchange_from_page(baseline), true_ex, false_ex),
                    extra={
                        "true_vs_baseline": round(compare_pages(baseline, true_page).ratio, 4),
                        "false_vs_baseline": round(compare_pages(baseline, false_page).ratio, 4),
                    },
                )
                continue

            if time_probes and time_spent < MAX_TIME_PROBES:
                time_spent += 1
                elapsed = await self._time_oracle(ctx, url, param, baseline, time_probes)
                if elapsed is not None:
                    page, exchange, delay = elapsed
                    findings += 1
                    yield self._finding(
                        ctx,
                        technique="time-based",
                        url=url,
                        param=param,
                        payload_class=f"blocking-sleep-{delay}s",
                        delta=compare_pages(baseline, page),
                        exchanges=(exchange_from_page(baseline), exchange),
                        extra={"delay_s": delay},
                    )

        if not findings:
            yield ctx.clean(
                "no injection differential observed",
                detail=f"probed {len(targets)} parameter(s) with quote, boolean and timing oracles",
            )

    # ------------------------------------------------------------------ oracles
    async def _error_oracle(
        self,
        ctx: CheckContext,
        url: str,
        param: str,
        baseline: Page,
        error_payloads: Sequence[str],
        signatures: Mapping[str, Any],
    ) -> _ErrorHit | None:
        """A quote/backslash delta whose response carries a database error signature.

        Each family's pattern is tried separately rather than as one alternation, so the
        *family* is known from which pattern fired. A combined regex would report whichever
        alternative matched leftmost — usually the generic one — and throw away the engine
        identity the finding is worth reporting.
        """
        for payload in error_payloads:
            exchange = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            if exchange is None:
                continue
            hit = _match_family(exchange.body, signatures)
            if hit is None:
                continue
            family, match = hit
            page = page_from_exchange(exchange)
            delta = compare_pages(baseline, page)
            if not delta.status_changed and not delta.significant(
                min_ratio_drop=0.0, min_length_delta=1
            ):
                # The error text is identical to the baseline: the page already contains that
                # string (a documentation page quoting SQL, say), so it is not a differential.
                continue
            return _ErrorHit(
                page=page, exchange=exchange, signature=match.group(0)[:160], family=family
            )
        return None

    async def _boolean_oracle(
        self,
        ctx: CheckContext,
        url: str,
        param: str,
        baseline: Page,
        true_probes: Sequence[Any],
        false_probes: Sequence[Any],
    ) -> tuple[Page, Page, Any, Any] | None:
        """A true/false predicate pair: true resembles the baseline, false does not."""
        if not true_probes or not false_probes:
            return None
        true_probe, false_probe = true_probes[0], false_probes[0]
        true_exchange = await safe_fetch(
            ctx, probe_url(url, param, true_probe.payload), follow_redirects=False
        )
        if true_exchange is None:
            return None
        false_exchange = await safe_fetch(
            ctx, probe_url(url, param, false_probe.payload), follow_redirects=False
        )
        if false_exchange is None:
            return None
        true_page = page_from_exchange(true_exchange)
        false_page = page_from_exchange(false_exchange)
        if true_page.status >= 500 or false_page.status >= 500:
            # A server error on either half is the error oracle's business, not a boolean read.
            return None
        if not compare_pages(true_page, false_page).significant(min_ratio_drop=0.05):
            return None
        true_ratio = compare_pages(baseline, true_page).ratio
        false_ratio = compare_pages(baseline, false_page).ratio
        if true_ratio - false_ratio < BOOLEAN_MARGIN:
            return None
        return true_page, false_page, true_exchange, false_exchange

    async def _time_oracle(
        self,
        ctx: CheckContext,
        url: str,
        param: str,
        baseline: Page,
        time_probes: Sequence[Any],
    ) -> tuple[Page, Any, int] | None:
        """One blocking-sleep payload per family, until one exceeds the timing threshold."""
        delay = int(ctx.config.web.time_delay_s)
        threshold = baseline.elapsed_ms + ctx.config.web.time_delta_s * 1000.0
        for probe in time_probes:
            payload = probe.payload.replace("{delay}", str(delay))
            exchange = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            if exchange is None:
                continue
            if exchange.elapsed_ms >= threshold:
                return page_from_exchange(exchange), exchange, delay
        return None

    # ------------------------------------------------------------------ helpers
    async def _get(self, ctx: CheckContext, url: str) -> Page | None:
        exchange = await safe_fetch(ctx, url, follow_redirects=False)
        return None if exchange is None else page_from_exchange(exchange)

    def _finding(
        self,
        ctx: CheckContext,
        *,
        technique: str,
        url: str,
        param: str,
        payload_class: str,
        delta: Any,
        exchanges: Sequence[Any],
        extra: dict[str, Any],
    ) -> CheckResult:
        confidence = {"error-based": 0.85, "boolean-based": 0.6, "time-based": 0.7}[technique]
        return web_candidate(
            ctx,
            f"SQL injection oracle: {technique} differential in '{param}'",
            artifact={
                "signal": "sqli",
                "family": "sqli",
                "technique": technique,
                "endpoint": url,
                "parameter": param,
                "payload_class": payload_class,
                "delta": delta.to_dict(),
                "error_signature": None,
                "db_family": None,
                "nonce": nonce(),
                **extra,
            },
            exchanges=exchanges,
            confidence=confidence,
            detail=(
                f"{url} parameter '{param}': {technique} differential on a {payload_class} probe"
            ),
            source=url,
        )


def _match_family(body: str, signatures: Mapping[str, Any]) -> tuple[str | None, Any] | None:
    """The first family whose signature fires on ``body``, with its match object.

    ``generic`` is last in the corpus, so a specific engine identity always wins over the
    catch-all pattern — which is what makes ``db_family`` in the artifact trustworthy.
    """
    for family, pattern in signatures.items():
        match = pattern.search(body)
        if match is not None:
            return (None if family == "generic" else family), match
    return None
