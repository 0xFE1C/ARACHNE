"""WP-08 injection breadth: LDAP, XPath, code injection and command-argument injection.

These four families close the detection backlog REQ-DET-004 and REQ-DET-009 name. Every one
is **L1, read-only and differential**: the check establishes a benign baseline, sends one
inert probe, and reports only when the probe caused a *measured* difference the baseline did
not have. A payload that merely comes back in the response is never a finding (FP-2).

``m3.ldap-injection`` — CWE-90
    A malformed LDAP filter, matched against the directory server's own exception text; or a
    wildcard filter whose rendered result count exceeds a literal non-match. The wildcard
    broadens a filter the application built from the parameter, which a value that never
    reached the parser cannot do.
``m3.xpath-injection`` — CWE-643
    The XPath analogue: an unterminated predicate matched against the engine's exception
    text, or the inert ``' or '1'='1`` / ``' or '1'='2`` pair whose rendered result counts
    diverge. Quoting the value correctly makes both predicates literal, which is the decoy.
``m3.code-injection-oracle`` — CWE-94
    A bare arithmetic expression (``7*7*7``) in a parameter that suggests evaluation, with
    the *computed* result required and the raw probe not sufficient. This is the
    evaluation-context oracle the research asks for, distinct from SQL/command injection and
    from template injection (no template delimiters are sent).
``m3.argument-injection`` — CWE-77
    An unknown long option appended to a value that is plausibly concatenated into a command
    line. The utility's own argument parser answers with a diagnostic the baseline did not
    have, proving the value was split into argv. Nothing is executed: there is no separator,
    no shell, no command of our choosing.

**Shared differential oracle.** All four use the M3 shared comparison arithmetic —
:func:`~arachne.modules.m3.support.compare_pages` / :class:`BodyDelta` — for every
baseline/probe read, plus one result-count comparison over the application's own record
marker for the two query families. There is no private similarity or timing logic here.

**Read-only.** Every request is a GET. Nothing is stored, no form is submitted, no filter is
enumerated past the bounded probe set, and no entry is read beyond what the application's own
rendering returns.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.breadth_support import (
    benign_value,
    count_records,
    differs,
    fetch_page,
    first_signature,
    preferred,
    reproduce,
)
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "ArgumentInjectionOracle",
    "CodeInjectionOracle",
    "LdapInjectionOracle",
    "XpathInjectionOracle",
]


# --------------------------------------------------------------------------- LDAP injection
class LdapInjectionOracle(WebCheck, Module):
    """``m3.ldap-injection`` — filter-parser differential (ch03#2, CWE-90)."""

    metadata = CheckMetadata(
        id="m3.ldap-injection",
        module="M3",
        name="ldap-injection",
        version="1.0",
        title="LDAP injection oracle",
        description=(
            "Confirms that a parameter reaches an LDAP filter by two read-only differentials: "
            "a malformed filter whose response carries the directory server's own exception "
            "text, or a wildcard filter that renders more records than a literal non-match. "
            "No entry is read, modified or enumerated; the probe is bounded to the crawled "
            "parameter surface."
        ),
        research_ref="ch03#2",
        framework=("WSTG-INPV-06", "CWE-90"),
        cwe="CWE-90",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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
        assert isinstance(inventory, WebInventory)

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("ldap", "param_hints")}
        errors = payloads.strings("ldap", "error_payloads")
        signatures = payloads.mapping("ldap", "error_signatures")
        broaden = payloads.string("ldap", "broaden_payload", default="*")
        literal = payloads.string("ldap", "literal_payload", default="ar9x-no-such-entry")
        marker = payloads.string("ldap", "result_marker")
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no LDAP-like parameter to probe",
                detail="the crawl found no parameter whose name suggests a directory query",
            )
            return

        findings = 0
        for url, parameter in targets:
            benign = benign_value(url, parameter, "alice")
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue

            error_hit = await self._error_oracle(ctx, url, parameter, baseline, errors, signatures)
            if error_hit is not None:
                _, exchange, signature = error_hit
                findings += 1
                yield self._finding(
                    ctx,
                    technique="error-based",
                    url=url,
                    parameter=parameter,
                    payload=str(signature[0]),
                    observed=str(signature[1]),
                    baseline=baseline[1],
                    probe=exchange,
                    artifact_extra={"error_signature": signature[1]},
                    detail=(
                        f"{url} returned the directory server's own filter error for parameter "
                        f"'{parameter}' ({signature[1]})"
                    ),
                    confidence=0.85,
                )
                continue

            broadened = await self._broaden_oracle(
                ctx, url, parameter, baseline, broaden, literal, marker
            )
            if broadened is not None:
                _, broad_ex, _, none_ex, counts = broadened
                findings += 1
                yield self._finding(
                    ctx,
                    technique="filter-broadening",
                    url=url,
                    parameter=parameter,
                    payload=broaden,
                    observed=(
                        f"{counts['broad']} record(s) for the wildcard versus "
                        f"{counts['literal']} for a literal non-match"
                    ),
                    baseline=baseline[1],
                    probe=broad_ex,
                    second=none_ex,
                    artifact_extra={
                        "baseline_records": counts["baseline"],
                        "broad_records": counts["broad"],
                        "literal_records": counts["literal"],
                    },
                    detail=(
                        f"{url} parameter '{parameter}': an LDAP wildcard broadened the result "
                        f"set to {counts['broad']} record(s) where a literal non-match rendered "
                        f"{counts['literal']}"
                    ),
                    confidence=0.7,
                )
        if not findings:
            yield ctx.clean(
                "no LDAP filter differential observed",
                detail=f"probed {len(targets)} directory-like parameter(s)",
            )

    async def _error_oracle(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        baseline: tuple[Page, HttpExchange],
        errors: Sequence[str],
        signatures: Mapping[str, Any],
    ) -> tuple[Page, HttpExchange, tuple[str, str]] | None:
        for payload in errors:
            fetched = await fetch_page(ctx, probe_url(url, parameter, payload))
            if fetched is None:
                continue
            page, exchange = fetched
            signature = first_signature(page.body, signatures)
            if signature is None:
                continue
            if not differs(baseline[0], page):
                # The error text was already on the baseline page: not a differential.
                continue
            return page, exchange, (payload, signature)
        return None

    async def _broaden_oracle(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        baseline: tuple[Page, HttpExchange],
        broaden: str,
        literal: str,
        marker: str,
    ) -> tuple[Page, HttpExchange, Page, HttpExchange, dict[str, int]] | None:
        if not marker:
            return None
        broad = await fetch_page(ctx, probe_url(url, parameter, broaden))
        none = await fetch_page(ctx, probe_url(url, parameter, literal))
        if broad is None or none is None:
            return None
        counts = {
            "baseline": count_records(baseline[0].body, marker),
            "broad": count_records(broad[0].body, marker),
            "literal": count_records(none[0].body, marker),
        }
        if counts["broad"] < counts["baseline"] + 2 or counts["broad"] <= counts["literal"]:
            return None
        if not differs(broad[0], none[0]):
            return None
        return broad[0], broad[1], none[0], none[1], counts

    def _finding(
        self,
        ctx: CheckContext,
        *,
        technique: str,
        url: str,
        parameter: str,
        payload: str,
        observed: str,
        baseline: HttpExchange,
        probe: HttpExchange,
        artifact_extra: Mapping[str, Any],
        detail: str,
        confidence: float,
        second: HttpExchange | None = None,
    ) -> CheckResult:
        artifact = {
            "signal": "ldap-injection",
            "family": "ldap",
            "technique": technique,
            "endpoint": url,
            "parameter": parameter,
            "payload": payload,
            "observed": observed,
            "reproduce": reproduce("GET", probe.url),
            **artifact_extra,
        }
        return web_candidate(
            ctx,
            f"LDAP injection ({technique}) in '{parameter}'",
            artifact=artifact,
            exchanges=(baseline, probe, second),
            cwe="CWE-90",
            confidence=confidence,
            detail=detail,
            source=url,
        )


# --------------------------------------------------------------------------- XPath injection
class XpathInjectionOracle(WebCheck, Module):
    """``m3.xpath-injection`` — XPath engine differential (ch03#1, CWE-643)."""

    metadata = CheckMetadata(
        id="m3.xpath-injection",
        module="M3",
        name="xpath-injection",
        version="1.0",
        title="XPath injection oracle",
        description=(
            "Confirms that a parameter reaches an XPath expression by two read-only "
            "differentials: a malformed predicate whose response carries the XPath engine's "
            "own exception text, or the inert true/false predicate pair whose rendered result "
            "counts diverge. The second probe is the differential that a quoted value cannot "
            "reproduce; no node is read or extracted."
        ),
        research_ref="ch03#1",
        framework=("WSTG-INPV-09", "CWE-643"),
        cwe="CWE-643",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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
        assert isinstance(inventory, WebInventory)

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("xpath", "param_hints")}
        path_hints = tuple(hint.lower() for hint in payloads.strings("xpath", "path_hints"))
        errors = payloads.strings("xpath", "error_payloads")
        signatures = payloads.mapping("xpath", "error_signatures")
        true_probes = payloads.strings("xpath", "true_payloads")
        false_probes = payloads.strings("xpath", "false_payloads")
        marker = payloads.string("xpath", "result_marker")
        origin = origin_of(ctx.asset.value)
        pairs = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ]
        targets = preferred(
            pairs, lambda pair: any(hint in urlsplit(pair[0]).path.lower() for hint in path_hints)
        )[: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no XPath-like parameter to probe",
                detail="the crawl found no query parameter to test against an XPath expression",
            )
            return

        findings = 0
        for url, parameter in targets:
            benign = benign_value(url, parameter, "1")
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue

            error_hit = await self._error_oracle(ctx, url, parameter, baseline, errors, signatures)
            if error_hit is not None:
                _, exchange, signature = error_hit
                findings += 1
                yield self._finding(
                    ctx,
                    technique="xpath-error",
                    url=url,
                    parameter=parameter,
                    payload=str(signature[0]),
                    observed=str(signature[1]),
                    baseline=baseline[1],
                    probe=exchange,
                    artifact_extra={"error_signature": signature[1]},
                    detail=(
                        f"{url} returned the XPath engine's own error for parameter "
                        f"'{parameter}' ({signature[1]})"
                    ),
                    confidence=0.85,
                )
                continue

            boolean_hit = await self._boolean_oracle(
                ctx, url, parameter, baseline, true_probes, false_probes, marker
            )
            if boolean_hit is not None:
                _, true_ex, _, false_ex, counts = boolean_hit
                findings += 1
                yield self._finding(
                    ctx,
                    technique="xpath-boolean",
                    url=url,
                    parameter=parameter,
                    payload=true_probes[0],
                    observed=(
                        f"{counts['true']} record(s) for the true predicate versus "
                        f"{counts['false']} for the false one"
                    ),
                    baseline=baseline[1],
                    probe=true_ex,
                    second=false_ex,
                    artifact_extra={
                        "true_records": counts["true"],
                        "false_records": counts["false"],
                        "baseline_records": counts["baseline"],
                    },
                    detail=(
                        f"{url} parameter '{parameter}': the true predicate rendered "
                        f"{counts['true']} record(s) and the false one {counts['false']}"
                    ),
                    confidence=0.75,
                )
        if not findings:
            yield ctx.clean(
                "no XPath differential observed",
                detail=(
                    f"probed {len(targets)} query parameter(s) with malformed and "
                    "boolean predicates"
                ),
            )

    async def _error_oracle(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        baseline: tuple[Page, HttpExchange],
        errors: Sequence[str],
        signatures: Mapping[str, Any],
    ) -> tuple[Page, HttpExchange, tuple[str, str]] | None:
        for payload in errors:
            fetched = await fetch_page(ctx, probe_url(url, parameter, payload))
            if fetched is None:
                continue
            page, exchange = fetched
            signature = first_signature(page.body, signatures)
            if signature is None or not differs(baseline[0], page):
                continue
            return page, exchange, (payload, signature)
        return None

    async def _boolean_oracle(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        baseline: tuple[Page, HttpExchange],
        true_probes: Sequence[str],
        false_probes: Sequence[str],
        marker: str,
    ) -> tuple[Page, HttpExchange, Page, HttpExchange, dict[str, int]] | None:
        if not marker or not true_probes or not false_probes:
            return None
        true = await fetch_page(ctx, probe_url(url, parameter, true_probes[0]))
        false = await fetch_page(ctx, probe_url(url, parameter, false_probes[0]))
        if true is None or false is None:
            return None
        counts = {
            "baseline": count_records(baseline[0].body, marker),
            "true": count_records(true[0].body, marker),
            "false": count_records(false[0].body, marker),
        }
        if counts["true"] <= counts["false"] or counts["true"] < counts["baseline"]:
            return None
        if not differs(true[0], false[0]):
            return None
        return true[0], true[1], false[0], false[1], counts

    def _finding(
        self,
        ctx: CheckContext,
        *,
        technique: str,
        url: str,
        parameter: str,
        payload: str,
        observed: str,
        baseline: HttpExchange,
        probe: HttpExchange,
        artifact_extra: Mapping[str, Any],
        detail: str,
        confidence: float,
        second: HttpExchange | None = None,
    ) -> CheckResult:
        return web_candidate(
            ctx,
            f"XPath injection ({technique}) in '{parameter}'",
            artifact={
                "signal": "xpath-injection",
                "family": "xpath",
                "technique": technique,
                "endpoint": url,
                "parameter": parameter,
                "payload": payload,
                "observed": observed,
                "reproduce": reproduce("GET", probe.url),
                **artifact_extra,
            },
            exchanges=(baseline, probe, second),
            cwe="CWE-643",
            confidence=confidence,
            detail=detail,
            source=url,
        )


# --------------------------------------------------------------------------- code injection
class CodeInjectionOracle(WebCheck, Module):
    """``m3.code-injection-oracle`` — evaluation-context differential (ch03#6, CWE-94)."""

    metadata = CheckMetadata(
        id="m3.code-injection-oracle",
        module="M3",
        name="code-injection-oracle",
        version="1.0",
        title="Code injection oracle",
        description=(
            "Sends a bare arithmetic expression (7*7*7) to parameters that suggest an "
            "evaluation context and reports only when the *computed* result appears where the "
            "benign baseline did not have it. This is the evaluation-context oracle of "
            "research ch03#6, distinct from SQL and command injection and from template "
            "injection (no template delimiters are sent). Arithmetic only: no built-in, no "
            "attribute chain, no file access."
        ),
        research_ref="ch03#6",
        framework=("WSTG-INPV-11", "CWE-94"),
        cwe="CWE-94",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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
        assert isinstance(inventory, WebInventory)

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("code_injection", "param_hints")}
        probes = payloads.entries("code_injection", "arithmetic")
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no evaluation-like parameter to probe",
                detail="the crawl found no parameter whose name suggests an expression",
            )
            return

        findings = 0
        for url, parameter in targets:
            benign = benign_value(url, parameter, "1")
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue
            for entry in probes:
                probe = str(entry.get("probe", ""))
                expected = str(entry.get("expected", ""))
                if not probe or not expected:
                    continue
                fetched = await fetch_page(ctx, probe_url(url, parameter, probe))
                if fetched is None:
                    continue
                page, exchange = fetched
                # The computed result must appear, the benign page must not carry it, and the
                # response must actually differ: an echo of the raw probe is not evaluation.
                if expected not in page.body or expected in baseline[0].body:
                    continue
                if not differs(baseline[0], page):
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Code/expression evaluation in '{parameter}'",
                    artifact={
                        "signal": "code-injection",
                        "family": "code-injection",
                        "technique": "arithmetic-evaluation",
                        "endpoint": url,
                        "parameter": parameter,
                        "probe": probe,
                        "evaluated": expected,
                        "observed": f"the expression evaluated to {expected}",
                        "reproduce": reproduce("GET", probe_url(url, parameter, probe)),
                    },
                    exchanges=(baseline[1], exchange),
                    cwe="CWE-94",
                    confidence=0.85,
                    detail=(
                        f"{url} evaluated the expression '{probe}' to {expected} for parameter "
                        f"'{parameter}'"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no expression evaluation observed",
                detail=f"sent {len(probes)} arithmetic probe(s) to {len(targets)} parameter(s)",
            )


# ---------------------------------------------------------------------- command-argument injection
class ArgumentInjectionOracle(WebCheck, Module):
    """``m3.argument-injection`` — argv tokenization differential (ch03#8, CWE-77)."""

    metadata = CheckMetadata(
        id="m3.argument-injection",
        module="M3",
        name="argument-injection",
        version="1.0",
        title="Command-argument injection oracle",
        description=(
            "Appends an unknown long option to a value that is plausibly concatenated into a "
            "command line and reports when the wrapped utility's own argument parser answers "
            "with a diagnostic the baseline did not have. That proves the value was split into "
            "argv without neutralization — CWE-77's general command-injection precondition. "
            "No separator, shell metacharacter or command of our choosing is sent, and nothing "
            "is executed."
        ),
        research_ref="ch03#8",
        framework=("WSTG-INPV-12", "CWE-77"),
        cwe="CWE-77",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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
        assert isinstance(inventory, WebInventory)

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("arg_injection", "param_hints")}
        path_hints = tuple(hint.lower() for hint in payloads.strings("arg_injection", "path_hints"))
        option_template = payloads.string("arg_injection", "option_template", default="--{nonce}")
        diagnostics = tuple(
            marker.lower() for marker in payloads.strings("arg_injection", "diagnostics")
        )
        origin = origin_of(ctx.asset.value)
        candidates = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
            and any(hint in urlsplit(url).path.lower() for hint in path_hints)
        ][: ctx.config.web.max_params_per_check]
        if not candidates:
            yield ctx.clean(
                "no command-wrapper endpoint to probe",
                detail="the crawl found no command-like path with a host/argument parameter",
            )
            return

        findings = 0
        for url, parameter in candidates:
            benign = benign_value(url, parameter, "127.0.0.1")
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue
            marker = nonce()
            option = option_template.replace("{nonce}", marker)
            probe_url_value = f"{benign} {option}"
            fetched = await fetch_page(ctx, probe_url(url, parameter, probe_url_value))
            if fetched is None:
                continue
            page, exchange = fetched
            lowered = page.body.lower()
            if marker.lower() not in lowered:
                continue
            if marker.lower() in baseline[0].body.lower():
                continue
            diagnostic = next((item for item in diagnostics if item in lowered), None)
            if diagnostic is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Command-argument injection in '{parameter}'",
                artifact={
                    "signal": "argument-injection",
                    "family": "argument-injection",
                    "technique": "argv-tokenization",
                    "endpoint": url,
                    "parameter": parameter,
                    "injected_option": option,
                    "diagnostic": diagnostic,
                    "observed": (
                        f"the wrapped utility reported '{diagnostic}' for the injected option"
                    ),
                    "reproduce": reproduce("GET", probe_url(url, parameter, probe_url_value)),
                },
                exchanges=(baseline[1], exchange),
                cwe="CWE-77",
                confidence=0.7,
                detail=(
                    f"{url} passed '{option}' to a command's argument parser as a separate "
                    f"argument through parameter '{parameter}' ({diagnostic})"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no command-argument differential observed",
                detail=f"probed {len(candidates)} command-like parameter(s) with an unknown option",
            )
