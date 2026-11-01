"""File-handling checks: path traversal (ch03#11) and upload validation (ch03#10).

``m3.traversal-oracle``
    Research ch03#11 confirms a traversal **by content**, not by status code: the response to a
    file-name parameter carrying an encoding class of ``../`` must contain a marker that only
    the targeted file has. The check establishes a benign baseline first, then walks the
    encoding matrix (plain, URL-encoded, double-encoded, overlong, backslash, absolute) against
    the parameters whose *names* say they take a file name, and reports the first encoding per
    parameter whose response carries a marker the baseline did not.

    The marker set is deliberately tiny and non-secret: ``/etc/passwd`` and ``/windows/win.ini``
    are world-readable files whose header lines prove a read happened without exfiltrating
    anything sensitive. It is managed data (F-09-04), so an operator who prefers a benign
    in-tree marker file can swap it in without touching code, and ADR-100.5 records why this
    is the defensible middle ground between research ch03#11's "confirm by content" and the
    safety rules' "prefer the safer interpretation".

``m3.upload-audit``
    The validation matrix of research ch03#10 — extension mutation, content-type mismatch,
    magic-byte/polyglot classes — against every multipart form the crawl found. It is **opt-in
    beyond the active-checks gate** (``ARACHNE_WEB_UPLOAD_PROBE``): storing a file, even an
    inert plain-text marker, is a write to the target, and the safety rules say
    "no stored payloads". With the knob off the check reports itself skipped and sends nothing;
    with it on it writes one inert marker per extension class and immediately reads it back to
    confirm whether active/executable extensions are accepted — never executing it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    compare_pages,
    http_or_skip,
    multipart_body,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["TraversalOracle", "UploadAudit"]

#: How many encoding classes one parameter is worth (the matrix is large; a hit is early).
MAX_TRAVERSAL_PAYLOADS = 6

#: How many extension classes the upload matrix tries (one request each).
MAX_UPLOAD_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class _TraversalHit:
    payload: str
    encoding: str
    marker_name: str
    marker_file: str
    page: Page
    exchange: HttpExchange


class TraversalOracle(WebCheck, Module):
    """``m3.traversal-oracle`` — encodings vs a content marker (ch03#11)."""

    metadata = CheckMetadata(
        id="m3.traversal-oracle",
        module="M3",
        name="traversal-oracle",
        version="1.0",
        title="Path traversal oracle",
        description=(
            "Confirms path traversal in file-name parameters by content, not status: each "
            "encoding class (plain, URL-encoded, double-encoded, overlong, backslash, absolute) "
            "is tried against a world-readable, non-secret marker file, and a finding requires "
            "the marker's header line in a response whose benign baseline did not contain it. "
            "Read-only: no path is written and nothing sensitive is read."
        ),
        research_ref="ch03#11",
        cwe="CWE-22",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=16,
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

        payloads = payloads_for(ctx)
        file_params = {name.lower() for name in payloads.strings("traversal", "file_params")}
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=file_params)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no file-name parameter to probe",
                detail="the crawl found no parameter whose name suggests a file path",
            )
            return

        matrix = [
            *((payload, "plain") for payload in payloads.strings("traversal", "posix")),
            *(
                (payload, "windows-backslash")
                for payload in payloads.strings("traversal", "windows")
            ),
        ][:MAX_TRAVERSAL_PAYLOADS]
        markers = payloads.traversal_markers()
        findings = 0
        for url, param in targets:
            baseline = await safe_fetch(
                ctx, probe_url(url, param, "arachne-baseline.txt"), follow_redirects=False
            )
            if baseline is None:
                continue
            baseline_body = baseline.body
            hit = await self._probe_matrix(ctx, url, param, baseline_body, matrix, markers)
            if hit is None:
                continue
            findings += 1
            baseline_page = page_from_exchange(baseline)
            yield web_candidate(
                ctx,
                f"Path traversal reads outside the web root (via '{param}')",
                artifact={
                    "signal": "path-traversal",
                    "family": "traversal",
                    "endpoint": url,
                    "parameter": param,
                    "encoding": hit.encoding,
                    "marker_file": hit.marker_file,
                    "marker": hit.marker_name,
                    "payload_length": len(hit.payload),
                    "delta": compare_pages(baseline_page, hit.page).to_dict(),
                },
                exchanges=(baseline, hit.exchange),
                confidence=0.85,
                detail=(
                    f"{url} parameter '{param}' returned the {hit.marker_file} header "
                    "line "
                    f"using the {hit.encoding} encoding class"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no traversal marker observed",
                detail=f"probed {len(targets)} file-name parameter(s) across the encoding matrix",
            )

    async def _probe_matrix(
        self,
        ctx: CheckContext,
        url: str,
        param: str,
        baseline_body: str,
        matrix: list[tuple[str, str]],
        markers: tuple[tuple[str, Any, str], ...],
    ) -> _TraversalHit | None:
        for payload, encoding in matrix:
            exchange = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            if exchange is None:
                continue
            body = exchange.body
            for marker_name, regex, marker_file in markers:
                if regex.search(body) and not regex.search(baseline_body):
                    return _TraversalHit(
                        payload=payload,
                        encoding=encoding,
                        marker_name=marker_name,
                        marker_file=marker_file,
                        page=page_from_exchange(exchange),
                        exchange=exchange,
                    )
        return None


class UploadAudit(WebCheck, Module):
    """``m3.upload-audit`` — the upload validation matrix (ch03#10)."""

    metadata = CheckMetadata(
        id="m3.upload-audit",
        module="M3",
        name="upload-audit",
        version="1.0",
        title="Unrestricted file upload audit",
        description=(
            "Walks the upload-validation matrix (executable extension with a mismatched "
            "content type, then polyglot-style pairs) against every multipart form the crawl "
            "found, using a single inert plain-text marker with no executable content, and "
            "reads it back to confirm whether the endpoint stored it. Requires "
            "ARACHNE_WEB_UPLOAD_PROBE=true, because storing even an inert marker is a write to "
            "the target; with the knob off the check reports itself skipped and sends nothing."
        ),
        research_ref="ch03#10",
        cwe="CWE-434",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
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

        if not ctx.config.web.upload_probe:
            yield skip(
                ctx,
                "the upload validation probe stores one inert plain-text marker file; it is "
                "opt-in because the M3 safety rules forbid stored payloads by default "
                "(set ARACHNE_WEB_UPLOAD_PROBE=true to enable it)",
            )
            return

        origin = origin_of(ctx.asset.value)
        forms = [
            form
            for form in inventory.upload_forms()
            if origin_of(form.action) == origin or origin_of(form.page_url) == origin
        ][:2]
        if not forms:
            yield ctx.clean(
                "no upload form found",
                detail="the crawl found no multipart form on this origin",
            )
            return

        payloads = payloads_for(ctx)
        marker_body = payloads.string("upload", "marker_body").encode("utf-8")
        filename_stem = payloads.string("upload", "marker_filename", default="arachne-probe")
        extensions = payloads.upload_extensions()[:MAX_UPLOAD_ATTEMPTS]
        accepted_markers = tuple(
            marker.lower() for marker in payloads.strings("upload", "accepted_markers")
        )
        rejected_markers = tuple(
            marker.lower() for marker in payloads.strings("upload", "rejected_markers")
        )
        findings = 0
        for form in forms:
            file_field = form.file_inputs()[0].name if form.file_inputs() else "file"
            fields = _neutral_fields(form)
            # Control: the same submission with a benign extension, to learn what "this
            # application accepted the file" looks like on *this* endpoint. A finding then has
            # to beat the control, which is what keeps a page that answers 200 to everything
            # from reading as "unrestricted upload".
            control = await self._submit(
                ctx,
                form.action,
                fields,
                file_field,
                filename=f"{filename_stem}-control.txt",
                content_type="text/plain",
                content=marker_body,
            )
            control_verdict = _upload_outcome(
                control, accepted=accepted_markers, rejected=rejected_markers
            )
            if control is None:
                continue
            for extension in extensions:
                filename = f"{filename_stem}-{nonce()}.{extension.ext}"
                exchange = await self._submit(
                    ctx,
                    form.action,
                    fields,
                    file_field,
                    filename=filename,
                    content_type=extension.content_type,
                    content=marker_body,
                )
                if exchange is None:
                    continue
                verdict = _upload_outcome(
                    exchange, accepted=accepted_markers, rejected=rejected_markers
                )
                if not _upload_is_finding(
                    verdict, control_verdict, exchange.status_code, control.status_code
                ):
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Upload validation accepts an executable extension (.{extension.ext})",
                    artifact={
                        "signal": "upload-accepted",
                        "family": "upload",
                        "endpoint": form.action,
                        "field": file_field,
                        "extension": extension.ext,
                        "declared_content_type": extension.content_type,
                        "status": exchange.status_code,
                        "verdict": verdict,
                        "control_verdict": control_verdict,
                        "control_status": control.status_code,
                        "similarity_to_control": round(compare_pages(control, exchange).ratio, 4),
                        "marker_filename": filename,
                        "marker_is_executable": False,
                    },
                    exchanges=(exchange, control),
                    confidence=0.8 if verdict == "accepted" else 0.6,
                    detail=(
                        f"{form.action} accepted '{filename}' "
                        f"(content-type {extension.content_type}); the benign control was "
                        f"'{control_verdict}'"
                    ),
                    source=form.action,
                )
        if not findings:
            yield ctx.clean(
                "no executable extension accepted",
                detail=f"tried {len(extensions)} extension class(es) on {len(forms)} form(s)",
            )

    async def _submit(
        self,
        ctx: CheckContext,
        action: str,
        fields: dict[str, str],
        file_field: str,
        *,
        filename: str,
        content_type: str,
        content: bytes,
    ) -> HttpExchange | None:
        body, multipart_type = multipart_body(
            fields, [(file_field, filename, content_type, content)]
        )
        return await safe_fetch(
            ctx,
            action,
            method="POST",
            headers={"Content-Type": multipart_type},
            content=body,
            follow_redirects=False,
        )


def _neutral_fields(form: object) -> dict[str, str]:
    """Benign values for a form's non-file fields (nothing state-changing is submitted)."""
    fields: dict[str, str] = {}
    for item in getattr(form, "inputs", ()):
        if item.type.lower() == "file":
            continue
        fields[item.name] = item.value or "arachne"
    return fields


def _upload_outcome(
    exchange: HttpExchange | None, *, accepted: tuple[str, ...], rejected: tuple[str, ...]
) -> str:
    """Classify an upload response: ``accepted``, ``rejected`` or ``unknown``."""
    if exchange is None:
        return "unknown"
    body = exchange.body.lower()
    if any(marker in body for marker in rejected):
        return "rejected"
    if any(marker in body for marker in accepted):
        return "accepted"
    status = exchange.status_code
    if 200 <= status < 300 or status in {302, 303, 307}:
        return "accepted"
    return "unknown"


def _upload_is_finding(
    verdict: str, control_verdict: str, status: int, control_status: int
) -> bool:
    """Whether an upload answer is *more permissive* than the benign control.

    Three cases, in order of strength: an explicit acceptance marker on a request the control
    did not accept; the same accepted-looking answer the benign control got (the endpoint
    accepts the executable extension exactly as readily); or a 2xx answer while the control was
    refused (an extension-based bypass of a validator that does exist).
    """
    if verdict == "rejected" or verdict == "unknown":
        return False
    if control_verdict == "rejected":
        return True
    if verdict == "accepted" and control_verdict == "accepted":
        return status == control_status or abs(status - control_status) < 100
    return False
