"""``m6.webshell-yara`` — webshell detection by signature *and* behaviour (research ch06#24).

A webshell is a script an attacker planted in a web root to run commands, move files and
pivot. Two things make detecting it more than a signature match:

* The PHP2SHELL case study (docs/research/06- §Case studies (a)) is explicit that the first
  exploitation of an embargoed RCE *precedes* CVE-specific signatures, and that defenders must
  therefore watch behaviour — oversized single lines, encoded blocks, eval-heavy code,
  anomalous file timestamps — as well as markers. This check runs both: the corpus's signature
  rules (``eval($_POST[...]``, ``c99shell``, ``b374k`` ...) and behaviour heuristics.
* A webshell can be *served* (already in the web root and reachable) or *planted in a clone we
  can see on disk* (a repository with a committed shell, or a web-root directory). It reads
  both: served script content from the shared crawl (plus a bounded set of served shell-path
  candidates) and a local web root when the target declares one.

Nothing here is written, uploaded, renamed or executed: the scan is file-read-only and the
served half is GET-only (docs/spec/05- M6 "Safety").
"""

from __future__ import annotations

import math
import re
import statistics
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.support import exchange_from_page, owns_origin
from arachne.modules.m6.corpus import M6Corpus
from arachne.modules.m6.support import (
    corpus_for,
    finding_cap,
    iter_repo_files,
    local_root,
    m6_candidate,
    read_text,
    safe_fetch,
    skip,
    wordlist,
)

__all__ = ["WebshellYara", "scan_script_text"]

#: Encoded-payload block patterns (research ch06#24: "encoded strings").
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}|(?:[0-9a-fA-F]{2}){40,}")
_CHAR_CONCAT_RE = re.compile(r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}")
_EVAL_CALL_RE = re.compile(
    r"\b(?:eval|assert|create_function)\s*\(|preg_replace\s*\(\s*[^)]*\/[a-z]*e[a-z]*[\s'\"]",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ScriptSignals:
    """What one scanned script's bytes revealed (the artifact the rules read)."""

    signatures: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    heuristics: tuple[str, ...] = ()
    max_line: int = 0
    encoded_ratio: float = 0.0
    eval_count: int = 0
    entropy: float = 0.0
    mtime_skew_s: int | None = None

    @property
    def suspicious(self) -> bool:
        return bool(self.signatures or self.markers or self.heuristics)

    @property
    def critical_signatures(self) -> tuple[str, ...]:
        return tuple(item for item in self.signatures if item.startswith("critical:"))

    def confidence(self, severities: Mapping[str, str]) -> float:
        codes = {item.split(":", 1)[1] for item in self.signatures if ":" in item}
        if any(severities.get(code) == "critical" for code in codes):
            return 0.9
        if codes or self.markers:
            return 0.8
        if len(self.heuristics) >= 2:
            return 0.6
        return 0.45


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_encoded(block: str) -> bool:
    """A base64/hex-ish run is *encoded-looking* when it is long and high-entropy."""
    return len(block) >= 40 and _shannon_entropy(block) >= 3.5


def scan_script_text(
    text: str,
    corpus: M6Corpus,
    *,
    mtime_skew_s: int | None = None,
    future_skew_s: int | None = None,
) -> ScriptSignals:
    """Signature + behaviour signals for one script's text (pure; the unit-test seam)."""
    if not text.strip():
        return ScriptSignals(mtime_skew_s=mtime_skew_s)
    signatures: list[str] = []
    for signature in corpus.webshell_signatures():
        if signature.regex.search(text):
            signatures.append(f"{signature.severity}:{signature.id}")
    lowered = text.lower()
    markers = tuple(marker for marker in corpus.webshell_shell_markers() if marker in lowered)
    heuristics = corpus.webshell_heuristics()
    lines = text.splitlines() or [text]
    max_line = max(len(line) for line in lines)
    encoded_chars = sum(
        len(match.group(0)) for match in _BASE64_RE.finditer(text) if _looks_encoded(match.group(0))
    )
    encoded_chars += sum(len(match.group(0)) for match in _HEX_RE.finditer(text))
    encoded_ratio = encoded_chars / max(1, len(text))
    eval_count = len(_EVAL_CALL_RE.findall(text))
    entropy = _shannon_entropy(text)

    fired: list[str] = []
    if max_line > int(heuristics.get("max_line_length", 800)):
        fired.append("long-line")
    if encoded_ratio >= float(heuristics.get("packed_ratio", 0.4)) and encoded_chars >= int(
        heuristics.get("min_encoded_block", 200)
    ):
        fired.append("encoded-blocks")
    if _CHAR_CONCAT_RE.search(text):
        fired.append("char-concat")
    if entropy >= float(heuristics.get("entropy_threshold", 4.5)) and len(text) >= int(
        heuristics.get("min_encoded_block", 200)
    ):
        fired.append("high-entropy")
    if eval_count >= int(heuristics.get("eval_density", 3)):
        fired.append("eval-heavy")
    if mtime_skew_s is not None and mtime_skew_s > int(heuristics.get("timestamp_skew_s", 604800)):
        fired.append("timestamp-anomaly")
    if future_skew_s is not None and future_skew_s > int(heuristics.get("future_skew_s", 86400)):
        fired.append("future-artifact")
    return ScriptSignals(
        signatures=tuple(signatures),
        markers=markers,
        heuristics=tuple(fired),
        max_line=max_line,
        encoded_ratio=round(encoded_ratio, 3),
        eval_count=eval_count,
        entropy=round(entropy, 3),
        mtime_skew_s=mtime_skew_s,
    )


def _is_script_path(url_or_name: str, corpus: M6Corpus) -> bool:
    path = urlsplit(url_or_name).path.lower()
    return any(path.endswith(ext) for ext in corpus.webshell_script_extensions())


def _looks_like_script_text(text: str, corpus: M6Corpus) -> bool:
    if not text:
        return False
    lowered = text[:4096].lower()
    return any(marker in lowered for marker in corpus.webshell_script_markers())


class WebshellYara(Module):
    """``m6.webshell-yara`` — webshell signature + behaviour scan (ch06#24)."""

    metadata = CheckMetadata(
        id="m6.webshell-yara",
        version="1.0",
        title="Webshell signature and behaviour scan",
        description=(
            "Scans web-visible and locally-hosted script content for webshell classes, using "
            "the corpus signature rules (eval() over request superglobals, c99/r57/b374k "
            "markers, encoded payload execution) together with behaviour heuristics "
            "(oversized single lines, encoded blocks, eval-heavy code, anomalous file "
            "timestamps) so a PHP2SHELL-class artifact is caught before a CVE-specific "
            "signature exists (research ch06#24). File-read-only; served content is GET-only."
        ),
        module="M6",
        name="webshell-yara",
        research_ref="ch06#24",
        cwe="CWE-506",
        target_kinds=(
            TargetKind.URL,
            TargetKind.DOMAIN,
            TargetKind.GIT,
            TargetKind.CLOUD,
        ),
        severity_hint="critical",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=12,
        runs_on_discovered=False,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"url", "domain", "git", "cloud"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        root = local_root(ctx) if ctx.asset.kind in {"git", "cloud"} else None
        if root is not None and root.is_dir():
            async for result in self._scan_local(ctx, corpus, root):
                yield result
            return
        if ctx.asset.kind == "url" or ctx.web is not None:
            async for result in self._scan_served(ctx, corpus):
                yield result
            return
        yield skip(
            ctx,
            "no web root or served surface to scan: declare a web-root directory "
            "(repo:/path) or a URL target (F-01-01)",
        )

    # ------------------------------------------------------------------ local files
    async def _scan_local(
        self, ctx: CheckContext, corpus: M6Corpus, root: Path
    ) -> AsyncIterator[CheckResult]:
        extensions = tuple(sorted({e.lstrip(".") for e in corpus.webshell_script_extensions()}))
        globs = [f"*{ext}" for ext in extensions]
        paths = iter_repo_files(
            root,
            globs,
            max_files=ctx.config.m6.max_repo_files,
            max_bytes=ctx.config.m6.max_file_bytes,
        )
        if not paths:
            yield ctx.clean(
                "no script files under the declared web root",
                detail=f"reviewed {root} for web-script extensions",
            )
            return
        mtimes = _mtimes(paths)
        median = statistics.median(mtimes) if mtimes else None
        now = datetime.now(UTC).timestamp()
        findings = 0
        for path in paths:
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None or not (
                _is_script_path(path.name, corpus) or _looks_like_script_text(text, corpus)
            ):
                continue
            mtime = _mtime(path)
            skew = None if mtime is None or median is None else int(mtime - median)
            future = None if mtime is None else int(mtime - now)
            signals = scan_script_text(text, corpus, mtime_skew_s=skew, future_skew_s=future)
            if not signals.suspicious:
                continue
            findings += 1
            relative = _relative(path, root)
            yield m6_candidate(
                ctx,
                f"Webshell-class script: {relative}",
                artifact={
                    "signal": "webshell",
                    "family": "webshell",
                    "location": relative,
                    "served": False,
                    **_signals_payload(signals),
                },
                cwe="CWE-506",
                confidence=signals.confidence(_severities(corpus)),
                detail=_detail(relative, signals),
                source=relative,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                f"no webshell signature in {len(paths)} script file(s)",
                detail="signature and behaviour heuristics both came back clean",
            )

    # ------------------------------------------------------------------ served content
    async def _scan_served(self, ctx: CheckContext, corpus: M6Corpus) -> AsyncIterator[CheckResult]:
        inventory = ctx.web
        host = urlsplit(ctx.asset.value).hostname if ctx.asset.kind == "url" else None
        findings = 0
        seen: set[str] = set()
        if inventory is not None and (host is None or owns_origin(ctx)):
            for page in inventory.pages.values():
                if host is not None and urlsplit(page.url).hostname != host:
                    continue
                if not (
                    _is_script_path(page.url, corpus) or _looks_like_script_text(page.body, corpus)
                ):
                    continue
                seen.add(page.url)
                signals = scan_script_text(page.body, corpus)
                if not signals.suspicious:
                    continue
                findings += 1
                yield m6_candidate(
                    ctx,
                    f"Webshell-class content served at {page.url}",
                    artifact={
                        "signal": "webshell",
                        "family": "webshell",
                        "location": page.url,
                        "served": True,
                        "http_status": page.status,
                        **_signals_payload(signals),
                    },
                    exchanges=[exchange_from_page(page)],
                    cwe="CWE-506",
                    confidence=signals.confidence(_severities(corpus)),
                    detail=_detail(page.url, signals),
                    source=page.url,
                )
                if findings >= finding_cap(ctx):
                    return
        async for result in self._probe_candidates(ctx, corpus, host, seen, findings):
            findings += 1
            yield result
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                "no served webshell signature on the crawled surface",
                detail="signature and behaviour heuristics both came back clean",
            )

    async def _probe_candidates(
        self,
        ctx: CheckContext,
        corpus: M6Corpus,
        host: str | None,
        seen: set[str],
        already: int,
    ) -> AsyncIterator[CheckResult]:
        if ctx.http is None:
            return
        roots = _origin_roots(ctx)
        if not roots:
            return
        candidates = wordlist(ctx, corpus.webshell_served_wordlist())
        budget = min(ctx.config.m6.max_webshell_probes, len(candidates) * len(roots))
        probed = 0
        for root in roots:
            for name in candidates:
                if probed >= budget:
                    return
                url = urljoin(root, name.lstrip("/"))
                if url in seen:
                    continue
                probed += 1
                exchange = await safe_fetch(ctx, url)
                if exchange is None or exchange.status_code != 200:
                    continue
                seen.add(url)
                signals = scan_script_text(exchange.body, corpus)
                if not signals.suspicious:
                    continue
                yield m6_candidate(
                    ctx,
                    f"Webshell-class content served at {url}",
                    artifact={
                        "signal": "webshell",
                        "family": "webshell",
                        "location": url,
                        "served": True,
                        "http_status": exchange.status_code,
                        **_signals_payload(signals),
                    },
                    exchanges=[exchange],
                    cwe="CWE-506",
                    confidence=signals.confidence(_severities(corpus)),
                    detail=_detail(url, signals),
                    source=url,
                )


# --------------------------------------------------------------------------- helpers
def _severities(corpus: M6Corpus) -> dict[str, str]:
    return {signature.id: signature.severity for signature in corpus.webshell_signatures()}


def _signals_payload(signals: ScriptSignals) -> dict[str, object]:
    codes = tuple(item.split(":", 1)[1] for item in signals.signatures)
    return {
        "signatures": list(codes),
        "markers": list(signals.markers),
        "heuristics": list(signals.heuristics),
        "signature_count": len(codes),
        "heuristic_count": len(signals.heuristics),
        "max_line": signals.max_line,
        "encoded_ratio": signals.encoded_ratio,
        "eval_count": signals.eval_count,
        "entropy": signals.entropy,
        "mtime_skew_s": signals.mtime_skew_s,
    }


def _detail(location: str, signals: ScriptSignals) -> str:
    parts: list[str] = []
    codes = [item.split(":", 1)[1] for item in signals.signatures]
    if codes:
        parts.append("signatures " + ", ".join(codes))
    if signals.markers:
        parts.append("shell markers " + ", ".join(signals.markers))
    if signals.heuristics:
        parts.append("behaviour " + ", ".join(signals.heuristics))
    return f"{location}: " + "; ".join(parts) if parts else location


def _mtimes(paths: Iterable[Path]) -> list[float]:
    out: list[float] = []
    for path in paths:
        try:
            out.append(path.stat().st_mtime)
        except OSError:  # pragma: no cover - unreadable
            continue
    return out


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:  # pragma: no cover - unreadable
        return None


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - a path outside the root
        return path.as_posix()


def _origin_roots(ctx: CheckContext) -> tuple[str, ...]:
    """The origins to probe served shell paths against (declared URL roots, deduped)."""
    roots: list[str] = []
    if ctx.asset.kind == "url":
        roots.append(_origin(ctx.asset.value))
    try:
        records = ctx.step.store.list_assets(ctx.scan_id)
    except Exception:  # pragma: no cover - store hiccup
        records = ()
    for record in records:
        if record.kind == "url":
            roots.append(_origin(record.value))
    out: list[str] = []
    for root in roots:
        if root and root not in out:
            out.append(root)
    return tuple(out)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/"
