"""Restricted extraction helpers (F-08-06: no ``eval``, regex only).

Checks need to pull *structured* facts out of target-controlled text: secrets, endpoints,
email addresses, sensitive paths, script URLs. Every helper here is a bounded regular
expression or a bounded string scan — never an interpreter — and every one returns at most
``limit`` items, so a hostile body cannot turn a check into a denial-of-service against the
scanner (the linear-time discipline of the redaction patterns applies
here too).

Secrets are matched with the *same* pattern table the redactor uses
(:data:`arachne.core.redaction.SECRET_PATTERNS`), so "what counts as a secret" has one
definition in the codebase. A match is reported as a masked fingerprint plus its SHA-256
(:func:`arachne.modules.context.mask_secret`), never as the raw value: an extracted key is
evidence, and evidence is stored (F-08-04).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from arachne.core.redaction import SECRET_PATTERNS, mask_secret
from arachne.core.results import sha256_of
from arachne.core.safety import normalize_host

__all__ = [
    "DEFAULT_SENSITIVE_PATHS",
    "INTERNAL_HOSTNAME_HINTS",
    "Signals",
    "detect_secrets",
    "extract_emails",
    "extract_endpoints",
    "extract_named_assets",
    "extract_script_sources",
    "extract_urls",
    "internal_hostname_hints",
    "match_sensitive_paths",
    "scan_text",
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}\b")
#: An absolute http(s) URL inside text (bounded segments, no nested quantifiers).
_URL_RE = re.compile(r"https?://[^\s\"'<>()\\]{4,2048}")
#: A quoted path that looks like an application route. The query/hash is allowed by the
#: charset so ``'/search?q='`` is recognised as a route, and then cut in
#: :func:`extract_endpoints` — a parameter template is a route, a parameter *value* is not.
_ENDPOINT_RE = re.compile(r"""(?:"|'|`)((?:/[A-Za-z0-9._~!$&'()*+,;=:@%?#\-]{0,120}){1,8})["'`]""")
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]{0,400}?\ssrc\s*=\s*["']?([^"'\s>]{1,2048})["'\s>]""", re.IGNORECASE
)
#: Values that look like a version identifier, used to name assets found in markup.
_META_URL_RE = re.compile(r"""<meta[^>]{0,300}?content=["']([^"']{1,2048})["']""", re.IGNORECASE)

#: Path fragments that make an archived or harvested URL worth flagging (:
#: "diff results into asset/exposure ledger"). Deliberately short and specific: a long list
#: turns into a false-positive generator, and analysis (not the check) is where judgement
#: belongs (ADR-02).
DEFAULT_SENSITIVE_PATHS: tuple[tuple[str, str], ...] = (
    (".env", "environment file"),
    (".git/", "version-control metadata"),
    (".svn/", "version-control metadata"),
    ("wp-config", "CMS configuration"),
    ("config.php", "application configuration"),
    ("swagger", "API documentation"),
    ("openapi", "API documentation"),
    ("actuator", "management endpoint"),
    ("server-status", "server status page"),
    ("phpinfo", "debug page"),
    ("phpmyadmin", "database console"),
    ("jenkins", "build console"),
    ("kibana", "log console"),
    ("grafana", "dashboard"),
    ("prometheus", "metrics endpoint"),
    ("console", "admin console"),
    ("/admin", "administrative interface"),
    (".sql", "database dump"),
    (".bak", "backup file"),
    (".zip", "archive"),
    (".tar", "archive"),
    (".old", "backup file"),
    ("id_rsa", "private key"),
    (".pem", "key material"),
    (".tfstate", "infrastructure state"),
    ("docker-compose", "deployment descriptor"),
    ("/.aws/", "cloud credentials"),
    ("passwd", "credential file"),
)

#: Subdomain labels that mean "not production" (research ch01 method 21 / ch04 method 21).
INTERNAL_HOSTNAME_HINTS: tuple[str, ...] = (
    "admin",
    "staging",
    "stage",
    "dev",
    "develop",
    "test",
    "testing",
    "qa",
    "uat",
    "demo",
    "sandbox",
    "internal",
    "intranet",
    "vpn",
    "jenkins",
    "gitlab",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "backup",
    "old",
    "legacy",
    "beta",
    "preprod",
    "pre-prod",
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """A detected secret, identified but not disclosed."""

    kind: str
    masked: str
    sha256: str
    source: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {"kind": self.kind, "masked": self.masked, "sha256": self.sha256}
        if self.source:
            payload["source"] = self.source
        return payload


@dataclass(frozen=True, slots=True)
class Signals:
    """Everything :func:`scan_text` found in one body."""

    secrets: tuple[SecretMatch, ...] = ()
    endpoints: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    sensitive_paths: tuple[tuple[str, str], ...] = ()

    @property
    def has_secrets(self) -> bool:
        return bool(self.secrets)


# --------------------------------------------------------------------------- DOM sinks (S29)
#: The client-side sink families of research ch03#3's second half, as *source text* patterns.
#: A DOM-sink finding is a static reading of a bundle: this scanner runs no JavaScript engine
#: (ADR-100.4), so a match here says "this code shape is present", never "this is exploitable"
#: — which is why the check that uses it reports a candidate with modest confidence and names
#: the shape instead of claiming an XSS.
DOM_SINK_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*=")),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("eval", re.compile(r"(?<![\w.$])eval\s*\(")),
    ("Function-constructor", re.compile(r"(?<![\w.$])new\s+Function\s*\(")),
    ("string-timeout", re.compile(r"\bsetTimeout\s*\(\s*[\"'`]")),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("jquery-html", re.compile(r"\$\([^)]{0,80}\)\s*\.\s*(?:html|append)\s*\(")),
    ("location-assignment", re.compile(r"\b(?:location|location\.href|window\.location)\s*=")),
)

#: The attacker-influenceable *sources* that make a sink reachable from user input. A bundle
#: carrying a sink and one of these is the static precondition of DOM XSS; a sink alone is
#: ordinary code.
DOM_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("location.search", re.compile(r"\blocation\s*\.\s*search\b")),
    ("location.hash", re.compile(r"\blocation\s*\.\s*hash\b")),
    ("location.href", re.compile(r"\blocation\s*\.\s*href\b")),
    ("document.URL", re.compile(r"\bdocument\s*\.\s*(?:URL|documentURI|referrer)\b")),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b")),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\b")),
)


@dataclass(frozen=True, slots=True)
class DomSignals:
    """The DOM sink/source shapes one body contains (static; never executed)."""

    sinks: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    #: Sink families seen with a value in a body that also carries an attacker-influenceable
    #: source — the two-part precondition of a DOM-XSS path.
    reachable: tuple[str, ...] = ()

    @property
    def has_source_fed_sink(self) -> bool:
        return bool(self.reachable)


def dom_sink_signals(text: str, *, limit: int = 20) -> DomSignals:
    """The DOM sink families and input sources present in ``text`` (bounded, regex only).

    One linear scan per family — the same discipline the redaction patterns follow, because
    the text is target-controlled. Nothing is executed and nothing is normalised: this is a
    *textual* reading of a bundle, and it is reported as one.
    """
    sinks = tuple(name for name, pattern in DOM_SINK_FAMILIES if pattern.search(text))[:limit]
    sources = tuple(name for name, pattern in DOM_SOURCE_PATTERNS if pattern.search(text))[:limit]
    reachable = (
        tuple(name for name in sinks if _sink_meets_value(text, name))[:limit] if sources else ()
    )
    return DomSignals(sinks=sinks, sources=sources, reachable=reachable)


def _sink_meets_value(text: str, sink: str) -> bool:
    """True when the sink family appears with a non-empty value.

    A cheap proximity test, present for one specific false positive: ``el.innerHTML = ""``
    (the idiomatic way to clear a node, in nearly every bundle) must not read as a
    source-fed sink.
    """
    if sink in {"dangerouslySetInnerHTML", "jquery-html"}:
        return True  # these exist only in a value-passing form
    pattern = dict(DOM_SINK_FAMILIES).get(sink)
    if pattern is None:
        return False
    for match in pattern.finditer(text):
        tail = text[match.end() : match.end() + 80].lstrip()
        if tail[:1] in {"'", '"', "`"} and tail[1:2] in {"'", '"', "`", ";"}:
            continue  # an empty literal: a clear, not a sink use
        if tail[:1] in {";", ")", "}"}:
            continue
        return True
    return False


def detect_secrets(
    text: str, *, source: str | None = None, limit: int = 50
) -> tuple[SecretMatch, ...]:
    """Find credential-shaped strings, reported as masked fingerprints.

    ``SECRET_PATTERNS`` matches on shape; a weak or self-signed example in a documented API
    response is still reported, because deciding whether a key is live is analysis, and
    analysis is deliberately not this layer's job (ADR-02).
    """
    matches: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    for pattern in SECRET_PATTERNS:
        for found in pattern.regex.finditer(text):
            raw = found.group(0)
            digest = sha256_of(raw)
            key = (pattern.name, digest)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                SecretMatch(
                    kind=pattern.name,
                    masked=mask_secret(raw),
                    sha256=digest,
                    source=source,
                )
            )
            if len(matches) >= limit:
                return tuple(matches)
    return tuple(matches)


def extract_emails(text: str, *, limit: int = 100) -> tuple[str, ...]:
    """Distinct email addresses in ``text``, lower-cased."""
    found: dict[str, None] = {}
    for match in _EMAIL_RE.finditer(text):
        address = match.group(0).lower()
        found.setdefault(address, None)
        if len(found) >= limit:
            break
    return tuple(found)


def extract_urls(text: str, *, limit: int = 200) -> tuple[str, ...]:
    """Distinct absolute http(s) URLs in ``text``."""
    found: dict[str, None] = {}
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;)\"'>")
        found.setdefault(url, None)
        if len(found) >= limit:
            break
    return tuple(found)


def extract_endpoints(text: str, *, limit: int = 200) -> tuple[str, ...]:
    """Distinct route-like paths in ``text`` (the LinkFinder idea, without an interpreter).

    A candidate must be an absolute path (a leading ``/``, not ``//`` — a protocol-relative
    URL is a host, not a route), keep at least one more segment, and have its query and
    fragment cut away: ``'/api/v2/search?q='`` is the route ``/api/v2/search``.
    """
    found: dict[str, None] = {}
    for match in _ENDPOINT_RE.finditer(text):
        candidate = match.group(1).split("#", 1)[0].split("?", 1)[0]
        if not candidate.startswith("/") or candidate.startswith("//"):
            continue
        if len(candidate) < 4 or candidate.count("/") < 2:
            continue
        found.setdefault(candidate, None)
        if len(found) >= limit:
            break
    return tuple(found)


def extract_script_sources(markup: str, *, limit: int = 50) -> tuple[str, ...]:
    """``<script src=...>`` targets in an HTML document, in document order."""
    found: dict[str, None] = {}
    for match in _SCRIPT_SRC_RE.finditer(markup):
        source = match.group(1).strip()
        if source:
            found.setdefault(source, None)
        if len(found) >= limit:
            break
    return tuple(found)


def extract_named_assets(markup: str, *, limit: int = 100) -> tuple[str, ...]:
    """``<meta content=...>`` values that are URLs (manifests, oauth metadata, configs)."""
    found: dict[str, None] = {}
    for match in _META_URL_RE.finditer(markup):
        candidate = match.group(1).strip()
        if candidate.startswith(("http://", "https://", "/")):
            found.setdefault(candidate, None)
        if len(found) >= limit:
            break
    return tuple(found)


def match_sensitive_paths(
    url_or_path: str, *, patterns: tuple[tuple[str, str], ...] = DEFAULT_SENSITIVE_PATHS
) -> tuple[tuple[str, str], ...]:
    """Which sensitive-path patterns ``url_or_path`` matches (pattern, description)."""
    lowered = url_or_path.lower()
    return tuple((needle, label) for needle, label in patterns if needle in lowered)


def internal_hostname_hints(host: str) -> tuple[str, ...]:
    """Non-production labels present in ``host`` (``dev.api.example.com`` → ``dev``)."""
    normalized = normalize_host(host)
    labels = normalized.split(".")
    return tuple(label for label in labels if label in INTERNAL_HOSTNAME_HINTS)


def host_of(url: str) -> str | None:
    """The host of ``url``, normalized (``None`` when there is none)."""
    return normalize_host(urlsplit(url).hostname or "") or None


def scan_text(
    text: str,
    *,
    source: str | None = None,
    secrets: bool = True,
    endpoints: bool = True,
    emails: bool = False,
    sensitive_paths: bool = False,
    limit: int = 200,
) -> Signals:
    """Run the enabled extractors over one body and return everything found.

    One entry point (rather than each check calling four helpers) so the cost of scanning
    target-controlled text is visible in one place and bounded by one ``limit``.
    """
    found_urls = extract_urls(text, limit=limit)
    signals = Signals(
        secrets=detect_secrets(text, source=source, limit=limit) if secrets else (),
        endpoints=extract_endpoints(text, limit=limit) if endpoints else (),
        emails=extract_emails(text, limit=limit) if emails else (),
        urls=found_urls,
    )
    if sensitive_paths:
        hits: dict[tuple[str, str], None] = {}
        for url in found_urls:
            for hit in match_sensitive_paths(url):
                hits.setdefault(hit, None)
        signals = Signals(
            secrets=signals.secrets,
            endpoints=signals.endpoints,
            emails=signals.emails,
            urls=signals.urls,
            sensitive_paths=tuple(hits),
        )
    return signals
