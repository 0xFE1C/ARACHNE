"""Secret redaction (F-08-01, F-08-04, docs/spec/07- §5).

Redaction is applied **at evidence-capture time**, not at render time, so a later stage
cannot accidentally leak a value it never received. The same functions back the HTTP
client's evidence snapshots, the JSON log formatter, and audit metadata.

Design notes:

* Patterns are deliberately simple and linear (no nested quantifiers) so that a hostile
  target cannot cause catastrophic backtracking in the scanner.
* Both *pattern* redaction (a value that looks like a secret) and *key* redaction (a
  field named ``password``/``token``/...) are applied; the combination is what keeps
  the false-negative rate low in practice.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "ACCOUNTING_KEYS",
    "PLACEHOLDER",
    "POLICY_HEADERS",
    "SECRET_PATTERNS",
    "SENSITIVE_HEADERS",
    "SENSITIVE_KEYS",
    "SecretPattern",
    "contains_secret",
    "is_accounting_key",
    "is_secret_key",
    "mask_secret",
    "masked_secret_findings",
    "redact_headers",
    "redact_mapping",
    "redact_text",
    "redact_text_report",
    "redact_url",
    "redact_value",
]

PLACEHOLDER: Final = "[REDACTED]"

#: Characters of a captured secret kept for identification. Enough to correlate two
#: findings about the same credential, far too few to use it (F-08-04).
_MASK_PREFIX: Final = 4
_MASK_SUFFIX: Final = 2
_MASK_MIN_LENGTH: Final = 12


def mask_secret(value: str) -> str:
    """Return a non-usable fingerprint of a secret: ``AKIA…XY`` plus its length.

    Redaction is a safety net, not a licence: a secret-extraction check must report *that*
    a credential exists (so an operator can rotate it) without ever storing the value. A
    bare high-entropy string has no recognisable form for :func:`redact_text` to catch, so
    masking has to happen where the match is made.
    """
    text = value.strip()
    if len(text) < _MASK_MIN_LENGTH:
        return f"[masked:{len(text)} chars]"
    return f"{text[:_MASK_PREFIX]}…{text[-_MASK_SUFFIX:]} ({len(text)} chars)"


def _placeholder(name: str) -> str:
    return f"[REDACTED:{name}]"


def masked_secret_findings(text: str, *, limit: int = 50) -> tuple[tuple[str, str], ...]:
    """``(detector, masked fingerprint)`` for every credential shape in ``text``.

    The sidecar manifest's input (F-08-04): the *raw* match is masked here and discarded,
    so a caller receives only a non-reversible identifier. This is deliberately separate
    from :func:`redact_text_report`, which returns the detector names because a check must
    never see even a fingerprint it could correlate to a value it did not receive.

    Linear in ``len(text)`` for the same reason every other function here is: the text is
    target-controlled (``tests/unit/test_redaction_perf.py`` guards the family).
    """
    findings: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str) -> bool:
        if not value:
            return True
        masked = mask_secret(value)
        key = (kind, masked)
        if key in seen:
            return True
        seen.add(key)
        findings.append((kind, masked))
        return len(findings) < limit

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            if not _add(pattern.name, match.group(0)):
                return tuple(findings)
    if "PRIVATE KEY-----" in text:
        for match in _PEM_BEGIN_RE.finditer(text):
            # The header alone carries no key material; the length is the useful fact.
            block = text[match.start() : match.start() + 64]
            if not _add("private-key", block):
                return tuple(findings)
    if "=" in text or ":" in text:
        for match in _ASSIGNMENT_RE.finditer(text):
            key, value = match.group(2), match.group(3)
            if _is_redacted_value(value) or not _is_sensitive_key(key):
                continue
            if not _add("sensitive-key-value", value):
                return tuple(findings)
    return tuple(findings)


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A named regular expression whose matches are replaced by a placeholder."""

    name: str
    regex: re.Pattern[str]


#: Ordered pattern list. Each pattern is applied to the text produced by the previous
#: one. Every pattern here must be **linear** in the input length: body text is
#: target-controlled, so a superlinear pattern would be a denial-of-service vector
#: against the scanner itself. Unbounded lazy quantifiers are avoided for that reason
#: (PEM blocks and ``key = value`` assignments are handled by dedicated linear scans
#: below), and the unbounded segments that remain are single character classes that
#: cannot backtrack catastrophically. ``tests/unit/test_redaction_perf.py`` is the guard.
SECRET_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    SecretPattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretPattern("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,100}\b")),
    SecretPattern("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,100}\b")),
    SecretPattern("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,100}\b")),
    # Atomic groups keep the three segments linear: without them, a body full of "eyJ"
    # makes the engine re-scan the same span once per segment attempt.
    SecretPattern(
        "jwt",
        re.compile(
            r"\beyJ(?>[0-9A-Za-z_\-]{4,4096})\.eyJ(?>[0-9A-Za-z_\-]{4,4096})"
            r"\.(?>[0-9A-Za-z_\-]{4,4096})\b"
        ),
    ),
    SecretPattern(
        "credentialed-url",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)"
            r"://[^/\s:@]{1,64}:[^/\s@]{1,128}@",
            re.IGNORECASE,
        ),
    ),
    SecretPattern("bearer-token", re.compile(r"(?i)\bbearer\s+[0-9A-Za-z._\-]{8,4096}")),
    # An ``Authorization: Basic <base64>`` line. Anchored to the header name on purpose: a
    # bare ``basic <word>`` is ordinary English ("Basic plan: 3 seats") and redacting it
    # would be over-redaction of the kind that erases the finding it sits next to (S19
    # review). A credential presented as a header is already blanked wholesale by
    # ``redact_headers``; this covers the same value when it reaches the *text* path.
    SecretPattern(
        "basic-auth",
        re.compile(r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?basic\s+[0-9A-Za-z+/=]{8,4096}"),
    ),
    # An S3 presigned-URL signature reached the text path (a logged URL, an evidence body
    # quoting one). The query key is matched too, so a reader can still see that a
    # presigned URL was present — only the authorising value is gone.
    SecretPattern(
        "presigned-url",
        re.compile(r"(?i)(?<=[?&])x-amz-signature=[0-9a-f]{8,128}"),
    ),
    SecretPattern(
        "aws-secret-access-key",
        re.compile(
            r"(?i)\baws[_-]?secret[_-]?(?:access[_-]?)?key\b\s*[:=]\s*[\"']?([^\s\"',;&#\]}]{6,256})"
        ),
    ),
)

#: PEM private-key blocks: matched by :func:`_redact_pem_blocks`, not by a regex.
_PEM_BEGIN_RE: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]{0,40})?PRIVATE KEY-----"
)
_PEM_END_RE: Final[re.Pattern[str]] = re.compile(r"-----END (?:[A-Z0-9 ]{0,40})?PRIVATE KEY-----")
#: A legitimate PEM block is far smaller than this; the cap bounds the scan.
_MAX_PEM_BYTES: Final = 32 * 1024

#: ``key = value`` / ``"key": "value"`` scanner. Two properties keep it linear on
#: target-controlled text: (a) the key token is *bounded*, and (b) a delimiter must
#: precede it, so the engine does not attempt a 64-character token match at every
#: position inside a long run of word characters. Sensitivity itself is decided in
#: Python by :func:`_is_sensitive_key`, which is what lets it accept JSON, JS and
#: camelCase spellings without a combinatorial alternation.
#:
#: The separator is followed by *horizontal* whitespace only (``[ \t]*``), never ``\s*``.
#: That single-token choice matters: a non-sensitive outer key in an indented block
#: (``service:\n  api_key: …``) must not let its value span the newline and swallow the
#: inner ``api_key:`` — which would leave the inner secret unredacted (S13 review).
#:
#: ``&`` is in the delimiter set because a ``application/x-www-form-urlencoded`` body
#: separates its fields with it: without it, only the *first* field of a form body could
#: ever be redacted, so ``username=alice&password=...`` — the shape every credentialed
#: login submits (S19, REQ-CREDS-002) — kept its secret. ``|``/``?`` are included for the
#: same reason: they are the other separators a form-encoded or query-shaped value uses.
_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?:^|(?<=[\s,;:{(<"'\[=&|?]))(["']?)([A-Za-z0-9_.\-]{1,64})\1\s*[:=][ \t]*"""
    r"""["']?([^\s"',;&#\]}]{6,512})"""
)

#: Block-style YAML/ini: a key alone on its line (``db_password:``) whose value is on the
#: next, indented line. The inline pattern above stops at the newline (so a non-sensitive
#: outer key cannot swallow an inner ``api_key:``), so without this second match a
#: block-style secret would go unredacted — the two patterns together cover both the
#: ``service:\n  api_key: ...`` case (inline, matched from the inner key) and the
#: ``db_password:\n  hunter2`` case (block). Over-redacting is the safe direction here.
#: Groups mirror :data:`_ASSIGNMENT_RE`: ``(quote, key, value)``.
_BLOCK_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?m)^[ \t]*(["']?)([A-Za-z0-9_.\-]{1,64})\1[ \t]*[:=][ \t]*(?:[|>][-+]?[ \t]*)?\r?\n"""
    r"""[ \t]*(?![A-Za-z0-9_.\-]{1,64}[ \t]*:(?![^\s]))["']?([^\s"',;&#\]}]{6,512})"""
)

#: Substrings that make an ``identifier`` a secret-bearing key.
_SENSITIVE_KEY_SUBSTRINGS: Final[tuple[str, ...]] = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "apikey",
    "privatekey",
    "credential",
    "sessionid",
    "accesskey",
    "authkey",
    "clientkey",
    # Azure storage/Service Bus connection strings spell the credential ``AccountKey``;
    # its name carries no other marker, so without this entry ``;AccountKey=<b64>`` is the
    # one common cloud connection-string credential the key rule missed (S13 review).
    "accountkey",
)

#: Headers whose *name* contains a sensitive substring but whose value is a policy flag
#: (``Access-Control-Allow-Credentials: true``). Blanking these would erase the CORS
#: finding itself, so the key-aware rule steps aside for exactly this set (ADR-120.8).
POLICY_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "access_control_allow_credentials",
        "access_control_allow_origin",
        "access_control_allow_methods",
        "access_control_allow_headers",
        "access_control_expose_headers",
        "access_control_max_age",
    }
)

#: Header names whose value is always replaced.
SENSITIVE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-csrf-token",
    }
)

#: Key names whose *numeric* value is accounting metadata, not a credential (S9, F-04-07).
#:
#: ``prompt_tokens`` matches the "token" substring rule, so without this exemption the shared
#: client blanks every provider's usage block and the per-scan cost budget can never be
#: enforced. The exemption is deliberately narrow: it applies only when the value is a number
#: (a bare number cannot be a credential), only to key-based redaction, and only to this fixed
#: list — pattern redaction of the string itself still runs for everything else.
ACCOUNTING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "tokens_used",
        "max_tokens",
        "promptTokenCount".lower(),
        "candidatesTokenCount".lower(),
        "totalTokenCount".lower(),
        "prompt_eval_count",
        "eval_count",
    }
)


def is_accounting_key(key: object) -> bool:
    """True when ``key`` names token accounting rather than a secret (see ``ACCOUNTING_KEYS``)."""
    return _normalize_key(key) in ACCOUNTING_KEYS


#: Mapping keys whose value is always replaced, matched on a normalized key.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "id_token",
        "api_key",
        "apikey",
        "access_key",
        "access_key_id",
        "private_key",
        "authorization",
        "cookie",
        "set_cookie",
        "session",
        "session_id",
        "credential",
        "credentials",
    }
)

#: Query-string parameter names redacted inside URLs (the value, not the name).
_SENSITIVE_QUERY_KEYS: Final[frozenset[str]] = SENSITIVE_KEYS | {
    "key",
    "sig",
    "signature",
    "code",
    "state",
    # An S3 presigned URL (S20, REQ-DATA-002) carries a bearer credential in its query
    # string: the signature authorises the download until it expires, and the credential
    # scope names the key id. A presigned URL therefore has to be redacted like a password
    # wherever one is logged, audited or stored (they are normalized to ``x_amz_*``).
    "x_amz_signature",
    "x_amz_credential",
    "x_amz_security_token",
}

_MAX_DEPTH = 12


def _normalize_key(key: object) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def _is_sensitive_key(identifier: str) -> bool:
    """True when an identifier looks like it names a secret.

    Separators are stripped first, so ``aws_secret_access_key``, ``awsSecretAccessKey``
    and ``AWS-SECRET-ACCESS-KEY`` all collapse onto the same haystack. Substring matching
    (rather than whole-name equality) is deliberate: it is what catches composite names
    such as ``aws_secret_access_key`` and ``X-Auth-Token`` that no fixed list would
    enumerate, and over-redaction is the safe direction (docs/spec/07- §1.5).
    """
    collapsed = re.sub(r"[^a-z0-9]", "", identifier.lower())
    return any(marker in collapsed for marker in _SENSITIVE_KEY_SUBSTRINGS)


def is_secret_key(key: object) -> bool:
    """Public form used by :func:`redact_value` and :func:`redact_headers`."""
    name = str(key)
    return _normalize_key(name) in SENSITIVE_KEYS or _is_sensitive_key(name)


def _is_redacted_value(value: str) -> bool:
    """True when a value is already a redaction placeholder (makes redaction idempotent)."""
    return value.startswith("[REDACTED")


def _redact_pem_blocks(text: str) -> str:
    """Replace PEM private-key blocks (linear scan; a lazy regex would be quadratic)."""
    if "PRIVATE KEY-----" not in text:
        return text

    parts: list[str] = []
    position = 0
    # Once no END marker exists after the cursor, it exists nowhere later either, so the
    # search is not repeated per header (that would make an END-less body quadratic).
    ends_exhausted = False
    while True:
        begin = _PEM_BEGIN_RE.search(text, position)
        if begin is None:
            parts.append(text[position:])
            return "".join(parts)

        parts.append(text[position : begin.start()])
        parts.append(_placeholder("private-key"))

        end = None if ends_exhausted else _PEM_END_RE.search(text, begin.end())
        if end is not None and end.end() - begin.start() <= _MAX_PEM_BYTES:
            position = end.end()
        else:
            if end is None:
                ends_exhausted = True
            # Unterminated block (or an implausibly large one): consume just the header
            # and keep scanning, so the cost stays linear in the input length.
            position = begin.end()


def _redact_assignments(text: str) -> str:
    """Redact ``key: value`` / ``key=value`` pairs whose key names a secret.

    This is what catches ``"aws_secret_access_key": "..."``, ``dbPassword=hunter2`` and
    ``{"token": "abc123"}`` — values that match no secret *pattern* because they are
    ordinary strings.
    """
    redacted, _ = _redact_assignments_with_report(text)
    return redacted


def _looks_like_url(value: str) -> bool:
    """True for an absolute URL or a scheme-relative one (``//host/path``)."""
    return "://" in value or value.startswith("//")


def _redact_pairs(text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    """Redact the value of every sensitive pair ``pattern`` matches; return the count.

    Two jobs, one pass:

    * a pair whose **key** names a secret is replaced wholesale (``password=hunter2``);
    * a pair whose key is innocent but whose **value** is a URL is passed through
      :func:`redact_url`, because the credential is then *inside* the URL
      (``source: https://host/login?password=hunter2``).

    The second case is not hypothetical and not new: the shared JSON log formatter redacts a
    string field with :func:`redact_text`, so a logged ``"url"`` field is exactly this shape.
    The pair match consumes the whole value, which means the scanner would otherwise skip
    the query string entirely — the outer ``key: value`` match hides the inner one (S20
    review, REQ-OPS-004).

    Both :data:`_ASSIGNMENT_RE` and :data:`_BLOCK_ASSIGNMENT_RE` carry their key in group 2
    and their value in group 3, so one implementation serves both; only the value span is
    replaced, leaving any surrounding quotes so JSON stays parseable.
    """
    replaced = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal replaced
        key, value = match.group(2), match.group(3)
        if _is_redacted_value(value):
            return match.group(0)
        whole = match.group(0)
        relative_start = match.start(3) - match.start(0)
        relative_end = match.end(3) - match.start(0)
        if _is_sensitive_key(key):
            replaced += 1
            return f"{whole[:relative_start]}{_placeholder('value')}{whole[relative_end:]}"
        if _looks_like_url(value):
            inner = redact_url(value)
            if inner != value:
                replaced += 1
                return f"{whole[:relative_start]}{inner}{whole[relative_end:]}"
        return whole

    return pattern.sub(_replace, text), replaced


def _redact_assignments_with_report(text: str) -> tuple[str, int]:
    """``_redact_assignments`` plus how many sensitive pairs it replaced."""
    if "=" not in text and ":" not in text:
        return text, 0

    redacted, inline = _redact_pairs(text, _ASSIGNMENT_RE)
    redacted, block = _redact_pairs(redacted, _BLOCK_ASSIGNMENT_RE)
    return redacted, inline + block


#: A ``multipart/form-data`` part header naming its field. Linear (a bounded name token), and
#: the delimiter is required, so it cannot match inside an arbitrary word.
_MULTIPART_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?i)content-disposition:[ \t]*form-data;[ \t]*name="?([A-Za-z0-9_.\-]{1,64})"?"""
)
#: Where a part's headers end and its body begins.
_MULTIPART_HEADERS_END_RE: Final[re.Pattern[str]] = re.compile(r"\r?\n\r?\n")


def _part_body_end(text: str, start: int) -> int:
    """Where the part starting at ``start`` ends (the next MIME boundary, or the text's end)."""
    for marker in ("\r\n--", "\n--"):
        found = text.find(marker, start)
        if found >= 0:
            return found
    return len(text)


def _redact_multipart(text: str) -> tuple[str, int]:
    """Replace the bodies of ``multipart/form-data`` parts whose *field name* is sensitive.

    The last credential carrier the shared redactor could not see (S19 review): a login or
    upload submitted as ``multipart/form-data`` puts the value on its own line after a
    ``Content-Disposition`` header, where neither the ``key=value`` scanner nor the JSON path
    reaches it. Linear in the text: one pass over the part headers, and each part body is
    bounded by the next boundary.

    Only parts whose name looks sensitive are touched — a file part named ``avatar`` is left
    exactly as it was, so an upload finding keeps its evidence.
    """
    if "content-disposition" not in text.lower():
        return text, 0
    parts: list[str] = []
    position = 0
    replaced = 0
    for match in _MULTIPART_NAME_RE.finditer(text):
        if not _is_sensitive_key(match.group(1)):
            continue
        headers_end = _MULTIPART_HEADERS_END_RE.search(text, match.end())
        if headers_end is None:
            continue
        body_start = headers_end.end()
        if body_start <= position:  # already inside a part we replaced
            continue
        body_end = _part_body_end(text, body_start)
        if body_end <= body_start:
            continue
        parts.append(text[position:body_start])
        parts.append(_placeholder("multipart-value"))
        position = body_end
        replaced += 1
    if not replaced:
        return text, 0
    parts.append(text[position:])
    return "".join(parts), replaced


def redact_text(text: str) -> str:
    """Apply every secret detector to ``text``.

    Idempotent: redacting already-redacted text is a no-op (evidence can legitimately be
    redacted more than once on its way through the pipeline).
    """
    redacted, _ = redact_text_report(text)
    return redacted


def redact_text_report(text: str) -> tuple[str, tuple[str, ...]]:
    """Redact ``text`` and report which detectors fired: ``(redacted, kinds)``.

    The second value is how a check learns that a body *contained* credentials without ever
    receiving one: redaction happens at capture time (F-08-04), so a detection check that
    greps a captured body would only ever see placeholders. Reporting the matched kinds
    turns the redactor into the detector — one definition of "what a secret looks like", and
    no path by which a live value reaches a check, a log line, or a report.
    """
    kinds: list[str] = []
    redacted = text
    for pattern in SECRET_PATTERNS:
        if pattern.regex.search(redacted):
            kinds.append(pattern.name)
            redacted = pattern.regex.sub(_placeholder(pattern.name), redacted)
    if _PEM_BEGIN_RE.search(redacted):
        kinds.append("private-key")
        redacted = _redact_pem_blocks(redacted)
    redacted, replaced_pairs = _redact_assignments_with_report(redacted)
    if replaced_pairs:
        kinds.append("sensitive-key-value")
    redacted, replaced_parts = _redact_multipart(redacted)
    if replaced_parts:
        kinds.append("multipart-value")
    return redacted, tuple(kinds)


def contains_secret(text: str) -> bool:
    """Return ``True`` if any secret detector matches ``text``."""
    if any(pattern.regex.search(text) for pattern in SECRET_PATTERNS):
        return True
    if "PRIVATE KEY-----" in text and _PEM_BEGIN_RE.search(text):
        return True
    if "content-disposition" in text.lower() and any(
        _is_sensitive_key(match.group(1)) for match in _MULTIPART_NAME_RE.finditer(text)
    ):
        return True
    if "=" not in text and ":" not in text:
        return False
    for pattern in (_ASSIGNMENT_RE, _BLOCK_ASSIGNMENT_RE):
        for match in pattern.finditer(text):
            key, value = match.group(2), match.group(3)
            if _is_redacted_value(value):
                continue
            if _is_sensitive_key(key):
                return True
            # A URL whose query string carries a secret counts too: the value span hides it
            # from the key rule (see _redact_pairs).
            if _looks_like_url(value) and redact_url(value) != value:
                return True
    return False


def _redact_query(query: str) -> str:
    """Redact values of sensitive query parameters, preserving the rest verbatim."""
    if not query:
        return query
    parts: list[str] = []
    for chunk in query.split("&"):
        name, sep, value = chunk.partition("=")
        if sep and _normalize_key(name) in _SENSITIVE_QUERY_KEYS:
            parts.append(f"{name}={_placeholder('query-param')}")
        elif sep:
            parts.append(f"{name}={redact_text(value)}")
        else:
            parts.append(chunk)
    return "&".join(parts)


def redact_url(url: str) -> str:
    """Redact credentials and sensitive query parameters from a URL."""
    scheme, sep, rest = url.partition("://")
    if not sep:  # relative URL (redirect Location, path-only evidence)
        path, qmark, query = url.partition("?")
        redacted_path = redact_text(path)
        return f"{redacted_path}?{_redact_query(query)}" if qmark else redacted_path

    rest, hash_sep, fragment = rest.partition("#")
    rest, qmark, query = rest.partition("?")
    authority, slash, path = rest.partition("/")

    if "@" in authority:
        userinfo, _, host = authority.rpartition("@")
        user = userinfo.split(":", 1)[0]
        authority = f"{user}:{_placeholder('url-password')}@{host}"

    result = f"{scheme}://{authority}"
    if slash:
        result += f"/{redact_text(path)}"
    if qmark:
        result += f"?{_redact_query(query)}"
    if hash_sep:
        result += f"#{fragment}"
    return result


def redact_value(value: object, *, key: object | None = None, _depth: int = 0) -> object:
    """Recursively redact an arbitrary JSON-ish value.

    A value whose key is sensitive is replaced wholesale; strings are additionally
    scanned with :data:`SECRET_PATTERNS`. The one exception is a *numeric* value under an
    accounting key (:func:`is_accounting_key`): a token count is not a credential, and the
    per-scan cost budget (F-04-07) cannot work without it.
    """
    if key is not None and is_secret_key(key):
        if (
            is_accounting_key(key)
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ):
            return value
        return _placeholder("value")

    if _depth > _MAX_DEPTH:  # defensive: cyclic/deeply nested target JSON
        return PLACEHOLDER

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): redact_value(v, key=k, _depth=_depth + 1) for k, v in value.items()}
    if isinstance(value, (bytes, bytearray)):
        return redact_text(bytes(value).decode("utf-8", errors="replace"))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_value(item, key=key, _depth=_depth + 1) for item in value]
    return value


def redact_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Redact a mapping (headers, JSON object, evidence payload).

    ``Any`` is the honest value type: the input is arbitrary decoded JSON, and the
    contract is "the same shape comes back, with secrets replaced".
    """
    return {str(k): redact_value(v, key=k) for k, v in mapping.items()}


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Redact header values, keeping header names visible for evidence value."""
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        normalized = _normalize_key(name)
        if normalized not in POLICY_HEADERS and (
            normalized in SENSITIVE_HEADERS or is_secret_key(name)
        ):
            redacted[name] = _placeholder("header")
        else:
            redacted[name] = redact_text(value)
    return redacted
