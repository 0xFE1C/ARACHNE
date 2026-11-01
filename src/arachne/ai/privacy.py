"""Privacy modes for outbound model calls (F-04-08, F-08-01).

Evidence is redacted at *capture* time (F-08-04), so what this module protects is the second
leak surface: the prompt. Three modes, exactly the spec's table:

``local-only``
    Every provider must be local; an external endpoint is refused before any call is made.
    This is the air-gapped posture, and it is enforced here rather than in each adapter so no
    adapter can forget it.
``redact`` (default)
    Addressable evidence — URLs, hosts, IPs, e-mail addresses, credential shapes — is
    replaced by stable tokens (``[U1]``, ``[H2]``, ``[K3]``) and the reverse mapping is kept
    **locally** for report rendering. The token is stable within a scan, so the model can
    still reason about "the same host" and "a second credential".
``default``
    The evidence is sent as captured (already secret-redacted by the shared client). Only an
    operator who explicitly selects it gets this.

:func:`assert_no_provider_secrets` is the belt-and-braces check behind "prompts never include
configured provider keys": the engine calls it with the deployment's credentials immediately
before a call, and a match is a hard refusal rather than a warning.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from pydantic import SecretStr

from arachne.ai.transport import is_local_endpoint
from arachne.ai.types import PrivacyError
from arachne.core.redaction import SECRET_PATTERNS, redact_text

__all__ = [
    "PrivacyMode",
    "Redactor",
    "TokenMapper",
    "apply_privacy",
    "assert_no_provider_secrets",
    "detokenize",
    "enforce_local_only",
    "trim",
]

#: Order matters: URLs are tokenized before the hosts and IPs they contain, so a URL stays one
#: token instead of three. Every pattern is linear — the text is target-controlled.
_URL_RE: Final = re.compile(r"\bhttps?://[^\s\"'<>)\]},;]+")
_EMAIL_RE: Final = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")
_IPV4_RE: Final = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
#: A bare hostname. The lookarounds keep it off identifiers that merely contain a dot: a check
#: id such as ``m4.env-file-probe`` is our own vocabulary, not an address, and tokenizing it
#: would strip the prompt of the very context that makes the question answerable.
_HOST_RE: Final = re.compile(
    r"(?<![\w.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?![\w\-])",
    re.IGNORECASE,
)

#: Token prefixes per addressable kind ('s ``[H1]``/``[K3]`` spelling).
_TOKEN_PREFIX: Final[dict[str, str]] = {
    "url": "U",
    "host": "H",
    "ip": "I",
    "email": "E",
    "key": "K",
}


class PrivacyMode(StrEnum):
    """The F-04-08 modes. ``redact`` is the default."""

    LOCAL_ONLY = "local-only"
    REDACT = "redact"
    DEFAULT = "default"

    @classmethod
    def parse(cls, value: str | None) -> PrivacyMode:
        """Parse an operator's spelling; an unknown value is a configuration error."""
        if not value:
            return cls.REDACT
        normalized = value.strip().lower().replace("_", "-")
        for mode in cls:
            if mode.value == normalized:
                return mode
        msg = f"unknown privacy mode {value!r}; expected local-only, redact or default"
        raise PrivacyError(msg)


@dataclass
class TokenMapper:
    """Assigns stable ``[U1]``/``[H2]``/``[K3]`` tokens and keeps the local reverse mapping.

    The mapping is the reason "redact" is usable at all: a report rendered on the operator's
    machine can put the real host back, while the model only ever saw the token. It is
    deliberately *not* persisted anywhere by this module — a caller that wants it after the
    scan keeps it (``Redactor.mapping``).
    """

    mapping: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)

    def token(self, kind: str, value: str) -> str:
        """The token for ``value`` under ``kind``, minting one on first sight."""
        prefix = _TOKEN_PREFIX.get(kind, "X")
        existing = self._reverse.get(f"{prefix}\x00{value}")
        if existing is not None:
            return existing
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        token = f"[{prefix}{self._counters[prefix]}]"
        self._reverse[f"{prefix}\x00{value}"] = token
        self.mapping[token] = value
        return token

    def to_dict(self) -> dict[str, Any]:
        return {"tokens": dict(self.mapping), "counts": dict(self._counters)}


@dataclass
class Redactor:
    """Applies a privacy mode to prompt text, with one :class:`TokenMapper` per scan."""

    mode: PrivacyMode = PrivacyMode.REDACT
    mapper: TokenMapper = field(default_factory=TokenMapper)

    def transform(self, text: str) -> str:
        """Apply the mode to ``text`` (a no-op under ``default``)."""
        if self.mode is not PrivacyMode.REDACT:
            return text
        return apply_privacy(text, mode=self.mode, mapper=self.mapper)

    @property
    def mapping(self) -> dict[str, str]:
        return self.mapper.mapping

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode.value, **self.mapper.to_dict()}


def apply_privacy(text: str, *, mode: PrivacyMode, mapper: TokenMapper | None = None) -> str:
    """Tokenize the addressable parts of ``text`` for ``mode`` ``redact``.

    Credential *shapes* are tokenized first (``[K1]``), then URLs, e-mail addresses, IPv4
    addresses and bare hostnames. Whatever the tokenizer leaves behind that still looks like a
    secret goes through the capture-time redactor as a second net, so the prompt can never
    contain a value the evidence pipeline would have blanked.
    """
    if mode is not PrivacyMode.REDACT:
        return text
    effective = mapper or TokenMapper()
    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.regex.sub(lambda match: effective.token("key", match.group(0)), out)
    out = _URL_RE.sub(lambda match: effective.token("url", match.group(0)), out)
    out = _EMAIL_RE.sub(lambda match: effective.token("email", match.group(0)), out)
    out = _IPV4_RE.sub(lambda match: effective.token("ip", match.group(0)), out)
    out = _HOST_RE.sub(lambda match: effective.token("host", match.group(0)), out)
    return redact_text(out)


def detokenize(text: str, mapping: Mapping[str, str]) -> str:
    """Put the real values back, locally (for a report rendered on the operator's machine)."""
    out = text
    for token, value in sorted(mapping.items(), key=lambda item: -len(item[0])):
        if token in out:
            out = out.replace(token, value)
    return out


def trim(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters; return ``(text, truncated)``."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    return text[:limit], True


def enforce_local_only(mode: PrivacyMode, base_urls: Iterable[str]) -> None:
    """Refuse every non-local endpoint when the mode is ``local-only`` (F-04-08).

    An empty provider set is refused too: ``local-only`` without a local provider configured
    means the deployment asked for AI with nowhere legal to send it, which must be loud.
    """
    if mode is not PrivacyMode.LOCAL_ONLY:
        return
    external = [url for url in base_urls if not is_local_endpoint(url)]
    if external:
        listed = ", ".join(sorted(set(external)))
        raise PrivacyError(
            f"privacy mode 'local-only' refuses non-local model endpoints: {listed}; "
            "point base_url at localhost/a private address or use privacy mode 'redact'"
        )


def assert_no_provider_secrets(text: str, secrets: Iterable[SecretStr | str | None]) -> None:
    """Refuse a prompt that contains a configured provider credential .

    A match is a hard error, not a redaction: it means a secret reached prompt construction,
    and silently masking it would hide the bug that put it there.
    """
    for secret in secrets:
        if secret is None:
            continue
        value = secret.get_secret_value() if isinstance(secret, SecretStr) else str(secret)
        if len(value) >= 8 and value in text:
            raise PrivacyError(
                "refusing to send a prompt that contains a configured provider credential"
            )
