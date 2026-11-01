"""Defender alerts: the SIEM side of the conversation (S24, REQ-VALID-002).

A detection test is only half a test — the other half is what the defender's tooling
reported while it ran. This module is the ingest path for those reports, from three
sources that all land in the same normalized shape:

* **Webhook** — the SIEM posts alerts to ``POST /api/v1/purple/alerts``. The body may be a
  single alert, ``{"alerts": [...]}``, or newline-delimited JSON (the content type
  ARACHNE's own SIEM webhook destination already emits), so an existing forwarder needs no
  rewriting to talk to the ingest.
* **Pull** — the deployment configures ``ARACHNE_PURPLE_ALERTS_URL`` and a campaign run
  fetches the window's alerts through the shared scoped HTTP client.
* **File** — an export, for the air-gapped and the after-the-fact cases.

Field mapping is deliberately tolerant (a SIEM's vocabulary is not ARACHNE's) but not
guessing: an alert with no ATT&CK technique is kept and counted as *unmatched*, never
dropped and never attributed to a technique by keyword. The run ``nonce`` is what makes
"the defender saw *this test*" decidable (REQ-VALID-003), so an alert without a recognized
nonce is reported as unlinked rather than quietly counted as coverage.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arachne.core.errors import ConfigurationError
from arachne.core.proof import ProofRefused, parse_callback_token
from arachne.purple.attack import normalize_technique

__all__ = [
    "DefenderAlert",
    "parse_alert_document",
    "parse_alert_text",
]

#: The keys a SIEM export might use for the timestamp, tried in order.
_TIME_KEYS = ("observed_at", "timestamp", "time", "@timestamp", "event_time", "created_at")
#: The keys that might carry an ATT&CK technique id.
_TECHNIQUE_KEYS = ("technique", "technique_id", "attack_technique", "mitre_technique",
                   "signature_id")
#: The keys that might carry the run nonce (or free text containing it).
_NONCE_KEYS = ("nonce", "detection_nonce", "test_nonce", "message", "description", "title",
               "rule_name", "name")
_ID_KEYS = ("alert_id", "id", "uuid", "event_id")
_TITLE_KEYS = ("title", "name", "rule_name", "signature", "message", "description")

#: A nonce embedded in free text (the payloads ARACHNE emits put it in the clear, so a
#: defender's alert text usually carries it verbatim). Two forms: ARACHNE's own callback
#: token, and a ``nonce=<value>`` pair a forwarder may have written.
_CALLBACK_TOKEN_IN_TEXT = re.compile(r"\barachne-[A-Za-z0-9._-]+-[a-z0-9]{12,64}\b")
_NONCE_PAIR_IN_TEXT = re.compile(r"nonce[=: ]+([a-z0-9]{12,64})\b", re.IGNORECASE)
_BARE_NONCE = re.compile(r"^[a-z0-9]{12,64}$")


@dataclass(frozen=True, slots=True)
class DefenderAlert:
    """One normalized alert from the defender's tooling."""

    alert_id: str
    source: str
    observed_at: datetime
    title: str
    #: The ATT&CK technique the alert names, normalized; ``None`` when the alert names none
    #: (kept and counted as unmatched — the honest outcome).
    technique: str | None = None
    tactic: str | None = None
    #: The run nonce the alert carries, when one can be read from it.
    nonce: str | None = None
    severity: str | None = None
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "alert_id": self.alert_id,
            "source": self.source,
            "observed_at": self.observed_at.isoformat(),
            "title": self.title,
        }
        if self.technique:
            payload["technique"] = self.technique
        if self.tactic:
            payload["tactic"] = self.tactic
        if self.nonce:
            payload["nonce"] = self.nonce
        if self.severity:
            payload["severity"] = self.severity
        return payload


def _first(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _parse_moment(value: Any, *, where: str) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            msg = f"{where}: {value!r} is not an RFC 3339 timestamp"
            raise ConfigurationError(msg) from exc
    else:
        msg = f"{where}: a timestamp is required (one of {', '.join(_TIME_KEYS)})"
        raise ConfigurationError(msg)
    if moment.tzinfo is None:
        msg = f"{where}: timestamps must include a timezone (RFC 3339)"
        raise ConfigurationError(msg)
    return moment.astimezone(UTC)


def _nonce_from_text(text: str) -> str | None:
    """Read the run nonce out of free text, in the three shapes it actually appears in."""
    token_match = _CALLBACK_TOKEN_IN_TEXT.search(text)
    if token_match:
        try:
            return parse_callback_token(token_match.group(0)).nonce
        except ProofRefused:
            # A token-shaped string that is not one: try the other shapes below.
            pass
    pair = _NONCE_PAIR_IN_TEXT.search(text)
    if pair:
        return pair.group(1)
    return None


def _extract_nonce(mapping: Mapping[str, Any]) -> str | None:
    """Read the run nonce out of an alert, in the shapes a forwarder actually produces.

    Two explicit shapes only: a field whose whole value is a nonce, an ARACHNE callback
    token, or a ``nonce=<value>`` pair. A bare 24-character hex string *inside prose* is
    deliberately **not** treated as a nonce — it could equally be a file hash or a session
    id, and attributing the alert to this run on that basis would inflate coverage with
    evidence that does not say what the report claims it says.
    """
    for key in _NONCE_KEYS:
        value = mapping.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = value.strip()
        if _BARE_NONCE.match(candidate):
            return candidate
        found = _nonce_from_text(candidate)
        if found:
            return found
    return None


def normalize_alert(payload: Any, *, source: str, index: int = 0) -> DefenderAlert:
    """Turn one SIEM record into a :class:`DefenderAlert`; refuse only what is unusable.

    ``payload`` is deliberately ``Any``: the record comes from a third party's JSON, so the
    runtime check below is the contract — what a forwarder sends is not what a type says.
    A record with no timestamp cannot be placed in the window, so it is refused (loudly,
    with its index). Everything else — no technique, no nonce, unexpected keys — is kept,
    because an alert ARACHNE cannot attribute is still evidence of *something*.
    """
    if not isinstance(payload, Mapping):
        msg = f"{source} alert[{index}] must be a mapping"
        raise ConfigurationError(msg)
    where = f"{source} alert[{index}]"
    raw_id = _first(payload, _ID_KEYS)
    title = _first(payload, _TITLE_KEYS)
    alert_id = str(raw_id).strip() if raw_id is not None else ""
    if not alert_id:
        # A stable fallback: the SIEM may not give an id, but the alert must be addressable.
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = abs(hash(serialized)) % 10**8
        alert_id = f"{source}-{index}-{digest}"
    technique: str | None = None
    raw_technique = _first(payload, _TECHNIQUE_KEYS)
    if raw_technique is not None:
        try:
            technique = normalize_technique(str(raw_technique))
        except ValueError:
            technique = None
    tactic = _first(payload, ("tactic", "attack_tactic", "mitre_tactic"))
    severity = _first(payload, ("severity", "level", "priority"))
    return DefenderAlert(
        alert_id=alert_id,
        source=source,
        observed_at=_parse_moment(_first(payload, _TIME_KEYS), where=where),
        title=str(title or alert_id).strip(),
        technique=technique,
        tactic=str(tactic).strip().lower().replace("_", "-") if tactic else None,
        nonce=_extract_nonce(payload),
        severity=str(severity).strip().lower() if severity else None,
        raw=dict(payload),
    )


def parse_alert_document(
    document: Any, *, source: str = "webhook"
) -> tuple[DefenderAlert, ...]:
    """Parse a decoded SIEM payload: one alert, or ``{"alerts": [...]}``.

    Returns a tuple (possibly empty). An empty body is refused — a webhook that reports
    nothing is more likely a misconfiguration than a quiet defender, and silently
    ingesting nothing would make an empty coverage report look like a clean result.
    """
    if isinstance(document, Mapping):
        nested = document.get("alerts")
        if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes)):
            return tuple(
                normalize_alert(item, source=source, index=index)
                for index, item in enumerate(nested)
            )
        return (normalize_alert(document, source=source, index=0),)
    if isinstance(document, Sequence) and not isinstance(document, (str, bytes)):
        return tuple(
            normalize_alert(item, source=source, index=index)
            for index, item in enumerate(document)
        )
    msg = f"{source}: an alert payload must be an object or a list of objects"
    raise ConfigurationError(msg)


def parse_alert_text(text: str, *, source: str = "file") -> tuple[DefenderAlert, ...]:
    """Parse an export: JSON, ``{"alerts": [...]}``, or newline-delimited JSON.

    NDJSON is tried when the whole text does not decode as one JSON document, because that
    is the format ARACHNE's own SIEM webhook destination emits (``application/x-ndjson``)
    and therefore the format an operator is most likely to hand back to the ingest.
    """
    stripped = text.strip()
    if not stripped:
        msg = f"{source}: the alert payload is empty"
        raise ConfigurationError(msg)
    try:
        return parse_alert_document(json.loads(stripped), source=source)
    except json.JSONDecodeError:
        pass
    alerts: list[DefenderAlert] = []
    for index, line in enumerate(stripped.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError as exc:
            msg = f"{source}: line {index + 1} is neither JSON nor a valid NDJSON record"
            raise ConfigurationError(msg) from exc
        if isinstance(payload, Mapping):
            alerts.append(normalize_alert(payload, source=source, index=index))
    if not alerts:
        msg = f"{source}: no alerts could be read from the payload"
        raise ConfigurationError(msg)
    return tuple(alerts)
