"""The "Define" step: target definition, exclusions, attestation, scan options.

This module is the operator-facing contract of F-01-01 (a target definition is domains,
CIDR ranges, URLs, a Git or cloud reference, plus optional exclusions and an optional
authorization attestation), F-08-05 (the attestation is who / what scope / when, and is
copied into the report and the audit log) and part of F-01-09 (active checks need an
explicit opt-in *and* an authorized attestation).

Two deliberate properties:

* **Nothing here touches the network.** Compiling a definition into a scope and deciding
  whether an attestation covers it are pure string/arithmetic operations, so the dry-run
  planner can ask "would this be allowed?" without a single packet (F-01-10).
* **The attestation gate is deny-by-default.** :meth:`TargetDefinition.assert_authorized`
  is the single function the orchestrator calls before a live scan starts; if it returns,
  every declared target is covered by a live, unexpired attestation (F-01-02, docs/spec/07-
  §5).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from arachne.core.errors import AuthorizationError, ConfigurationError
from arachne.core.safety import (
    Scope,
    host_in_domain,
    host_matches_glob,
    is_valid_hostname,
    normalize_host,
    subnet_of,
    url_under_prefix,
)

# The hypothesis mode is a scan option, so its vocabulary lives with the option. It is a plain
# ``StrEnum`` in ``arachne.reasoning.model`` (which imports nothing from ``core``), so this is
# a leaf import and not a cycle — the reasoning *executor* imports this module, never the other
# way round.
from arachne.reasoning.model import HypothesisBudget, HypothesisMode

__all__ = [
    "TARGET_DEFINITION_VERSION",
    "AuthorizationAttestation",
    "DetectionWindow",
    "EngineName",
    "ModuleSelection",
    "PurpleRunOptions",
    "ScanOptions",
    "ScanRequest",
    "TargetDefinition",
    "TargetKind",
    "TargetSelector",
    "load_scan_request",
    "load_scan_request_from_text",
    "parse_scan_request",
]

#: Bumped when the serialized target definition changes shape (docs/spec/07- §4).
TARGET_DEFINITION_VERSION = "1.0"

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: A Git reference in scp-like form, e.g. ``git@github.com:owner/repo.git``.
_SCP_LIKE_GIT = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}:[^:\s]+$")
_GIT_SCHEMES = frozenset({"https", "http", "ssh", "git"})


class TargetKind(StrEnum):
    """The kinds of target a scan can be defined over (F-01-01)."""

    DOMAIN = "domain"
    #: A host pattern: an exact hostname, or ``*.example.com`` for subdomains only.
    DOMAIN_PATTERN = "domain_pattern"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    GIT = "git"
    CLOUD = "cloud"
    #: A **local artifact** (an APK/IPA, a container image layer): a filesystem path the
    #: operator authorized for offline analysis (S29, REQ-DEPTH-005). It is a target kind
    #: precisely so it inherits the same deny-by-default scope gate as every other input:
    #: nothing is read unless the target definition named it *and* the attestation covers it.
    ARTIFACT = "artifact"


class EngineName(StrEnum):
    """Analysis engine selected for a scan (F-03-01). Consumed by the Analyzer (S9)."""

    HEURISTIC = "heuristic"
    AI = "ai"
    HYBRID = "hybrid"


# --------------------------------------------------------------------------- normalizers
# Each returns the canonical form of a value or raises ValueError. They are the only place
# that knows how a kind is spelled, so scope compilation, attestation matching and
# serialization cannot drift apart.


def _normalize_domain(value: str) -> str:
    if not is_valid_hostname(value):
        msg = f"{value!r} is not a valid domain name"
        raise ValueError(msg)
    return normalize_host(value)


def _normalize_domain_pattern(value: str) -> str:
    candidate = normalize_host(value)
    if candidate.startswith("*."):
        if not is_valid_hostname(candidate[2:]):
            msg = f"{value!r} is not a valid domain pattern"
            raise ValueError(msg)
        return candidate
    if not is_valid_hostname(candidate):
        msg = f"{value!r} is not a valid host pattern"
        raise ValueError(msg)
    return candidate


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:
        msg = f"{value!r} is not a valid IP address"
        raise ValueError(msg) from exc


def _normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        msg = f"{value!r} is not a valid CIDR network"
        raise ValueError(msg) from exc
    if network.prefixlen == 0:
        # A default route as a scan target means "everything on the internet".
        msg = f"refusing {value!r}: a default route is never a scan target"
        raise ValueError(msg)
    if network.is_unspecified:
        msg = f"refusing {value!r}: the unspecified address is never a scan target"
        raise ValueError(msg)
    return str(network)


def _normalize_url(value: str) -> str:
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        msg = f"{value!r} is not an http(s) URL"
        raise ValueError(msg)
    host = normalize_host(parts.hostname or "")
    if not host:
        msg = f"{value!r} has no host"
        raise ValueError(msg)
    if parts.username or parts.password:
        # Credentials embedded in a target URL would be stored and logged as target data.
        msg = "refusing a target URL with embedded credentials; supply them via config"
        raise ValueError(msg)
    try:
        port = parts.port
    except ValueError as exc:
        msg = f"{value!r} has an invalid port"
        raise ValueError(msg) from exc
    default_port = 443 if scheme == "https" else 80
    authority = host if port in (None, default_port) else f"{host}:{port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{authority}{path}{query}"


def _normalize_git(value: str) -> str:
    candidate = value.strip()
    if _SCP_LIKE_GIT.match(candidate):
        return candidate
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in _GIT_SCHEMES or not parts.hostname:
        msg = f"{value!r} is not a recognised Git reference"
        raise ValueError(msg)
    host = normalize_host(parts.hostname)
    path = parts.path or "/"
    return f"{parts.scheme.lower()}://{host}{path}"


def _cloud_parts(value: str) -> tuple[str, str] | None:
    """Split ``provider:reference``; ``None`` when the shape does not match."""
    provider, separator, reference = value.strip().partition(":")
    if not separator:
        return None
    provider = provider.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", provider):
        return None
    if not reference or any(character.isspace() for character in reference):
        return None
    return provider, reference


def _normalize_cloud(value: str) -> str:
    parts = _cloud_parts(value)
    if parts is None:
        msg = f"{value!r} is not a 'provider:reference' cloud target"
        raise ValueError(msg)
    return f"{parts[0]}:{parts[1]}"


def _normalize_artifact(value: str) -> str:
    """Canonical form of a local artifact path: absolute, expanded, lexically normalised.

    Deliberately *lexical*: the path need not exist yet (an operator may write the target
    definition before staging the file), and resolving symlinks here would make the value
    depend on the machine that parsed it. The check that reads the file refuses a missing or
    non-file path, and the scope gate compares normalised paths, so both ends agree.
    """
    candidate = os.path.normpath(str(Path(value.strip()).expanduser()))
    if not candidate.startswith(os.sep):
        msg = f"{value!r} is not an absolute path (an artifact target must be absolute)"
        raise ValueError(msg)
    if "\x00" in candidate:
        msg = "an artifact path must not contain a NUL byte"
        raise ValueError(msg)
    return candidate


_NORMALIZERS: dict[TargetKind, Any] = {
    TargetKind.DOMAIN: _normalize_domain,
    TargetKind.DOMAIN_PATTERN: _normalize_domain_pattern,
    TargetKind.URL: _normalize_url,
    TargetKind.IP: _normalize_ip,
    TargetKind.CIDR: _normalize_cidr,
    TargetKind.GIT: _normalize_git,
    TargetKind.CLOUD: _normalize_cloud,
    TargetKind.ARTIFACT: _normalize_artifact,
}


def _url_prefix_of(value: str) -> str:
    """The scope prefix a URL target implies: scheme, authority and path — no query.

    A query string is a property of one request, not of a scope boundary, and the scope
    matcher compares paths (`url_under_prefix`), so keeping the query would make the
    prefix unmatchable.
    """
    parts = urlsplit(value)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


class TargetSelector(BaseModel):
    """One declared target, validated and normalized on construction."""

    model_config = _MODEL_CONFIG

    kind: TargetKind
    value: str = Field(min_length=1, max_length=2048)
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _normalize(self) -> Self:
        normalized = _NORMALIZERS[self.kind](self.value)
        if normalized != self.value:
            object.__setattr__(self, "value", normalized)
        return self

    @property
    def host(self) -> str | None:
        """The host this selector refers to, when it has one."""
        if self.kind is TargetKind.URL:
            return normalize_host(urlsplit(self.value).hostname or "") or None
        if self.kind is TargetKind.GIT:
            parts = urlsplit(self.value)
            if parts.hostname:
                return normalize_host(parts.hostname)
            return self.value.split("@", 1)[-1].split(":", 1)[0].lower() or None
        if self.kind in (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN, TargetKind.IP):
            return self.value
        return None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind.value, "value": self.value}
        if self.note:
            payload["note"] = self.note
        return payload


# --------------------------------------------------------------------------- attestation


def _classify_attested_entry(entry: str) -> tuple[TargetKind, str]:
    """Infer the kind of an ``allowed_targets`` entry from its shape.

    An attestation is written by a human, so its scope list is free-form text in the same
    vocabulary as targets (``example.com``, ``*.example.com``, ``192.0.2.0/24``,
    ``https://example.com/api/``, ``aws:123456789012``). Inferring the kind keeps the
    fixture readable while still giving the coverage check a precise comparison to make.
    """
    candidate = entry.strip()
    if not candidate:
        msg = "an allowed_targets entry is empty"
        raise ValueError(msg)
    if "://" in candidate:
        scheme = urlsplit(candidate).scheme.lower()
        if scheme in {"http", "https"}:
            return (TargetKind.URL, _normalize_url(candidate))
        if scheme in _GIT_SCHEMES:
            return (TargetKind.GIT, _normalize_git(candidate))
        msg = f"{candidate!r}: unsupported scheme in an attestation entry"
        raise ValueError(msg)
    if _SCP_LIKE_GIT.match(candidate):
        return (TargetKind.GIT, candidate)
    if candidate.startswith(("/", "~")):
        # A path, not a network: an artifact grant. Checked before the CIDR attempt so
        # ``/srv/builds`` cannot be mistaken for a range.
        return (TargetKind.ARTIFACT, _normalize_artifact(candidate))
    if "/" in candidate:
        try:
            return (TargetKind.CIDR, _normalize_cidr(candidate))
        except ValueError:
            pass
    if _cloud_parts(candidate) is not None:
        return (TargetKind.CLOUD, _normalize_cloud(candidate))
    try:
        return (TargetKind.IP, _normalize_ip(candidate))
    except ValueError:
        pass
    if candidate.startswith("*."):
        return (TargetKind.DOMAIN_PATTERN, _normalize_domain_pattern(candidate))
    return (TargetKind.DOMAIN, _normalize_domain(candidate))


class DetectionWindow(BaseModel):
    """The coordinated purple-team time window agreed with the defender (S24, REQ-VALID-001).

    A detection test aims to be *seen*, so when it runs matters as much as what it does:
    the defender must know to watch, and the test must be bounded to the interval both
    sides agreed. ``starts_at``/``ends_at`` are that interval; ``coordinator`` names who
    agreed it, ``defender`` the side watching (contact detail, never a secret).

    Two structural properties make the class meaningfully different from a note:

    * **An attestation carrying a window must sit inside its own authorization** — the
      window may not start before the attestation was signed nor end after it expires
      (validated on :class:`AuthorizationAttestation`), so a purple run can never outlive
      the authority it rests on.
    * **Purple-team mode is refused without one** (:meth:`TargetDefinition.authorization_errors`
      with ``purple=True``): there is no "untimed purple team", because an untimed
      detection test is an attack.
    """

    model_config = _MODEL_CONFIG

    starts_at: datetime
    ends_at: datetime
    coordinator: str = Field(min_length=3, max_length=256)
    defender: str | None = Field(default=None, max_length=256)
    reference: str | None = Field(default=None, max_length=256)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "detection-window timestamps must include a timezone (RFC 3339)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_span(self) -> Self:
        if self.ends_at <= self.starts_at:
            msg = "detection window ends_at must be after starts_at"
            raise ValueError(msg)
        return self

    def contains(self, now: datetime) -> bool:
        """True when ``now`` is inside the window (inclusive of both ends)."""
        moment = now.astimezone(UTC)
        return self.starts_at <= moment <= self.ends_at

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (what ``targets.auth_attestation`` and reports carry)."""
        payload: dict[str, Any] = {
            "starts_at": self.starts_at.isoformat(),
            "ends_at": self.ends_at.isoformat(),
            "coordinator": self.coordinator,
        }
        if self.defender:
            payload["defender"] = self.defender
        if self.reference:
            payload["reference"] = self.reference
        if self.notes:
            payload["notes"] = self.notes
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        """Rebuild from the stored form; the single parse path for every reader."""
        return cls.model_validate(dict(payload))


class AuthorizationAttestation(BaseModel):
    """Who authorized what scope, and when (F-08-05, F-01-09).

    ``allowed_targets`` is the attested scope. Coverage is checked per declared target
    (see :meth:`covers`), so an attestation cannot be "for example.com" while the scan
    quietly includes something else.

    ``detection_window`` (S24, REQ-VALID-001) turns the attestation into the
    *detection-window* class: the same grant, additionally bounded to a coordinated
    purple-team interval agreed with the defender. It is optional, so every pre-S24
    attestation keeps working byte-for-byte; purple-team mode simply refuses to run
    without one.
    """

    model_config = _MODEL_CONFIG

    attested_by: str = Field(min_length=3, max_length=256)
    attested_at: datetime
    scope_statement: str = Field(min_length=10, max_length=4000)
    allowed_targets: tuple[str, ...] = Field(min_length=1)
    authorization_ref: str | None = Field(default=None, max_length=256)
    contact: str | None = Field(default=None, max_length=256)
    active_checks_authorized: bool = False
    #: **Off by default** (S15, REQ-PROOF-003). True when the authorization covers L3/L4
    #: proof: one-shot command execution and minimal *reversible* state changes on the
    #: attested scope. A live scan with L3/L4 checks in its plan is refused without it,
    #: and the refusal is audited as ``proof.rejected``.
    state_changes_authorized: bool = False
    #: The coordinated purple-team interval (S24, REQ-VALID-001). ``None`` (the default)
    #: means this attestation authorizes no detection test at all: a scan asking for
    #: purple-team mode is refused and the refusal is audited.
    detection_window: DetectionWindow | None = None
    expires_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("attested_at", "expires_at")
    @classmethod
    def _require_tz(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "attestation timestamps must include a timezone (RFC 3339)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_window(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.attested_at:
            msg = "expires_at must be after attested_at"
            raise ValueError(msg)
        if self.detection_window is not None:
            # The purple window must sit inside the authorization that carries it: a test
            # may not be scheduled before the grant was signed or past its expiry.
            if self.detection_window.starts_at < self.attested_at:
                msg = "detection_window.starts_at must not precede attested_at"
                raise ValueError(msg)
            if self.expires_at is not None and self.detection_window.ends_at > self.expires_at:
                msg = "detection_window.ends_at must not be after the attestation's expires_at"
                raise ValueError(msg)
        for entry in self.allowed_targets:
            _classify_attested_entry(entry)  # raises ValueError on a malformed entry
        return self

    # ------------------------------------------------------------------ coverage
    def is_future_dated(self, now: datetime) -> bool:
        """True when the attestation claims to have been signed in the future."""
        return self.attested_at > now

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def covers(self, selector: TargetSelector) -> bool:
        """True when some attested entry covers ``selector``.

        Conservative by construction: it returns True only for the shapes it explicitly
        understands, so an unrecognised combination fails closed (the scan is refused)
        rather than open.

        Since S30 this delegates to :func:`entry_covers_selector`, so a *second* grant
        cross-checked against the same targets — the fuzzing attestation — is judged by
        literally the same call rather than by a copy of the rule.
        """
        return any(entry_covers_selector(entry, selector) for entry in self.allowed_targets)

    def uncovered(self, selectors: tuple[TargetSelector, ...]) -> tuple[TargetSelector, ...]:
        return tuple(selector for selector in selectors if not self.covers(selector))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (what ``targets.auth_attestation`` and reports carry)."""
        payload: dict[str, Any] = {
            "attested_by": self.attested_by,
            "attested_at": self.attested_at.isoformat(),
            "scope_statement": self.scope_statement,
            "allowed_targets": list(self.allowed_targets),
            "active_checks_authorized": self.active_checks_authorized,
            "state_changes_authorized": self.state_changes_authorized,
        }
        if self.authorization_ref:
            payload["authorization_ref"] = self.authorization_ref
        if self.contact:
            payload["contact"] = self.contact
        if self.detection_window is not None:
            payload["detection_window"] = self.detection_window.to_dict()
        if self.expires_at:
            payload["expires_at"] = self.expires_at.isoformat()
        if self.notes:
            payload["notes"] = self.notes
        return payload

    def summary(self) -> dict[str, Any]:
        """The short form used in plans, reports and audit metadata (F-08-05)."""
        return {
            "attested_by": self.attested_by,
            "attested_at": self.attested_at.isoformat(),
            "authorization_ref": self.authorization_ref,
            "active_checks_authorized": self.active_checks_authorized,
            "state_changes_authorized": self.state_changes_authorized,
            "detection_window": (
                self.detection_window.to_dict() if self.detection_window is not None else None
            ),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "allowed_targets": list(self.allowed_targets),
        }


def entry_covers_selector(entry: str, selector: TargetSelector) -> bool:
    """Does one attested scope entry (as spelled in a grant) cover ``selector``?

    The public form of the coverage rule, for a caller holding a *second* grant that has to be
    cross-checked against the same targets. The fuzzing attestation (S30, area FUZZ) is one:
    it names its own ``allowed_targets``, and "does this fuzzing grant cover every target the
    definition declares" must be answered by the same rule the scan attestation uses, or the
    two could disagree about the same estate. A malformed entry raises ``ValueError`` — the
    model validator refuses one at construction, so reaching that here is a programming error
    rather than bad input.
    """
    return _entry_covers_selector(*_classify_attested_entry(entry), selector)


def _entry_covers_selector(
    entry_kind: TargetKind, entry_value: str, selector: TargetSelector
) -> bool:
    """Does one attested scope entry cover one declared target?

    An explicit if/elif rather than a ``match``: every branch is written out, and the
    fall-through is a real ``False`` (unrecognised combinations fail closed).
    """
    value = selector.value
    if entry_kind is TargetKind.DOMAIN:
        if selector.kind is TargetKind.DOMAIN:
            return host_in_domain(value, entry_value)
        if selector.kind is TargetKind.DOMAIN_PATTERN:
            base = value[2:] if value.startswith("*.") else value
            return host_in_domain(base, entry_value)
        if selector.kind is TargetKind.URL:
            return host_in_domain(selector.host or "", entry_value)
        return False
    if entry_kind is TargetKind.DOMAIN_PATTERN:
        if selector.kind is TargetKind.DOMAIN_PATTERN:
            base = value[2:] if value.startswith("*.") else value
            return host_matches_glob(value, entry_value) or host_matches_glob(base, entry_value)
        if selector.kind is TargetKind.DOMAIN:
            # A subdomain-only grant never covers a domain target (whose scope includes
            # the apex).
            return host_matches_glob(value, entry_value)
        return False
    if entry_kind is TargetKind.IP:
        return selector.kind is TargetKind.IP and _normalize_ip(entry_value) == value
    if entry_kind is TargetKind.CIDR:
        entry_network = ipaddress.ip_network(entry_value, strict=False)
        if selector.kind is TargetKind.IP:
            return ipaddress.ip_address(value) in entry_network
        if selector.kind is TargetKind.CIDR:
            return subnet_of(ipaddress.ip_network(value, strict=False), entry_network)
        return False
    if entry_kind is TargetKind.URL:
        return _url_entry_covers(entry_value, selector)
    if entry_kind is TargetKind.GIT:
        if selector.kind is not TargetKind.GIT:
            return False
        return value == entry_value or value.rstrip("/") == entry_value.rstrip("/")
    if entry_kind is TargetKind.CLOUD:
        if selector.kind is not TargetKind.CLOUD:
            return False
        if entry_value.endswith("*"):
            return value.startswith(entry_value[:-1])
        return value == entry_value or value.startswith(f"{entry_value}/")
    if entry_kind is TargetKind.ARTIFACT:
        if selector.kind is not TargetKind.ARTIFACT:
            return False
        # An entry naming the artifact itself, or a directory that contains it. The path
        # comparison is on the normalised value, so ``/srv/builds/`` and ``/srv/builds``
        # grant the same directory.
        if value == entry_value:
            return True
        return value.startswith(entry_value.rstrip("/") + "/")
    # Unreachable while every TargetKind is handled above; kept as a fail-closed guard for
    # the day the enum grows a member (a new kind must not be covered by accident).
    return False  # type: ignore[unreachable]


def _url_entry_covers(entry_value: str, selector: TargetSelector) -> bool:
    """A URL entry covers a URL target under the same prefix, and a plain host target."""
    entry_parts = urlsplit(entry_value)
    entry_host = normalize_host(entry_parts.hostname or "")
    if selector.kind is TargetKind.URL:
        selector_host = selector.host or ""
        if selector_host != entry_host:
            return False
        return url_under_prefix(selector.value, entry_value)
    if selector.kind is TargetKind.GIT:
        # An http(s) Git reference is written as a URL, so an attestation entry spelled
        # that way has to cover it; otherwise no Git target on a forge could be attested.
        return selector.value.rstrip("/") == entry_value.rstrip("/")
    if selector.kind in (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN):
        # Only the URL's own host is attested; a domain target would broaden that to
        # every subdomain, so it is not covered.
        return selector.value == entry_host
    if selector.kind is TargetKind.IP:
        return selector.value == entry_host
    return False


# --------------------------------------------------------------------------- scan options


class ModuleSelection(BaseModel):
    """Which modules a scan wants (F-02-09); defaults are the safe passive set."""

    model_config = _MODEL_CONFIG

    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()
    #: Opt-in checks to run by name (S7). A check with ``enabled_by_default=False`` is
    #: inert unless it is named here; this list never *excludes* a default check, it only
    #: adds the ones the operator asked for (``--check m4.default-credentials``).
    checks: tuple[str, ...] = ()
    #: An **exact allowlist** (S21). When non-empty it replaces the module selection: only
    #: these checks are planned and executed and every other catalogue check is withheld with
    #: the ``check-not-allowlisted`` skip code. This is how a hypothesis run executes exactly
    #: the probes reasoning asked for — ``checks`` *adds*, ``only`` *bounds*, and conflating
    #: the two would let one hypothesis quietly run a whole module.
    only: tuple[str, ...] = ()

    @field_validator("enabled", "disabled")
    @classmethod
    def _validate_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            if not re.fullmatch(r"M[1-6]", name):
                msg = f"{name!r} is not a module id (expected M1..M6)"
                raise ValueError(msg)
        return value

    @field_validator("checks", "only")
    @classmethod
    def _validate_check_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for check in value:
            if not re.fullmatch(r"m[1-6]\.[a-z0-9]+(?:-[a-z0-9]+)*", check):
                msg = f"{check!r} is not a check id (expected mN.check-name)"
                raise ValueError(msg)
        return tuple(dict.fromkeys(value))

    def includes(self, module: str) -> bool:
        """True when ``module`` is selected: an empty ``enabled`` list means "all"."""
        if module in self.disabled:
            return False
        return not self.enabled or module in self.enabled

    def allows(self, check_id: str) -> bool:
        """True when ``check_id`` may be planned: the allowlist's rule, else the module's."""
        if self.only:
            return check_id in self.only
        return self.includes(check_id.split(".", 1)[0].upper())


class PurpleRunOptions(BaseModel):
    """The purple-team replay selection for one scan (S24, area VALID, REQ-VALID-001).

    A purple run is a *scan* whose whole purpose is to be seen: it replays a named subset
    of the proof ladder's actions so the defender's controls have something known to
    detect. Three things travel with the request and nowhere else:

    ``campaign``
        the campaign this run belongs to (the trend unit and the report's handle).
    ``actions``
        the exact proof check ids to replay — an *allowlist*, not an addition: the
        pipeline runs precisely these and nothing else (the S21 ``only`` primitive).
        Empty is refused: a purple run with no action would still be admitted, scheduled
        and reported, which is worse than a refusal.
    ``nonce``
        the run's visible tag. Generated at admission when absent, and then carried into
        every emitted payload and matched against every ingested alert, which is what
        makes "did the defender see *this test*" a decidable question (REQ-VALID-003).

    The action list is validated here; whether each id exists, is a proof action and is
    replayable is decided against the shipped technique map at plan time, so a typo is a
    loud refusal rather than a silently empty run.
    """

    model_config = _MODEL_CONFIG

    campaign: str = Field(min_length=1, max_length=64)
    actions: tuple[str, ...] = Field(min_length=1)
    nonce: str | None = None

    @field_validator("campaign")
    @classmethod
    def _validate_campaign(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value):
            msg = f"{value!r} is not a campaign id (lowercase letters, digits, . _ -)"
            raise ValueError(msg)
        return value

    @field_validator("actions")
    @classmethod
    def _validate_actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for check in value:
            if not re.fullmatch(r"m[1-6]\.[a-z0-9]+(?:-[a-z0-9]+)*", check):
                msg = f"{check!r} is not a check id (expected mN.check-name)"
                raise ValueError(msg)
        return tuple(dict.fromkeys(value))

    @field_validator("nonce")
    @classmethod
    def _validate_nonce(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # The proof nonce alphabet is the only one a payload may carry, and reusing it
        # keeps the two visible-by-design tags readable by the same tooling.
        if not re.fullmatch(r"[a-z0-9]{12,64}", value):
            msg = f"{value!r} is not a purple nonce (12-64 lowercase alphanumerics)"
            raise ValueError(msg)
        return value


class ScanOptions(BaseModel):
    """Everything about a scan that is not the target itself (§3 lifecycle, step 1)."""

    model_config = _MODEL_CONFIG

    engine: EngineName = EngineName.HEURISTIC
    modules: ModuleSelection = ModuleSelection()
    #: Explicit opt-in for active checks; the attestation must authorize them too (F-01-09).
    active_checks: bool = False
    notes: str | None = Field(default=None, max_length=2000)
    #: Credential **labels** to authenticate with (S19, REQ-CREDS-001/002/003). Labels only,
    #: never material: the executing node resolves a label against *its own* vault, which is
    #: what keeps credentials out of scan requests, the queue, the control plane and the
    #: report. A label this node does not hold is refused and audited rather than fetched
    #: from elsewhere (``credential.unresolved``).
    credentials: tuple[str, ...] = ()
    #: Agentic reasoning for this scan (S21, area AGENT). ``off`` is the default and means the
    #: pipeline is exactly what it was before S21: no hypothesis step, no extra request, no
    #: extra audit line. Any other value adds the ``hypothesis`` step, which proposes and runs
    #: additional checks through the planner/orchestrator under a per-scan budget.
    hypotheses: HypothesisMode = HypothesisMode.OFF
    #: The operator's explicit approval for out-of-band and state-changing hypotheses
    #: (REQ-AGENT-005). A check id named here may be proposed at L2+; an L3/L4 id additionally
    #: needs the attestation's state-change authorization, exactly as in the main pipeline.
    #: Interactive scans get this from the operator; a scheduled scan must already carry it in
    #: its admitted request, which is what "pre-existing attestation" means.
    proof_approved: tuple[str, ...] = ()
    #: This scan's own hypothesis budget (S21, REQ-AGENT-001). ``None`` takes the deployment
    #: default from ``ARACHNE_HYPOTHESIS_*``. A scan that sets it cannot exceed it: the budget
    #: travels with the journal and is spent one hypothesis at a time.
    hypothesis_budget: HypothesisBudget | None = None
    #: Purple-team detection validation (S24, area VALID, REQ-VALID-001). ``None`` (the
    #: default) is an ordinary scan: no purple gate, no technique tagging, no emitted test
    #: artifacts. Set, the scan replays exactly the named proof actions under the
    #: attestation's detection window, tags every artifact with the run nonce, refuses to
    #: act outside the window (audited) and stops itself when the window closes.
    purple: PurpleRunOptions | None = None

    @model_validator(mode="after")
    def _validate_purple(self) -> Self:
        # A purple run replays *active* proof actions by definition, so the operator's own
        # opt-in must be present too — the attestation alone was never enough (F-01-09).
        if self.purple is not None and not self.active_checks:
            msg = "purple-team mode replays active proof actions and requires active_checks=True"
            raise ValueError(msg)
        return self

    @field_validator("credentials")
    @classmethod
    def _validate_credentials(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for label in value:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}", label):
                msg = f"{label!r} is not a credential label (letters, digits, . _ -)"
                raise ValueError(msg)
        return tuple(dict.fromkeys(value))

    @field_validator("proof_approved")
    @classmethod
    def _validate_approved(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for check in value:
            if not re.fullmatch(r"m[1-6]\.[a-z0-9]+(?:-[a-z0-9]+)*", check):
                msg = f"{check!r} is not a check id (expected mN.check-name)"
                raise ValueError(msg)
        return tuple(dict.fromkeys(value))


class TargetDefinition(BaseModel):
    """The persisted, authorized definition of what a scan may touch (F-01-01)."""

    model_config = _MODEL_CONFIG

    version: str = TARGET_DEFINITION_VERSION
    name: str = Field(min_length=1, max_length=255)
    targets: tuple[TargetSelector, ...] = Field(min_length=1)
    exclusions: tuple[TargetSelector, ...] = ()
    attestation: AuthorizationAttestation | None = None

    # ------------------------------------------------------------------ scope
    def compile_scope(self) -> Scope:
        """Compile this definition into the ``Scope`` the HTTP client enforces.

        Mapping: ``domain`` → domain suffix; ``domain_pattern`` → host/glob;
        ``ip`` → host; ``cidr`` → network; ``url`` → URL prefix; ``git`` and ``cloud`` →
        a reference. A Git selector *also* puts its own host in scope, because a Git check
        fetches from exactly that host; a cloud reference names an account or bucket, so
        any host a check needs to reach must be declared separately. Exclusions feed the
        matching exclusion dimensions and always win.
        """
        allowed_hosts: list[str] = []
        allowed_domains: list[str] = []
        allowed_networks: list[str] = []
        url_prefixes: list[str] = []
        allowed_refs: list[str] = []
        allowed_artifacts: list[str] = []
        excluded_hosts: list[str] = []
        excluded_domains: list[str] = []
        excluded_networks: list[str] = []
        excluded_url_prefixes: list[str] = []
        excluded_refs: list[str] = []
        excluded_artifacts: list[str] = []

        for selector in self.targets:
            if selector.kind is TargetKind.DOMAIN:
                allowed_domains.append(selector.value)
            elif selector.kind in (TargetKind.DOMAIN_PATTERN, TargetKind.IP):
                allowed_hosts.append(selector.value)
            elif selector.kind is TargetKind.CIDR:
                allowed_networks.append(selector.value)
            elif selector.kind is TargetKind.URL:
                url_prefixes.append(_url_prefix_of(selector.value))
            elif selector.kind is TargetKind.GIT:
                allowed_refs.append(selector.value)
                if selector.host is not None:
                    allowed_hosts.append(selector.host)
            elif selector.kind is TargetKind.CLOUD:
                allowed_refs.append(selector.value)
            elif selector.kind is TargetKind.ARTIFACT:
                allowed_artifacts.append(selector.value)

        for selector in self.exclusions:
            if selector.kind is TargetKind.DOMAIN:
                excluded_domains.append(selector.value)
            elif selector.kind in (TargetKind.DOMAIN_PATTERN, TargetKind.IP):
                excluded_hosts.append(selector.value)
            elif selector.kind is TargetKind.CIDR:
                excluded_networks.append(selector.value)
            elif selector.kind is TargetKind.URL:
                excluded_url_prefixes.append(_url_prefix_of(selector.value))
            elif selector.kind in (TargetKind.GIT, TargetKind.CLOUD):
                excluded_refs.append(selector.value)
                if selector.kind is TargetKind.GIT and selector.host is not None:
                    excluded_hosts.append(selector.host)
            elif selector.kind is TargetKind.ARTIFACT:
                excluded_artifacts.append(selector.value)

        return Scope(
            allowed_hosts=tuple(allowed_hosts),
            allowed_domains=tuple(allowed_domains),
            allowed_networks=tuple(allowed_networks),
            url_prefixes=tuple(url_prefixes),
            allowed_refs=tuple(allowed_refs),
            allowed_artifacts=tuple(allowed_artifacts),
            excluded_hosts=tuple(excluded_hosts),
            excluded_domains=tuple(excluded_domains),
            excluded_networks=tuple(excluded_networks),
            excluded_url_prefixes=tuple(excluded_url_prefixes),
            excluded_refs=tuple(excluded_refs),
            excluded_artifacts=tuple(excluded_artifacts),
        )

    # ------------------------------------------------------------------ authorization
    def authorization_errors(
        self,
        *,
        active_checks: bool = False,
        purple: bool = False,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        """Every reason a live scan would be refused; empty when it is authorized.

        Exposed separately from :meth:`assert_authorized` so the dry-run can *report* the
        reasons (and refuse anyway) instead of raising at the first one.
        """
        moment = (now or datetime.now(UTC)).astimezone(UTC)
        attestation = self.attestation
        if attestation is None:
            return ("no authorization attestation is attached to this target definition",)
        errors: list[str] = []
        if attestation.is_future_dated(moment):
            errors.append(
                f"attestation is dated in the future ({attestation.attested_at.isoformat()})"
            )
        if attestation.is_expired(moment) and attestation.expires_at is not None:
            errors.append(f"attestation expired at {attestation.expires_at.isoformat()}")
        uncovered = attestation.uncovered(self.targets)
        if uncovered:
            listed = ", ".join(f"{item.kind.value}:{item.value}" for item in uncovered)
            errors.append(f"attestation does not cover: {listed}")
        if active_checks and not attestation.active_checks_authorized:
            errors.append(
                "active checks were requested but the attestation does not authorize them"
            )
        if purple:
            # REQ-VALID-001: the detection-window attestation class is what authorizes a
            # purple-team replay. Without it there is no purple mode at all — an untimed
            # detection test is an attack, and ARACHNE does not run those.
            if attestation.detection_window is None:
                errors.append(
                    "purple-team mode requires a detection-window attestation "
                    "(attestation.detection_window), which this target definition does not carry"
                )
            if not attestation.active_checks_authorized:
                errors.append(
                    "purple-team mode replays active proof actions but the attestation does "
                    "not authorize active checks"
                )
        return tuple(errors)

    def assert_authorized(
        self,
        *,
        active_checks: bool = False,
        purple: bool = False,
        now: datetime | None = None,
    ) -> AuthorizationAttestation:
        """Refuse the scan unless a complete attestation covers every declared target.

        This is the gate the orchestrator calls before a live scan; F-08-05 additionally
        requires the attestation to be recorded in the report and the audit log, which the
        caller does with the returned object. ``purple`` (S24) additionally demands the
        detection-window class (REQ-VALID-001).
        """
        errors = self.authorization_errors(active_checks=active_checks, purple=purple, now=now)
        if errors:
            raise AuthorizationError(
                "scan not authorized: " + "; ".join(errors),
                reason="; ".join(errors),
            )
        assert self.attestation is not None  # guaranteed by authorization_errors
        return self.attestation

    def is_live_ready(
        self,
        *,
        active_checks: bool = False,
        purple: bool = False,
        now: datetime | None = None,
    ) -> bool:
        return not self.authorization_errors(active_checks=active_checks, purple=purple, now=now)

    # ------------------------------------------------------------------ serialization
    def scope_dict(self) -> dict[str, Any]:
        """The value stored in ``targets.scope_json``."""
        return {
            "version": self.version,
            "targets": [item.to_dict() for item in self.targets],
            "exclusions": [item.to_dict() for item in self.exclusions],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.scope_dict()
        payload["name"] = self.name
        payload["attestation"] = self.attestation.to_dict() if self.attestation else None
        return payload


# --------------------------------------------------------------------------- loading


class ScanRequest(BaseModel):
    """A target definition plus run options — the fixture document (F-01-01, F-07-01).

    YAML shape::

        target:
          name: lab-fixture
          targets:
            - {kind: url, value: "https://example.com/"}
          exclusions:
            - {kind: domain, value: admin.example.com}
          attestation:
            attested_by: "Jane Operator <jane@example.com>"
            attested_at: "2026-10-01T00:00:00Z"
            scope_statement: "Bug bounty program SEC-1234, scope example.com"
            allowed_targets: ["example.com"]
        options:
          engine: heuristic
          active_checks: false
    """

    model_config = _MODEL_CONFIG

    target: TargetDefinition
    options: ScanOptions = ScanOptions()


def parse_scan_request(data: Any, *, source: str = "<memory>") -> ScanRequest:
    """Validate an already-parsed fixture document into a :class:`ScanRequest`."""
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping at the top level, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return ScanRequest.model_validate(data)
    except ValidationError as exc:
        detail = _format_validation(exc)
        raise ConfigurationError(f"{source}: invalid scan request: {detail}") from exc


def load_scan_request_from_text(text: str, *, source: str = "<text>") -> ScanRequest:
    """Parse YAML or JSON text into a :class:`ScanRequest`."""
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only, never yaml.load
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML/JSON: {exc}") from exc
    if data is None:
        msg = f"{source}: document is empty"
        raise ConfigurationError(msg)
    return parse_scan_request(data, source=source)


def load_scan_request(path: str | Path) -> ScanRequest:
    """Load a scan request fixture from a YAML/JSON file (the CLI's ``--target``)."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"target fixture {resolved} does not exist or is not a file"
        raise ConfigurationError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read target fixture {resolved}: {exc}") from exc
    if resolved.suffix.lower() == ".json":
        try:
            return parse_scan_request(json.loads(text), source=str(resolved))
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"{resolved}: not valid JSON: {exc}") from exc
    return load_scan_request_from_text(text, source=str(resolved))


def _format_validation(exc: ValidationError) -> str:
    """One-line-per-error summary of a pydantic failure (no docs URL noise)."""
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)
