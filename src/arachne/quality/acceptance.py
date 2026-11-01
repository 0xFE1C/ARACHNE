"""Risk acceptance: a finding we know about, owned, justified and time-limited (REQ-QUAL-003).

Risk acceptance is not suppression with a nicer name, and the difference is the whole point:

* a **suppression** says "this is not a finding" (a false positive, a hardened control);
* an **acceptance** says "this is a real finding, and we are choosing to live with it until
  *date*, on *owner*'s authority, for *reason*".

Four fields are therefore mandatory — owner, justification and an expiry — and one behaviour is
mandatory too: **an expired acceptance re-opens its finding automatically**. That is enforced
here as a pure decision (:func:`reopen_expired`) which the store applies, so "the clock test" is
a test of this function rather than of a background job that might be off.

The clock is injected everywhere (:func:`active_at`, :func:`reopen_expired`), because a test of
an expiry must not depend on the wall clock, and because an operator reviewing a report asks
"was this accepted *at that time*?" about a past moment.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "AcceptanceSet",
    "ReopenDecision",
    "RiskAcceptance",
    "active_at",
    "reopen_expired",
]

_MODEL = ConfigDict(frozen=True, extra="forbid")

#: A justification shorter than this is a shrug, not a decision.
MIN_JUSTIFICATION_CHARS: Final = 12


class RiskAcceptance(BaseModel):
    """One accepted risk: what it covers, who owns it, why, and until when."""

    model_config = _MODEL

    id: int | None = None
    finding_id: int | None = Field(default=None, ge=1)
    check_id: str | None = Field(default=None, max_length=128)
    asset_pattern: str | None = Field(default=None, max_length=512)
    owner: str = Field(min_length=2, max_length=128)
    justification: str = Field(min_length=MIN_JUSTIFICATION_CHARS, max_length=2000)
    accepted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    #: Required: an acceptance without an end is a permanent hole in the process.
    expires_at: datetime
    revoked_at: datetime | None = None
    #: Recorded when the expiry re-opened the finding, so the history is readable.
    reopened_at: datetime | None = None
    actor: str = Field(default="unknown", min_length=1, max_length=128)

    @field_validator("justification")
    @classmethod
    def _justification_is_a_reason(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if len(cleaned) < MIN_JUSTIFICATION_CHARS:
            msg = (
                f"an acceptance justification must be at least {MIN_JUSTIFICATION_CHARS} "
                "characters"
            )
            raise ValueError(msg)
        return cleaned

    @field_validator("accepted_at", "expires_at", "revoked_at", "reopened_at")
    @classmethod
    def _require_tz(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "acceptance timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def model_post_init(self, __context: Any) -> None:
        if self.expires_at <= self.accepted_at:
            msg = "an acceptance must expire after it was accepted"
            raise ValueError(msg)
        if not (self.finding_id or self.check_id):
            msg = "an acceptance needs a finding_id or a check_id"
            raise ValueError(msg)

    @property
    def active(self) -> bool:
        """``True`` while the acceptance is in force *now* (see :func:`active_at`)."""
        return active_at(self, datetime.now(UTC))

    @property
    def expired(self) -> bool:
        return self.revoked_at is None and self.expires_at <= datetime.now(UTC)

    def covers(self, *, check_id: str, asset: str, finding_id: int | None = None) -> bool:
        """Whether this acceptance covers one observed finding (in force, at *now*)."""
        if not self.active:
            return False
        if self.finding_id is not None:
            return finding_id is not None and self.finding_id == finding_id
        if self.check_id and self.check_id != check_id:
            return False
        if self.asset_pattern:
            from fnmatch import fnmatchcase

            return fnmatchcase(asset, self.asset_pattern)
        return True

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def active_at(acceptance: RiskAcceptance, moment: datetime) -> bool:
    """Whether an acceptance is in force at ``moment`` (the injectable clock)."""
    if acceptance.revoked_at is not None and acceptance.revoked_at <= moment:
        return False
    return acceptance.accepted_at <= moment < acceptance.expires_at


@dataclass(frozen=True, slots=True)
class ReopenDecision:
    """One finding whose acceptance lapsed: what to re-open and why."""

    finding_id: int
    acceptance_id: int | None
    owner: str
    expired_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "acceptance_id": self.acceptance_id,
            "owner": self.owner,
            "expired_at": self.expired_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class AcceptanceSet:
    """The acceptances in force for a scan or a project (read once, applied once)."""

    acceptances: tuple[RiskAcceptance, ...] = ()

    @classmethod
    def of(
        cls, items: Iterable[RiskAcceptance], *, moment: datetime | None = None
    ) -> AcceptanceSet:
        now = moment or datetime.now(UTC)
        return cls(acceptances=tuple(item for item in items if active_at(item, now)))

    def match(
        self, *, check_id: str, asset: str, finding_id: int | None = None
    ) -> RiskAcceptance | None:
        for item in self.acceptances:
            if item.covers(check_id=check_id, asset=asset, finding_id=finding_id):
                return item
        return None

    def covers(self, *, check_id: str, asset: str, finding_id: int | None = None) -> bool:
        return self.match(check_id=check_id, asset=asset, finding_id=finding_id) is not None

    def __len__(self) -> int:
        return len(self.acceptances)

    def __bool__(self) -> bool:
        return bool(self.acceptances)


def reopen_expired(
    acceptances: Sequence[RiskAcceptance], *, moment: datetime
) -> tuple[ReopenDecision, ...]:
    """The findings whose acceptance expired at ``moment`` and must be re-opened.

    Pure and total: it names every lapsed acceptance that has not already been re-opened, so
    the caller (the store) applies exactly this list. An acceptance that was revoked is not
    re-opened — the operator already handled it — and one without a finding id (a rule-wide
    acceptance) produces no decision because there is no single finding to re-open; its
    findings simply stop being covered.
    """
    out: list[ReopenDecision] = []
    for acceptance in acceptances:
        if acceptance.finding_id is None:
            continue
        if acceptance.reopened_at is not None:
            continue
        if acceptance.revoked_at is not None:
            continue
        if acceptance.expires_at > moment:
            continue
        out.append(
            ReopenDecision(
                finding_id=acceptance.finding_id,
                acceptance_id=acceptance.id,
                owner=acceptance.owner,
                expired_at=acceptance.expires_at,
            )
        )
    return tuple(sorted(out, key=lambda item: (item.finding_id, item.acceptance_id or 0)))
