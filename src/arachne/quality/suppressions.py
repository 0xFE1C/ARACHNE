"""Suppression rules: what an operator has decided is not a finding (REQ-QUAL-001/002).

A suppression is a decision, so it carries the four things a decision needs to be reviewed:
**what** it covers (a finding, a rule, or a rule+asset pattern), **why** (a mandatory comment),
**who** decided, and **when** (version and timestamp). The requirements' three properties fall
out of that shape:

* *versioned* — every rule gets the next value from a single monotonic sequence, so a report can
  state "suppressions v7" and two reports can be compared;
* *attributed* — the actor is recorded and audited (`suppression.changed`);
* *commented* — the reason is required (a minimum length, not a placeholder), because a
  suppression without a reason is indistinguishable from hiding a finding.

Matching is deliberately simple and total: a **rule** suppression silences one check id, a
**pattern** suppression silences one or more check ids on assets matching an fnmatch pattern,
and a **finding** suppression silences exactly one finding. Precedence is most-specific first,
which is also the order a reader would expect: a finding rule explains a single decision; a
pattern explains a class.

The module is pure. Applying suppressions — excluding findings from a diff, counting them — is
the diff's job (`arachne.report.diff`), and storing them is the quality store's.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arachne.core.errors import ConfigurationError

__all__ = [
    "Suppression",
    "SuppressionKind",
    "SuppressionSelector",
    "SuppressionSet",
]

_MODEL = ConfigDict(frozen=True, extra="forbid")

SuppressionKind = Literal["finding", "rule", "pattern"]

#: A reason shorter than this is not a reason. Eight characters rules out "fp", "x", "n/a".
MIN_REASON_CHARS: Final = 8


class SuppressionSelector(BaseModel):
    """What a suppression covers. At least one selector must be set."""

    model_config = _MODEL

    check_id: str | None = Field(default=None, max_length=128)
    asset_pattern: str | None = Field(default=None, max_length=512)
    finding_id: int | None = Field(default=None, ge=1)

    @property
    def is_empty(self) -> bool:
        return not self.check_id and not self.asset_pattern and self.finding_id is None


class Suppression(BaseModel):
    """One operator decision to silence a finding, a rule or a rule-on-a-pattern."""

    model_config = _MODEL

    #: ``None`` until the store assigns it.
    id: int | None = None
    #: The global rule version this suppression is part of (monotonic, never reused).
    version: int = Field(default=1, ge=1)
    kind: SuppressionKind = "rule"
    check_id: str | None = Field(default=None, max_length=128)
    asset_pattern: str | None = Field(default=None, max_length=512)
    finding_id: int | None = Field(default=None, ge=1)
    reason: str = Field(min_length=MIN_REASON_CHARS, max_length=2000)
    actor: str = Field(default="unknown", min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    #: A revoked rule stays in the table so a report from before the revocation still reads.
    active: bool = True

    @field_validator("created_at", "expires_at")
    @classmethod
    def _require_tz(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "suppression timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @field_validator("reason")
    @classmethod
    def _reason_is_not_a_placeholder(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if len(cleaned) < MIN_REASON_CHARS:
            msg = f"a suppression reason must be at least {MIN_REASON_CHARS} characters"
            raise ValueError(msg)
        return cleaned

    def model_post_init(self, __context: Any) -> None:
        # ``model_post_init`` rather than a validator because the rule depends on two fields.
        if self.kind == "finding" and self.finding_id is None:
            msg = "a finding suppression needs finding_id"
            raise ConfigurationError(msg)
        if self.kind == "rule" and not self.check_id:
            msg = "a rule suppression needs check_id"
            raise ConfigurationError(msg)
        if self.kind == "pattern" and not (self.check_id and self.asset_pattern):
            msg = "a pattern suppression needs check_id and asset_pattern"
            raise ConfigurationError(msg)

    def matches(self, *, check_id: str, asset: str, finding_id: int | None = None) -> bool:
        """Whether this rule covers one observed finding (expiry and revocation included)."""
        if not self.active:
            return False
        if self.expires_at is not None and self.expires_at <= datetime.now(UTC):
            return False
        if self.kind == "finding":
            return finding_id is not None and self.finding_id == finding_id
        if self.check_id and self.check_id != check_id:
            return False
        if self.kind == "rule":
            return True
        return bool(self.asset_pattern) and fnmatchcase(asset, self.asset_pattern or "")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


@dataclass(frozen=True, slots=True)
class SuppressionSet:
    """The active rules, as one read-only set the diff consults once per scan."""

    suppressions: tuple[Suppression, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.suppressions)

    def __len__(self) -> int:
        return len(self.suppressions)

    @property
    def version(self) -> int:
        """The highest version in force — what a report cites as "suppressions vN"."""
        return max((item.version for item in self.suppressions), default=0)

    @classmethod
    def of(cls, items: Iterable[Suppression]) -> SuppressionSet:
        """The active, unexpired rules, most specific first."""
        now = datetime.now(UTC)
        live = [
            item
            for item in items
            if item.active and (item.expires_at is None or item.expires_at > now)
        ]
        order = {"finding": 0, "pattern": 1, "rule": 2}
        live.sort(key=lambda item: (order.get(item.kind, 9), item.version, item.id or 0))
        return cls(suppressions=tuple(live))

    def match(
        self, *, check_id: str, asset: str, finding_id: int | None = None
    ) -> Suppression | None:
        """The most specific rule covering this finding, or ``None``."""
        for item in self.suppressions:
            if item.matches(check_id=check_id, asset=asset, finding_id=finding_id):
                return item
        return None

    def covers(self, *, check_id: str, asset: str, finding_id: int | None = None) -> bool:
        return self.match(check_id=check_id, asset=asset, finding_id=finding_id) is not None

    def describe(self) -> dict[str, Any]:
        """A compact description for a report's scope section."""
        return {
            "version": self.version,
            "count": len(self.suppressions),
            "kinds": {
                kind: sum(1 for item in self.suppressions if item.kind == kind)
                for kind in ("finding", "rule", "pattern")
            },
        }


def selectors_of(suppression: Suppression) -> SuppressionSelector:
    """The selector view of a suppression (for a UI table or a test)."""
    return SuppressionSelector(
        check_id=suppression.check_id,
        asset_pattern=suppression.asset_pattern,
        finding_id=suppression.finding_id,
    )


def sort_for_display(suppressions: Sequence[Suppression]) -> tuple[Suppression, ...]:
    """Newest and most specific first — the order an operator reviews a list in."""
    order = {"finding": 0, "pattern": 1, "rule": 2}
    return tuple(
        sorted(
            suppressions,
            key=lambda item: (
                0 if item.active else 1,
                order.get(item.kind, 9),
                -item.version,
                item.id or 0,
            ),
        )
    )
