"""Identity persistence for enterprise access (S17, area IDAM: REQ-IDAM-001/003).

Three small stores over three tables, next to the writer of each table:

* :class:`ServiceAccountStore` — API keys as service accounts: hashed secrets verified with
  :func:`hmac.compare_digest` (the S12 storage discipline, unchanged), an optional
  ``expires_at``, ``last_used_at`` tracking and an in-place rotation that returns the new
  secret exactly once and leaves the old one rejected.
* :class:`SsoFlowStore` — pending OIDC authorization-code flows. The ``state`` is the
  primary key and single-use nonce; ``consume`` deletes the row, so a replayed callback
  finds nothing.
* :class:`SessionStore` — minted browser sessions after a login. Only the SHA-256 hash of
  the opaque token is stored, so a database read cannot replay a live session.

None of these stores is a scan dependency: the CLI and the orchestrator run without the
identity layer, exactly as they run without the API.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.data.models import (
    AuthSession,
    ProvisionedGroup,
    ProvisionedPrincipal,
    ServiceAccount,
    SsoFlow,
)
from arachne.data.scan_store import as_utc

__all__ = [
    "GroupRecord",
    "PrincipalRecord",
    "ProvisionedPrincipalStore",
    "ServiceAccountRecord",
    "ServiceAccountStore",
    "SessionRecord",
    "SessionStore",
    "SsoFlowRecord",
    "SsoFlowStore",
    "hash_secret",
    "new_secret",
]

#: How many bytes of entropy a generated secret carries (32 bytes → 64 hex chars).
_SECRET_BYTES = 32


def new_secret() -> str:
    """A fresh, high-entropy API key secret (never logged, returned exactly once)."""
    return secrets.token_urlsafe(_SECRET_BYTES)


def hash_secret(secret: str) -> str:
    """SHA-256 hex digest of a secret — the same format :func:`arachne.api.auth.hash_secret`
    produces (a test pins the two together). Unsalted by design: the secret is a
    high-entropy random token, not a user password.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _active(row: ServiceAccount, now: datetime) -> bool:
    if row.revoked_at is not None:
        return False
    expires = as_utc(row.expires_at)
    return expires is None or expires > now


@dataclass(frozen=True, slots=True)
class ServiceAccountRecord:
    """One service account as the API and the audit trail see it (never the secret)."""

    id: int
    label: str
    role: str
    project: str | None = None
    owner: str | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    rotated_from: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "role": self.role,
            "project": self.project,
            "owner": self.owner,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": self.revoked_at is not None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "rotated_from": self.rotated_from,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def _account(row: ServiceAccount) -> ServiceAccountRecord:
    return ServiceAccountRecord(
        id=int(row.id),
        label=str(row.label),
        role=str(row.role),
        project=row.project,
        owner=row.owner,
        expires_at=as_utc(row.expires_at),
        last_used_at=as_utc(row.last_used_at),
        revoked_at=as_utc(row.revoked_at),
        rotated_from=row.rotated_from,
        created_by=row.created_by,
        created_at=as_utc(row.created_at),
    )


class ServiceAccountStore:
    """Service accounts: hashed secrets, expiry, last-used tracking and rotation."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ writes
    def create(
        self,
        label: str,
        role: str,
        *,
        project: str | None = None,
        owner: str | None = None,
        created_by: str | None = None,
        expires_in_s: int | None = None,
        expires_at: datetime | None = None,
        secret: str | None = None,
        rotated_from: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> tuple[ServiceAccountRecord, str]:
        """Create a service account; returns ``(record, secret)`` — the secret once."""
        effective_secret = secret or new_secret()
        expiry = expires_at
        if expiry is None and expires_in_s is not None:
            expiry = datetime.now(UTC) + timedelta(seconds=expires_in_s)
        with self._session_factory() as session:
            row = ServiceAccount(
                label=label,
                role=role,
                project=project,
                owner=owner,
                digest=hash_secret(effective_secret),
                expires_at=expiry,
                rotated_from=rotated_from,
                created_by=created_by or owner,
                meta_json=dict(meta or {}),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _account(row), effective_secret

    def rotate(
        self,
        label: str,
        *,
        actor: str | None = None,
        expires_in_s: int | None = None,
    ) -> tuple[ServiceAccountRecord, str] | None:
        """Rotate ``label`` in place: a new secret, the old one immediately rejected.

        Returns ``(record, new_secret)`` or ``None`` when the label does not exist. The
        rotation is recorded on the row (``rotated_from`` names the lineage and the
        rotation count rides in ``meta_json``), so the history is queryable without a
        second table.
        """
        with self._session_factory() as session:
            row = session.scalar(select(ServiceAccount).where(ServiceAccount.label == label))
            if row is None:
                return None
            fresh = new_secret()
            row.digest = hash_secret(fresh)
            row.rotated_from = label
            row.revoked_at = None
            row.last_used_at = None
            if expires_in_s is not None:
                row.expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_s)
            meta = dict(row.meta_json or {})
            meta["rotations"] = int(meta.get("rotations", 0)) + 1
            meta["rotated_by"] = actor
            row.meta_json = meta
            session.commit()
            session.refresh(row)
            return _account(row), fresh

    def revoke(self, label: str, *, actor: str | None = None) -> ServiceAccountRecord | None:
        """Revoke ``label`` (a revoked key never authenticates). ``None`` if absent."""
        with self._session_factory() as session:
            row = session.scalar(select(ServiceAccount).where(ServiceAccount.label == label))
            if row is None:
                return None
            row.revoked_at = datetime.now(UTC)
            meta = dict(row.meta_json or {})
            meta["revoked_by"] = actor
            row.meta_json = meta
            session.commit()
            session.refresh(row)
            return _account(row)

    def delete(self, label: str) -> bool:
        with self._session_factory() as session:
            result = session.execute(delete(ServiceAccount).where(ServiceAccount.label == label))
            session.commit()
            return bool(result.rowcount or 0)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ reads
    def get(self, label: str) -> ServiceAccountRecord | None:
        with self._session_factory() as session:
            row = session.scalar(select(ServiceAccount).where(ServiceAccount.label == label))
            return None if row is None else _account(row)

    def list_accounts(self, *, include_revoked: bool = True) -> tuple[ServiceAccountRecord, ...]:
        query = select(ServiceAccount).order_by(ServiceAccount.label)
        if not include_revoked:
            query = query.where(ServiceAccount.revoked_at.is_(None))
        with self._session_factory() as session:
            rows = session.scalars(query).all()
        return tuple(_account(row) for row in rows)

    def labels(self) -> tuple[str, ...]:
        return tuple(account.label for account in self.list_accounts(include_revoked=False))

    def verify(self, presented: str | None) -> ServiceAccountRecord | None:
        """Return the active account for ``presented``, or ``None`` (constant-time compare).

        A revoked or expired account is refused *after* the digest matches, so the timing
        does not reveal whether the secret was right. A successful verify stamps
        ``last_used_at`` (REQ-IDAM-003).
        """
        if not presented:
            return None
        digest = hash_secret(presented)
        now = datetime.now(UTC)
        with self._session_factory() as session:
            rows = session.scalars(select(ServiceAccount)).all()
            match: ServiceAccount | None = None
            for row in rows:
                if hmac.compare_digest(str(row.digest), digest):
                    match = row
                    break
            if match is None:
                return None
            if not _active(match, now):
                return None
            match.last_used_at = now
            session.commit()
            session.refresh(match)
            return _account(match)

    def revoke_owned_by(self, owner: str, *, actor: str | None = None) -> tuple[str, ...]:
        """Revoke every active key owned by ``owner``; returns the labels revoked (REQ-IDAM-007).

        Deprovisioning a person has to take their machine credentials with them: a key that
        outlives its owner's directory entry is exactly the "leaver" hole SCIM exists to
        close. One transaction, so a deactivation is all-or-nothing.
        """
        if not owner:
            return ()
        now = datetime.now(UTC)
        revoked: list[str] = []
        with self._session_factory() as session:
            rows = session.scalars(
                select(ServiceAccount).where(ServiceAccount.owner == owner)
            ).all()
            for row in rows:
                if row.revoked_at is not None:
                    continue
                row.revoked_at = now
                meta = dict(row.meta_json or {})
                meta["revoked_by"] = actor
                meta["revoked_reason"] = "deprovisioned"
                row.meta_json = meta
                revoked.append(str(row.label))
            session.commit()
        return tuple(sorted(revoked))


@dataclass(frozen=True, slots=True)
class SsoFlowRecord:
    """A pending OIDC flow (``state`` is the single-use key)."""

    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str
    next_path: str = "/ui/"
    created_at: datetime | None = None
    expires_at: datetime | None = None


class SsoFlowStore:
    """Pending OIDC authorization-code flows, consumed exactly once."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
        next_path: str = "/ui/",
        ttl_s: int = 600,
    ) -> SsoFlowRecord:
        state = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = SsoFlow(
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                next_path=next_path,
                expires_at=now + timedelta(seconds=ttl_s),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return SsoFlowRecord(
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                next_path=next_path,
                created_at=as_utc(row.created_at),
                expires_at=as_utc(row.expires_at),
            )

    def consume(self, state: str) -> SsoFlowRecord | None:
        """Fetch *and delete* the flow named by ``state``; ``None`` if absent or expired."""
        if not state:
            return None
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(select(SsoFlow).where(SsoFlow.state == state))
            if row is None:
                return None
            record = SsoFlowRecord(
                state=str(row.state),
                nonce=str(row.nonce),
                code_verifier=str(row.code_verifier),
                redirect_uri=str(row.redirect_uri),
                next_path=str(row.next_path),
                created_at=as_utc(row.created_at),
                expires_at=as_utc(row.expires_at),
            )
            session.delete(row)
            session.commit()
        expires = record.expires_at
        if expires is not None and expires <= now:
            return None
        return record

    def purge_expired(self) -> int:
        with self._session_factory() as session:
            result = session.execute(delete(SsoFlow).where(SsoFlow.expires_at <= datetime.now(UTC)))
            session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """A minted login session's identity (never its token)."""

    subject: str
    role: str
    email: str | None = None
    name: str | None = None
    project: str | None = None
    groups: tuple[str, ...] = ()
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_seen_at: datetime | None = None

    @property
    def display(self) -> str:
        return self.email or self.name or self.subject


class SessionStore:
    """Browser sessions: hashed tokens, expiry, last-seen tracking."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        subject: str,
        role: str,
        email: str | None = None,
        name: str | None = None,
        project: str | None = None,
        groups: tuple[str, ...] | list[str] = (),
        ttl_s: int = 8 * 3600,
    ) -> tuple[SessionRecord, str]:
        token = secrets.token_urlsafe(_SECRET_BYTES)
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = AuthSession(
                token_hash=hash_secret(token),
                subject=subject,
                email=email,
                name=name,
                role=role,
                project=project,
                groups_json=list(groups),
                expires_at=now + timedelta(seconds=ttl_s),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _session(row), token

    def resolve(self, token: str | None) -> SessionRecord | None:
        """The identity behind ``token``, or ``None`` when absent/expired (stamps last-seen)."""
        if not token:
            return None
        digest = hash_secret(token)
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(select(AuthSession).where(AuthSession.token_hash == digest))
            if row is None:
                return None
            expires = as_utc(row.expires_at)
            if expires is not None and expires <= now:
                return None
            row.last_seen_at = now
            session.commit()
            session.refresh(row)
            return _session(row)

    def revoke_subject(self, subject: str) -> int:
        """Delete every session for ``subject``; returns how many were revoked (REQ-IDAM-007).

        SCIM deprovisioning has to end the subject's *sessions*, not only their ability to
        obtain new ones: a deactivation that leaves a live browser session is worse than no
        SCIM at all, because the directory says the person is gone and the API disagrees.
        """
        if not subject:
            return 0
        with self._session_factory() as session:
            rows = session.scalars(select(AuthSession).where(AuthSession.subject == subject)).all()
            for row in rows:
                session.delete(row)
            session.commit()
        return len(rows)

    def active_subjects(self) -> tuple[str, ...]:
        """Every subject with a live session (the deprovisioning audit's "before" reading)."""
        with self._session_factory() as session:
            rows = session.scalars(
                select(AuthSession.subject)
                .where(AuthSession.expires_at > datetime.now(UTC))
                .distinct()
            ).all()
        return tuple(sorted(str(item) for item in rows))

    def revoke(self, token: str | None) -> bool:
        if not token:
            return False
        with self._session_factory() as session:
            result = session.execute(
                delete(AuthSession).where(AuthSession.token_hash == hash_secret(token))
            )
            session.commit()
            return bool(result.rowcount or 0)  # type: ignore[attr-defined]

    def purge_expired(self) -> int:
        with self._session_factory() as session:
            result = session.execute(
                delete(AuthSession).where(AuthSession.expires_at <= datetime.now(UTC))
            )
            session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]


def _session(row: AuthSession) -> SessionRecord:
    groups = row.groups_json or []
    return SessionRecord(
        subject=str(row.subject),
        role=str(row.role),
        email=row.email,
        name=row.name,
        project=row.project,
        groups=tuple(str(item) for item in groups),
        created_at=as_utc(row.created_at),
        expires_at=as_utc(row.expires_at),
        last_seen_at=as_utc(row.last_seen_at),
    )


# --------------------------------------------------------------------- SCIM provisioning


@dataclass(frozen=True, slots=True)
class PrincipalRecord:
    """One provisioned principal (the IdP's view of a person), tenant-free by design."""

    id: int
    subject: str
    user_name: str
    display_name: str | None = None
    emails: tuple[str, ...] = ()
    active: bool = True
    groups: tuple[str, ...] = ()
    external_id: str | None = None
    version: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def primary_email(self) -> str | None:
        return self.emails[0] if self.emails else None


@dataclass(frozen=True, slots=True)
class GroupRecord:
    """One provisioned group: a directory group whose display name maps to a role."""

    id: int
    group_id: str
    display_name: str
    members: tuple[str, ...] = ()
    external_id: str | None = None
    version: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None


def _principal(row: ProvisionedPrincipal) -> PrincipalRecord:
    return PrincipalRecord(
        id=int(row.id),
        subject=str(row.subject),
        user_name=str(row.user_name),
        display_name=row.display_name,
        emails=tuple(str(item) for item in (row.emails_json or [])),
        active=bool(row.active),
        groups=tuple(str(item) for item in (row.groups_json or [])),
        external_id=row.external_id,
        version=int(row.version),
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
    )


def _group(row: ProvisionedGroup) -> GroupRecord:
    return GroupRecord(
        id=int(row.id),
        group_id=str(row.group_id),
        display_name=str(row.display_name),
        members=tuple(str(item) for item in (row.members_json or [])),
        external_id=row.external_id,
        version=int(row.version),
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
    )


class ProvisionedPrincipalStore:
    """The SCIM directory mirror: principals, groups and their membership (REQ-IDAM-007).

    Two tables, one store, because the SCIM resource model is genuinely two resources and the
    membership lives on the group. Every write bumps ``version``, which is the ``meta.version``
    an IdP can use for optimistic concurrency.

    Role is **never** stored: it is derived from ``groups`` by ``SsoSettings.role_for`` at
    login, so a group change takes effect on the next login with no authorisation column to
    keep in step (docs/scim-ldap-interface.md §2).
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ principals
    def upsert_principal(
        self,
        *,
        subject: str,
        user_name: str,
        display_name: str | None = None,
        emails: tuple[str, ...] = (),
        groups: tuple[str, ...] = (),
        external_id: str | None = None,
        active: bool = True,
    ) -> tuple[PrincipalRecord, bool]:
        """Create or reconcile one principal. ``True`` in the second slot means "created".

        ``POST /Users`` is idempotent on the subject, which is what RFC 7644 §3.3 asks for: a
        retried create reconciles the attributes instead of failing, so an IdP that lost the
        response does not have to guess.
        """
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(
                select(ProvisionedPrincipal).where(ProvisionedPrincipal.subject == subject)
            )
            created = row is None
            if row is None:
                row = ProvisionedPrincipal(
                    subject=subject,
                    user_name=user_name,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            row.user_name = user_name
            row.display_name = display_name
            row.emails_json = list(emails)
            row.groups_json = list(groups)
            row.external_id = external_id
            row.active = active
            row.version = int(row.version or 0) + 1 if not created else 1
            row.updated_at = now
            session.commit()
            session.refresh(row)
            return _principal(row), created

    def get_principal(self, reference: str | int) -> PrincipalRecord | None:
        """Resolve by numeric row id (the SCIM ``id``) or by subject."""
        with self._session_factory() as session:
            row = self._find(session, reference)
            return None if row is None else _principal(row)

    def get_by_user_name(self, user_name: str) -> PrincipalRecord | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(ProvisionedPrincipal).where(ProvisionedPrincipal.user_name == user_name)
            )
            return None if row is None else _principal(row)

    def list_principals(
        self, *, user_name: str | None = None, external_id: str | None = None
    ) -> tuple[PrincipalRecord, ...]:
        query = select(ProvisionedPrincipal).order_by(ProvisionedPrincipal.id)
        if user_name is not None:
            query = query.where(ProvisionedPrincipal.user_name == user_name)
        if external_id is not None:
            query = query.where(ProvisionedPrincipal.external_id == external_id)
        with self._session_factory() as session:
            rows = session.scalars(query).all()
        return tuple(_principal(row) for row in rows)

    def update_principal(
        self,
        reference: str | int,
        *,
        user_name: str | None = None,
        display_name: str | None = None,
        emails: tuple[str, ...] | None = None,
        groups: tuple[str, ...] | None = None,
        external_id: str | None = None,
        active: bool | None = None,
    ) -> PrincipalRecord | None:
        """Replace the named attributes; ``None`` means "leave alone". Bumps ``version``."""
        with self._session_factory() as session:
            row = self._find(session, reference)
            if row is None:
                return None
            if user_name is not None:
                row.user_name = user_name
            if display_name is not None:
                row.display_name = display_name
            if emails is not None:
                row.emails_json = list(emails)
            if groups is not None:
                row.groups_json = list(groups)
            if external_id is not None:
                row.external_id = external_id
            if active is not None:
                row.active = active
            row.version = int(row.version or 0) + 1
            row.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(row)
            return _principal(row)

    def delete_principal(self, reference: str | int) -> bool:
        """Hard delete. SCIM ``DELETE`` does **not** use this — it deactivates the row."""
        with self._session_factory() as session:
            row = self._find(session, reference)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    @staticmethod
    def _find(session: Session, reference: str | int) -> ProvisionedPrincipal | None:
        """A row by id or by subject; subjects are opaque strings, so both are accepted."""
        if isinstance(reference, int) or (isinstance(reference, str) and reference.isdigit()):
            row = session.get(ProvisionedPrincipal, int(reference))
            if row is not None:
                return row
        return session.scalar(
            select(ProvisionedPrincipal).where(ProvisionedPrincipal.subject == str(reference))
        )

    @classmethod
    def _canonical_members(cls, session: Session, members: tuple[str, ...]) -> list[str]:
        """Member references → principal ids, so a group and its members agree on one spelling.

        An IdP may send a member as the subject, the ``userName`` or the resource id; storing
        whichever arrived is how a group ends up "containing" somebody that ``GET /Users``
        cannot connect to it. A value that resolves to nothing is kept verbatim: a member may
        legally be provisioned after the group is.
        """
        canonical: list[str] = []
        for member in members:
            row = cls._find(session, member)
            value = str(row.id) if row is not None else str(member)
            if value not in canonical:
                canonical.append(value)
        return canonical

    # ------------------------------------------------------------------ groups
    def upsert_group(
        self,
        *,
        group_id: str,
        display_name: str,
        members: tuple[str, ...] = (),
        external_id: str | None = None,
    ) -> tuple[GroupRecord, bool]:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(
                select(ProvisionedGroup).where(ProvisionedGroup.group_id == group_id)
            )
            created = row is None
            if row is None:
                row = ProvisionedGroup(
                    group_id=group_id, display_name=display_name, created_at=now, updated_at=now
                )
                session.add(row)
            row.display_name = display_name
            row.members_json = self._canonical_members(session, members)
            row.external_id = external_id
            row.version = 1 if created else int(row.version or 0) + 1
            row.updated_at = now
            session.commit()
            session.refresh(row)
            return _group(row), created

    def get_group(self, reference: str | int) -> GroupRecord | None:
        with self._session_factory() as session:
            row = self._find_group(session, reference)
            return None if row is None else _group(row)

    def list_groups(self, *, display_name: str | None = None) -> tuple[GroupRecord, ...]:
        query = select(ProvisionedGroup).order_by(ProvisionedGroup.id)
        if display_name is not None:
            query = query.where(ProvisionedGroup.display_name == display_name)
        with self._session_factory() as session:
            rows = session.scalars(query).all()
        return tuple(_group(row) for row in rows)

    def update_group(
        self,
        reference: str | int,
        *,
        display_name: str | None = None,
        members: tuple[str, ...] | None = None,
        external_id: str | None = None,
    ) -> GroupRecord | None:
        with self._session_factory() as session:
            row = self._find_group(session, reference)
            if row is None:
                return None
            if display_name is not None:
                row.display_name = display_name
            if members is not None:
                row.members_json = self._canonical_members(session, members)
            if external_id is not None:
                row.external_id = external_id
            row.version = int(row.version or 0) + 1
            row.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(row)
            return _group(row)

    def delete_group(self, reference: str | int) -> bool:
        with self._session_factory() as session:
            row = self._find_group(session, reference)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def remove_member(self, reference: str | int) -> tuple[str, ...]:
        """Drop a principal from every group it is in; returns the groups it left.

        The leaver case, and it has to clear *both* sides of the membership: the group's
        ``members_json`` (so ``GET /Groups`` stops reporting the person) and the principal's
        ``groups_json`` (which is what the role is derived from — a stale entry there would
        hand the role straight back on reactivation).

        ``reference`` is either the principal's row id or its subject, because a SCIM group's
        ``members`` may carry either and both resolve to the same person.
        """
        if reference is None or reference == "":
            return ()
        with self._session_factory() as session:
            principal = self._find(session, reference)
            if principal is None:
                return ()
            tokens = {str(principal.subject), str(principal.id)}
            left: list[str] = [str(item) for item in (principal.groups_json or [])]
            for row in session.scalars(select(ProvisionedGroup)).all():
                members = [str(item) for item in (row.members_json or [])]
                if not tokens & set(members):
                    continue
                row.members_json = [item for item in members if item not in tokens]
                row.version = int(row.version or 0) + 1
                row.updated_at = datetime.now(UTC)
                left.append(str(row.group_id))
            # The membership list itself goes: a deactivated principal that kept the claim
            # would be handed its old role the moment it was reactivated.
            principal.groups_json = []
            principal.version = int(principal.version or 0) + 1
            principal.updated_at = datetime.now(UTC)
            session.commit()
        return tuple(sorted(set(left)))

    def groups_for(self, subject: str) -> tuple[str, ...]:
        """The group ids ``subject`` is a member of (the principal's ``groups_json`` source)."""
        return tuple(group.group_id for group in self.list_groups() if subject in group.members)

    def set_groups(self, reference: str | int, groups: tuple[str, ...]) -> PrincipalRecord | None:
        """Write a principal's group membership to **both** sides of the relationship.

        SCIM has two views of the same fact — ``User.groups`` and ``Group.members`` — and an
        IdP may write either. An implementation that updates only the side it was written
        through ends up with a user whose role says one thing and whose group says another,
        which is exactly the state a leaver must never reach. So every write reconciles both,
        using the principal's SCIM id as the canonical member value (RFC 7643 §4.2 makes
        ``members.value`` the member resource's ``id``, and :meth:`upsert_principal` returns
        that id, so both directions of the reference resolve).
        """
        wanted = [str(group) for group in groups]
        with self._session_factory() as session:
            principal = self._find(session, reference)
            if principal is None:
                return None
            member = str(principal.id)
            for row in session.scalars(select(ProvisionedGroup)).all():
                members = [str(item) for item in (row.members_json or [])]
                belongs = str(row.group_id) in wanted
                present = member in members
                if belongs and not present:
                    row.members_json = [*members, member]
                elif not belongs and present:
                    row.members_json = [item for item in members if item != member]
                else:
                    continue
                row.version = int(row.version or 0) + 1
                row.updated_at = datetime.now(UTC)
            principal.groups_json = wanted
            principal.version = int(principal.version or 0) + 1
            principal.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(principal)
            return _principal(principal)

    @staticmethod
    def _find_group(session: Session, reference: str | int) -> ProvisionedGroup | None:
        if isinstance(reference, int) or (isinstance(reference, str) and reference.isdigit()):
            row = session.get(ProvisionedGroup, int(reference))
            if row is not None:
                return row
        return session.scalar(
            select(ProvisionedGroup).where(ProvisionedGroup.group_id == str(reference))
        )
