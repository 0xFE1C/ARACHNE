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

from arachne.data.models import AuthSession, ServiceAccount, SsoFlow
from arachne.data.scan_store import as_utc

__all__ = [
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
