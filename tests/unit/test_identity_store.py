"""Unit tests for the identity stores (S17, REQ-IDAM-003).

The service-account accept criteria are asserted here: hashed storage with the same format
the static key store uses, ``hmac.compare_digest`` verification, a rotation that rejects
the old secret and accepts the new one, optional expiry, revoke, and last-used tracking.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.api.auth import hash_secret
from arachne.data.db import create_all, create_db_engine, create_session_factory
from arachne.data.identity_store import (
    ServiceAccountStore,
    SessionStore,
    SsoFlowStore,
)
from arachne.data.identity_store import (
    hash_secret as identity_hash_secret,
)
from arachne.data.models import ServiceAccount


@pytest.fixture
def factory(tmp_path: Path) -> sessionmaker[Session]:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'identity.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


# --------------------------------------------------------------------------- hashing
def test_the_identity_store_uses_the_same_secret_format_as_the_key_store() -> None:
    assert identity_hash_secret("s3cret") == hash_secret("s3cret")


# --------------------------------------------------------------------------- service accounts
def test_a_service_account_stores_only_a_digest_and_verifies_it(
    factory: sessionmaker[Session],
) -> None:
    store = ServiceAccountStore(factory)
    record, secret = store.create(
        "ci-pipeline", "scanner", owner="alice@corp", created_by="user alice@corp"
    )
    assert record.role == "scanner" and record.owner == "alice@corp"
    with factory() as session:
        row = session.scalar(select(ServiceAccount).where(ServiceAccount.label == "ci-pipeline"))
        assert row is not None
        assert row.digest == hash_secret(secret)
        assert secret not in row.digest
        assert len(row.digest) == 64
    verified = store.verify(secret)
    assert verified is not None and verified.label == "ci-pipeline"
    assert verified.last_used_at is not None


def test_rotation_rejects_the_old_secret_and_accepts_the_new(
    factory: sessionmaker[Session],
) -> None:
    store = ServiceAccountStore(factory)
    _record, old_secret = store.create("deploy", "scanner")
    assert store.verify(old_secret) is not None

    rotated = store.rotate("deploy", actor="user admin@corp")
    assert rotated is not None
    record, new_secret = rotated
    assert record.rotated_from == "deploy"
    assert new_secret != old_secret
    assert store.verify(old_secret) is None, "the rotated-away secret must be rejected"
    assert store.verify(new_secret) is not None, "the new secret must work"


def test_a_revoked_key_never_authenticates(factory: sessionmaker[Session]) -> None:
    store = ServiceAccountStore(factory)
    _record, secret = store.create("temp", "viewer")
    assert store.revoke("temp") is not None
    assert store.verify(secret) is None
    account = store.get("temp")
    assert account is not None and account.revoked_at is not None


def test_expiry_is_optional_and_enforced(factory: sessionmaker[Session]) -> None:
    store = ServiceAccountStore(factory)
    _r, permanent = store.create("permanent", "viewer")
    assert store.verify(permanent) is not None

    _r2, expired = store.create(
        "expired", "viewer", expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    assert store.verify(expired) is None

    _r3, future = store.create("future", "viewer", expires_in_s=3600)
    assert store.verify(future) is not None


def test_last_used_tracking_starts_empty_and_updates_on_use(
    factory: sessionmaker[Session],
) -> None:
    store = ServiceAccountStore(factory)
    record, secret = store.create("tracker", "viewer")
    assert record.last_used_at is None
    store.verify(secret)
    used = store.get("tracker")
    assert used is not None and used.last_used_at is not None


def test_a_wrong_secret_matches_nothing(factory: sessionmaker[Session]) -> None:
    store = ServiceAccountStore(factory)
    store.create("one", "viewer")
    store.create("two", "admin")
    assert store.verify("nope") is None
    assert store.verify("") is None
    assert store.verify(None) is None


def test_labels_exclude_revoked_accounts(factory: sessionmaker[Session]) -> None:
    store = ServiceAccountStore(factory)
    store.create("live", "viewer")
    store.create("dead", "viewer")
    store.revoke("dead")
    assert store.labels() == ("live",)


# --------------------------------------------------------------------------- flows
def test_a_flow_is_consumed_exactly_once(factory: sessionmaker[Session]) -> None:
    flows = SsoFlowStore(factory)
    flow = flows.create(nonce="n", code_verifier="v", redirect_uri="https://app/cb", ttl_s=60)
    consumed = flows.consume(flow.state)
    assert consumed is not None and consumed.nonce == "n"
    assert flows.consume(flow.state) is None, "a replayed state must find nothing"
    assert flows.consume("") is None
    assert flows.consume("unknown") is None


def test_an_expired_flow_is_not_consumable(factory: sessionmaker[Session]) -> None:
    flows = SsoFlowStore(factory)
    flow = flows.create(nonce="n", code_verifier="v", redirect_uri="https://app/cb", ttl_s=60)
    with factory() as session:
        from arachne.data.models import SsoFlow

        row = session.get(SsoFlow, 1)
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    assert flows.consume(flow.state) is None


# --------------------------------------------------------------------------- sessions
def test_a_session_token_is_stored_hashed_and_resolves(factory: sessionmaker[Session]) -> None:
    sessions = SessionStore(factory)
    record, token = sessions.create(
        subject="alice", role="scanner", email="alice@corp", groups=("g",), ttl_s=60
    )
    assert record.email == "alice@corp"
    resolved = sessions.resolve(token)
    assert resolved is not None and resolved.role == "scanner"
    assert resolved.last_seen_at is not None
    # The raw token is not stored anywhere.
    with factory() as session:
        from arachne.data.models import AuthSession

        row = session.scalar(select(AuthSession))
        assert row is not None and row.token_hash == hash_secret(token)
        assert token not in row.token_hash
    assert sessions.resolve("nope") is None
    assert sessions.resolve(None) is None


def test_revoking_a_session_makes_it_unresolvable(factory: sessionmaker[Session]) -> None:
    sessions = SessionStore(factory)
    _record, token = sessions.create(subject="bob", role="viewer", ttl_s=60)
    assert sessions.revoke(token)
    assert sessions.resolve(token) is None
    assert not sessions.revoke("nope")
