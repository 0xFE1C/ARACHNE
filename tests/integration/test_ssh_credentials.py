"""SSH credentials: key and password support, the scope gate, and a real authentication.

REQ-CREDS-006 has four acceptance criteria and this module is where three of them are
measured:

* a vault entry holds an SSH key or password and **no artifact** ever carries it;
* an authenticated SSH check produces a result an anonymous one cannot;
* an out-of-scope SSH credential is refused **before any connection** — with every socket
  entry point armed, so "before" is a fact rather than an intention.

The fourth (the credential gate still passes) is covered by ``tests/test_no_default_credentials.py``
and by the gate command in the handoff.

The lab credential is generated per run rather than written down: a fixture password in the
source tree is indistinguishable from a shipped default to a secret scanner, and the honest
fix is not to have one.
"""

from __future__ import annotations

import secrets
import socket
from pathlib import Path
from typing import Any

import pytest
from tests.lab.ssh_lab import SshLabServer

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import NetSettings, RateLimitSettings, Settings
from arachne.core.ed25519 import derive_public_key
from arachne.core.ratelimit import HostRateLimiter
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.core.vault import CredentialScope, FileCredentialVault
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.ssh import SshAuthenticator

pytestmark = pytest.mark.integration

LOOPBACK = "127.0.0.1"
SSH_USER = "labuser"
#: Generated per run: a lab fixture, never a default. A literal here would read as a shipped
#: credential to every scanner that matters.
SSH_PASSWORD = secrets.token_urlsafe(18)
#: The Ed25519 seed the fixture authorizes — derived deterministically so a failure is
#: reproducible. Public knowledge by construction; it authorizes nothing outside the fixture.
KEY_SEED = bytes(range(32))


def _settings() -> Settings:
    return Settings(
        net=NetSettings(connect_timeout_s=2.0, read_timeout_s=4.0, banner_wait_s=0.2),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
    )


def _client(sink: MemoryAuditSink, transport: Any = None, *, host: str = LOOPBACK) -> Any:
    from arachne.core.net import ScopedNetClient

    settings = _settings()
    return ScopedNetClient(
        settings=settings,
        scope=Scope(allowed_hosts=(host,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver((LOOPBACK,)),
        limiter=HostRateLimiter(settings.rate_limit),
        auditor=Auditor(sink, actor="pytest"),
        transport=transport,
    )


def _service(port: int) -> ServiceRecord:
    return ServiceRecord(host=LOOPBACK, port=port, protocol="tcp", service="ssh")


def _vault(tmp_path: Path) -> FileCredentialVault:
    # The passphrase is generated per run, for the same reason the lab password is: a literal
    # in a test file is indistinguishable from a shipped default.
    return FileCredentialVault(tmp_path / "vault.json", passphrase=secrets.token_urlsafe(24))


# --------------------------------------------------------------------------- the handshake
async def test_a_password_credential_authenticates_against_the_lab() -> None:
    sink = MemoryAuditSink()
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        client = _client(sink)
        result = await SshAuthenticator(client, _service(lab.port)).attempt(
            SSH_USER, SSH_PASSWORD, {"auth_method": "password"}
        )
    assert result.attempted is True
    assert result.accepted is True, result.detail
    assert result.status_name == "SUCCESS"
    assert lab.attempts and lab.attempts[0]["method"] == "password"
    assert lab.attempts[0]["accepted"] is True


async def test_a_wrong_password_is_refused_not_an_error() -> None:
    sink = MemoryAuditSink()
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        client = _client(sink)
        result = await SshAuthenticator(client, _service(lab.port)).attempt(
            SSH_USER, secrets.token_urlsafe(18), {"auth_method": "password"}
        )
    assert result.attempted is True
    assert result.accepted is False
    assert result.status_name == "FAILURE"
    assert "refused" in result.detail


async def test_an_ed25519_key_authenticates_against_the_lab() -> None:
    public = derive_public_key(KEY_SEED)
    with SshLabServer(username=SSH_USER, password=None, public_key=public) as lab:
        sink = MemoryAuditSink()
        client = _client(sink)
        result = await SshAuthenticator(client, _service(lab.port)).attempt(
            SSH_USER, KEY_SEED.hex(), {"auth_method": "publickey", "key_type": "ed25519"}
        )
    assert result.attempted is True
    assert result.accepted is True, result.detail
    assert result.status_name == "SUCCESS"
    assert lab.attempts[0]["method"] == "publickey"


async def test_the_client_records_that_it_verified_the_host_key() -> None:
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        client = _client(MemoryAuditSink())
        result = await SshAuthenticator(client, _service(lab.port)).attempt(
            SSH_USER, SSH_PASSWORD, {"auth_method": "password"}
        )
    steps = [step for step in result.exchanges if step.get("step") == "host_key"]
    assert steps and steps[0]["verified"] is True
    # The exchange carries no secret: versions, algorithm names, a fingerprint, a verdict.
    rendered = repr(result.exchanges)
    assert SSH_PASSWORD not in rendered


async def test_a_non_ed25519_key_is_refused_without_sending_it() -> None:
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        client = _client(MemoryAuditSink())
        result = await SshAuthenticator(client, _service(lab.port)).attempt(
            SSH_USER, KEY_SEED.hex(), {"auth_method": "publickey", "key_type": "rsa"}
        )
    assert result.attempted is False, "a key this build cannot use must not be sent"
    assert result.status_name == "UNSUPPORTED_KEY_TYPE"
    assert lab.attempts == [], "the peer was sent a credential-bearing request"


# --------------------------------------------------------------------------- the scope gate
async def test_an_out_of_scope_ssh_credential_never_opens_a_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REQ-CREDS-006 / G7 clause 6: refused before connect, with every socket entry armed."""
    attempted: list[str] = []

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        attempted.append("socket")
        raise AssertionError("an armed socket was reached")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)

    from arachne.core.net import SocketTransport

    monkeypatch.setattr(SocketTransport, "open_stream", forbidden)
    monkeypatch.setattr(SocketTransport, "tcp", forbidden)

    sink = MemoryAuditSink()
    # The scope authorizes a *different* host, so the SSH target is refused.
    client = _client(sink, host="app.internal")
    result = await SshAuthenticator(client, _service(2222)).attempt(
        SSH_USER, SSH_PASSWORD, {"auth_method": "password"}
    )

    assert attempted == [], f"an out-of-scope SSH attempt reached the network: {attempted}"
    assert result.attempted is True
    assert result.accepted is False
    assert "scope" in result.detail.lower() or "OutOfScope" in result.status_name
    assert [event.action for event in sink.events] == [AuditAction.SCOPE_REJECTED]


# --------------------------------------------------------------------------- the check
async def _run_check(
    lab: SshLabServer,
    tmp_path: Path,
    *,
    secret: str | None,
    extra: dict[str, str] | None = None,
    scope_hosts: tuple[str, ...] = (LOOPBACK,),
) -> tuple[list[Any], Any, Any]:
    """Run ``m2.ssh-auth`` the way a scan does: real socket, real vault, real broker."""
    from tests.helpers.checks import asset_for, make_step_context, settings_for_checks
    from tests.helpers.vault import make_vault

    from arachne.core.config import SafetySettings
    from arachne.core.net import ScopedNetClient
    from arachne.core.planner import ScanStep
    from arachne.creds.broker import CredentialBroker
    from arachne.modules.context import CheckContext, ModuleConfig
    from arachne.modules.m2.inventory import NetworkInventory
    from arachne.modules.m2.ssh import SshAuth

    settings = settings_for_checks(
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
    )
    client = ScopedNetClient(
        settings=settings,
        scope=Scope(allowed_hosts=(LOOPBACK,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        auditor=None,
    )
    inventory = NetworkInventory(max_hosts=4, max_ports=32)
    record = inventory.host(LOOPBACK, declared=True)
    record.alive = True
    inventory.add_service(LOOPBACK, lab.port, service="ssh")

    step, memory = make_step_context(seed=[("host", LOOPBACK)])
    step.net = client
    step.inventory = inventory
    step.step = ScanStep.DISCOVERY
    if secret is not None:
        vault = make_vault(
            tmp_path,
            entries={
                "lab-ssh": {
                    "kind": "ssh",
                    "username": SSH_USER,
                    "secret": secret,
                    "scope": CredentialScope(hosts=scope_hosts),
                    "extra": extra or {"auth_method": "password"},
                }
            },
        )
        step.credentials = CredentialBroker(
            store=vault,
            labels=("lab-ssh",),
            auditor=memory.auditor,
            scan_id=memory.scan_id,
            hosts=(LOOPBACK,),
        )
    check = SshAuth()
    context = CheckContext(
        step=step,
        module=check,
        asset=asset_for("host", LOOPBACK),
        config=ModuleConfig(),
    )
    results = [result async for result in check.run(context)]
    try:
        return results, memory, check
    finally:
        await client.aclose()


async def test_an_authenticated_ssh_check_reports_access_an_anonymous_one_cannot(
    tmp_path: Path,
) -> None:
    """REQ-CREDS-006: the credentialed check establishes something the anonymous scan cannot."""
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        anonymous, _memory, _check = await _run_check(lab, tmp_path / "anon", secret=None)
        authenticated, memory, _check = await _run_check(
            lab, tmp_path / "authed", secret=SSH_PASSWORD
        )

    # Anonymous: the check has no credential capability and says so — no access, no finding.
    assert len(anonymous) == 1
    note = anonymous[0].evidence[0].payload
    assert note["skipped"] is True and "no credential capability" in note["reason"]

    # Authenticated: one finding that states the account has shell access.
    assert len(authenticated) == 1
    result = authenticated[0]
    assert result.status == "info"
    assert "accepted" in result.title.lower()
    assert "SUCCESS" in (result.detail or "")
    evidence = " ".join(repr(dict(item.payload)) for item in result.evidence)
    assert "'accepted': True" in evidence
    # The credential is nowhere in the finding, the evidence or the audit trail.
    assert SSH_PASSWORD not in evidence
    assert SSH_USER not in evidence
    assert all(SSH_PASSWORD not in repr(event.to_dict()) for event in memory.sink.events)
    # ...and the release was audited, so "which credential authenticated?" is answerable.
    actions = [event.action.value for event in memory.sink.events]
    assert "credential.released" in actions


async def test_an_ssh_credential_outside_its_scope_sends_nothing(tmp_path: Path) -> None:
    """REQ-CREDS-005's SSH half: the broker refuses before the authenticator is consulted."""
    with SshLabServer(username=SSH_USER, password=SSH_PASSWORD) as lab:
        results, memory, _check = await _run_check(
            lab, tmp_path, secret=SSH_PASSWORD, scope_hosts=("app.internal",)
        )
    assert len(results) == 1
    note = results[0].evidence[0].payload
    assert note["skipped"] is True and "no SSH credential" in note["reason"]
    assert lab.attempts == [], "the peer was contacted despite the scope refusal"
    actions = [event.action.value for event in memory.sink.events]
    assert "credential.scope_rejected" in actions
    assert "credential.released" not in actions


# --------------------------------------------------------------------------- the vault
def test_the_vault_holds_an_ssh_key_and_never_publishes_it(tmp_path: Path) -> None:
    """REQ-CREDS-006: a vault entry can hold an SSH key; the key is never logged or exported."""
    vault = _vault(tmp_path)
    seed_hex = KEY_SEED.hex()
    entry = vault.put(
        "lab-ssh",
        kind="ssh",
        username=SSH_USER,
        secret=seed_hex,
        scope=CredentialScope(hosts=(LOOPBACK,)),
        extra={"auth_method": "publickey", "key_type": "ed25519"},
    )
    assert entry.kind == "ssh"
    assert seed_hex not in repr(entry)
    assert seed_hex not in str(entry.to_dict())
    # The file on disk is encrypted and carries neither the seed nor the username.
    blob = (tmp_path / "vault.json").read_text()
    assert blob.startswith("ARACHNE-CV-1")
    assert seed_hex not in blob
    assert SSH_USER not in blob
    # The broker can still resolve it, which is the only path to the material.
    from arachne.core.vault import release_seam

    handle = vault.resolve("lab-ssh", host=LOOPBACK)
    assert handle is not None
    material = handle.material(release_seam())
    assert material.secret_value() == seed_hex
    assert material.extra_values()["auth_method"] == "publickey"


def test_an_ssh_credential_declares_its_method_and_key_type(tmp_path: Path) -> None:
    from arachne.core.errors import ConfigurationError

    vault = _vault(tmp_path)
    with pytest.raises(ConfigurationError, match="auth_method"):
        vault.put(
            "bad", kind="ssh", username=SSH_USER, secret="x", extra={"auth_method": "kerberos"}
        )
    with pytest.raises(ConfigurationError, match="ed25519"):
        vault.put(
            "bad",
            kind="ssh",
            username=SSH_USER,
            secret=KEY_SEED.hex(),
            extra={"auth_method": "publickey", "key_type": "rsa"},
        )
    # A password credential needs no key type.
    assert vault.put("ok", kind="ssh", username=SSH_USER, secret=SSH_PASSWORD).kind == "ssh"


def test_the_ssh_material_never_appears_in_a_handle_repr(tmp_path: Path) -> None:
    """The verdict carries a status name and a label — never the password or the key."""
    vault = _vault(tmp_path)
    vault.put(
        "lab-ssh",
        kind="ssh",
        username=SSH_USER,
        secret=SSH_PASSWORD,
        scope=CredentialScope(hosts=(LOOPBACK,)),
        extra={"auth_method": "password"},
    )
    from arachne.core.vault import release_seam

    handle = vault.resolve("lab-ssh", host=LOOPBACK)
    assert handle is not None
    assert SSH_PASSWORD not in repr(handle)
    assert SSH_PASSWORD not in str(handle.to_dict())
    material = handle.material(release_seam())
    assert material.secret_value() == SSH_PASSWORD
