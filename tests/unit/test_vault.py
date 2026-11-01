"""The credential vault: encrypted at rest, opaque handles, scope confinement (S19).

REQ-CREDS-002's two halves are tested here at the unit level — "encrypted at rest, released
only as an opaque scoped handle" — and REQ-CREDS-005's confinement rule: a credential is
bound to the hosts and URL prefixes it was stored for, and an unscoped entry covers nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from arachne.core.errors import (
    ConfigurationError,
    CredentialError,
    CredentialScopeError,
    VaultLockedError,
)
from arachne.core.vault import (
    VAULT_MAGIC,
    CredentialScope,
    FileCredentialVault,
    release_seam,
)

PASSPHRASE = "correct horse battery staple"
SECRET = "lab-portal-password-1"
USERNAME = "alice"


def vault(tmp_path: Path, *, passphrase: str = PASSPHRASE) -> FileCredentialVault:
    return FileCredentialVault(tmp_path / "vault.enc", passphrase=passphrase)


def store(
    store_vault: FileCredentialVault,
    *,
    label: str = "portal",
    kind: str = "web-form",
    scope: CredentialScope | None = None,
) -> None:
    store_vault.put(
        label,
        kind=kind,
        username=USERNAME,
        secret=SECRET,
        scope=scope if scope is not None else CredentialScope(url_prefixes=("http://127.0.0.1/",)),
        extra={"csrf_token": "t0ken"},
        login={"url": "http://127.0.0.1/login", "format": "form"},
        created_by="pytest",
    )


# --------------------------------------------------------------------------- at rest
def test_the_vault_file_is_ciphertext_and_carries_no_secret(tmp_path: Path) -> None:
    store_vault = vault(tmp_path)
    store(store_vault)
    raw = (tmp_path / "vault.enc").read_bytes()
    # The file is the encrypted format, and neither the secret nor the username is in it.
    assert raw.decode("ascii").splitlines()[0] == VAULT_MAGIC
    assert SECRET not in raw.decode("utf-8", errors="replace")
    assert USERNAME not in raw.decode("utf-8", errors="replace")


def test_a_wrong_passphrase_is_refused(tmp_path: Path) -> None:
    store(vault(tmp_path))
    other = FileCredentialVault(tmp_path / "vault.enc", passphrase="not the passphrase")
    with pytest.raises(ConfigurationError, match="could not be authenticated"):
        other.labels()


def test_a_tampered_vault_file_is_refused(tmp_path: Path) -> None:
    store(vault(tmp_path))
    path = tmp_path / "vault.enc"
    lines = path.read_text().splitlines()
    lines[3] = lines[3][:-4] + ("AAAA" if not lines[3].endswith("AAAA") else "BBBB")
    path.write_text("\n".join(lines) + "\n")
    other = FileCredentialVault(path, passphrase=PASSPHRASE)
    with pytest.raises(ConfigurationError, match="could not be authenticated"):
        other.labels()


def test_a_vault_without_a_passphrase_refuses_to_exist(tmp_path: Path) -> None:
    with pytest.raises(VaultLockedError, match="non-empty passphrase"):
        FileCredentialVault(tmp_path / "vault.enc", passphrase="")


def test_a_configured_path_without_a_key_is_a_refusal(tmp_path: Path) -> None:
    from types import SimpleNamespace

    settings = SimpleNamespace(vault=SimpleNamespace(path=str(tmp_path / "v.enc"), key=None))
    with pytest.raises(VaultLockedError, match="ARACHNE_VAULT_KEY"):
        FileCredentialVault.from_settings(settings)


def test_no_path_means_no_vault() -> None:
    from types import SimpleNamespace

    settings = SimpleNamespace(vault=SimpleNamespace(path=None, key=None))
    assert FileCredentialVault.from_settings(settings) is None


def test_entries_survive_a_reload(tmp_path: Path) -> None:
    store(vault(tmp_path))
    reread = FileCredentialVault(tmp_path / "vault.enc", passphrase=PASSPHRASE)
    labels = reread.labels()
    assert labels == ("portal",)
    handle = reread.resolve("portal", url="http://127.0.0.1/portal")
    assert handle is not None
    material = handle.material(release_seam())
    assert material.username == USERNAME
    assert material.secret_value() == SECRET
    assert material.extra_value("csrf_token") == "t0ken"


# --------------------------------------------------------------------------- handles
def test_a_handle_publishes_no_material(tmp_path: Path) -> None:
    store(vault(tmp_path))
    handle = vault(tmp_path).resolve("portal", url="http://127.0.0.1/portal")
    assert handle is not None
    # The public surface is label/kind/scope and the scope predicates — nothing else, and in
    # particular nothing that yields the secret or the username.
    public = [name for name in dir(handle) if not name.startswith("_")]
    rendered = json.dumps(handle.to_dict()) + repr(handle)
    assert SECRET not in rendered
    assert USERNAME not in rendered
    for name in public:
        value = getattr(handle, name)
        if callable(value):
            continue
        assert SECRET not in str(value)
    assert set(handle.describe()) == {"label", "kind", "scope", "scope_summary"}
    assert "secret" not in " ".join(public)


def test_material_needs_the_broker_capability(tmp_path: Path) -> None:
    store(vault(tmp_path))
    handle = vault(tmp_path).resolve("portal", url="http://127.0.0.1/portal")
    assert handle is not None
    with pytest.raises(CredentialError, match="opaque handles"):
        handle.material(object())
    with pytest.raises(CredentialError, match="opaque handles"):
        handle.material("seam")
    assert handle.material(release_seam()).secret_value() == SECRET


def test_material_repr_is_redacted() -> None:
    from arachne.core.vault import CredentialMaterial

    material = CredentialMaterial(username=USERNAME, secret=SecretStr(SECRET))
    assert SECRET not in repr(material)
    assert "**********" in repr(material)


# --------------------------------------------------------------------------- scope
def test_a_credential_outside_its_scope_is_refused(tmp_path: Path) -> None:
    store(vault(tmp_path))
    loaded = vault(tmp_path)
    with pytest.raises(CredentialScopeError, match="does not cover"):
        loaded.resolve("portal", url="https://other.example.com/portal")
    with pytest.raises(CredentialScopeError, match="does not cover"):
        loaded.resolve("portal", host="other.example.com")


def test_a_host_scoped_credential_covers_its_host_and_its_subdomains_only(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded, scope=CredentialScope(hosts=("app.example.com",)))
    assert loaded.resolve("portal", host="app.example.com") is not None
    assert loaded.resolve("portal", host="APP.example.com.") is not None
    with pytest.raises(CredentialScopeError):
        loaded.resolve("portal", host="api.example.com")


def test_an_unscoped_credential_covers_nothing(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded, scope=CredentialScope())
    assert CredentialScope().empty
    with pytest.raises(CredentialScopeError):
        loaded.resolve("portal", url="http://127.0.0.1/portal")


def test_an_unknown_label_resolves_to_none(tmp_path: Path) -> None:
    assert vault(tmp_path).resolve("absent") is None


def test_a_revoked_credential_is_refused_not_absent(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded)
    loaded.revoke("portal")
    assert loaded.get("portal") is not None and not loaded.get("portal").active  # type: ignore[union-attr]
    assert loaded.records() == ()
    assert loaded.records(include_revoked=True)[0].revoked_at is not None
    with pytest.raises(CredentialScopeError, match="revoked"):
        loaded.resolve("portal", url="http://127.0.0.1/portal")


def test_removing_an_entry_takes_its_material_with_it(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded)
    assert loaded.remove("portal") is True
    assert loaded.remove("portal") is False
    assert loaded.resolve("portal") is None
    assert PASSPHRASE not in (tmp_path / "vault.enc").read_text()


# --------------------------------------------------------------------------- writing
def test_put_replaces_in_place_and_keeps_the_original_creation_time(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded)
    first = loaded.get("portal")
    loaded.put("portal", kind="web-json", username="bob", secret="second-secret")
    second = loaded.get("portal")
    assert second is not None and first is not None
    assert second.created_at == first.created_at
    assert second.kind == "web-json"
    assert len(loaded.labels()) == 1


def test_an_invalid_label_or_kind_or_empty_secret_is_refused(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    with pytest.raises(ConfigurationError, match="label"):
        loaded.put("", kind="web-form", username="a", secret="b")
    with pytest.raises(ConfigurationError, match="label"):
        loaded.put("x" * 65, kind="web-form", username="a", secret="b")
    with pytest.raises(ConfigurationError, match="credential kind"):
        loaded.put("ok", kind="telnet", username="a", secret="b")
    with pytest.raises(ConfigurationError, match="non-empty secret"):
        loaded.put("ok", kind="web-form", username="a", secret="")


def test_the_entry_cap_is_enforced(tmp_path: Path) -> None:
    loaded = FileCredentialVault(tmp_path / "v.enc", passphrase=PASSPHRASE, max_entries=2)
    for index in range(2):
        loaded.put(f"c{index}", kind="web-form", username="a", secret="b")
    with pytest.raises(ConfigurationError, match="already holds"):
        loaded.put("c3", kind="web-form", username="a", secret="b")
    # Replacing an existing label is still allowed at the cap.
    loaded.put("c0", kind="web-form", username="a", secret="b2")
    assert len(loaded.labels()) == 2


def test_records_never_carry_material(tmp_path: Path) -> None:
    loaded = vault(tmp_path)
    store(loaded)
    rendered = json.dumps([record.to_dict() for record in loaded.records()])
    assert SECRET not in rendered and USERNAME not in rendered
    assert loaded.records()[0].has_login_spec is True
    assert loaded.records()[0].has_extra is True
