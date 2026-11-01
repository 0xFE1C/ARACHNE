"""Test helpers for the S19 credential vault and credentialed scans.

A vault is a real encrypted file, so a test builds one in ``tmp_path`` and points the scan at
it. Nothing here mocks the crypto or the scope check: a test that asserts a credential was
refused must be able to trust that the refusal came from the production path.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from arachne.core.config import VaultSettings
from arachne.core.vault import CredentialScope, FileCredentialVault

__all__ = [
    "LAB_PASSPHRASE",
    "make_vault",
    "portal_credential",
    "vault_settings",
]

#: The passphrase every test vault uses. It is a test constant, and it never leaves tmp_path.
LAB_PASSPHRASE = "test-vault-passphrase"


def make_vault(
    tmp_path: Path,
    *,
    entries: Mapping[str, Mapping[str, Any]] | None = None,
    passphrase: str = LAB_PASSPHRASE,
    name: str = "credentials.enc",
) -> FileCredentialVault:
    """An encrypted vault file in ``tmp_path``, optionally pre-populated.

    Each ``entries`` value is passed straight to :meth:`FileCredentialVault.put`, so a test
    declares exactly the entry it wants (kind, scope, username, secret, extra, login).
    """
    vault = FileCredentialVault(tmp_path / name, passphrase=passphrase)
    for label, fields in dict(entries or {}).items():
        payload = dict(fields)
        vault.put(label, created_by="pytest", **payload)
    return vault


def vault_settings(
    tmp_path: Path, *, passphrase: str = LAB_PASSPHRASE
) -> VaultSettings:
    """The :class:`VaultSettings` pointing at this test's vault file."""
    return VaultSettings(
        path=str(tmp_path / "credentials.enc"),
        key=SecretStr(passphrase),
    )


def portal_credential(
    base_url: str,
    *,
    username: str,
    password: str,
    scope_hosts: tuple[str, ...] = ("127.0.0.1",),
    login: Mapping[str, Any] | None = None,
    kind: str = "web-form",
    extra: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The keyword arguments for a web credential scoped to the web lab.

    The default ``login`` block declares the lab's flow explicitly (URL, field names, the
    canary and the *soft* logout), which is the documented path for an application whose
    login is known; omit it to exercise detection from the crawl's own form.
    """
    base = base_url.rstrip("/")
    declared: dict[str, Any] | None
    if login is None:
        declared = {
            "url": f"{base}/login",
            "format": "form",
            "username_field": "username",
            "password_field": "password",
            "protected_url": f"{base}/portal/keep-alive",
            "logout_url": f"{base}/logout-soft",
        }
    else:
        declared = dict(login) or None
    return {
        "kind": kind,
        "username": username,
        "secret": password,
        "scope": CredentialScope(hosts=scope_hosts),
        "extra": dict(extra or {}),
        "login": declared,
    }
