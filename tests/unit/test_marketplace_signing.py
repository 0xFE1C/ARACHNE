"""Content-pack and marketplace-index signing is fail-closed, with rotation (REQ-ECOS-008).

REQ-ECOS-008's rationale is the reason these are safety-shaped tests rather than feature tests:
the marketplace index is a **trust-redirection document**, so reviewing the packs while trusting
an unverified index protects nothing. The properties asserted here are the requirement's own
words:

* an unsigned or wrongly signed pack is refused with an actionable message;
* an index entry pointing at an unverified pack is refused **before download**;
* the key set is configurable and defaults to none — fail-closed, not fail-open;
* rotation is possible without a flag day: two keys are valid during the overlap.

The keys below are test material held in variables, never literals in ``src/`` (F-08-01): the
production path reads them from ``ARACHNE_INTEGRITY_KEY`` and ``ARACHNE_CONTENT_KEYS``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import Settings, reset_settings_cache
from arachne.core.errors import ConfigurationError
from arachne.core.signing import DeploymentSigner, SigningKeyring, build_content_keyring
from arachne.plugins.marketplace import (
    INDEX_DOMAIN,
    load_marketplace,
    require_verified_entry,
    sign_index,
)
from arachne.plugins.review import review_pack
from arachne.resil.packs import build_pack, read_pack

runner = CliRunner()

#: The deployment's own key (``ARACHNE_INTEGRITY_KEY`` in production).
OWN_KEY = "index-signing-test-key-000000000001"
#: The previous key, kept in the rotation set while content is re-signed.
OLD_KEY = "index-signing-test-key-000000000002"
#: Somebody else's key: never in any key set here.
FOREIGN_KEY = "index-signing-test-key-000000000003"

OWN = DeploymentSigner(OWN_KEY)
OLD = DeploymentSigner(OLD_KEY)
FOREIGN = DeploymentSigner(FOREIGN_KEY)

INDEX: dict[str, object] = {
    "version": "2.0",
    "updated": "2026-11-04",
    "plugins": [
        {
            "name": "local-plugin",
            "kind": "check",
            "description": "a locally built check pack",
            "version": "1.0",
            "source": "/tmp/local-plugin",
            "entry_point_group": "arachne.modules",
            "verified": True,
            "pack_key_id": OWN.key_id,
        }
    ],
}


def _write_index(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "index.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _pack(tmp_path: Path, *, signer: DeploymentSigner | None) -> bytes:
    root = tmp_path / "content"
    root.mkdir(exist_ok=True)
    (root / "check.yaml").write_text(
        "checks:\n  - name: m4.local\n    proof: L1\n", encoding="utf-8"
    )
    data, _, _ = build_pack({"checks": root}, name="local", version="1.0", signer=signer)
    return data


def _keyring(*signers: DeploymentSigner) -> SigningKeyring:
    return SigningKeyring(signers)


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., None]]:
    """Point the cached settings the CLI reads at a key (or at no key) for one test."""

    def apply(**pairs: str | None) -> None:
        for name, value in pairs.items():
            if value is None:
                monkeypatch.delenv(name, raising=False)
            else:
                monkeypatch.setenv(name, value)
        reset_settings_cache()

    apply(ARACHNE_INTEGRITY_KEY=None, ARACHNE_CONTENT_KEYS=None, ARACHNE_MARKETPLACE=None)
    yield apply
    reset_settings_cache()


# ------------------------------------------------------------------ the pack half
def test_an_unsigned_pack_is_refused_with_an_actionable_message(tmp_path: Path) -> None:
    data = _pack(tmp_path, signer=None)
    with pytest.raises(Exception, match="carries no signature") as excinfo:
        read_pack(data, keyring=_keyring(OWN))
    assert str(excinfo.value).strip(), "the refusal must say something"
    # The review pipeline reports the same refusal as a *gate outcome* with a reason.
    report = review_pack(
        read_pack(data, keyring=_keyring(OWN), require_signature=False), keyring=_keyring(OWN)
    )
    assert report.listed is False
    assert report.gate("signature") is not None
    assert "never listed" in report.gate("signature").detail  # type: ignore[union-attr]


def test_a_pack_signed_by_another_deployment_is_refused(tmp_path: Path) -> None:
    data = _pack(tmp_path, signer=FOREIGN)
    with pytest.raises(Exception, match="does not verify"):
        read_pack(data, keyring=_keyring(OWN))


def test_a_pack_signed_by_either_rotation_key_verifies(tmp_path: Path) -> None:
    """The overlap: the pack may still be signed by the previous key while content is re-signed."""
    rotation = _keyring(OWN, OLD)
    assert read_pack(_pack(tmp_path, signer=OWN), keyring=rotation) is not None
    assert read_pack(_pack(tmp_path, signer=OLD), keyring=rotation) is not None
    # ... and a key outside the set is still refused.
    with pytest.raises(Exception, match="does not verify"):
        read_pack(_pack(tmp_path, signer=FOREIGN), keyring=rotation)


def test_no_key_configured_refuses_every_signed_pack(tmp_path: Path) -> None:
    """Fail-closed, not fail-open: an empty key set accepts nothing."""
    data = _pack(tmp_path, signer=OWN)
    empty = SigningKeyring()
    assert empty.key_ids() == ()
    assert empty.verify("any.domain", b"payload", OWN.sign("any.domain", b"payload")) is False
    with pytest.raises(Exception, match="no content key is configured"):
        read_pack(data, keyring=empty)


def test_the_keyring_reports_which_keys_it_would_accept(tmp_path: Path) -> None:
    ring = _keyring(OWN, OLD)
    assert ring.key_ids() == (OWN.key_id, OLD.key_id)
    assert ring.admits(OLD.key_id) is True
    assert ring.admits(FOREIGN.key_id) is False
    assert ring.admits(None) is False
    # The primary is the deployment's own key: a rotation key verifies but never mints.
    assert ring.signer is OWN
    signature = ring.sign(INDEX_DOMAIN, b"payload")
    assert signature.startswith(f"v1:{OWN.key_id}:")


# ------------------------------------------------------------------ the index half
def test_an_unsigned_operator_supplied_index_is_refused(tmp_path: Path) -> None:
    path = _write_index(tmp_path, INDEX)
    with pytest.raises(ConfigurationError, match="carries no signature") as excinfo:
        load_marketplace(path, keyring=_keyring(OWN))
    assert "ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX" in str(excinfo.value)


def test_an_unsigned_index_loads_only_with_the_documented_escape_hatch(tmp_path: Path) -> None:
    path = _write_index(tmp_path, INDEX)
    catalogue = load_marketplace(path, keyring=_keyring(OWN), allow_unsigned=True)
    assert catalogue.trust == "unsigned"
    assert catalogue.verified is False
    assert [entry.name for entry in catalogue.entries] == ["local-plugin"]


def test_a_signed_index_verifies(tmp_path: Path) -> None:
    path = _write_index(tmp_path, sign_index(INDEX, OWN))
    catalogue = load_marketplace(path, keyring=_keyring(OWN))
    assert catalogue.verified is True
    assert catalogue.trust == "signed"
    assert catalogue.signature_key_id == OWN.key_id


def test_signing_is_idempotent(tmp_path: Path) -> None:
    once = sign_index(INDEX, OWN)
    twice = sign_index(once, OWN)
    assert once == twice


def test_a_signed_index_with_no_key_configured_is_refused(tmp_path: Path) -> None:
    path = _write_index(tmp_path, sign_index(INDEX, OWN))
    with pytest.raises(ConfigurationError, match="no content key configured"):
        load_marketplace(path, keyring=SigningKeyring())


def test_an_index_signed_by_an_untrusted_key_is_refused_and_names_the_key(tmp_path: Path) -> None:
    path = _write_index(tmp_path, sign_index(INDEX, FOREIGN))
    with pytest.raises(ConfigurationError) as excinfo:
        load_marketplace(path, keyring=_keyring(OWN))
    message = str(excinfo.value)
    assert FOREIGN.key_id in message
    assert OWN.key_id in message, "the refusal must name what it would have accepted"


def test_an_index_edited_after_signing_is_refused(tmp_path: Path) -> None:
    """The tamper case: one character in one entry, and the index no longer loads."""
    signed = sign_index(INDEX, OWN)
    plugins = signed["plugins"]
    assert isinstance(plugins, list)
    entry = dict(plugins[0])
    entry["source"] = "/tmp/somewhere-else"
    tampered = {**signed, "plugins": [entry]}
    path = _write_index(tmp_path, tampered)
    with pytest.raises(ConfigurationError, match="does not verify"):
        load_marketplace(path, keyring=_keyring(OWN))


def test_an_index_signed_by_the_previous_key_verifies_during_the_overlap(tmp_path: Path) -> None:
    """Rotation without a flag day: the old signature still verifies while keys change over."""
    path = _write_index(tmp_path, sign_index(INDEX, OLD))
    catalogue = load_marketplace(path, keyring=_keyring(OWN, OLD))
    assert catalogue.verified is True
    assert catalogue.signature_key_id == OLD.key_id
    # ... and with the rotation set gone, the same index is refused.
    with pytest.raises(ConfigurationError, match="does not verify"):
        load_marketplace(path, keyring=_keyring(OWN))


def test_the_bundled_index_needs_no_runtime_signature() -> None:
    """It ships inside the package: its integrity is the package's, not a runtime signature."""
    catalogue = load_marketplace(keyring=SigningKeyring())
    assert catalogue.trust == "bundled"
    assert catalogue.verified is True


# ------------------------------------------------------------------ the entry half
def test_an_entry_from_an_unverified_index_is_refused(tmp_path: Path) -> None:
    catalogue = load_marketplace(
        _write_index(tmp_path, INDEX), keyring=_keyring(OWN), allow_unsigned=True
    )
    entry = catalogue.entries[0]
    with pytest.raises(ConfigurationError, match="not signature-verified") as excinfo:
        require_verified_entry(catalogue, entry, keyring=_keyring(OWN))
    assert "nothing was downloaded" in str(excinfo.value)


def test_an_entry_that_names_no_pack_key_is_refused(tmp_path: Path) -> None:
    """A 'verified' claim with nothing behind it is an assertion, not a fact (spec §7)."""
    document = {**INDEX, "plugins": [{**INDEX["plugins"][0], "pack_key_id": None}]}  # type: ignore[index]
    catalogue = load_marketplace(
        _write_index(tmp_path, sign_index(document, OWN)), keyring=_keyring(OWN)
    )
    with pytest.raises(ConfigurationError, match="names no pack_key_id"):
        require_verified_entry(catalogue, catalogue.entries[0], keyring=_keyring(OWN))


def test_an_entry_pointing_at_an_untrusted_pack_key_is_refused(tmp_path: Path) -> None:
    document = {
        **INDEX,
        "plugins": [{**INDEX["plugins"][0], "pack_key_id": FOREIGN.key_id}],  # type: ignore[index]
    }
    catalogue = load_marketplace(
        _write_index(tmp_path, sign_index(document, OWN)), keyring=_keyring(OWN)
    )
    with pytest.raises(ConfigurationError, match="Refused before download"):
        require_verified_entry(catalogue, catalogue.entries[0], keyring=_keyring(OWN))


def test_an_entry_marked_unreviewed_is_refused(tmp_path: Path) -> None:
    document = {
        **INDEX,
        "plugins": [{**INDEX["plugins"][0], "verified": False}],  # type: ignore[index]
    }
    catalogue = load_marketplace(
        _write_index(tmp_path, sign_index(document, OWN)), keyring=_keyring(OWN)
    )
    with pytest.raises(ConfigurationError, match="not marked as reviewed"):
        require_verified_entry(catalogue, catalogue.entries[0], keyring=_keyring(OWN))


def test_a_trusted_entry_passes(tmp_path: Path) -> None:
    catalogue = load_marketplace(
        _write_index(tmp_path, sign_index(INDEX, OWN)), keyring=_keyring(OWN)
    )
    require_verified_entry(catalogue, catalogue.entries[0], keyring=_keyring(OWN))


# ------------------------------------------------------------------ the CLI
def test_the_cli_refuses_to_install_from_an_unverified_index(
    tmp_path: Path, cli_env: Callable[..., None]
) -> None:
    """'Refused before download': the refusal happens and no installer runs at all."""
    cli_env(ARACHNE_INTEGRITY_KEY=OWN_KEY)
    path = _write_index(tmp_path, INDEX)
    refused = runner.invoke(
        app,
        ["plugin", "install", "--entry", "local-plugin", "--index", str(path), "--dry-run"],
    )
    assert refused.exit_code == 2, refused.output
    assert "REFUSED" in refused.output
    assert "signature" in refused.output
    assert "would execute" not in refused.output, "a download step ran after a refusal"


def test_the_cli_refuses_an_entry_outside_the_download_boundary(
    tmp_path: Path, cli_env: Callable[..., None]
) -> None:
    """A signed index whose entry names an untrusted pack key is refused before pip."""
    cli_env(ARACHNE_INTEGRITY_KEY=OWN_KEY)
    document = {
        **INDEX,
        "plugins": [{**INDEX["plugins"][0], "pack_key_id": FOREIGN.key_id}],  # type: ignore[index]
    }
    path = _write_index(tmp_path, sign_index(document, OWN))
    refused = runner.invoke(
        app,
        ["plugin", "install", "--entry", "local-plugin", "--index", str(path), "--dry-run"],
    )
    assert refused.exit_code == 2
    assert "does not accept" in refused.output


def test_the_cli_installs_from_a_verified_index_after_verification(
    tmp_path: Path, cli_env: Callable[..., None]
) -> None:
    """The happy path: the index verifies, the entry is trusted, and pip is *then* invoked."""
    cli_env(ARACHNE_INTEGRITY_KEY=OWN_KEY)
    package = tmp_path / "local-plugin"
    package.mkdir()
    (package / "pyproject.toml").write_text("[project]\nname='local-plugin'\n", encoding="utf-8")
    document = {
        **INDEX,
        "plugins": [{**INDEX["plugins"][0], "source": str(package)}],  # type: ignore[index]
    }
    path = _write_index(tmp_path, sign_index(document, OWN))
    installed = runner.invoke(
        app,
        ["plugin", "install", "--entry", "local-plugin", "--index", str(path), "--dry-run"],
    )
    assert installed.exit_code == 0, installed.output
    assert "-m pip install" in installed.output


def test_the_cli_marketplace_refuses_an_unverified_index(
    tmp_path: Path, cli_env: Callable[..., None]
) -> None:
    path = _write_index(tmp_path, INDEX)
    cli_env(ARACHNE_MARKETPLACE=str(path))
    refused = runner.invoke(app, ["plugin", "marketplace"])
    assert refused.exit_code == 2
    assert "carries no signature" in refused.output


# ------------------------------------------------------------------ the settings seam
def test_the_key_set_comes_from_the_environment_and_defaults_to_none() -> None:
    """'Configurable and defaults to none': no key configured means no key accepted."""
    assert build_content_keyring(Settings()).key_ids() == (), "no key by default"

    loaded = Settings.from_env(
        {
            "ARACHNE_INTEGRITY_KEY": OWN_KEY,
            "ARACHNE_CONTENT_KEYS": f"{OLD_KEY},\n{FOREIGN_KEY}",
        }
    )
    ring = build_content_keyring(loaded)
    assert len(ring) == 3, "the deployment key plus both rotation keys"
    assert ring.signer is not None
    assert ring.signer.key_id == OWN.key_id, "signing uses the deployment's own key"
    # A blank entry is skipped rather than admitted as a key.
    sparse = Settings.from_env({"ARACHNE_CONTENT_KEYS": f"{OLD_KEY},,"})
    assert len(build_content_keyring(sparse)) == 1


def test_the_content_keys_are_never_rendered() -> None:
    """A rotation key is a secret: it must not be printable through the settings object."""
    settings = Settings.from_env({"ARACHNE_CONTENT_KEYS": OLD_KEY})
    assert OLD_KEY not in repr(settings.integrity)
    assert OLD_KEY not in str(settings.integrity.content_keys)
