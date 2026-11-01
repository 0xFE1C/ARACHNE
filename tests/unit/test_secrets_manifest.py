"""The operator's secrets manifest: masked ledger, encrypted at rest (F-08-04, ADR-120.6).

Three properties are the whole point of the class and none of them is visible in a scan's
output, so they are asserted here:

1. **No usable value is stored.** The manifest records a detector name and a masked
   fingerprint; the file must not contain the raw credential.
2. **The file on disk is ciphertext.** A wrong passphrase and a tampered byte are both
   refused, and the plaintext JSON does not appear in the bytes.
3. **The default is off, and a path without a key is refused.** A deployment that has not
   configured the feature writes nothing, and one that configured only a path gets an error
   rather than an unencrypted ledger.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from tests.conftest import TARGET_HOST

from arachne.core.config import SecretsSettings, Settings
from arachne.core.errors import ConfigurationError
from arachne.core.http import ScopedHttpClient
from arachne.core.redaction import masked_secret_findings
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.secrets import (
    MANIFEST_MAGIC,
    SecretsManifest,
    decrypt_manifest,
    encrypt_manifest,
    load_manifest,
)

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "sup3rs3cr3t-db-password"
PASSPHRASE = "correct horse battery staple"


# --------------------------------------------------------------------------- encryption
def test_encrypt_decrypt_round_trips_and_produces_ciphertext() -> None:
    payload = json.dumps({"secrets": [{"kind": "aws-access-key-id"}]}).encode()
    blob = encrypt_manifest(payload, PASSPHRASE)
    assert blob.startswith(MANIFEST_MAGIC.encode())
    assert payload not in blob
    assert decrypt_manifest(blob, PASSPHRASE) == payload


def test_a_wrong_passphrase_is_refused() -> None:
    blob = encrypt_manifest(b"secret payload", PASSPHRASE)
    with pytest.raises(ConfigurationError, match="could not be authenticated"):
        decrypt_manifest(blob, "not the passphrase")


def test_a_tampered_manifest_is_refused() -> None:
    blob = encrypt_manifest(b"secret payload", PASSPHRASE).decode()
    lines = blob.splitlines()
    # Flip one base64 character of the ciphertext; the MAC must catch it.
    cipher = lines[3]
    lines[3] = ("A" if cipher[0] != "A" else "B") + cipher[1:]
    with pytest.raises(ConfigurationError, match="could not be authenticated"):
        decrypt_manifest("\n".join(lines).encode(), PASSPHRASE)


def test_a_malformed_or_truncated_file_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        decrypt_manifest(b"not a manifest", PASSPHRASE)
    blob = encrypt_manifest(b"x", PASSPHRASE).decode().splitlines()[:2]
    with pytest.raises(ConfigurationError):
        decrypt_manifest("\n".join(blob).encode(), PASSPHRASE)


def test_an_empty_passphrase_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="non-empty passphrase"):
        encrypt_manifest(b"x", "")
    with pytest.raises(ConfigurationError, match="non-empty passphrase"):
        SecretsManifest("m.enc", passphrase="")


# --------------------------------------------------------------------------- the ledger
def test_the_manifest_masks_values_and_writes_ciphertext(tmp_path: Path) -> None:
    path = tmp_path / "secrets.enc"
    manifest = SecretsManifest(path, passphrase=PASSPHRASE)
    for kind, masked in masked_secret_findings(
        f"aws_access_key_id={AWS_ACCESS_KEY}\ndb_password={DB_PASSWORD}\n"
    ):
        manifest.record(kind, masked, source="https://example.com/.env", check="m4.env-file-probe")
    assert len(manifest) >= 1
    written = manifest.flush()
    assert written == path

    raw = path.read_bytes()
    assert AWS_ACCESS_KEY.encode() not in raw
    assert AWS_SECRET_KEY.encode() not in raw
    assert DB_PASSWORD.encode() not in raw

    records = load_manifest(path, PASSPHRASE)
    assert records
    assert {item["kind"] for item in records} & {"aws-access-key-id", "sensitive-key-value"}
    assert all(item["source"] == "https://example.com/.env" for item in records)
    assert all("masked" in item and item["masked"] for item in records)


def test_the_manifest_deduplicates_and_caps() -> None:
    manifest = SecretsManifest("unused.enc", passphrase=PASSPHRASE, max_records=2)
    assert manifest.record("a", "AAAA...AA (12 chars)", source="s") is not None
    assert manifest.record("a", "AAAA...AA (12 chars)", source="s") is None  # duplicate
    assert manifest.record("b", "BBBB...BB (12 chars)", source="s") is not None
    assert manifest.record("c", "CCCC...CC (12 chars)", source="s") is None  # capped


def test_an_empty_manifest_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "empty.enc"
    assert SecretsManifest(path, passphrase=PASSPHRASE).flush() is None
    assert not path.exists()


# --------------------------------------------------------------------------- configuration
def test_the_manifest_is_off_unless_a_path_is_configured() -> None:
    assert SecretsSettings().enabled is False
    assert SecretsManifest.from_settings(Settings()) is None
    assert SecretsSettings(manifest_path="x.enc", manifest_key=None).enabled is True


def test_a_path_without_a_key_is_refused_rather_than_written_in_clear() -> None:
    settings = Settings(secrets=SecretsSettings(manifest_path="/tmp/secret.enc"))
    with pytest.raises(ConfigurationError, match="ARACHNE_SECRETS_MANIFEST_KEY"):
        SecretsManifest.from_settings(settings)


def test_settings_read_the_manifest_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "ARACHNE_SECRETS_MANIFEST": "/tmp/arachne-secrets.enc",
            "ARACHNE_SECRETS_MANIFEST_KEY": PASSPHRASE,
            "ARACHNE_SECRETS_MANIFEST_MAX": "42",
        }
    )
    assert settings.secrets.manifest_path == "/tmp/arachne-secrets.enc"
    assert settings.secrets.max_records == 42
    assert settings.secrets.manifest_key is not None
    assert settings.secrets.manifest_key.get_secret_value() == PASSPHRASE
    # A secret read from the environment must not print itself.
    assert PASSPHRASE not in repr(settings.secrets)


# --------------------------------------------------------------------------- capture time
async def test_the_http_client_feeds_the_manifest_masked_values(tmp_path: Path) -> None:
    """Redaction and the ledger are the same step: the client records, then discards."""
    path = tmp_path / "capture.enc"
    manifest = SecretsManifest(path, passphrase=PASSPHRASE)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}\nDB_PASSWORD={DB_PASSWORD}\n",
            headers={"content-type": "text/plain"},
        )

    client = ScopedHttpClient(
        settings=Settings(log_level="CRITICAL"),
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        policy=UrlSafetyPolicy(),
        transport=httpx.MockTransport(handler),
        secrets_manifest=manifest,
    )
    exchange = await client.get(f"https://{TARGET_HOST}/.env")
    assert AWS_ACCESS_KEY not in exchange.body
    assert DB_PASSWORD not in exchange.body
    await client.aclose()

    assert path.exists()
    records = load_manifest(path, PASSPHRASE)
    kinds = {item["kind"] for item in records}
    assert "aws-access-key-id" in kinds
    assert "sensitive-key-value" in kinds
    assert AWS_ACCESS_KEY not in path.read_text(errors="replace")


async def test_a_manifest_write_failure_does_not_fail_the_scan(tmp_path: Path) -> None:
    """An audit/ledger sink failing must never abort the work it was recording."""
    manifest = SecretsManifest(tmp_path / "sub" / "x.enc", passphrase=PASSPHRASE)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}",
            headers={"content-type": "text/plain"},
        )

    client = ScopedHttpClient(
        settings=Settings(log_level="CRITICAL"),
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        policy=UrlSafetyPolicy(),
        transport=httpx.MockTransport(handler),
        secrets_manifest=manifest,
    )
    await client.get(f"https://{TARGET_HOST}/x")
    manifest.path = tmp_path / "blocked"  # a directory cannot be replaced by a file
    (tmp_path / "blocked").mkdir()
    await client.aclose()  # must not raise
