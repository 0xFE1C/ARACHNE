"""Redaction fuzz test (F-08-01, F-08-04, and §9 #3).

Where ``test_redaction.py`` pins a handful of literals, this file drives the redactor with
a broad, *generated* corpus of credential shapes so a regression in any one detector — or a
new detector that quietly drops a family — fails here rather than in production.

Two properties are asserted, for every generated secret:

* **No leak.** The raw value must not survive ``redact_text`` / ``redact_headers`` /
  ``redact_url`` in any realistic carrier (JSON, YAML, an env/log line, SQL, a header, an
  Azure connection string, a URL query), and ``contains_secret`` must flag the carrier.
* **Linear cost.** Redaction stays linear on adversarial input, so a hostile target cannot
  turn a 64 KB body into a hang (the family ``test_redaction_perf.py`` guards).

Design note on "standalone" vs "carrier": a bare high-entropy string with no recognisable
prefix is, by design, undetectable by pattern alone — ``mask_secret``'s docstring states
that masking has to happen where the match is made (``core/redaction.py:53-64``). The real
guarantee is therefore *carrier-aware*: any of these values carried under a sensitive key,
header, or context is removed. Families that a ``SECRET_PATTERNS`` regex also recognises in
isolation carry ``standalone=True`` and are asserted to be caught bare as well; the rest are
asserted only in their carriers. Nothing impossible is claimed.

``hypothesis`` is deliberately *not* used: it is not an installed dev dependency
(``pip show hypothesis`` → not found), and a seeded ``random.Random`` plus an explicit
carrier matrix is fully reproducible and needs no new dependency. The corpus is bounded
(≈ 10^3 short redactions), so the suite runs in well under a second.
"""

from __future__ import annotations

import base64
import json
import random
import string
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from arachne.core.redaction import (
    contains_secret,
    masked_secret_findings,
    redact_headers,
    redact_text,
    redact_url,
)

#: Fixed seed: the corpus is random-looking but every run is byte-identical, so a failure
#: is reproducible from the message alone.
_RNG_SEED = 0x5EC5A9
_VARIANTS_PER_FAMILY = 4

_ALNUM = string.ascii_letters + string.digits
_B64 = string.ascii_letters + string.digits + "+/="
_B64URL = string.ascii_letters + string.digits + "-_"
_HEX = "0123456789abcdef"
_UPPER = string.ascii_uppercase + string.digits


def _rand(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class SecretFamily:
    """One credential shape: a name, whether a bare form is pattern-detectable, a generator."""

    name: str
    standalone: bool
    make: Callable[[random.Random], str]


def _jwt(rng: random.Random) -> str:
    header = "eyJ" + _rand(rng, _B64URL, 20)
    payload = "eyJ" + _rand(rng, _B64URL, 40)
    signature = _rand(rng, _B64URL, 43)
    return f"{header}.{payload}.{signature}"


def _pem(label: str) -> Callable[[random.Random], str]:
    def make(rng: random.Random) -> str:
        body = "\n".join(_rand(rng, _B64, 64) for _ in range(3))
        return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"

    return make


def _connection_string(scheme: str) -> Callable[[random.Random], str]:
    def make(rng: random.Random) -> str:
        return (
            f"{scheme}://{_rand(rng, string.ascii_lowercase, 6)}:"
            f"{_rand(rng, _ALNUM, 18)}@db.internal:5432/app"
        )

    return make


#: Every family the fuzz corpus must cover. ``standalone`` mirrors what ``SECRET_PATTERNS``
#: actually matches in isolation (verified against the live redactor, not assumed).
FAMILIES: tuple[SecretFamily, ...] = (
    SecretFamily("aws-access-key-id", True, lambda r: "AKIA" + _rand(r, _UPPER, 16)),
    SecretFamily("aws-session-key-id", True, lambda r: "ASIA" + _rand(r, _UPPER, 16)),
    SecretFamily("github-ghp-token", True, lambda r: "ghp_" + _rand(r, _ALNUM, 40)),
    SecretFamily("github-pat-token", False, lambda r: "github_pat_" + _rand(r, _ALNUM, 52)),
    SecretFamily("stripe-live-key", True, lambda r: "sk_live_" + _rand(r, _ALNUM, 24)),
    SecretFamily("openai-style-key", False, lambda r: "sk-proj-" + _rand(r, _ALNUM, 40)),
    SecretFamily(
        "slack-token", True, lambda r: f"xoxb-{_rand(r, _ALNUM, 12)}-{_rand(r, _ALNUM, 16)}"
    ),
    SecretFamily("google-api-key", True, lambda r: "AIza" + _rand(r, _B64URL, 35)),
    SecretFamily("twilio-key", False, lambda r: "SK" + _rand(r, _HEX, 32)),
    SecretFamily(
        "sendgrid-key", False, lambda r: f"SG.{_rand(r, _B64URL, 22)}.{_rand(r, _B64URL, 43)}"
    ),
    SecretFamily("npm-token", False, lambda r: "npm_" + _rand(r, _ALNUM, 36)),
    SecretFamily("pypi-token", False, lambda r: "pypi-" + _rand(r, _B64URL, 40)),
    SecretFamily("jwt", True, _jwt),
    SecretFamily("pem-rsa", True, _pem("RSA PRIVATE KEY")),
    SecretFamily("pem-ec", True, _pem("EC PRIVATE KEY")),
    SecretFamily("pem-openssh", True, _pem("OPENSSH PRIVATE KEY")),
    SecretFamily("bare-base64", False, lambda r: _rand(r, _B64, 44)),
    SecretFamily("bare-hex", False, lambda r: _rand(r, _HEX, 64)),
    SecretFamily("connection-postgres", True, _connection_string("postgres")),
    SecretFamily("connection-mysql", True, _connection_string("mysql")),
    # An operator's credential is usually an *ordinary* string with no recognisable shape: it
    # is only ever protected by the key it is submitted under (S19, REQ-CREDS-002). This
    # family is therefore carrier-dependent by construction, and the carrier set below is what
    # the credential path actually walks.
    SecretFamily(
        "user-password",
        False,
        lambda r: (
            f"{_rand(r, string.ascii_lowercase, 8)}-{_rand(r, _ALNUM, 10)}-{r.randrange(100)}"
        ),
    ),
)

#: Text carriers: each wraps a secret under a sensitive key/context. A leak in any is a bug.
_TEXT_CARRIERS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("json", lambda s: f'{{"service": {{"api_key": "{s}"}}}}'),
    ("yaml", lambda s: f"service:\n  api_key: {s}\n"),
    ("dotenv-log", lambda s: f"2026-10-29T09:00:00Z INFO config APP_SECRET={s}"),
    ("access-log", lambda s: f'level=info msg="auth ok" token={s} user=alice'),
    # The carrier *is* a SQL literal in a test fixture; no database is ever reached.
    ("sql", lambda s: f"UPDATE users SET password='{s}' WHERE id=1"),  # noqa: S608
    ("header-line", lambda s: f"X-Api-Key: {s}"),
    (
        "azure-connection-string",
        lambda s: f"DefaultEndpointsProtocol=https;AccountKey={s};EndpointSuffix=core.windows.net",
    ),
)

#: Header carriers: the header *name* is sensitive, so the whole value must be blanked.
_HEADER_CARRIERS: tuple[tuple[str, str, Callable[[str], str]], ...] = (
    ("authorization", "Authorization", lambda s: s),
    ("api-key", "X-Api-Key", lambda s: s),
    ("bearer", "Authorization", lambda s: f"Bearer {s}"),
    ("cookie", "Cookie", lambda s: f"session={s}"),
    ("set-cookie", "Set-Cookie", lambda s: f"session={s}; Path=/; HttpOnly"),
)


#: Credential carriers (S19): the shapes a credentialed scan submits or receives. A leak in any
#: of them is a leak of the vaulted credential, so each is checked for the secret *and* the
#: username.
_CREDENTIAL_CARRIERS: tuple[tuple[str, Callable[[str, str], str]], ...] = (
    # The single most common login body, and the shape the redactor missed before S19: the
    # credential is the *second* field, so a delimiter-class miss left it in the clear.
    ("form-login-body", lambda user, secret: f"username={user}&password={secret}&submit=Log+in"),
    ("form-csrf-body", lambda user, secret: f"csrf_token=t0ken&user={user}&passwd={secret}"),
    ("json-login-body", lambda user, secret: f'{{"username": "{user}", "password": "{secret}"}}'),
    ("query-login", lambda user, secret: f"https://app.local/login?user={user}&password={secret}"),
    (
        "multipart-login",
        lambda user, secret: (
            '------arachne1a2b\r\nContent-Disposition: form-data; name="username"\r\n\r\n'
            f"{user}\r\n"
            '------arachne1a2b\r\nContent-Disposition: form-data; name="password"\r\n\r\n'
            f"{secret}\r\n------arachne1a2b--\r\n"
        ),
    ),
    (
        "basic-auth-line",
        lambda user, secret: "Authorization: Basic "
        + base64.b64encode(f"{user}:{secret}".encode()).decode(),
    ),
)

#: Response-side carriers: the session a login hands back.
_CREDENTIAL_RESPONSE_CARRIERS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("auth-cookie-header", lambda secret: f"Set-Cookie: AUTH_SID={secret}; Path=/; HttpOnly"),
    ("session-json", lambda _secret: '{"session_id": "AUTH-SESSION-TOKEN", "user": "carol"}'),
)


def _variants(family: SecretFamily) -> tuple[str, ...]:
    rng = random.Random(f"{_RNG_SEED}:{family.name}")
    return tuple(family.make(rng) for _ in range(_VARIANTS_PER_FAMILY))


def _corpus() -> list[tuple[str, str]]:
    return [(family.name, secret) for family in FAMILIES for secret in _variants(family)]


def _head(failures: list[str], limit: int = 20) -> str:
    shown = failures[:limit]
    suffix = f"\n... and {len(failures) - limit} more" if len(failures) > limit else ""
    return "\n".join(shown) + suffix


def test_no_secret_survives_in_any_text_carrier() -> None:
    assert len(_corpus()) >= 50, "the corpus collapsed; check the family generators"
    failures: list[str] = []
    for family, secret in _corpus():
        for carrier_name, build in _TEXT_CARRIERS:
            text = build(secret)
            redacted = redact_text(text)
            if secret in redacted:
                failures.append(f"[{family}/{carrier_name}] raw secret survived: {text[:80]!r}")
            if "[REDACTED" not in redacted:
                failures.append(f"[{family}/{carrier_name}] no redaction marker: {redacted[:80]!r}")
            if not contains_secret(text):
                failures.append(f"[{family}/{carrier_name}] contains_secret missed it")
    assert not failures, "secret text carriers leaked:\n" + _head(failures)


def test_no_secret_survives_in_any_header() -> None:
    failures: list[str] = []
    for family, secret in _corpus():
        for carrier_name, header_name, build in _HEADER_CARRIERS:
            value = build(secret)
            redacted = redact_headers({header_name: value})
            out = redacted[header_name]
            if secret in out:
                failures.append(f"[{family}/{carrier_name}] raw secret survived in {header_name}")
            if not out.startswith("[REDACTED"):
                failures.append(
                    f"[{family}/{carrier_name}] {header_name} not blanked: {out[:60]!r}"
                )
    assert not failures, "secret header carriers leaked:\n" + _head(failures)


def test_no_secret_survives_in_a_url_query() -> None:
    failures: list[str] = []
    for family, secret in _corpus():
        redacted = redact_url(f"https://callback.local/h?token={secret}&page=2")
        if secret in redacted:
            failures.append(f"[{family}] raw secret survived in URL: {redacted[:80]!r}")
        if not contains_secret(f"token={secret}"):
            failures.append(f"[{family}] contains_secret missed the keyed value")
    assert not failures, "URL query carriers leaked:\n" + _head(failures)


def test_pattern_recognizable_secrets_are_caught_standalone() -> None:
    """A family a ``SECRET_PATTERNS`` regex recognises must be caught with no key at all."""
    failures: list[str] = []
    families = [family for family in FAMILIES if family.standalone]
    assert families, "no standalone family left; the flag no longer tracks the patterns"
    for family in families:
        for secret in _variants(family):
            redacted = redact_text(secret)
            if secret in redacted:
                failures.append(f"[{family.name}] raw secret survived bare: {secret[:60]!r}")
            if not contains_secret(secret):
                failures.append(f"[{family.name}] contains_secret missed the bare form")
    assert not failures, "standalone pattern families leaked:\n" + _head(failures)


def test_carrier_only_families_are_not_claimed_to_be_bare_detectable() -> None:
    """Documents the other half honestly: these need a key/context, not a pattern.

    Asserting the *absence* of a bare detection keeps the boundary explicit — if someone
    later adds a prefix pattern that does catch one, this test tells them to flip its
    ``standalone`` flag and move it into the family above.
    """
    unexpectedly_caught = [
        family.name
        for family in FAMILIES
        if not family.standalone and any(contains_secret(secret) for secret in _variants(family))
    ]
    assert not unexpectedly_caught, (
        "these families are now bare-detectable; set standalone=True: "
        + ", ".join(unexpectedly_caught)
    )


def test_masked_fingerprints_never_reveal_the_whole_secret() -> None:
    """The secrets ledger input is a masked fingerprint, not the value (F-08-04)."""
    failures: list[str] = []
    for family, secret in _corpus():
        for _detector, masked in masked_secret_findings(f"token={secret}"):
            if secret in masked:
                failures.append(f"[{family}] masked fingerprint leaked the value: {masked!r}")
    assert not failures, "masking leaked:\n" + _head(failures)


def test_all_families_in_one_document_do_not_interfere() -> None:
    """A realistic 'kitchen-sink' blob: every family at once, all must be removed."""
    blob = " | ".join(
        carrier(secret) for family, secret in _corpus() for carrier in (lambda s: f'token="{s}"',)
    )
    redacted = redact_text(blob)
    leaked = [secret for _family, secret in _corpus() if secret in redacted]
    assert not leaked, f"{len(leaked)} secret(s) survived the combined document"


# ------------------------------------------------------------------ linear-cost guard
#: Generous ceiling: a linear redactor handles 256 KB of adversarial prefix soup in a few
#: milliseconds; anything superlinear blows through this by orders of magnitude.
_MAX_SECONDS = 1.0
_BIG = 256 * 1024

_ADVERSARIAL: dict[str, str] = {
    "account-key-assignments": ("AccountKey=" + "A" * 24 + ";" * 1) * (_BIG // 38),
    "sk-prefix-run": ("sk-" * (_BIG // 3))[:_BIG],
    "sk-proj-prefix-run": ("sk-proj-" * (_BIG // 8))[:_BIG],
    "npm-prefix-run": ("npm_" * (_BIG // 4))[:_BIG],
    "pypi-prefix-run": ("pypi-" * (_BIG // 5))[:_BIG],
    "sendgrid-prefix-run": ("SG." * (_BIG // 3))[:_BIG],
    "twilio-prefix-run": ("SK" * (_BIG // 2))[:_BIG],
    "github-pat-run": ("github_pat_" * (_BIG // 11))[:_BIG],
    "basic-prefix-run": ("Basic " * (_BIG // 6))[:_BIG],
    "azure-conn-run": ("DefaultEndpointsProtocol=https;AccountKey=x;" * (_BIG // 46))[:_BIG],
}


@pytest.mark.parametrize("label", sorted(_ADVERSARIAL))
def test_redaction_stays_linear_on_adversarial_input(label: str) -> None:
    text = _ADVERSARIAL[label]
    started = time.perf_counter()
    redact_text(text)
    elapsed = time.perf_counter() - started
    assert elapsed < _MAX_SECONDS, f"{label}: redact_text took {elapsed:.2f}s (superlinear?)"


@pytest.mark.parametrize("label", sorted(_ADVERSARIAL))
def test_contains_secret_stays_linear_on_adversarial_input(label: str) -> None:
    text = _ADVERSARIAL[label]
    started = time.perf_counter()
    contains_secret(text)
    elapsed = time.perf_counter() - started
    assert elapsed < _MAX_SECONDS, f"{label}: contains_secret took {elapsed:.2f}s (superlinear?)"


# --------------------------------------------------------------------------- S19 credential path
_CRED_USERNAMES: tuple[str, ...] = ("carol", "svc-backup", "alice@example.com")


def test_no_credential_survives_any_login_carrier() -> None:
    """REQ-CREDS-002: the credential path is fuzzed, and the *secret* never survives it.

    The password here is an ordinary string with no recognisable shape, so this test is really
    about the **carrier**: a form body, a JSON login, a multipart part, a query string and a
    Basic header must each have the value replaced, and the detector must fire, whatever the
    field is named and wherever it sits in the body.

    The *username* is deliberately out of scope for this assertion, and the boundary is
    recorded rather than glossed (ADR-240.7, security review §11): a username is an identifier,
    not a secret. Treating ``username``/``user``/``email`` as secret *keys* would blank exactly
    the fields ``m3.auth-session-audit``'s enumeration evidence and M4's exposure checks must
    name to be useful. The vault encrypts the username with the secret at rest and no vault
    path (handle, entry list, audit record) exposes it — that is asserted in
    ``test_a_vault_handle_never_leaks_its_material`` and in the zero-occurrence scan test.
    """
    failures: list[str] = []
    family = next(item for item in FAMILIES if item.name == "user-password")
    for secret in _variants(family):
        for username in _CRED_USERNAMES:
            for name, carrier in _CREDENTIAL_CARRIERS:
                text = carrier(username, secret)
                redacted = redact_text(text)
                if secret in redacted:
                    failures.append(f"{name}: the password survived")
                if "[REDACTED" not in redacted:
                    failures.append(f"{name}: nothing was redacted at all")
                if not contains_secret(text):
                    failures.append(f"{name}: the detector did not fire")
    assert not failures, "credential carriers leaked:\n" + _head(failures)


def test_the_username_is_not_treated_as_a_secret_key() -> None:
    """The documented boundary: identifiers stay readable (the counterpart of the test above)."""
    assert not contains_secret("username=carol&remember=1")
    assert redact_text("username=carol&remember=1") == "username=carol&remember=1"
    # ...while the value beside it is still protected, whatever the field is called.
    assert "hunter2secret" not in redact_text("username=carol&password=hunter2secret")


def test_a_session_value_never_survives_a_response_carrier() -> None:
    """A session handed back to the scanner is protected on both paths it can travel.

    A ``Set-Cookie`` value is blanked by :func:`redact_headers` — the path every response
    header actually takes through the HTTP client (``core.http._capture``), and the reason the
    session cookie is invisible to a check at all (the client's own jar holds it). A
    ``session_id`` inside a JSON body is redacted by key, which is the body path.
    """
    from arachne.core.redaction import redact_headers, redact_value

    failures: list[str] = []
    family = next(item for item in FAMILIES if item.name == "bare-hex")
    for secret in _variants(family):
        for name, carrier in _CREDENTIAL_RESPONSE_CARRIERS:
            text = carrier(secret)
            if name == "auth-cookie-header":
                redacted = redact_headers({"Set-Cookie": f"AUTH_SID={secret}; Path=/; HttpOnly"})
                leaked = any(secret in value for value in redacted.values())
            else:
                redacted = json.dumps(redact_value(json.loads(text)))
                leaked = secret in redacted
            if leaked:
                failures.append(f"{name}: the session value survived")
    # A value with no key and no shape is not a secret (the honest other half of this test).
    assert not contains_secret("AUTH-SESSION-TOKEN")
    assert not failures, _head(failures)


def test_the_multipart_carrier_leaves_a_non_credential_part_alone() -> None:
    """The part-name test is a *sensitive-name* test, not "redact every part"."""
    body = (
        '--b\r\nContent-Disposition: form-data; name="password"\r\n\r\nhunter2\r\n'
        '--b\r\nContent-Disposition: form-data; name="avatar"; filename="a.png"\r\n'
        "Content-Type: image/png\r\n\r\nPNGDATA\r\n--b--\r\n"
    )
    redacted = redact_text(body)
    assert "hunter2" not in redacted
    assert "PNGDATA" in redacted


def test_a_vault_handle_never_leaks_its_material(tmp_path: Path) -> None:
    """The handle is the check-facing surface; fuzzed secrets must not be reachable from it."""
    from arachne.core.errors import CredentialError
    from arachne.core.vault import CredentialScope, FileCredentialVault, release_seam

    vault = FileCredentialVault(tmp_path / "fuzz.enc", passphrase="fuzz-passphrase")
    family = next(item for item in FAMILIES if item.name == "user-password")
    failures: list[str] = []
    for index, secret in enumerate(_variants(family)):
        label = f"cred{index}"
        vault.put(
            label,
            kind="web-form",
            username="carol",
            secret=secret,
            scope=CredentialScope(hosts=("app.local",)),
            extra={"csrf": secret[::-1]},
        )
        handle = vault.resolve(label, host="app.local")
        assert handle is not None
        rendered = json.dumps(handle.to_dict()) + repr(handle) + str(handle.describe())
        if secret in rendered:
            failures.append(f"{label}: the secret is reachable from the handle's description")
        if secret in repr(handle.material(release_seam())):
            failures.append(f"{label}: the material's repr shows the secret")
        try:
            handle.material(object())
        except CredentialError:
            pass
        else:
            failures.append(f"{label}: the material was released without the broker's seam")
        # The entries an operator lists are metadata only.
        if secret in json.dumps([record.to_dict() for record in vault.records()]):
            failures.append(f"{label}: a listed entry carries the secret")
    assert not failures, _head(failures)


def test_no_secret_survives_an_s3_presigned_url() -> None:
    """A presigned URL is a bearer credential (S20, REQ-DATA-002).

    The signature authorises the download for as long as it lives, and the credential scope
    names the key id, so a logged or audited presigned URL is a credential on the wire. Both
    the structured path (``redact_url``, which knows the ``X-Amz-*`` query keys) and the text
    path (a URL pasted into a log line or a body) must remove it.
    """
    failures: list[str] = []
    for family, secret in _corpus():
        signature = "".join(random.Random(secret).choices(_HEX, k=64))
        url = (
            "https://s3.example.com/evidence/ab/cd/object"
            f"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={secret}"
            f"&X-Amz-Signature={signature}&X-Amz-Date=20260101T000000Z"
        )
        redacted = redact_url(url)
        text_redacted = redact_text(f"downloading {url}")
        for carrier, rendered in (("redact_url", redacted), ("redact_text", text_redacted)):
            if secret in rendered:
                failures.append(f"[{family}] credential survived {carrier}: {rendered[:90]!r}")
            if signature in rendered:
                failures.append(f"[{family}] signature survived {carrier}: {rendered[:90]!r}")
        if not contains_secret(url):
            failures.append(f"[{family}] contains_secret missed a presigned URL")
    assert not failures, "presigned URL carriers leaked:\n" + _head(failures)


def test_a_credential_inside_a_url_embedded_in_text_never_survives() -> None:
    """The URL-in-text carrier (S20 review): a logged ``url`` field is a ``redact_text`` call.

    The shared JSON log formatter redacts a string field with ``redact_text``, so
    ``{"url": "https://host/path?password=..."}`` reaches the text path — and the assignment
    scanner used to consume the whole URL as one ``key: value`` pair, hiding the inner
    parameter. Traces make this shape common (an ``http.url`` span attribute), so it is
    asserted for every generated family.
    """
    failures: list[str] = []
    for family, secret in _corpus():
        for template in (
            "source: https://example.com/login?password={secret}&page=2",
            '{{"url": "https://example.com/login?token={secret}"}}',
            "GET https://api.example.com/v1?api_key={secret} HTTP/1.1",
        ):
            carrier = template.format(secret=secret)
            redacted = redact_text(carrier)
            if secret in redacted:
                failures.append(f"[{family}] {carrier[:40]!r} → {redacted[:80]!r}")
            if not contains_secret(carrier):
                failures.append(f"[{family}] contains_secret missed {carrier[:40]!r}")
    assert not failures, "URL-in-text carriers leaked:\n" + _head(failures)
