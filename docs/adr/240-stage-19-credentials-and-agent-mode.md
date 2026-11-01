# ADR-240 — Stage 19: authenticated & agent-based scanning (area CREDS)

*Status: accepted (S19). Requirements: REQ-CREDS-001…005. Gate: G3 (`historical` spec path `docs/03-delivery-plan.md`
§5).*

## 240.1 Credentialed web scanning rides the existing HTTP path

`ScopedHttpClient` already owns a cookie jar — an `httpx.AsyncClient` stores every `Set-Cookie`
and replays it on later requests — and it already redacts `cookie`/`set-cookie`/`authorization`
at capture time. So an authenticated web session needs **no second egress path and no session
state in a check**:

1. the checks handler crawls the surface **unauthenticated** first (`ctx.web_baseline`);
2. the credential broker submits the login through the same client, whose jar now holds the
   session cookie;
3. the handler crawls again; the authenticated surface becomes `ctx.web` and the difference is
   recorded (`session.authenticated_only`).

Ordering is what makes the baseline honest: a crawl taken before the login cannot contain a
session cookie. The whole M3 pass afterwards is authenticated, which is the point of a
credentialed scan. The session token is never materialised in ARACHNE's own code — the client's
jar holds it, the exchange evidence blanks it, and a check receives a `WebSession` describing
*outcomes* (`authenticated`, `reauths`, `authenticated_only`, `logout_survived`).

**Alternative rejected:** a dedicated "authenticated client" with an operator-supplied cookie
header (the S6 `ARACHNE_WEB_SESSION_COOKIE` path). That is a static demo session, not a login:
it cannot expire, cannot be re-established, and cannot answer "did logout end the session?".

## 240.2 The vault is a node-local encrypted file, not a database table

The requirement is "encrypted at rest, exposed to checks only as opaque scoped handles"
(REQ-CREDS-002). A file satisfies it with two properties a table would not give us:

* **Node locality is structural.** "Credentials cannot leave their scan scope" (REQ-CREDS-005)
  and "an internal agent pulls jobs inside the target network" (REQ-CREDS-003) both reduce to
  *which node holds the material*. A local file answers that by construction: a node has the
  credentials it was given, and no more. A central table would make the internal node's
  credentials readable by every node that shares the database.
* **No new schema.** The S7 secrets-manifest crypto is reused verbatim
  (`core.secrets.encrypt_blob`: scrypt → SHAKE-256 keystream → HMAC-SHA256, encrypt-then-MAC)
  under a distinct magic, so a manifest cannot be replayed as a vault and no migration is
  needed.

The cost is that the vault has no API/DB surface; operators manage it with `arachne vault`
(`put`/`list`/`show`/`revoke`/`remove`), and the secret is read from an environment variable or a
prompt — never argv, so it cannot land in a shell history or a process list.

A configured `ARACHNE_VAULT_PATH` with **no** `ARACHNE_VAULT_KEY` is a refusal, not a silent
downgrade (the same rule `SecretsManifest.from_settings` applies): writing or reading
credentials in the clear would defeat the requirement the class exists for.

## 240.3 Opaque handles, one release seam

`CredentialHandle`'s public surface is `label`, `kind`, `scope` and the two scope predicates.
It *carries* the material but publishes no accessor; reading it needs
`material(seam)` where `seam` is the private token `core.vault.release_seam()` returns.
`arachne.creds` imports it and nothing in the module layer does, so a check that reaches for a
secret gets a `CredentialError` that says the boundary was crossed, rather than a value.

`CredentialMaterial.__repr__` is redacted, `CredentialEntry.to_dict()` is metadata only, and the
fuzz suite asserts that neither a handle's description nor an entry listing contains a fuzzed
secret for any of its variants.

**What the broker returns instead:**

| kind | check-facing result |
|---|---|
| `web-form` / `web-json` | `WebSession` (session established? expired? re-authenticated? what did it reach? did logout end it?) |
| `ssh` / `smb` | `ProtocolAuthResult` (attempted? accepted? the peer's NTSTATUS) |

For a protocol attempt the check supplies an `Authenticator` (the protocol byte-work stays in
the module layer, next to `m2/wire.py`); the broker reads the material, calls
`attempt(username, password, extra)` for exactly one exchange and drops it. So `m2.smb-auth` can
prove "these credentials are valid" without ever holding them.

## 240.4 M2 gets exactly one credentialed check, opt-in and single-target

`m2.smb-auth` authenticates **one operator-declared credential** against **one service** to
prove or disprove that access exists. It is `enabled_by_default=False`, needs the active-checks
opt-in *and* an attestation, and `requires_credentials=("smb",)`.

Default-credential spraying, password spraying and credential reuse across targets stay
unimplemented (M2 "Safety", research ch02#29-30). S19 changes *who may verify a
credential the operator already owns*, not whether ARACHNE guesses credentials.

The SSH half of REQ-CREDS-004 is **designed but not implemented** (deviation, recorded in the S19 acceptance record): stdlib-only SSH password auth needs a key exchange and an AEAD cipher
(`diffie-hellman-group14-sha256` + `chacha20-poly1305@openssh.com` is the realistic minimal
subset), i.e. a real client *and* a real peer in the lab. That is a work package of its own; the
spraying prohibition and the credential-kind seam (`requires_credentials=("ssh",)`) are in place
so it composes without redesign.

## 240.5 NTLMv2 is implemented, with a pinned MD4

SMB credential verification (MS-NLMP) needs an NT hash, i.e. MD4, which `hashlib` does not
guarantee (`hashlib.new("md4")` depends on OpenSSL's legacy provider). MD4 is 45 lines here,
pinned by RFC 1320 test vectors, and is used for nothing else. The rest is `hmac`/`hashlib`:
NTLMv2 hash = HMAC-MD5(NT hash, UPPER(user)+domain), response = HMAC-MD5(key, challenge+blob).
No crypto dependency is added (C-01's dependency-light default).

## 240.6 The lab's SMB conversation is stateless-per-probe

`ScopedNetClient.tcp` is request/response: one connection per probe. An NTLMSSP handshake spans
two SESSION_SETUP round trips, so the lab keeps the server challenge it issued in module state
and verifies round 2 against it. Two SMB conversations must not interleave in one test — the
protocol-lab form is sequential by construction, and the service is a fixture, not a server.

The lab verifies the NTLMv2 response the way a real server does: it recomputes the HMAC with the
password it holds (constant-time compare), so a valid/invalid credential test is a genuine
protocol exchange rather than a scripted reply.

## 240.7 The username is an identifier, not a secret

The redactor protects by *shape* (patterns) and by *key* (`password`/`token`/`secret`/…). A
username matches neither, and S19 does not add it to the sensitive-key list, deliberately:
treating `username`/`user`/`email` as secret keys would blank exactly the account names that
`m3.auth-session-audit`'s enumeration evidence and M4's exposure checks exist to report.

What S19 does guarantee, and tests:

* the **secret** appears in no log line, audit record, evidence blob, report (Markdown or JSON),
  control-plane payload or vault-file byte stream — asserted end-to-end by
  `tests/test_credential_safety.py`;
* the **username** is encrypted with the secret at rest and published by no vault path (handle
  description, entry listing, audit record, `stats["credentials"]`, report methodology);
* the only place a username is legible is the login exchange's own request body — evidence of a
  submitted form, under the same policy as every other submitted field.

## 240.8 Internal agent mode adds no gate and no relaxation

`ARACHNE_AGENT_MODE=internal` marks an agent deployed inside the target network. It changes
**where a credential may come from**, not what is allowed:

* the scan request carries credential **labels**, never material, so nothing secret crosses the
  control plane (asserted on the persisted request document);
* the label is resolved **after** leasing, against this node's own vault; a label this node does
  not hold is refused and audited (`credential.unresolved`) rather than fetched centrally — this
  is what makes "the credentials I was given" the whole story for an internal node;
* the scope, authorization and proof gates are re-run on the executing node by the same code
  path as an external agent's (`Orchestrator.execute`/`resume`, REQ-SCALE-008);
* the mode and the vault's location are on the audit trail (`agent.mode`), so "was this scan
  run from inside the network?" is answerable afterwards.

## 240.9 Report schema 1.5

`scope.credentials` (labels) and `scope.authenticated` (bool) were added to the versioned
report schema so a report can state that it describes an authenticated surface, and with which
vault entry — labels only, as the vault never publishes material. The checks step persists the
same summary into `scans.stats["credentials"]` (the S15 proof-journal pattern), which is what the
report builder reads. No existing field changed; every test that pins a schema version asserts
`REPORT_SCHEMA_VERSION`.

## 240.10 Deviations recorded

1. **REQ-CREDS-004's SSH half is designed, not implemented** (240.4). SMB is implemented and
   verified with valid and invalid credentials.
2. **The vault is a file, not a resource** (240.2): no API surface, by design.
3. `m3.session-logout` reports a session that survives a logout (CWE-613) by *re-probing*; a
   logout that only clears the client cookie is indistinguishable from a real one without
   replaying the token, which no component may do. The lab plants the honest variant (a logout
   endpoint that changes nothing), and the limitation is in the security review.
4. The crawl's destructive-path guard gained `-`/`_` as trailing boundaries (S19 review): a
   hyphenated `/logout-soft` was being *followed*, which would log the scanner out mid-scan.